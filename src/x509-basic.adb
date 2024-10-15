with Ada.Calendar.Formatting; use Ada.Calendar.Formatting;
with Ada.Strings.Bounded; use Ada.Strings.Bounded;
with Ada.Text_IO; use Ada.Text_IO;

with X509.Logs; use X509.Logs;

package body X509.Basic is

   ----------------------------------------------------------------------------
   --  Check_Bounds
   --  Convenience function for avoiding out-of-bounds indexing.
   --
   --  Given the certificate string, current index and the length of the
   --  object to be parsed, will the index remain in bounds during the
   --  object parsing?
   ----------------------------------------------------------------------------
   function Check_Bounds (Cert_Slice : String;
                          Index      : Natural;
                          Obj_Len    : Unsigned_32) return Boolean is
   begin
      return Unsigned_32 (Index) + Obj_Len - 1 <= Unsigned_32 (Cert_Slice'Last);
   end Check_Bounds;

   ---------------------------------------------------------------------------
   --  Is_String
   --  Return True if the type tag represented by the input is one of any of
   --  the possible string types. We treat them all the same.
   ---------------------------------------------------------------------------
   function Is_String (Tag : Character) return Boolean is
      Tag_C : Natural := Character'Pos (Tag);
   begin
      return Tag_C = TYPE_UTF8STRING or
             Tag_C = TYPE_PRINTSTRING or
             Tag_C = TYPE_NUMSTRING;
   end Is_String;

   ----------------------------------------------------------------------------
   --  Parse_Boolean
   ----------------------------------------------------------------------------
   procedure Parse_Boolean (Cert_Slice : String;
                            Index      : in out Natural;
                            Value      : out Boolean;
                            Cert       : in out Certificate)
   is
   begin
      Value := False;

      if not Cert.Valid then
         return;
      end if;

      Log(TRACE, "Parse_Boolean");

      if Byte_At (Cert_Slice, Index) /= TYPE_BOOLEAN then
         Log (FATAL, "Expected a Boolean at" & Index'Image & ", got " & Byte_At (Cert_Slice, Index)'Image);
         Cert.Valid := False;
         Value := False;
         return;
      end if;

      Index := Index + 1;

      --  Expect length to be 1
      if Byte_At (Cert_Slice, Index) /= 1 then
         --  Log (FATAL, "Boolean length must be 1");
         Log (FATAL, "Boolean length must be 1");
         Cert.Valid := False;
         Value := False;
         return;
      end if;

      Index := Index + 1;

      --  Expect 0x00 for False, any other value for True.
      if Byte_At (Cert_Slice, Index) = 0 then
         Value := False;
      else
         if Byte_At (Cert_Slice, Index) /= 16#FF# then
            Log (WARN, "Boolean value not 0x00 or 0xFF. Though legal, it is uncommon and may indicate a malicious or erroneous certificate.");
         end if;

         Value := True;
      end if;

      Index := Index + 1;

   end Parse_Boolean;

   ----------------------------------------------------------------------------
   --  Parse_Null
   ----------------------------------------------------------------------------
   procedure Parse_Null (Cert_Slice : String;
                         Index      : in out Natural;
                         Cert       : in out Certificate)
   is
   begin
      if not Cert.Valid then
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_NULL then
         Log (FATAL, "Expected a Null at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      --  Expect the byte following the null to be 0x00, indicating the end of this field.
      --  If it's not, then we've got a malformed certificate.
      if Cert_Slice (Index) /= ASCII.NUl then
         Log (FATAL, "Expected a Null terminator at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;
   end Parse_Null;

   ----------------------------------------------------------------------------
   --  Parse_Size
   ----------------------------------------------------------------------------
   procedure Parse_Size (Cert_Slice : String;
                         Index      : in out Natural;
                         Size       : out Unsigned_32;
                         Cert       : in out Certificate) is
      Num_Octets : Unsigned_8;
   begin
      if not Cert.Valid then
         Size := 0;
         return;
      end if;

      if (Unsigned_8 (Byte_At (Cert_Slice, Index)) and 16#80#) = 0 then
         --  If top bit is 0 then it's a short variant.
         Size := Unsigned_32 (Byte_At (Cert_Slice, Index) and 16#7F#);
         Index := Index + 1;
      else
         --  Otherwise, it's a long variant. The lower 7 bits will contain
         --  the number of octets holding the size. Anything more than 4 and
         --  we balk, since this would be an insanely long certificate and
         --  is almost certainly malicious.
         Num_Octets := (Byte_At (Cert_Slice, Index) and 16#7F#);

         if Num_Octets > 4 then
            Cert.Valid := False;
            Size := 0;
            return;
         else
            --  We were lied to about the size.
            if Cert_Slice'Last < Index + Natural (Num_Octets) then
               Cert.Valid := False;
               return;
            end if;

            Size := 0;
            Index := Index + 1;

            for I in reverse 0 .. Num_Octets - 1 loop
               Size := Size or 
                        Shift_Left (Unsigned_32 (
                           Byte_At (Cert_Slice, Index)), 
                           Natural (8 * I));
               Index := Index + 1;
            end loop;
         end if;
      end if;
   end Parse_Size;

   ----------------------------------------------------------------------------
   --  Parse_Sequence_Data
   ----------------------------------------------------------------------------
   procedure Parse_Sequence_Data (Cert_Slice : String;
                                  Index      : in out Natural;
                                  Size       : out Unsigned_32;
                                  Cert       : in out Certificate) is
   begin
      if not Cert.Valid then
         Size := 0;
         return;
      end if;

      Log (TRACE, "Parse_Sequence_Data");

      if Byte_At (Cert_Slice, Index) /= TYPE_SEQUENCE then
         Log (FATAL, "Expected a Sequence at" &
                    Index'Image &
                    " found byte" & 
                    Byte_At (Cert_Slice, Index)'Image &
                    " instead.");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

      Index := Index + 1;

      Parse_Size (Cert_Slice, Index, Size, Cert);
      -- Put_Line (" Sequence Size: " & Size'Image);

      if not Check_Bounds (Cert_Slice, Index, Size) then
         Log (FATAL, "Sequence length greater than certificate size");
         -- Put_Line ("  Cert_Slice'Last:" & Cert_Slice'Last'Image);
         -- Put_Line ("  Size: " & Size'Image);
         Cert.Valid := False;
         return;
      end if;

   end Parse_Sequence_Data;

   ----------------------------------------------------------------------------
   --  Parse_Set
   ----------------------------------------------------------------------------
   procedure Parse_Set (Cert_Slice : String;
                        Index      : in out Natural;
                        Size       : out Unsigned_32;
                        Cert       : in out Certificate)
   is
   begin
      if not Cert.Valid then
         Size := 0;
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_SET then
         Log (FATAL, "Expected a Set at " &
                   Index'Image &
                   " found byte" &
                   Byte_At (Cert_Slice, Index)'Image &
                   " instead.");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

      Index := Index + 1;

      Parse_Size (Cert_Slice, Index, Size, Cert);

      if not Check_Bounds (Cert_Slice, Index, Size) then
         Log (FATAL, "Set length greater than certificate size");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

      -- Put_Line (" Set Size: " & Size'Image);
   end Parse_Set;

   ----------------------------------------------------------------------------
   -- Parse_Bit_String_Header
   ----------------------------------------------------------------------------
   procedure Parse_Bit_String_Header (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Size       : out Unsigned_32;
                                      Cert       : in out Certificate)
   is
      Unused_Bits : Unsigned_8;
   begin
      if not Cert.Valid then
         Size := 0;
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_BITSTRING then
         Log (FATAL, "Expected a Bit String at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      -- Expect length, then a single byte containing the number of unused
      -- bits at the _end_ of the bit string.
      Parse_Size (Cert_Slice, Index, Size, Cert);
      Size := Size - 1;
      Put_Line (" Bit String Size:" & Size'Image);

      Unused_Bits := Byte_At (Cert_Slice, Index);
      Index := Index + 1;

      --  Indicates malicious or corrupted certificate.
      if Unused_Bits > 7 then
         Log (FATAL, "Excessive unused bits in bit string.");
         Cert.Valid := False;
         return;
      end if;

      Put_Line (" Unused Bits: " & Unused_Bits'Image);
   end Parse_Bit_String_Header;

   ----------------------------------------------------------------------------
   --  Parse_Object_Identifier
   ----------------------------------------------------------------------------
   procedure Parse_Object_Identifier (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Object_ID  : out OID.Object_ID;
                                      Cert       : in out Certificate)
   is
      Num_Octets : Natural;

      use type OID.Object_ID;
   begin
      if Byte_At (Cert_Slice, Index) /= TYPE_OBJECTID then
         Log (FATAL, "Expected Object Identifier for Signature Algorithm");
         Object_ID := OID.Unknown;
         Cert.Valid := False;
         return;
      end if;

      Log (TRACE, "Parse_Object_Identifier");

      Index := Index + 1;

      --  Number of octets for object ID follows
      Num_Octets := Natural (Byte_At (Cert_Slice, Index));

      --  Object ID shouldn't be more than a handful of bytes in an X.509 cert. 
      --  If the MSb is set, indicating a length > 127, or if it's longer than
      --  our cert itself, then we balk.
      if Num_Octets > 127 or 
         not Check_Bounds (Cert_Slice, Index, Unsigned_32 (Num_Octets)) then
         Log (FATAL, "Object ID too large");
         Object_ID := OID.UNKNOWN;
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      -- DH ("Looking up OID", 
      --     To_Byte_Seq (Cert_Slice (Index .. Index + Num_Octets - 1)));

      Object_ID := OID.Lookup (Cert_Slice (Index .. Index + Num_Octets - 1));

      Log (TRACE, " Found Object ID " & Object_ID'Image);

      if Object_ID = OID.Unknown then
         Cert.Valid := False;
         return;
      end if;

      Index := Index + Num_Octets;
   end Parse_Object_Identifier;

   ----------------------------------------------------------------------------
   --  Parse_Integer (small version)
   ----------------------------------------------------------------------------
   procedure Parse_Integer (Cert_Slice : String;
                            Index      : in out Natural;
                            Value      : out Integer;
                            Cert       : in out Certificate)
   is
      Size : Natural;
      Raw  : Unsigned_32 := 0;
   begin
      if not Cert.Valid then
         Value := 0;
         return;
      end if;

      Log (TRACE, "Parse_Integer");

      --  Check the tag
      if Byte_At (Cert_Slice, Index) /= TYPE_INTEGER then
         Log (FATAL, "Expected Integer");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      --  Parse the length field. For our purposes, we'll assume the length
      --  field is a single byte. If it's not, then we'll balk. MSB must be
      --  0, indicating a short form length.
      if Byte_At (Cert_Slice, Index) > 127 then
         Log (FATAL, "Integer length too large");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      Size := Natural (Byte_At (Cert_Slice, Index));

      --  Furthermore, this function is intended for parsing small integers
      --  like the version number, so we'll balk if the integer is too large.
      if Size > 4 then
         Log (FATAL, "Integer too large for this function");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      if Size = 0 then
         Log (FATAL, "Zero-length integer specified");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      --  Read in raw bytes
      Index := Index + 1;

      for I in 0 .. Size - 1 loop
         Raw := Raw or 
                  Shift_Left (Unsigned_32 (Byte_At (Cert_Slice, Index)), (8 * I));
         Index := Index + 1;
      end loop;

      --  Is MSB 1? If so then we're dealing with a 2's complement negative
      if (Raw and 16#80_00_00_00#) /= 0 then
         --  We're dealing with a negative number. We need to invert the bits
         --  and add 1 to get the absolute value.
         Raw := not Raw + 1;
         Value := - Integer (Raw);
      else
         Value := Integer (Raw);
      end if;

   end Parse_Integer;

   ----------------------------------------------------------------------------
   --  Parse_Integer (large version)
   ----------------------------------------------------------------------------
   procedure Parse_Integer (Cert_Slice : String;
                            Index      : in out Natural;
                            Length     : out Natural;
                            Bytes      : out Key_Bytes;
                            Cert       : in out Certificate)
   is
      Size : Unsigned_32 := 0;
   begin
      Length := 0;

      if not Cert.Valid then
         Bytes := (others => 0);
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_INTEGER then
         Log (FATAL, "Expected Integer");
         Bytes := (others => 0);
         Cert.Valid := False;
         return;
      end if;

      --  Skip tag
      Index := Index + 1;

      Parse_Size (Cert_Slice, Index, Size, Cert);

      if Size = 0 then
         Bytes := (others => 0);
         Cert.Valid := False;
         return;
      end if;

      Put_Line (" Size of integer: " & Size'Image);
      Length := Natural(Size);

      if Length > Key_Bytes'Length or
         not Check_Bounds (Cert_Slice, Index, Unsigned_32 (Length)) then
         Log (FATAL, "Integer too large");
         Bytes := (others => 0);
         Cert.Valid := False;
         return;
      end if;

      for I in 0 .. Length - 1 loop
         Bytes (I) := Unsigned_8 (Byte_At (Cert_Slice, Index));
         Index := Index + 1;
      end loop;
   end Parse_Integer;

   ----------------------------------------------------------------------------
   --  Parse_Bit_String
   ----------------------------------------------------------------------------
   procedure Parse_Bit_String (Cert_Slice  : String;
                               Index       : in out Natural;
                               Length      : out Natural;
                               Unused_Bits : out Unsigned_8;
                               Bytes       : out Key_Bytes;
                               Cert        : in out Certificate)
   is
      Size : Unsigned_32;
   begin
      if not Cert.Valid then
         Length := 0;
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_BITSTRING then
         Log (FATAL, "Expected a Bit String at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      -- Expect length in bytes, then a single byte containing the number of unused
      -- bits at the _end_ of the bit string.
      Parse_Size (Cert_Slice, Index, Size, Cert);
      
      if Size = 0 then
         Log (FATAL, "Bit String length cannot be zero");
         Cert.Valid := False;
         return;
      end if;

      Unused_Bits := Byte_At (Cert_Slice, Index);
      Index := Index + 1;

      --  Indicates malicious or corrupted certificate.
      if Unused_Bits > 7 then
         Log (FATAL, "Excessive unused bits in bit string.");
         Cert.Valid := False;
         Length := 0;
         return;
      end if;

      -- Adjust length to account for unused bits byte
      Length := Natural (Size) - 1;
   
      Log (TRACE, "Bit String Size (bytes):" & Length'Image);
      Log (TRACE, "Unused Bits: " & Unused_Bits'Image);

      --  Read in the bytes
      for I in 0 .. Length - 1 loop
         Bytes (I) := Unsigned_8 (Byte_At (Cert_Slice, Index));
         Index := Index + 1;
      end loop;
   end Parse_Bit_String;

   ----------------------------------------------------------------------------
   --  Parse_Time
   ----------------------------------------------------------------------------
   procedure Parse_Time (Cert_Slice : String;
                         Index      : in out Natural;
                         Period     : in out Time;
                         Cert       : in out Certificate)
   is
      Year, Month, Day, Hour, Minute, Second : Natural;
   begin

      if not Cert.Valid then
         return;
      end if;

      --  Difference is YY vs YYYY. 
      case Byte_At (Cert_Slice, Index) is
         when TYPE_UTCTIME =>
            --  Skip tag
            Index := Index + 1;

            --  Expect 13 bytes YYMMDDhhmmssZ
            if Byte_At (Cert_Slice, Index) /= 13 then
               Log (FATAL, "UTCTime must be 13 bytes");
               Cert.Valid := False;
               return;
            end if;

            --  Skip length
            Index := Index + 1;

            if not Check_Bounds (Cert_Slice, Index, 13) then
               Log (FATAL, "Time stamp too large");
               Cert.Valid := False;
               return;
            end if;
            
            Year   := Natural'Value (Cert_Slice (Index .. Index + 1));
            Index  := Index + 2;

            --  Dates after 31 Dec 2049 should use GeneralizedTime per RFC 5280
            if Year > 49 then
               Year := 1900 + Year;
            else
               Year := 2000 + Year;
            end if;

         when TYPE_GENTIME =>
            --  Skip tag
            Index := Index + 1;

            --  Expect 15 bytes YYYYMMDDhhmmssZ
            if Byte_At (Cert_Slice, Index) /= 15 then
               Log (FATAL, "Generalized_Time must be 15 bytes");
               Cert.Valid := False;
               return;
            end if;

            --  Skip length
            Index := Index + 1;

            if not Check_Bounds (Cert_Slice, Index, 13) then
               Log (FATAL, "Time stamp too large");
               Cert.Valid := False;
               return;
            end if;

            Year   := Natural'Value (Cert_Slice (Index .. Index + 3));
            Index  := Index + 4;
         when others =>
            Log (FATAL, "Expected valid time type");
            Cert.Valid := False;
            return;
      end case;

      Month  := Natural'Value (Cert_Slice (Index .. Index + 1));
      Index  := Index + 2;
      Day    := Natural'Value (Cert_Slice (Index .. Index + 1));
      Index  := Index + 2;
      Hour   := Natural'Value (Cert_Slice (Index .. Index + 1));
      Index  := Index + 2;
      Minute := Natural'Value (Cert_Slice (Index .. Index + 1));
      Index  := Index + 2;
      Second := Natural'Value (Cert_Slice (Index .. Index + 1));
      Index  := Index + 2;

      if Cert_Slice (Index) /= 'Z' then
         Log (FATAL, "Certificate validity must be a GMT time");
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      --  Make sure limits make sense
      if Month  not in 1 .. 12 or
         Day    not in 1 .. 31 or
         Hour   not in 0 .. 23 or
         Minute not in 0 .. 59 or
         Second not in 0 .. 59 then
            Log (FATAL, "Bad time stamp in certificate");
            Cert.Valid := False;
            return;
      end if;

      Period := Time_Of (Year, Month, Day, Hour, Minute, Second);

   exception
      when E : Constraint_Error =>
         Log (FATAL, "Invalid character in time stamp");
         Cert.Valid := False;
         return;
   end Parse_Time;

   ----------------------------------------------------------------------------
   --  Parse_Octet_String_Header
   ----------------------------------------------------------------------------
   procedure Parse_Octet_String_Header (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Length     : out Natural;
                                        Cert       : in out Certificate)
   is
      Size : Unsigned_32;
   begin
      if not Cert.Valid then
         Length := 0;
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_OCTETSTRING then
         Log (FATAL, "Expected an Octet String at " & Index'Image);
         Cert.Valid := False;
         Length := 0;
         return;
      end if;

      Index := Index + 1;

      Parse_Size (Cert_Slice, Index, Size, Cert);
      Log (DEBUG, "Octet String Size: " & Size'Image);
      Length := Natural(Size);
   end Parse_Octet_String_Header;

   ----------------------------------------------------------------------------
   --  Parse_Octet_String
   ----------------------------------------------------------------------------
   procedure Parse_Octet_String (Cert_Slice : String;
                                 Index      : in out Natural;
                                 Length     : out Natural;
                                 Bytes      : out Key_Bytes;
                                 Cert       : in out Certificate)
   is
   begin
      if not Cert.Valid then
         Length := 0;
         return;
      end if;

      Parse_Octet_String_Header (Cert_Slice, Index, Length, Cert);

      if not Cert.Valid or Length = 0 then
         Log (FATAL, "Octet String length cannot be zero");
         return;
      end if;

      if not Check_Bounds (Cert_Slice, Index, Unsigned_32 (Length)) then
         Log (FATAL, "Octet String length greater than certificate size");
         Cert.Valid := False;
         Length := 0;
         return;
      end if;

      for I in 0 .. Length - 1 loop
         Bytes (I) := Unsigned_8 (Byte_At (Cert_Slice, Index));
         Index := Index + 1;
      end loop;
   end Parse_Octet_String;

   ----------------------------------------------------------------------------
   --  Generic_Parse_String
   ----------------------------------------------------------------------------
   procedure Generic_Parse_String (Cert_Slice : String;
                                   Index      : in out Natural;
                                   S          : in out P.Bounded_String;
                                   Cert       : in out Certificate)
   is
      Actual_Length : Unsigned_32;
   begin
      if not Cert.Valid then
         S := P.To_Bounded_String ("");
         return;
      end if;

      if not Is_String (Cert_Slice (Index)) then
         Log (FATAL, "Expected a string type, got" & Byte_At(Cert_Slice, Index)'Image);
         Cert.Valid := False;
         S := P.To_Bounded_String ("");
         return;
      end if;

      --  Skip tag
      Index := Index + 1;

      --  Ensure length of string does not exceed the RFC string upper-bound
      Parse_Size (Cert_Slice, Index, Actual_Length, Cert);

      -- Put_Line ("String size: " & Actual_Length'Image);
      if not Cert.Valid or Actual_Length > Unsigned_32 (P.Max_Length) then
         S := P.To_Bounded_String ("");
         return;
      end if;

      if not Check_Bounds (Cert_Slice, Index, Actual_Length) then
         Cert.Valid := False;
         S := P.To_Bounded_String ("");
         return;
      end if;

      --  We ensure the string will fit within the RFC 5280 prescribed bounds,
      --  but additionally specify a "Drop" param here as it's non-throwing.
      S := P.To_Bounded_String (Source => 
                                 Cert_Slice (Index .. Index + 
                                    Natural (Actual_Length) - 1),
                                Drop   => Ada.Strings.Right);

      Index := Index + Natural (Actual_Length);
   end Generic_Parse_String;

   ----------------------------------------------------------------------------
   --  Byte_At
   ----------------------------------------------------------------------------
   function Byte_At (Cert_Slice : String; Index : in Natural) return Unsigned_8
   is
   begin
      return Character'Pos (Cert_Slice(Index));
   end Byte_At;

end X509.Basic;
