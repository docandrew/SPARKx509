with Ada.Calendar.Formatting; use Ada.Calendar.Formatting;
with Ada.Text_IO; use Ada.Text_IO;

with OID;
with SPARKx509.Debug; use SPARKx509.Debug;

package body X509 with
   SPARK_Mode
is
   TYPE_BOOLEAN     : constant := 16#01#;
   TYPE_INTEGER     : constant := 16#02#;
   TYPE_BITSTRING   : constant := 16#03#;
   TYPE_OCTETSTRING : constant := 16#04#;
   TYPE_NULL        : constant := 16#05#;
   TYPE_OBJECTID    : constant := 16#06#;
   TYPE_REAL        : constant := 16#09#;
   TYPE_UTF8STRING  : constant := 16#0C#;
   TYPE_NUMSTRING   : constant := 16#12#;
   TYPE_PRINTSTRING : constant := 16#13#;
   TYPE_UTCTIME     : constant := 16#17#;
   TYPE_GENTIME     : constant := 16#18#;
   TYPE_SEQUENCE    : constant := 16#30#;
   TYPE_SET         : constant := 16#31#;
   TYPE_VERSION     : constant := 16#A0#;

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

   --  Fwd declare and contracts
   procedure Parse_Size (Cert_Slice : String;
                         Index      : in out Natural;
                         Size       : out Unsigned_32;
                         Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

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

      if (Unsigned_8 (Character'Pos (Cert_Slice (Index))) and 16#80#) = 0 then
         --  If top bit is 0 then it's a short variant.
         Size := Character'Pos (Cert_Slice (Index)) and 16#7F#;
         Index := Index + 1;
      else
         --  Otherwise, it's a long variant. The lower 7 bits will contain
         --  the number of octets holding the size. Anything more than 4 and
         --  we balk, since this would be an insanely long certificate and
         --  is almost certainly malicious.
         Num_Octets := (Character'Pos (Cert_Slice (Index)) and 16#7F#);

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
                           Character'Pos (Cert_Slice (Index))), 
                           Natural (8 * I));
               Index := Index + 1;
            end loop;
         end if;
      end if;
   end Parse_Size;

   ---------------------------------------------------------------------------
   -- Return True if the type tag represented by the input is one of any of
   -- the possible string types.
   ---------------------------------------------------------------------------
   function Is_String (Tag : Character) return Boolean is
      Tag_C : Natural := Character'Pos (Tag);
   begin
      return Tag_C = TYPE_UTF8STRING or
             Tag_C = TYPE_PRINTSTRING or
             Tag_C = TYPE_NUMSTRING;
   end Is_String;

   ---------------------------------------------------------------------------
   -- Parse_String
   ---------------------------------------------------------------------------
   generic
      with Package P is new Generic_Bounded_Length (<>);
   procedure Generic_Parse_String (Cert_Slice : String;
                                   Index      : in out Natural;
                                   S          : in out P.Bounded_String;
                                   Cert       : in out Certificate);

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
         Put_Line ("FATAL: Expected a string type");
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

   --  Generic instantiations for the various bounded string types
   procedure Parse_Country
      is new Generic_Parse_String (UB_Country_Name);
   procedure Parse_State
      is new Generic_Parse_String (UB_State);
   procedure Parse_Locality
      is new Generic_Parse_String (UB_Locality);
   procedure Parse_Common_Name
      is new Generic_Parse_String (UB_Common_Name);
   procedure Parse_Org
      is new Generic_Parse_String (UB_Org);
   procedure Parse_Org_Unit
      is new Generic_Parse_String (UB_Org_Unit);
   procedure Parse_Title
      is new Generic_Parse_String (UB_Title);
   procedure Parse_Given_Name
      is new Generic_Parse_String (UB_Given_Name);
   procedure Parse_Surname
      is new Generic_Parse_String (UB_Surname);
   procedure Parse_Initials
      is new Generic_Parse_String (UB_Initials);
   procedure Parse_Pseudonym
      is new Generic_Parse_String (UB_Pseudonym);
   procedure Parse_Generation
      is new Generic_Parse_String (UB_Generation);

   --  Fwd declare and contracts
   procedure Parse_Null (Cert_Slice : String;
                         Index      : in out Natural;
                         Cert       : in out Certificate);

   procedure Parse_Null (Cert_Slice : String;
                         Index      : in out Natural;
                         Cert       : in out Certificate)
   is
   begin
      if not Cert.Valid then
         return;
      end if;

      if Character'Pos (Cert_Slice (Index)) /= TYPE_NULL then
         Put_Line ("FATAL: Expected a Null at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      --  Expect the byte following the null to be 0x00, indicating the end of this field.
      --  If it's not, then we've got a malformed certificate.
      if Cert_Slice (Index) /= ASCII.NUl then
         Put_Line ("FATAL: Expected a Null terminator at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;
   end Parse_Null;

   --  Fwd declare and contracts
   procedure Parse_Sequence_Data (Cert_Slice : String;
                                  Index      : in out Natural;
                                  Size       : out Unsigned_32;
                                  Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Sequence_Data (Cert_Slice : String;
                                  Index      : in out Natural;
                                  Size       : out Unsigned_32;
                                  Cert       : in out Certificate) is
   begin
      if not Cert.Valid then
         Size := 0;
         return;
      end if;

      if Character'Pos (Cert_Slice (Index)) /= TYPE_SEQUENCE then
         Put_Line ("FATAL: Expected a Sequence at " &
                    Index'Image &
                    " found byte" & 
                    Character'Pos (Cert_Slice (Index))'Image &
                    " instead.");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

      Index := Index + 1;

      Parse_Size (Cert_Slice, Index, Size, Cert);
      -- Put_Line (" Sequence Size: " & Size'Image);

      if not Check_Bounds (Cert_Slice, Index, Size) then
         Put_Line ("FATAL: Sequence length greater than certificate size");
         -- Put_Line ("  Cert_Slice'Last:" & Cert_Slice'Last'Image);
         -- Put_Line ("  Size: " & Size'Image);
         Cert.Valid := False;
         return;
      end if;

   end Parse_Sequence_Data;

   --  Fwd declare and contracts
   procedure Parse_Set (Cert_Slice : String;
                        Index      : in out Natural;
                        Size       : out Unsigned_32;
                        Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

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

      if Character'Pos (Cert_Slice (Index)) /= TYPE_SET then
         Put_Line ("FATAL: Expected a Set at " &
                   Index'Image &
                   " found byte" &
                   Character'Pos (Cert_Slice (Index))'Image &
                   " instead.");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

      Index := Index + 1;

      Parse_Size (Cert_Slice, Index, Size, Cert);

      if not Check_Bounds (Cert_Slice, Index, Size) then
         Put_Line ("FATAL: Set length greater than certificate size");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

      -- Put_Line (" Set Size: " & Size'Image);
   end Parse_Set;

   --  Fwd declare and contracts
   procedure Parse_Version (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Version (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate) is
      Version : Natural;
   begin
      if not Cert.Valid then
         return;
      end if;

      if Character'Pos (Cert_Slice (Index)) /= TYPE_VERSION then
         --  no version supplied, assume v1, Index remains unchanged
         Put_Line ("No X.509 version supplied, assuming default v1");
         Cert.Version := 1;
      else
         Index := Index + 1;
         --  How long? Should be 3 bytes representing a universal type integer
         if Character'Pos (Cert_Slice (Index)) /= 3 then
            Put_Line ("FATAL: Expected X.509 version to be 3 bytes (it wasn't).");
            Cert.Valid := False;
            return;
         end if;

         --  Version should be a universal type integer
         Index := Index + 1;
         if Character'Pos (Cert_Slice (Index)) /= TYPE_INTEGER then
            Put_Line ("FATAL: Expected X.509 version to be an integer");
            Cert.Valid := False;
            return;
         end if;

         --  Integer should be 1 byte long
         Index := Index + 1;
         if Character'Pos (Cert_Slice (Index)) /= 1 then
            Put_Line ("FATAL: Expected X.509 version integer to be 1 byte");
            Cert.Valid := False;
            return;
         end if;

         Index := Index + 1;
         Version := Character'Pos (Cert_Slice (Index));

         if not (Version in 1 | 2 | 3) then
            Put_Line ("FATAL: Expected X.509 version 1, 2 or 3, got" &
                      Version'Image);
            Cert.Valid := False;
            return;
         else
            Index := Index + 1;
            Cert.Version := Version;
         end if;
      end if;
   end Parse_Version;

   --  Fwd declare and contracts
   procedure Parse_Serial (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Serial (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate) is
      Serial_Size : Unsigned_32;
   begin
      if not Cert.Valid then
         return;
      end if;

      --  Serial number should be a universal integer
      if Character'Pos (Cert_Slice (Index)) /= TYPE_INTEGER then
         Put_Line ("FATAL: Expected X.509 serial number (ASN.1 Integer)");
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;
      Parse_Size (Cert_Slice, Index, Serial_Size, Cert);

      --  RFC 5280 mandates serials no larger than 20 bytes.
      if Serial_Size > 20 then
         Put_Line ("FATAL: X.509 Serial Number too large");
         Cert.Valid := False;
         return;
      end if;

      if Serial_Size = 0 then
         Put_Line ("FATAL: X.509 Serial Number length cannot be zero");
         Cert.Valid := False;
         return;
      end if;

      if Index + Natural (Serial_Size) > Cert_Slice'Last then
         Put_Line ("FATAL: X.509 serial length exceeds certificate size");
         Cert.Valid := False;
         return;
      end if;

      Cert.Serial_Length := Serial_Number_Length(Serial_Size);

      --  Read in the serial bytes.
      for I in 1 .. Cert.Serial_Length loop
         Cert.Serial (I) := Unsigned_8 (Character'Pos (Cert_Slice (Index)));
         Index := Index + 1;
      end loop;
   end Parse_Serial;

   --  Fwd declare and contracts
   procedure Parse_Object_Identifier (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Object_ID  : out OID.Object_ID;
                                      Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Object_Identifier (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Object_ID  : out OID.Object_ID;
                                      Cert       : in out Certificate)
   is
      Num_Octets : Natural;

      use type OID.Object_ID;
   begin
      if Character'Pos (Cert_Slice (Index)) /= TYPE_OBJECTID then
         Put_Line ("FATAL: Expected Object Identifier for Signature Algorithm");
         Object_ID := OID.Unknown;
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      --  Number of octets for object ID follows
      Num_Octets := Character'Pos (Cert_Slice (Index));

      --  Object ID shouldn't be more than a handful of bytes in an X.509 cert. 
      --  If the MSb is set, indicating a length > 127, or if it's longer than
      --  our cert itself, then we balk.
      if Num_Octets > 127 or 
         not Check_Bounds (Cert_Slice, Index, Unsigned_32 (Num_Octets)) then
         Put_Line ("FATAL: Object ID too large");
         Object_ID := OID.UNKNOWN;
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      -- DH ("Looking up OID", 
      --     To_Byte_Seq (Cert_Slice (Index .. Index + Num_Octets - 1)));

      Object_ID := OID.Lookup (Cert_Slice (Index .. Index + Num_Octets - 1));

      if Object_ID = OID.Unknown then
         Cert.Valid := False;
         return;
      end if;

      Index := Index + Num_Octets;
   end Parse_Object_Identifier;

   --  Fwd declare and contracts
   --  Parse_Integer
   --  Parse an ASN.1 integer. This is a universal type, so we expect the
   --  tag to be 0x02. The length of the integer is variable, so we need
   --  to parse the length field to determine how many bytes to read.
   procedure Parse_Integer (Cert_Slice : String;
                            Index      : in out Natural;
                            Value      : out Integer;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

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

      --  Check the tag
      if Character'Pos (Cert_Slice (Index)) /= TYPE_INTEGER then
         Put_Line ("FATAL: Expected Integer");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      --  Parse the length field. For our purposes, we'll assume the length
      --  field is a single byte. If it's not, then we'll balk. MSB must be
      --  0, indicating a short form length.
      if Character'Pos (Cert_Slice (Index)) > 127 then
         Put_Line ("FATAL: Integer length too large");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      Size := Character'Pos (Cert_Slice (Index));

      --  Furthermore, this function is intended for parsing small integers
      --  like the version number, so we'll balk if the integer is too large.
      if Size > 4 then
         Put_Line ("FATAL: Integer too large for this function");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      if Size = 0 then
         Put_Line ("FATAL: Zero-length integer specified");
         Value := 0;
         Cert.Valid := False;
         return;
      end if;

      --  Read in raw bytes
      Index := Index + 1;

      for I in 0 .. Size - 1 loop
         Raw := Raw or 
                  Shift_Left (Unsigned_32 (Character'Pos (Cert_Slice (Index))), (8 * I));
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

   --  Fwd declare and contracts
   --  Parse_Integer for large integers like a RSA key modulus
   procedure Parse_Integer (Cert_Slice : String;
                            Index      : in out Natural;
                            Length     : out Natural;
                            Bytes      : out Key_Bytes;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

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

      if Character'Pos (Cert_Slice (Index)) /= TYPE_INTEGER then
         Put_Line ("FATAL: Expected Integer");
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
         Put_Line ("FATAL: Integer too large");
         Bytes := (others => 0);
         Cert.Valid := False;
         return;
      end if;

      for I in 0 .. Length - 1 loop
         Bytes (I) := Unsigned_8 (Character'Pos (Cert_Slice (Index)));
         Index := Index + 1;
      end loop;
   end Parse_Integer;

   --  Fwd declare and contracts
   procedure Parse_Bit_String (Cert_Slice : String;
                               Index      : in out Natural;
                               Length     : out Natural;
                               Bytes      : out Key_Bytes;
                               Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Bit_String (Cert_Slice : String;
                               Index      : in out Natural;
                               Length     : out Natural;
                               Bytes      : out Key_Bytes;
                               Cert       : in out Certificate)
   is
      Size : Unsigned_32;
      Unused_Bits : Unsigned_8;
   begin
      if not Cert.Valid then
         Length := 0;
         return;
      end if;

      if Character'Pos (Cert_Slice (Index)) /= TYPE_BITSTRING then
         Put_Line ("FATAL: Expected a Bit String at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      -- Expect length in bytes, then a single byte containing the number of unused
      -- bits at the _end_ of the bit string.
      Parse_Size (Cert_Slice, Index, Size, Cert);
      
      if Size = 0 then
         Put_Line ("FATAL: Bit String length cannot be zero");
         Cert.Valid := False;
         return;
      end if;

      Unused_Bits := Character'Pos (Cert_Slice (Index));
      Index := Index + 1;

      --  Indicates malicious or corrupted certificate.
      if Unused_Bits > 7 then
         Put_Line ("FATAL: Excessive unused bits in bit string.");
         Cert.Valid := False;
         Length := 0;
         return;
      end if;

      -- Adjust length to account for unused bits byte
      Length := Natural (Size) - 1;
   
      Put_Line (" Bit String Size (bytes):" & Length'Image);
      Put_Line (" Unused Bits: " & Unused_Bits'Image);

      --  Read in the bytes
      for I in 0 .. Length - 1 loop
         Bytes (I) := Unsigned_8 (Character'Pos (Cert_Slice (Index)));
         Index := Index + 1;
      end loop;
   end Parse_Bit_String;

   --  Fwd declare and contracts
   --  Parse_Bit_String_Header parses the header of a bit string, but does not
   --  read in the bytes. This is useful for bit strings which are actually
   --  sequences of other objects, like the public key.
   --  @param Size is the size of the bit string in bytes, not including the
   --     unused bits byte.
   procedure Parse_Bit_String_Header (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Size       : out Unsigned_32;
                                      Cert       : in out Certificate);

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

      if Character'Pos (Cert_Slice (Index)) /= TYPE_BITSTRING then
         Put_Line ("FATAL: Expected a Bit String at " & Index'Image);
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;

      -- Expect length, then a single byte containing the number of unused
      -- bits at the _end_ of the bit string.
      Parse_Size (Cert_Slice, Index, Size, Cert);
      Size := Size - 1;
      Put_Line (" Bit String Size:" & Size'Image);

      Unused_Bits := Character'Pos (Cert_Slice (Index));
      Index := Index + 1;

      --  Indicates malicious or corrupted certificate.
      if Unused_Bits > 7 then
         Put_Line ("FATAL: Excessive unused bits in bit string.");
         Cert.Valid := False;
         return;
      end if;

      Put_Line (" Unused Bits: " & Unused_Bits'Image);
   end Parse_Bit_String_Header;

   --  Fwd declare and contracts
   procedure Parse_Algorithm (Cert_Slice : String;
                              Index      : in out Natural;
                              Algorithm  : in out Algorithm_Identifier;
                              Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Algorithm (Cert_Slice : String;
                              Index      : in out Natural;
                              Algorithm  : in out Algorithm_Identifier;
                              Cert       : in out Certificate)
   is
      Seq_Size   : Unsigned_32;
      Object_ID  : OID.Object_ID;
   begin
      --  Expect a sequence containing an object identifier and then an optional parameter
      Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);

      if not Cert.Valid then
         return;
      end if;

      Parse_Object_Identifier (Cert_Slice, Index, Object_ID, Cert);

      if not Cert.Valid then
         return;
      end if;

      if Object_ID not in RSA_ENCRYPTION .. ID_EDDSA448_PH then
         Put_Line ("FATAL: Unknown Signature Algorithm");
         Algorithm := UNKNOWN_ALGORITHM;
         Cert.Valid := False;
         return;
      else
         Algorithm := Algorithm_Identifier (Object_ID);
         Cert.Signature_Algorithm := Algorithm;
      end if;

      -- Depends on signature algorithm
      case Algorithm is
         when RSA_ENCRYPTION | SHA256_WITH_RSA | SHA384_WITH_RSA | SHA512_WITH_RSA | SHA224_WITH_RSA =>
            -- Expect a single parameter, a null
            Parse_Null (Cert_Slice, Index, Cert);
         when ID_EDDSA25519 =>
            -- Expect no parameters
            null;
         when others =>
            Put_Line ("FATAL: Unsupported Algorithm " & Algorithm'Image);
      end case;
   end Parse_Algorithm;

   --  Fwd declare and contracts
   procedure Parse_Signature_Algorithm (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Signature_Algorithm (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Cert       : in out Certificate)
   is
   begin
      Parse_Algorithm (Cert_Slice, Index, Cert.Signature_Algorithm, Cert);
   end Parse_Signature_Algorithm;

   --  Fwd declare and contracts
   procedure Parse_Public_Key_Algorithm (Cert_Slice : String;
                                         Index      : in out Natural;
                                         Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;                                         
   
   procedure Parse_Public_Key_Algorithm (Cert_Slice : String;
                                         Index      : in out Natural;
                                         Cert       : in out Certificate)
   is
   begin
      Parse_Algorithm (Cert_Slice, Index, Cert.Public_Key_Algorithm, Cert);
   end Parse_Public_Key_Algorithm;

   --  Fwd declare and contracts
   procedure Parse_Identification (Cert_Slice : String;
                                   Index      : in out Natural;
                                   ID         : in out Identification_Type;
                                   Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Identification (Cert_Slice : String;
                                   Index      : in out Natural;
                                   ID         : in out Identification_Type;
                                   Cert       : in out Certificate)
   is
      Size          : Unsigned_32;
      Seq_End       : Natural;
      ID_Component  : OID.Object_ID;
   begin
      --  Expect a sequence of sets of sequences
      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);
      
      if Cert.Valid and Size /= 0 then
         Seq_End := Index + Natural (Size);
      else
         Cert.Valid := False;
         return;
      end if;
      
      while Index < Seq_End loop
         Parse_Set (Cert_Slice, Index, Size, Cert);
         Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);

         --  Expect Object Identifier and then a string of some sort. The type
         --  of string we'll parse depends on the object ID. This is because
         --  different string types have different sizes/character sets here.
         Parse_Object_Identifier (Cert_Slice, Index, ID_Component, Cert);

         if not Cert.Valid then
            return;
         end if;

         case ID_Component is
            when OID.COUNTRY =>
               Put ("Country: ");
               Parse_Country (Cert_Slice, Index, ID.Country, Cert);
               Put_Line (UB_Country_Name.To_String (ID.Country));
            when OID.STATE_OR_PROVINCE =>
               Put ("State: ");
               Parse_State (Cert_Slice, Index, ID.State, Cert);
               Put_Line (UB_State.To_String (ID.State));
            when OID.LOCALITY =>
               Put ("Locality: ");
               Parse_Locality (Cert_Slice, Index, ID.Locality, Cert);
               Put_Line (UB_Locality.To_String (ID.Locality));
            when OID.ORG =>
               Put ("Organization: ");
               Parse_Org (Cert_Slice, Index, ID.Org, Cert);
               Put_Line (UB_Org.To_String (ID.Org));
            when OID.ORG_UNIT =>
               Put ("Organizational Unit: ");
               Parse_Org_Unit (Cert_Slice, Index, ID.Org_Unit, Cert);
               Put_Line (UB_Org_Unit.To_String (ID.Org_Unit));
            when OID.COMMON_NAME =>
               Put ("Common Name: ");
               Parse_Common_Name (Cert_Slice, Index, ID.Common_Name, Cert);
               Put_Line (UB_Common_Name.To_String (ID.Common_Name));
            when OID.GIVEN_NAME =>
               Put ("Given Name: ");
               Parse_Given_Name (Cert_Slice, Index, ID.Given_Name, Cert);
               Put_Line (UB_Given_Name.To_String (ID.Given_Name));
            when OID.SURNAME =>
               Put ("Surname: ");
               Parse_Surname (Cert_Slice, Index, ID.Surname, Cert);
               Put_Line (UB_Surname.To_String (ID.Surname));
            when OID.INITIALS =>
               Put ("Initials: ");
               Parse_Initials (Cert_Slice, Index, ID.Initials, Cert);
               Put_Line (UB_Initials.To_String (ID.Initials));
            when OID.GENERATION_QUALIFIER =>
               Put ("Generation: ");
               Parse_Generation (Cert_Slice, Index, ID.Generation, Cert);
               Put_Line (UB_Generation.To_String (ID.Generation));
            when OID.PSEUDONYM =>
               Put ("Pseudonym: ");
               Parse_Pseudonym (Cert_Slice, Index, ID.Pseudonym, Cert);
               Put_Line (UB_Pseudonym.To_String (ID.Pseudonym));
            when others =>
               Put_Line ("FATAL: Inappropriate Identification Field");
               Cert.Valid := False;
               return;
         end case;
      end loop;
   end Parse_Identification;

   --  Fwd declare and contracts
   procedure Parse_Issuer (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Issuer (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate)
   is
   begin
      Parse_Identification (Cert_Slice, Index, Cert.Issuer, Cert);
   end Parse_Issuer;

   --  Fwd declare and contracts
   procedure Parse_Subject (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Subject (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
   is
   begin
      Parse_Identification (Cert_Slice, Index, Cert.Subject, Cert);
   end Parse_Subject;

   --  Fwd declare and contracts
   procedure Parse_Time (Cert_Slice : String;
                         Index      : in out Natural;
                         Period     : in out Time;
                         Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
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
      case Character'Pos (Cert_Slice (Index)) is
         when TYPE_UTCTIME =>
            --  Skip tag
            Index := Index + 1;

            --  Expect 13 bytes YYMMDDhhmmssZ
            if Character'Pos (Cert_Slice (Index)) /= 13 then
               Put_Line ("FATAL: UTCTime must be 13 bytes");
               Cert.Valid := False;
               return;
            end if;

            --  Skip length
            Index := Index + 1;

            if not Check_Bounds (Cert_Slice, Index, 13) then
               Put_Line ("FATAL: Time stamp too large");
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
            if Character'Pos (Cert_Slice (Index)) /= 15 then
               Put_Line ("FATAL: Generalized_Time must be 15 bytes");
               Cert.Valid := False;
               return;
            end if;

            --  Skip length
            Index := Index + 1;

            if not Check_Bounds (Cert_Slice, Index, 13) then
               Put_Line ("FATAL: Time stamp too large");
               Cert.Valid := False;
               return;
            end if;

            Year   := Natural'Value (Cert_Slice (Index .. Index + 3));
            Index  := Index + 4;
         when others =>
            Put_Line ("FATAL: Expected valid time type");
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
         Put_Line ("FATAL: Certificate validity must be a GMT time");
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
            Put_Line ("FATAL: Bad time stamp in certificate");
            Cert.Valid := False;
            return;
      end if;

      Period := Time_Of (Year, Month, Day, Hour, Minute, Second);

   exception
      when E : Constraint_Error =>
         Put_Line ("FATAL: Invalid character in time stamp");
         Cert.Valid := False;
         return;
   end Parse_Time;

   --  Fwd declare and contracts
   procedure Parse_Validity_Period (Cert_Slice : String;
                                    Index      : in out Natural;
                                    Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Validity_Period (Cert_Slice : String;
                                    Index      : in out Natural;
                                    Cert       : in out Certificate)
   is
      Seq_Size : Unsigned_32;
   begin
      if not Cert.Valid then
         return;
      end if;

      --  Expect a sequence of 2 UTCTime objects or 2 GeneralizedTime
      --  objects.
      Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);
      Parse_Time (Cert_Slice, Index, Cert.Valid_From, Cert);
      Parse_Time (Cert_Slice, Index, Cert.Valid_To, Cert);
   end Parse_Validity_Period;

   --  Fwd declare and contracts
   procedure Parse_RSA_Key (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_RSA_Key (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
   is
      Bit_String_Size : Unsigned_32;
      Seq_Size        : Unsigned_32;

      Modulus_Size    : Natural;
      Modulus         : Key_Bytes;
      Exponent        : Integer;
   begin
      --  RSA public key is a Bit String containing a sequence of two
      --  integers, modulus and exponent
      Parse_Bit_String_Header (Cert_Slice, Index, Bit_String_Size, Cert);

      if not Cert.Valid or Bit_String_Size = 0 then
         Put_Line ("FATAL: Invalid RSA public key bit string");
         return;
      end if;

      Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);

      if not Cert.Valid OR Seq_Size = 0 then
         Put_Line ("FATAL: Invalid RSA public key sequence");
         return;
      end if;

      --  Modulus
      Parse_Integer (Cert_Slice, Index, Modulus_Size, Modulus, Cert);

      Put_Line (" Cert still valid? " & Boolean'Image (Cert.Valid));
      Put_Line (" Modulus Bytes:");
      Put_Key_Bytes (Modulus, Natural(Modulus_Size));
      --  Exponent
      Parse_Integer (Cert_Slice, Index, Exponent, Cert);

      if Exponent < 0 then
         Put_Line ("FATAL: RSA public key exponent cannot be negative");
         Cert.Valid := False;
         return;
      end if;

      if Cert.Valid then
         Cert.Public_Key.Modulus_Length := Natural (Modulus_Size);
         Cert.Public_Key.Modulus := Modulus;
         Cert.Public_Key.Exponent := Unsigned_32(Exponent);
      end if;
   end Parse_RSA_Key;

   --  Fwd declare and contracts
   --  Parse_ED25519_Key
   --  Parse an ED25519 public key. This is a bit string with the key
   procedure Parse_ED25519_Key (Cert_Slice : String;
                                Index      : in out Natural;
                                Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_ED25519_Key (Cert_Slice : String;
                                Index      : in out Natural;
                                Cert       : in out Certificate)
   is
      Length : Integer;
      Key    : Key_Bytes;
   begin

      if not Cert.Valid then
         return;
      end if;

      Parse_Bit_String (Cert_Slice, Index, Length, Key, Cert);

      if not Cert.Valid or Length /= ED25519_PUBLIC_KEY_SIZE then
         Put_Line ("FATAL: Invalid ED25519 public key bit string");
         return;
      end if;

      Put_Line (" Key Bytes:");
      Put_Key_Bytes (Key, Natural (Length));

      Cert.Public_Key.Key := Key;
      Cert.Public_Key.Key_Size := Natural (Length);
   end Parse_ED25519_Key;

   --  Fwd declare and contracts
   procedure Parse_Public_Key (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Public_Key (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
   is
   begin
      --  Format of the public key depends on the algorithm
      case Cert.Public_Key_Algorithm is
         when RSA_ENCRYPTION =>
            Cert.Public_Key := (Key_Type => RSA_ENCRYPTION, others => <>);
            Parse_RSA_Key (Cert_Slice, Index, Cert);
         when ID_EDDSA25519 =>
            Cert.Public_Key := (Key_Type => ID_EDDSA25519, others => <>);
            Parse_ED25519_Key (Cert_Slice, Index, Cert);
         when others =>
            Put_Line ("FATAL: Unsupported public key algorithm.");
            Cert.Valid := False;
            return;
      end case;
   end Parse_Public_Key;

   --  Fwd declare and contracts
   procedure Parse_Public_Key_Info (Cert_Slice : String;
                                            Index      : in out Natural;
                                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Public_Key_Info (Cert_Slice : String;
                                            Index      : in out Natural;
                                            Cert       : in out Certificate)
   is
      Size : Unsigned_32;
   begin
      if not Cert.Valid then
         return;
      end if;

      -- Expect a sequence of key algo and the key itself.
      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);

      if not Cert.Valid then
         return;
      end if;

      Parse_Public_Key_Algorithm (Cert_Slice, Index, Cert);

      if not Cert.Valid then
         return;
      end if;

      Parse_Public_Key (Cert_Slice, Index, Cert);
   end Parse_Public_Key_Info;

   -- Fwd declare and contracts
   procedure Parse_Extension (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Extension (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
   is
   begin
      null;
   end Parse_Extension;

   -- Fwd declare and contracts
   procedure Parse_Extensions (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Extensions (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
   is
      Size : Unsigned_32;
      Extensions_Start : Natural;
   begin
      --  Expect a sequence of extensions
      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);

      if not Cert.Valid then
         return;
      end if;

      --  Parse each extension
      while Index < Cert.Extensions_Len + Extensions_Start loop
         Parse_Extension (Cert_Slice, Index, Cert);
      end loop;
   end Parse_Extensions;

   --  Fwd declare and contracts
   procedure Parse_Cert_Info (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Cert_Info (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
   is
      Size : Unsigned_32;
   begin
      --  Expect a constructed universal type sequence with
      --  Version, Serial Number, Signature Algorithm, Issuer, 
      --   Validity, Subject, Subject Key Info, Extensions
      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);
      Parse_Version (Cert_Slice, Index, Cert);
      Parse_Serial (Cert_Slice, Index, Cert);
      Parse_Signature_Algorithm (Cert_Slice, Index, Cert);
      Parse_Issuer (Cert_Slice, Index, Cert);
      Parse_Validity_Period (Cert_Slice, Index, Cert);
      Parse_Subject (Cert_Slice, Index, Cert);
      Parse_Public_Key_Info (Cert_Slice, Index, Cert);
      Parse_Extensions (Cert_Slice, Index, Cert);

      if not Cert.Valid then
         Put_Line ("Parse Error.");
         return;
      end if;

      Put_Line ("Valid From: " & Image (Cert.Valid_From));
      Put_Line ("Valid To:   " & Image (Cert.Valid_To));

      Put_Line ("Certificate Version: " & Cert.Version'Image);
      Put ("Certificate Serial:  ");

      Put_Serial (Cert.Serial, Cert.Serial_Length);
      New_Line;

      Put_Line ("Signature Algorithm: " & Cert.Signature_Algorithm'Image);
      Put_Line ("Certificate Algorithm: " & Cert.Public_Key_Algorithm'Image);
   end Parse_Cert_Info;

   procedure Parse_Certificate (Cert_Bytes : String; Cert : out Certificate)
   is
      Index    : Natural := Cert_Bytes'First;
      Size     : Unsigned_32;
      Msg_Size : Natural;
   begin
      --  Cert is valid until proven otherwise.
      Cert.Valid := True;

      --  Expect sequence with Cert Info, Signature Algorithm, Signature
      Parse_Sequence_Data (Cert_Bytes, Index, Size, Cert);
      Msg_Size := Cert_Bytes'Last - Index + 1;

      --  Sanity check that size of sequence = size of rest of message
      if Size /= Unsigned_32 (Msg_Size) then
         Put_Line ("FATAL: X.509 Sequence Size doesn't match message size");
         Put_Line (" Expected:" & Size'Image & " Actual:" & Msg_Size'Image);
         Cert.Valid := False;
         return;
      end if;

      Parse_Cert_Info (Cert_Bytes, Index, Cert);
   end Parse_Certificate;

end X509;
