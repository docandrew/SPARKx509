
with Ada.Text_IO; use Ada.Text_IO;

with OID;
with X509Ada.Debug; use X509Ada.Debug;

package body ASN1 with
   SPARK_Mode
is
   TYPE_BOOLEAN     : constant := 16#01#;
   TYPE_INTEGER     : constant := 16#02#;
   TYPE_BITSTRING   : constant := 16#03#;
   TYPE_OCTETSTRING : constant := 16#04#;
   TYPE_OBJECTID    : constant := 16#06#;
   TYPE_REAL        : constant := 16#09#;
   TYPE_UTF8STRING  : constant := 16#0C#;
   TYPE_NUMSTRING   : constant := 16#12#;
   TYPE_PRINTSTRING : constant := 16#13#;
   TYPE_UTCTIME     : constant := 16#17#;
   TYPE_SEQUENCE    : constant := 16#30#;
   TYPE_SET         : constant := 16#31#;
   TYPE_VERSION     : constant := 16#A0#;

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
         --  we balk.
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
      Put_Line (" Sequence Size: " & Size'Image);
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
      Put_Line (" Set Size: " & Size'Image);
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

      if Index + Natural (Serial_Size) > Cert_Slice'Last then
         Put_Line ("FATAL: X.509 serial length exceeds certificate size");
         Cert.Valid := False;
         return;
      end if;

      --  Read in the serial bytes.
      for I in Cert.Serial'Range loop
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
      if Num_Octets > 127 or Num_Octets + Index > Cert_Slice'Last then
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
   procedure Parse_Signature_Algorithm (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Signature_Algorithm (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Cert       : in out Certificate)
   is
      Seq_Size  : Unsigned_32;
      Object_ID : OID.Object_ID;
   begin
      --  Expect a sequence containing an object identifier
      Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);
      Parse_Object_Identifier (Cert_Slice, Index, Object_ID, Cert);

      Put_Line ("Signature Algorithm: " & Object_ID'Image);
   end Parse_Signature_Algorithm;

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
         --  different string types have different sizes here.
         Parse_Object_Identifier (Cert_Slice, Index, ID_Component, Cert);

         case ID_Component is
            when OID.COUNTRY => null;
            when OID.STATE_OR_PROVINCE => null;
            when OID.LOCALITY => null;
            when OID.ORG => null;
            when OID.ORG_UNIT => null;
            when OID.COMMON_NAME => null;
            when OID.GIVEN_NAME => null;
            when OID.SURNAME => null;
            when OID.INITIALS => null;
            when OID.GENERATION_QUALIFIER => null;
            when OID.PSEUDONYM => null;
            when others => null;
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
      Size      : Unsigned_32;
      Seq_End   : Natural;
      Object_ID : OID.Object_ID;

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

      Put_Line ("Certificate Version: " & Cert.Version'Image);
      Put ("Certificate Serial:  ");
      for I in Cert.Serial'Range loop
         PB (Cert.Serial (I));

         if I /= Cert.Serial'Last then
            Put (":");
         end if;
      end loop;
      New_Line;
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
      -- Parse_Algorithm (Cert_Bytes (Index .. Cert_Bytes'Last), Index, Cert);
      -- Parse_Signature (Cert_Bytes (Index .. Cert_Bytes'Last), Index, Cert);
   end Parse_Certificate;

end ASN1;