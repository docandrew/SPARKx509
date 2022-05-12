with Ada.Text_IO; use Ada.Text_IO;

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

   procedure Parse_Sequence_Data (Cert_Slice : String;
                                  Index      : in out Natural;
                                  Size       : out Unsigned_32;
                                  Cert       : in out Certificate) is
   begin
      if Character'Pos (Cert_Slice (Index)) /= TYPE_SEQUENCE then
         Put_Line ("FATAL: Expected Sequence Data at " &
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

   procedure Parse_Cert_Info (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate) is
      Size : Unsigned_32;
   begin
      --  Expect a constructed universal type sequence with
      --  Version, Serial Number, Signature Algorithm, Issuer, 
      --   Validity, Subject, Subject Key Info, Extensions
      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);
   end Parse_Cert_Info;

   procedure Parse_Certificate (Cert_Bytes : String; Cert : out Certificate) is
      Index : Natural := Cert_Bytes'First;
      Size  : Unsigned_32;
   begin
      --  Expect sequence with Cert Info, Signature Algorithm, Signature
      Parse_Sequence_Data (Cert_Bytes, Index, Size, Cert);

      Parse_Cert_Info (Cert_Bytes, Index, Cert);
      -- Parse_Algorithm (Cert_Bytes (Index .. Cert_Bytes'Last), Index, Cert);
      -- Parse_Signature (Cert_Bytes (Index .. Cert_Bytes'Last), Index, Cert);
   end Parse_Certificate;

end ASN1;