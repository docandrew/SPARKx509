with Interfaces; use Interfaces;

package ASN1 with
   SPARK_Mode
is
   --  Maximum length of serial number is 20 per RFC 5280
   type Serial_Number_Type is array (Natural range <>) of Unsigned_8;

   type Object_Identifier is array (Natural range <>) of Natural;

   -- @field Valid False if an error was found during parsing, True otherwise.
   type Certificate is record
      Valid   : Boolean;
      Version : Integer;
      Serial  : Serial_Number_Type (1 .. 20) := (others => 0);
   end record;

   procedure Parse_Certificate (Cert_Bytes : String; Cert : out Certificate);

end ASN1;