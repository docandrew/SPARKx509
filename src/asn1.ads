with Interfaces; use Interfaces;

package ASN1 with
   SPARK_Mode
is
   --  Maximum length of serial number per RFC 5280
   type Serial_Number_Type is array (Natural range 1 .. 20) of Unsigned_8;

   -- @field Valid False if an error was found during parsing, True otherwise.
   type Certificate is record
      Valid   : Boolean;
      Version : Integer;
      Serial  : Serial_Number_Type;
   end record;

   procedure Parse_Certificate (Cert_Bytes : String; Cert : out Certificate);

end ASN1;