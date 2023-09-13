with Interfaces; use Interfaces;
with SPARKx509; use SPARKx509;
with ASN1; use ASN1;

package SPARKx509.Debug is

   procedure PB (X : in Unsigned_8);

   procedure Put_Serial (X : in Serial_Number_Type; L : in Serial_Number_Length);

   procedure Put_Key_Bytes (X : in Key_Bytes; L : in Natural);

   procedure DH (S : in String; D : in Byte_Seq);

   function To_Byte_Seq (S : String) return Byte_Seq;

end SPARKx509.Debug;
