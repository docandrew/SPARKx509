with Interfaces; use Interfaces;
with SPARKx509; use SPARKx509;

package SPARKx509.Debug is

   procedure PB (X : in Unsigned_8);

   procedure DH (S : in String; D : in Byte_Seq);

   function To_Byte_Seq (S : String) return Byte_Seq;

end SPARKx509.Debug;
