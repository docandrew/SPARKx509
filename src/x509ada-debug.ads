with Interfaces; use Interfaces;
with x509Ada; use x509Ada;

package x509Ada.Debug is

   procedure PB (X : in Unsigned_8);

   procedure DH (S : in String; D : in Byte_Seq);

   function To_Byte_Seq (S : String) return Byte_Seq;

end x509Ada.Debug;
