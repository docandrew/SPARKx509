with x509Ada; use x509Ada;

package x509Ada.Debug is

   procedure DH (S : in String; D : in Byte_Seq);

   function To_Byte_Seq (S : String) return Byte_Seq;

end x509Ada.Debug;
