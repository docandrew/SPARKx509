package X509ada
   with SPARK_Mode
is

   type Byte is range 0 .. 255;
   type Byte_Seq is array (Natural range <>) of Byte;

end X509ada;
