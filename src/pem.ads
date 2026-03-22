---------------------------------------------------------------------------
--  @summary
--  PEM Decoding Routines
--
--  @description
--  This package decodes PEM-encoded data (RFC 7468) to raw DER bytes.
--  PEM is Base64-wrapped DER with header/footer lines, e.g.:
--
--    -----BEGIN CERTIFICATE-----
--    MIIBfz...
--    -----END CERTIFICATE-----
--
--  Supported labels: CERTIFICATE, PRIVATE KEY, PUBLIC KEY, and any
--  other label — the label is returned so the caller can check it.
---------------------------------------------------------------------------
package PEM
   with SPARK_Mode
is
   Max_DER_Length   : constant := 65536;
   Max_Label_Length : constant := 64;

   subtype DER_Index is Natural range 0 .. Max_DER_Length - 1;
   subtype DER_Bytes is String (1 .. Max_DER_Length);

   subtype Label_String is String (1 .. Max_Label_Length);

   type Decode_Result is record
      OK        : Boolean := False;
      Label     : Label_String := (others => ' ');
      Label_Len : Natural := 0;
      DER       : DER_Bytes := (others => Character'Val (0));
      DER_Len   : Natural := 0;
   end record;

   ---------------------------------------------------------------------------
   --  Decode a PEM-encoded string to raw DER bytes.
   --
   --  Strips the -----BEGIN <label>----- / -----END <label>----- lines,
   --  ignores line breaks (CR, LF), and Base64-decodes the content.
   --
   --  @param Input  The full PEM text including header and footer lines.
   --  @param Result Decoded DER bytes, label, and success flag.
   ---------------------------------------------------------------------------
   procedure Decode (Input : String; Result : out Decode_Result);

end PEM;
