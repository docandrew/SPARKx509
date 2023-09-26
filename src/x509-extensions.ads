

package X509.Extensions with
    SPARK_Mode
is
   -- Fwd declare and contracts
   procedure Parse_Extension (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
   with Pre => Index in Cert_Slice'Range;

end X509.Extensions;

