--  X509.Parser — DER certificate parsing
--
--  Parses a DER-encoded X.509 certificate into a Certificate record.
--  All sub-procedures (name parsing, extension parsing, etc.) are
--  internal to the body.

package X509.Parser with
   SPARK_Mode => On
is
   procedure Parse_Certificate
     (DER  : in     Byte_Seq;
      Cert :    out Certificate;
      OK   :    out Boolean)
   with Pre  => DER'First = 0 and DER'Last < N32'Last,
        Post => (if OK then Is_Valid (Cert)
                              and Spans_Valid (Cert, DER'Last));

end X509.Parser;
