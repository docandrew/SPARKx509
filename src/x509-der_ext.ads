--  X509.DER_Ext -- ASN.1 helpers shared by the CRL and OCSP parsers
--
--  Kept out of X509.DER and X509.Parser so the certificate parser's
--  proof is untouched. Parse_Time_Value is a verbatim copy of the
--  private procedure of the same name in X509.Parser (RFC 5280
--  4.1.2.5 time parsing); Parse_Time_TLV and Next_Extension are the
--  two ASN.1 walkers every revocation object needs.

with X509.DER; use X509.DER;

package X509.DER_Ext with
   SPARK_Mode => On
is
   --  Parse the VALUE bytes of a UTCTime (YYMMDDHHMMSSZ, 13 bytes) or
   --  GeneralizedTime (YYYYMMDDHHMMSSZ, 15 bytes) at Pos. Len is the
   --  value length. On success Pos is advanced past the value; on any
   --  malformed digit or out-of-range field OK is False.
   procedure Parse_Time_Value
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      Len  : in     N32;
      T    :    out Date_Time;
      OK   : in out Boolean)
   with Pre  => OK,
        Post => (if OK then Pos = Pos'Old + Len);

   --  Parse a complete Time TLV at Pos. Strict RFC 5280 4.1.2.5 /
   --  RFC 6960 form: UTCTime exactly 13 bytes or GeneralizedTime exactly
   --  15 bytes, ending in 'Z', no fractional seconds. On success Pos is
   --  advanced past the TLV.
   procedure Parse_Time_TLV
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      T    :    out Date_Time;
      OK   : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then Pos > Pos'Old and Pos <= DER'Last + 1);

   --  Walk one Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER,
   --  critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING } at Pos.
   --  RFC 5280 4.2: extnValue must be non-empty, the SEQUENCE must
   --  contain nothing else. On success Pos is advanced to the end of
   --  the extension and both the OID and the value are readable.
   procedure Next_Extension
     (DER       : in     Byte_Seq;
      Pos       : in out N32;
      OID_Start :    out N32;
      OID_Len   :    out N32;
      Critical  :    out Boolean;
      Val_Start :    out N32;
      Val_Len   :    out N32;
      OK        : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then
                   Pos > Pos'Old
                   and OID_Len > 0 and Val_Len > 0
                   and Can_Read (DER, OID_Start, OID_Len)
                   and Can_Read (DER, Val_Start, Val_Len)
                   and Val_Start + Val_Len = Pos);

   --  SEQUENCE header at Pos: on success Pos is at the content, which
   --  is readable for Len bytes. Unlike X509.DER.Parse_Sequence this
   --  publishes the advance, which every Loop_Variant (Increases => Pos)
   --  walker in the CRL / OCSP parsers relies on.
   procedure Parse_Sequence_Hdr
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then Pos > Pos'Old and Pos <= DER'Last + 1
                 and Can_Read (DER, Pos, Len)
                 and Pos + Len <= DER'Last + 1);

   --  EXPLICIT [n] wrapper with tag Expected at Pos: on success Pos is
   --  at the wrapped content and Wrap_End is one past it.
   procedure Enter_Explicit
     (DER      : in     Byte_Seq;
      Pos      : in out N32;
      Expected : in     Byte;
      Wrap_End :    out N32;
      OK       : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then Pos > Pos'Old and Pos <= Wrap_End
                 and Wrap_End <= DER'Last + 1);

   --  OCTET STRING at Pos: on success Pos is at the content and Str_End
   --  is one past it (content may be empty).
   procedure Enter_Octet_String
     (DER     : in     Byte_Seq;
      Pos     : in out N32;
      Str_End :    out N32;
      OK      : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then Pos > Pos'Old and Pos <= Str_End
                 and Str_End <= DER'Last + 1);

   --  RFC 5280 6.3.3 (b)(2)(i): a CRL whose issuingDistributionPoint
   --  names a distribution point only covers certificates whose
   --  cRLDistributionPoints contains a matching name. CRL_DP_Ext is the
   --  certificate's cRLDistributionPoints extension value (SEQUENCE OF
   --  DistributionPoint TLV); IDP_DPN is the CRL's DistributionPointName
   --  TLV ([0] fullName GeneralNames or [1] nameRelativeToCRLIssuer
   --  RDN). Names compare as DER GeneralNames; a relative name is
   --  expanded with the issuer Name content given for its side (the
   --  certificate's issuer for the certificate's DP, the CRL's issuer
   --  for the IDP). True when some DistributionPoint of the certificate
   --  carries a distributionPoint name that matches one of the IDP's.
   --  DistributionPoints without a distributionPoint field (cRLIssuer
   --  only) never match: indirect CRLs are out of scope.
   function DP_Name_Matches
     (Cert_DER    : Byte_Seq;
      CRL_DP_Ext  : Span;
      Cert_Issuer : Span;
      CRL_DER     : Byte_Seq;
      IDP_DPN     : Span;
      CRL_Issuer  : Span) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
               and CRL_DER'First = 0 and CRL_DER'Last < N32'Last
               and Span_In_Range (CRL_DP_Ext, Cert_DER'Last)
               and Span_In_Range (Cert_Issuer, Cert_DER'Last)
               and Span_In_Range (IDP_DPN, CRL_DER'Last)
               and Span_In_Range (CRL_Issuer, CRL_DER'Last);

   --  DER BOOLEAN value at Pos (tag 0x01, length 1). Value True when
   --  the octet is non-zero (DER requires 0xFF; X.690 8.2.2).
   procedure Parse_Boolean
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      Value :    out Boolean;
      OK    : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then Pos > Pos'Old and Pos <= DER'Last + 1);

end X509.DER_Ext;
