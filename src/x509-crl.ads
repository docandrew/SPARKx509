--  X509.CRL -- Certificate Revocation List parser (RFC 5280 section 5)
--
--  Parses a DER CertificateList into a CRL_View: spans into the caller's
--  DER buffer plus the fields a verifier needs (issuer, thisUpdate,
--  nextUpdate, signature, AKID, CRL number, issuingDistributionPoint
--  flags) and a bounded walk over revokedCertificates for serial lookup.
--  The revoked list is NOT copied: Lookup re-walks the DER on demand, so
--  a CRL_View is small however large the CRL is.
--
--  Like X509.Parse this is a parser, not a policy engine. Signature
--  verification, issuer matching, freshness and the IDP / delta /
--  indirect scope rules live in the TLS layer (SPARKTLS.Revocation),
--  which reads the getters below.
--
--  Usage:
--    X509.CRL.Parse (DER, V, OK);
--    if OK then
--       --  verify signature over DER (TBS (V).First .. TBS (V).Last)
--       X509.CRL.Lookup (DER, V, Serial_Bytes, Found, When, Reason, Has_Reason);
--    end if;

package X509.CRL with
   SPARK_Mode => On
is
   type CRL_View is private;

   function Is_Valid (V : CRL_View) return Boolean;

   --  Every span in V points inside DER (0 .. DER_Last).
   function Spans_Valid (V : CRL_View; DER_Last : N32) return Boolean;

   procedure Parse
     (DER : in     Byte_Seq;
      V   :    out CRL_View;
      OK  :    out Boolean)
   with Pre  => DER'First = 0 and DER'Last < N32'Last,
        Post => (if OK then Is_Valid (V) and Spans_Valid (V, DER'Last));

   ----------------------------------------------------------------------------
   --  TBSCertList fields
   ----------------------------------------------------------------------------

   --  1 (no version field) or 2. RFC 5280 5.1.2.1: v2 whenever
   --  extensions are present.
   function Version (V : CRL_View) return Natural;

   --  Full TBSCertList TLV (tag + length + content): the bytes the
   --  signature covers.
   function TBS (V : CRL_View) return Span;

   --  Content of the issuer Name SEQUENCE (same convention as the
   --  certificate parser's issuer / subject raw spans).
   function Issuer_Raw (V : CRL_View) return Span;

   function This_Update     (V : CRL_View) return Date_Time;
   function Has_Next_Update (V : CRL_View) return Boolean;
   function Next_Update     (V : CRL_View) return Date_Time;

   --  Signature algorithm from TBSCertList.signature and from the outer
   --  CertificateList.signatureAlgorithm; RFC 5280 5.1.1.2 requires them
   --  to be identical.
   function Sig_Algorithm   (V : CRL_View) return Algorithm_ID;
   function Sig_Algorithm_2 (V : CRL_View) return Algorithm_ID;

   function Sig_Length (V : CRL_View) return N32;
   function Sig_Data   (V : CRL_View) return Byte_Seq
   with Pre  => Sig_Length (V) > 0 and Sig_Length (V) <= Max_Sig_Bytes,
        Post => Sig_Data'Result'First = 0
                and Sig_Data'Result'Length = Sig_Length (V);

   --  Number of revokedCertificates entries (0 when the list is absent).
   function Revoked_Count (V : CRL_View) return N32;

   ----------------------------------------------------------------------------
   --  CRL extensions (RFC 5280 5.2)
   ----------------------------------------------------------------------------

   --  authorityKeyIdentifier keyIdentifier [0] content (5.2.1)
   function Authority_Key_ID (V : CRL_View) return Span;

   --  cRLNumber INTEGER content (5.2.3)
   function Has_CRL_Number (V : CRL_View) return Boolean;
   function CRL_Number     (V : CRL_View) return Span;

   --  deltaCRLIndicator present (5.2.4): this is a delta CRL.
   function Is_Delta_CRL (V : CRL_View) return Boolean;

   --  issuingDistributionPoint (5.2.5) and its flags. When Has_IDP is
   --  False all flags are False.
   function Has_IDP                     (V : CRL_View) return Boolean;
   function IDP_Has_Distribution_Point  (V : CRL_View) return Boolean;
   --  The IDP's distributionPoint DistributionPointName TLV: [0] fullName
   --  GeneralNames or [1] nameRelativeToCRLIssuer RDN (RFC 5280 5.2.5).
   --  Present iff IDP_Has_Distribution_Point.
   function IDP_Distribution_Point      (V : CRL_View) return Span;
   function IDP_Only_User_Certs         (V : CRL_View) return Boolean;
   function IDP_Only_CA_Certs           (V : CRL_View) return Boolean;
   function IDP_Only_Some_Reasons       (V : CRL_View) return Boolean;
   function IDP_Indirect_CRL            (V : CRL_View) return Boolean;
   function IDP_Only_Attribute_Certs    (V : CRL_View) return Boolean;

   --  A critical CRL extension this parser does not recognize
   --  (RFC 5280 5.2: the CRL MUST then be rejected).
   function Has_Unknown_Critical_Extension (V : CRL_View) return Boolean;

   --  An extension the profile requires to be non-critical was marked
   --  critical (cRLNumber, RFC 5280 5.2.3) or a required one is missing
   --  (cRLNumber on a v2 CRL): the CRL is not RFC 5280 conforming.
   function Has_Bad_Extension (V : CRL_View) return Boolean;

   --  Some entry carries a critical crlEntryExtension other than
   --  reasonCode / invalidityDate -- in practice certificateIssuer
   --  (5.3.3), which only appears in indirect CRLs.
   function Has_Critical_Entry_Extension (V : CRL_View) return Boolean;

   ----------------------------------------------------------------------------
   --  Revoked-serial lookup
   ----------------------------------------------------------------------------

   Max_Serial_Bytes : constant := 20;  --  RFC 5280 4.1.2.2

   --  Search revokedCertificates for an entry whose userCertificate
   --  INTEGER content equals Serial byte-for-byte (both are minimal DER
   --  INTEGER contents, e.g. Cert_DER (Serial (Cert).First .. .Last)).
   --  On a hit, Revocation_Date is the entry's revocationDate and, when
   --  the entry has a reasonCode extension, Has_Reason is True and
   --  Reason is the CRLReason value (RFC 5280 5.3.1).
   procedure Lookup
     (DER             : in     Byte_Seq;
      V               : in     CRL_View;
      Serial          : in     Byte_Seq;
      Found           :    out Boolean;
      Revocation_Date :    out Date_Time;
      Has_Reason      :    out Boolean;
      Reason          :    out Natural)
   with Pre => DER'First = 0 and DER'Last < N32'Last
               and Is_Valid (V) and Spans_Valid (V, DER'Last)
               and Serial'Length > 0
               and Serial'Length <= Max_Serial_Bytes;

private

   type CRL_View is record
      Valid_Flag      : Boolean      := False;
      CRL_Version     : Natural      := 1;

      S_TBS           : Span;
      S_Issuer_Raw    : Span;
      S_Revoked       : Span;   --  content of revokedCertificates
      S_AKID          : Span;
      S_CRL_Number    : Span;
      S_IDP_DP        : Span;   --  IDP DistributionPointName TLV

      This_Upd        : Date_Time;
      Next_Upd        : Date_Time;
      Has_Next        : Boolean      := False;

      Sig_Algo        : Algorithm_ID := Algo_Unknown;
      Sig_Algo_2      : Algorithm_ID := Algo_Unknown;
      Sig_Buf         : Byte_Seq (0 .. Max_Sig_Bytes - 1) := (others => 0);
      Sig_Buf_Len     : N32          := 0;

      Revoked_Num     : N32          := 0;

      Has_Number      : Boolean      := False;
      Is_Delta        : Boolean      := False;
      IDP_Present     : Boolean      := False;
      IDP_DP          : Boolean      := False;
      IDP_User        : Boolean      := False;
      IDP_CA          : Boolean      := False;
      IDP_Reasons     : Boolean      := False;
      IDP_Indirect    : Boolean      := False;
      IDP_Attr        : Boolean      := False;
      Unknown_Crit    : Boolean      := False;
      Bad_Ext         : Boolean      := False;
      Crit_Entry_Ext  : Boolean      := False;
   end record;

   function Spans_Valid (V : CRL_View; DER_Last : N32) return Boolean is
     (Span_In_Range (V.S_TBS, DER_Last)
      and then Span_In_Range (V.S_Issuer_Raw, DER_Last)
      and then Span_In_Range (V.S_Revoked, DER_Last)
      and then Span_In_Range (V.S_AKID, DER_Last)
      and then Span_In_Range (V.S_CRL_Number, DER_Last)
      and then Span_In_Range (V.S_IDP_DP, DER_Last));

   function Is_Valid (V : CRL_View) return Boolean is (V.Valid_Flag);

end X509.CRL;
