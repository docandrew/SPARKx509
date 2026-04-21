with Interfaces; use Interfaces;

--  X.509 Certificate Parser (SPARK-verified)
--
--  Certificates are parsed from DER-encoded byte sequences.
--  The Certificate type stores:
--    - Crypto fields (key, signature) in fixed-size internal buffers
--    - Name/extension fields as Span offsets into the original DER
--
--  Callers keep the DER buffer alive and pass it to getters that
--  need to resolve name fields. Crypto getters are self-contained.
--
--  Usage:
--    Parse (DER, Cert, OK);
--    if OK and then Has_Subject_CN (Cert) then
--       CN_Span := Subject_CN (Cert);
--       --  DER (CN_Span.First .. CN_Span.Last) is the CN bytes
--    end if;
--    if PK_Algorithm (Cert) = Algo_RSA then
--       --  PK_Data (Cert) returns the modulus bytes
--    end if;

package X509 with
   SPARK_Mode => On
is
   subtype Byte is Unsigned_8;
   subtype N32  is Unsigned_32;

   type Byte_Seq is array (N32 range <>) of Byte;

   --================================================================
   --  Algorithm identifiers
   --================================================================

   type Algorithm_ID is
     (Algo_Unknown,
      --  Signature algorithms
      Algo_RSA_PKCS1_SHA1,
      Algo_RSA_PKCS1_SHA256,
      Algo_RSA_PKCS1_SHA384,
      Algo_RSA_PKCS1_SHA512,
      Algo_RSA_PSS,
      Algo_ECDSA_P256_SHA256,
      Algo_ECDSA_P384_SHA384,
      Algo_Ed25519,
      --  Public key algorithms
      Algo_RSA,
      Algo_EC_P256,
      Algo_EC_P384,
      Algo_EC_Ed25519);

   --================================================================
   --  Span: a byte range [First..Last] into the DER buffer
   --  Present = False means the field was not found during parsing.
   --================================================================

   type Span is record
      First   : N32     := 0;
      Last    : N32     := 0;
      Present : Boolean := False;
   end record;

   function Span_Length (S : Span) return N32 is
     (if S.Present and then S.Last >= S.First
      then S.Last - S.First + 1
      else 0);

   --================================================================
   --  Date/time (pure record, no exceptions, fully SPARK)
   --================================================================

   type Date_Time is record
      Year   : Natural := 0;
      Month  : Natural := 0;
      Day    : Natural := 0;
      Hour   : Natural := 0;
      Minute : Natural := 0;
      Second : Natural := 0;
   end record;

   function DT_Before (A, B : Date_Time) return Boolean is
     (A.Year < B.Year
      or else (A.Year = B.Year and A.Month < B.Month)
      or else (A.Year = B.Year and A.Month = B.Month and A.Day < B.Day)
      or else (A.Year = B.Year and A.Month = B.Month and A.Day = B.Day
               and A.Hour < B.Hour)
      or else (A.Year = B.Year and A.Month = B.Month and A.Day = B.Day
               and A.Hour = B.Hour and A.Minute < B.Minute)
      or else (A.Year = B.Year and A.Month = B.Month and A.Day = B.Day
               and A.Hour = B.Hour and A.Minute = B.Minute
               and A.Second < B.Second));

   function DT_Before_Or_Equal (A, B : Date_Time) return Boolean is
     (not DT_Before (B, A));

   --================================================================
   --  Certificate (opaque type)
   --================================================================

   type Certificate is private;

   --================================================================
   --  Span validity — proves all DER offsets are in range
   --================================================================

   --  True if a single span is within DER'Range (or not present)
   function Span_In_Range (S : Span; DER_Last : N32) return Boolean is
     (not S.Present or else (S.First <= DER_Last and S.Last <= DER_Last));

   --  True if all spans in the certificate point within DER(0..DER_Last).
   --  This is the central safety predicate: if Spans_Valid holds, then
   --  every getter that resolves a span against the DER is safe.
   function Spans_Valid
     (Cert     : Certificate;
      DER_Last : N32) return Boolean;

   --  Algorithms are recognized (not Algo_Unknown) and match
   function Algorithms_Valid (Cert : Certificate) return Boolean;

   --================================================================
   --  Parser
   --================================================================

   procedure Parse
     (DER  : in     Byte_Seq;
      Cert :    out Certificate;
      OK   :    out Boolean)
   with Pre  => DER'First = 0 and DER'Last < N32'Last,
        Post => (if OK then Is_Valid (Cert)
                              and Spans_Valid (Cert, DER'Last)
                              and Algorithms_Valid (Cert));

   --================================================================
   --  Validity & version
   --================================================================

   function Is_Valid   (Cert : Certificate) return Boolean;
   function Version    (Cert : Certificate) return Natural;

   --================================================================
   --  Name field getters (return Spans into the DER)
   --  Caller uses the span to slice the original DER buffer.
   --================================================================

   --  Issuer fields
   function Issuer_CN       (Cert : Certificate) return Span;
   function Issuer_Org      (Cert : Certificate) return Span;
   function Issuer_Country  (Cert : Certificate) return Span;

   --  Subject fields
   function Subject_CN      (Cert : Certificate) return Span;
   function Subject_Org     (Cert : Certificate) return Span;
   function Subject_Country (Cert : Certificate) return Span;

   --  Convenience: check presence
   function Has_Issuer_CN   (Cert : Certificate) return Boolean;
   function Has_Subject_CN  (Cert : Certificate) return Boolean;

   --================================================================
   --  Subject Alternative Names
   --================================================================

   Max_SANs : constant := 16;
   --  TODO: Google certs have 137+ DNS SANs but increasing this
   --  bloats Certificate (and thus Cert_Pool/Root_Pool) significantly.
   --  Need to decouple SAN storage from the Certificate record.

   function SAN_Count (Cert : Certificate) return Natural;
   function SAN_DNS   (Cert : Certificate; Index : Positive) return Span
   with Pre => Index >= 1 and Index <= SAN_Count (Cert)
               and SAN_Count (Cert) <= Max_SANs;

   function IP_SAN_Count (Cert : Certificate) return Natural;
   function IP_SAN       (Cert : Certificate; Index : Positive) return Span
   with Pre => Index >= 1 and Index <= IP_SAN_Count (Cert)
               and IP_SAN_Count (Cert) <= Max_SANs;

   --================================================================
   --  Public key getters (self-contained, copied during parse)
   --================================================================

   Max_PK_Bytes : constant := 1024;  --  RSA-8192 modulus

   function PK_Algorithm  (Cert : Certificate) return Algorithm_ID;
   function PK_Length      (Cert : Certificate) return N32;
   function PK_Data        (Cert : Certificate) return Byte_Seq
   with Pre  => PK_Length (Cert) > 0
                and PK_Length (Cert) <= Max_PK_Bytes,
        Post => PK_Data'Result'First = 0
                and PK_Data'Result'Length = PK_Length (Cert);
   function RSA_Exponent   (Cert : Certificate) return Unsigned_32;

   --================================================================
   --  Signature getters (self-contained, copied during parse)
   --================================================================

   Max_Sig_Bytes : constant := 1024;  --  RSA-8192 signature

   function Sig_Algorithm  (Cert : Certificate) return Algorithm_ID;
   function Sig_Length      (Cert : Certificate) return N32;
   function Sig_Data        (Cert : Certificate) return Byte_Seq
   with Pre  => Sig_Length (Cert) > 0
                and Sig_Length (Cert) <= Max_Sig_Bytes,
        Post => Sig_Data'Result'First = 0
                and Sig_Data'Result'Length = Sig_Length (Cert);

   --================================================================
   --  TBS (To Be Signed) — span into the DER
   --  Used for signature verification: hash DER(TBS.First..TBS.Last)
   --================================================================

   function TBS (Cert : Certificate) return Span;

   --================================================================
   --  Validity dates
   --================================================================

   function Not_Before (Cert : Certificate) return Date_Time;
   function Not_After  (Cert : Certificate) return Date_Time;

   --================================================================
   --  Extension getters
   --================================================================

   function Is_CA         (Cert : Certificate) return Boolean;
   function Has_Path_Len_Constraint (Cert : Certificate) return Boolean;
   function Path_Len_Constraint     (Cert : Certificate) return Natural;
   function Has_Key_Usage (Cert : Certificate) return Boolean;

   --  Key usage bits (RFC 5280 Section 4.2.1.3)
   function KU_Digital_Signature (Cert : Certificate) return Boolean;
   function KU_Key_Encipherment  (Cert : Certificate) return Boolean;
   function KU_Key_Cert_Sign     (Cert : Certificate) return Boolean;
   function KU_CRL_Sign          (Cert : Certificate) return Boolean;

   --  Authority Key Identifier
   function Authority_Key_ID (Cert : Certificate) return Span;
   function AKID_Serial      (Cert : Certificate) return Span;
   function Subject_Key_ID   (Cert : Certificate) return Span;

   --================================================================
   --  Serial number
   --================================================================

   function Serial (Cert : Certificate) return Span;

   --================================================================
   --  Validation
   --================================================================

   --  Check if the certificate is currently within its validity period.
   --  Now is typically Ada.Calendar.Clock.
   function Is_Date_Valid
     (Cert : Certificate;
      Now  : Date_Time) return Boolean;

   --  Check if a hostname matches the certificate.
   --  Checks Subject CN and SAN DNS names.
   --  DER is needed to resolve the Span-based name fields.
   function Matches_Hostname
     (Cert     : Certificate;
      DER      : Byte_Seq;
      Hostname : String) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last
               and Spans_Valid (Cert, DER'Last);

   --  CABF BR 7.1.4.3: if the cert has a Subject CN, it must be a
   --  byte-for-byte copy of a SAN dNSName or iPAddress value.
   --  Returns True if CN is absent, or if CN matches a SAN entry.
   function CN_In_SAN
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last
               and Spans_Valid (Cert, DER'Last);

   function Is_Self_Issued
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last
               and Spans_Valid (Cert, DER'Last);

   function AKI_Matches_SKI
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last
               and Spans_Valid (Cert, DER'Last);

   --================================================================
   --  Chain validation (structural checks between issuer and subject)
   --================================================================

   --  RFC 5280 §7.1: Check if Issuer_DER's subject DN matches Cert_DER's
   --  issuer DN.  Comparison is semantic: RDN attributes are matched by
   --  OID, and PrintableString/UTF8String values are compared after
   --  case folding and whitespace normalization (collapse runs, trim).
   --  Falls back to byte-exact comparison for non-string types.
   function Issuer_Matches
     (Cert      : Certificate;
      Cert_DER  : Byte_Seq;
      Issuer    : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
               and Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
               and Spans_Valid (Cert, Cert_DER'Last)
               and Spans_Valid (Issuer, Issuer_DER'Last);
   --  RFC 5280 §7.1: True only if both names are present and
   --  semantically equal after PrintableString/UTF8String
   --  normalization (case folding, whitespace collapsing/trimming).

   --  Check if the issuer's Key Usage allows cert signing.
   --  RFC 5280 §4.2.1.3: keyCertSign bit must be set.
   function Issuer_May_Sign (Issuer : Certificate) return Boolean;

   --  Check if the issuer's EKU (if present) is compatible with cert signing.
   --  RFC 5280 §4.2.1.12: if EKU present, must not restrict to non-signing.
   function Issuer_EKU_Allows_Signing (Issuer : Certificate) return Boolean;

   --  Check if the cert has EKU with id-kp-serverAuth (for TLS server validation).
   function Has_EKU_Server_Auth (Cert : Certificate) return Boolean;
   function Has_EKU_Any_Purpose (Cert : Certificate) return Boolean;
   function Has_EKU (Cert : Certificate) return Boolean;
   function Is_EKU_Critical (Cert : Certificate) return Boolean;

   --  Check if the cert satisfies the issuer's name constraints.
   --  Returns True if no name constraints or all constraints satisfied.
   --  Needs both DER buffers to compare DNS names.
   function Satisfies_Name_Constraints
     (Cert       : Certificate;
      Cert_DER   : Byte_Seq;
      Issuer     : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
               and Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
               and Spans_Valid (Cert, Cert_DER'Last)
               and Spans_Valid (Issuer, Issuer_DER'Last);

   --================================================================
   --  Structural validation getters
   --================================================================

   --  True if the cert contains a critical extension we don't understand.
   --  RFC 5280: MUST reject certs with unrecognized critical extensions.
   function Has_Unknown_Critical_Extension (Cert : Certificate) return Boolean;
   function Has_Duplicate_Extension (Cert : Certificate) return Boolean;
   function Has_Extensions (Cert : Certificate) return Boolean;
   function Sig_Algorithm_2 (Cert : Certificate) return Algorithm_ID;
   function Is_Key_Usage_Critical (Cert : Certificate) return Boolean;
   function Is_Basic_Constraints_Critical (Cert : Certificate) return Boolean;
   function Has_Key_Cert_Sign_Without_CA (Cert : Certificate) return Boolean;

   --  RFC 5280 §4.2: Extension criticality enforcement
   function Has_Bad_Extension_Criticality (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.1.2.2: Serial number validation
   function Has_Bad_Serial (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.1.2.5: Time format validation
   function Has_Bad_Time_Format (Cert : Certificate) return Boolean;

   --  RFC 5280 §4.2.1.6: SAN must not be malformed (empty or blank DNS)
   function Has_Bad_SAN (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.3: Key Usage must have at least one bit set
   function Has_Empty_Key_Usage_Value (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.2: CA certs should have Subject Key ID
   function CA_Missing_Subject_Key_ID (Cert : Certificate) return Boolean;

   --  RFC 5280 §4.1.2.8: uniqueIDs only allowed in v2 and v3
   function Has_Unique_ID_Version_Error (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.6: SAN must be critical when subject is empty
   function Has_SAN_Subject_Error (Cert : Certificate) return Boolean;

   --  RFC 5280 §4.2: Extension value content validation
   function Has_Bad_Ext_Content (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.1: Public key structural validation
   function Has_Bad_PubKey (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.1: AKID present but missing keyIdentifier
   function Has_AKID_Missing_Key_ID (Cert : Certificate) return Boolean;
   --  CABF 7.1.2.1.3: AKI contains authorityCertIssuer field
   function Has_AKID_Issuer (Cert : Certificate) return Boolean;

   --  RFC 5280 §4.2.1.10: NameConstraints on a non-CA cert
   function Has_Name_Constraints_NonCA (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.10: NameConstraints is non-critical
   function Has_NC_Noncritical (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.14: InhibitAnyPolicy with negative value
   function Has_Bad_Inhibit_Value (Cert : Certificate) return Boolean;

   --  RFC 5280 Appendix A / X.690: DER encoding violations
   function Has_Bad_DER (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.4: Certificate policies validation
   function Has_Bad_Cert_Policy (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.1: AKID issuer/serial both-or-neither
   function Has_Bad_AKID (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.1.2.6: Subject encoding (no T61String, valid PrintableString)
   function Has_Bad_Subject_Encoding (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.12: EKU valid OIDs
   function Has_Bad_EKU_Content (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.2.1.13: CRL DP not reasons-only
   function Has_Bad_CRL_DP (Cert : Certificate) return Boolean;

   --  RFC 5280 §4.2.1.6: SAN critical with non-empty subject
   function Has_SAN_Critical_With_Subject (Cert : Certificate) return Boolean;
   --  RFC 5280 §4.1.2.1: v3 UniqueID present but no extensions
   function Has_V3_UniqueID_NoExts (Cert : Certificate) return Boolean;

   --  RFC 5280 §4.2.1.9: pathLen present but cA is FALSE
   function Has_Path_Len_Without_CA (Cert : Certificate) return Boolean;

   --  Comprehensive structural validation (everything except signature).
   --  The postcondition formally encodes RFC 5280 requirements:
   --  if True is returned, ALL of these conditions hold.
   function Is_Structurally_Valid
     (Cert : Certificate;
      Now  : Date_Time) return Boolean
   with Post =>
     (if Is_Structurally_Valid'Result then
        --  RFC 5280 4.1: Must have parsed successfully
        Is_Valid (Cert)
        --  RFC 5280 4.2: No unrecognized critical extensions
        and not Has_Unknown_Critical_Extension (Cert)
        --  RFC 5280 4.1.2.5: Must be within validity period
        and Is_Date_Valid (Cert, Now)
        --  Must have known signature algorithm
        and Sig_Algorithm (Cert) /= Algo_Unknown
        --  Must have known public key algorithm
        and PK_Algorithm (Cert) /= Algo_Unknown
        --  Must have TBS data for signature verification
        and TBS (Cert).Present
        --  RFC 5280 4.1.2.1: v1/v2 certs must not have extensions
        and (Version (Cert) >= 3 or else not Has_Extensions (Cert))
        --  RFC 5280 4.2: No duplicate extensions
        and not Has_Duplicate_Extension (Cert)
        --  RFC 5280 4.1.1.2: TBS and outer sig algo must match when both known
        and (Sig_Algorithm_2 (Cert) = Algo_Unknown
             or else Sig_Algorithm (Cert) = Sig_Algorithm_2 (Cert))
        --  RFC 5280 4.2.1.3: keyCertSign requires CA
        and not Has_Key_Cert_Sign_Without_CA (Cert)
        --  RFC 5280 4.2: Extension criticality enforcement
        and not Has_Bad_Extension_Criticality (Cert)
        --  RFC 5280 4.1.2.2: Serial number validation
        and not Has_Bad_Serial (Cert)
        --  RFC 5280 4.1.2.5: Time format validation
        and not Has_Bad_Time_Format (Cert)
        --  RFC 5280 4.2.1.6: SAN must not be malformed
        and not Has_Bad_SAN (Cert)
        --  RFC 5280 4.2.1.3: Key Usage must have at least one bit set
        and not Has_Empty_Key_Usage_Value (Cert)
        --  RFC 5280 4.2.1.2: CA certs should have Subject Key ID
        and not CA_Missing_Subject_Key_ID (Cert)
        --  RFC 5280 4.1.2.8: uniqueIDs only in v2/v3
        and not Has_Unique_ID_Version_Error (Cert)
        --  RFC 5280 4.2.1.6: SAN must be critical if subject empty
        and not Has_SAN_Subject_Error (Cert)
        --  RFC 5280 4.2: Extension value must not be empty
        and not Has_Bad_Ext_Content (Cert)
        --  RFC 5280 4.2.1.1: Public key must be structurally valid
        and not Has_Bad_PubKey (Cert)
        --  RFC 5280 4.2.1.1: AKID must contain keyIdentifier
        and not Has_AKID_Missing_Key_ID (Cert)
        --  RFC 5280 4.2.1.10: NameConstraints only on CA certs
        and not Has_Name_Constraints_NonCA (Cert)
        --  RFC 5280 4.2.1.14: InhibitAnyPolicy must not be negative
        and not Has_Bad_Inhibit_Value (Cert)
        --  RFC 5280 Appendix A / X.690: Valid DER encoding
        and not Has_Bad_DER (Cert)
        --  RFC 5280 4.2.1.4: Certificate policies
        and not Has_Bad_Cert_Policy (Cert)
        --  RFC 5280 4.2.1.1: AuthKeyID issuer/serial both or neither
        and not Has_Bad_AKID (Cert)
        --  RFC 5280 4.1.2.6: Subject encoding (no T61String, PrintableString valid)
        and not Has_Bad_Subject_Encoding (Cert)
        --  RFC 5280 4.2.1.12: EKU valid OIDs
        and not Has_Bad_EKU_Content (Cert)
        --  RFC 5280 4.2.1.13: CRL DP not reasons-only
        and not Has_Bad_CRL_DP (Cert)
        --  RFC 5280 4.2.1.6: SAN critical with non-empty subject
        and not Has_SAN_Critical_With_Subject (Cert)
        --  RFC 5280 4.1.2.1: v3 UniqueID without extensions
        and not Has_V3_UniqueID_NoExts (Cert)
        --  RFC 5280 4.2.1.9: pathLen requires cA=TRUE
        and not Has_Path_Len_Without_CA (Cert));

private

   type SAN_Array is array (1 .. Max_SANs) of Span;

   type Certificate is record
      Valid_Flag           : Boolean       := False;
      Cert_Version         : Natural       := 0;

      --  Name spans (offsets into DER)
      S_Issuer_CN          : Span;
      S_Issuer_Org         : Span;
      S_Issuer_Country     : Span;
      S_Subject_CN         : Span;
      S_Subject_Org        : Span;
      S_Subject_Country    : Span;

      --  Raw DN spans (for byte-level issuer/subject matching)
      S_Issuer_Raw         : Span;  --  full issuer SEQUENCE content
      S_Subject_Raw        : Span;  --  full subject SEQUENCE content

      --  Name constraints (from issuer's NameConstraints extension)
      S_Permitted_Subtrees : Span;  --  span of permittedSubtrees [0]
      S_Excluded_Subtrees  : Span;  --  span of excludedSubtrees [1]

      --  Serial number span
      S_Serial             : Span;

      --  TBS span
      S_TBS                : Span;

      --  Validity
      Validity_Not_Before  : Date_Time;
      Validity_Not_After   : Date_Time;

      --  Public key (copied into local buffer)
      PK_Algo              : Algorithm_ID  := Algo_Unknown;
      PK_Buf               : Byte_Seq (0 .. Max_PK_Bytes - 1) := (others => 0);
      PK_Buf_Len           : N32          := 0;
      PK_RSA_Exp           : Unsigned_32  := 0;

      --  Signature (copied into local buffer)
      Sig_Algo             : Algorithm_ID  := Algo_Unknown;
      Sig_Buf              : Byte_Seq (0 .. Max_Sig_Bytes - 1) := (others => 0);
      Sig_Buf_Len          : N32          := 0;

      --  Extensions
      Ext_Is_CA            : Boolean       := False;
      Ext_Has_Path_Len     : Boolean       := False;
      Ext_Path_Len         : Natural       := 0;
      Ext_Key_Usage        : Unsigned_16   := 0;
      Ext_Has_Key_Usage    : Boolean       := False;
      Ext_Key_Usage_Crit   : Boolean       := False;
      Ext_Basic_Crit       : Boolean       := False;
      Ext_Unknown_Critical : Boolean       := False;
      Ext_Duplicate        : Boolean       := False;
      Has_Extensions       : Boolean       := False;

      --  Second signature algorithm (after TBS, must match first)
      Sig_Algo_2           : Algorithm_ID  := Algo_Unknown;
      S_Auth_Key_ID        : Span;
      S_AKID_Serial        : Span;
      S_Subject_Key_ID     : Span;

      --  Subject Alternative Names (DNS)
      SANs                 : SAN_Array     := (others => (0, 0, False));
      SAN_Num              : Natural       := 0;
      SAN_Ext_Value        : Span          := (0, 0, False);
      --  Span of the full SAN extension SEQUENCE OF value in DER.
      --  Used by Matches_Hostname to iterate all SANs directly
      --  from DER when SAN_Num exceeds Max_SANs.
      SAN_Has_Email        : Boolean       := False;
      SAN_Has_Other_Name   : Boolean       := False;

      --  Subject Alternative Names (IP address: 4 bytes IPv4, 16 bytes IPv6)
      IP_SANs              : SAN_Array     := (others => (0, 0, False));
      IP_SAN_Num           : Natural       := 0;

      --  RFC 5280 validation flags
      Bad_Ext_Criticality  : Boolean       := False;
      Bad_Serial           : Boolean       := False;
      Bad_Time_Format      : Boolean       := False;
      Bad_SAN              : Boolean       := False;
      Empty_Key_Usage      : Boolean       := False;
      Has_Subject          : Boolean       := False;
      Has_Unique_ID        : Boolean       := False;
      SAN_Noncrit_Empty_Subj : Boolean     := False;
      Bad_Ext_Content      : Boolean       := False;
      Bad_PubKey           : Boolean       := False;
      AKID_Missing_Key_ID  : Boolean       := False;
      AKID_Has_Issuer      : Boolean       := False;
      Has_Name_Constraints : Boolean       := False;
      NC_Noncritical       : Boolean       := False;
      Bad_Inhibit_Value    : Boolean       := False;
      Bad_DER              : Boolean       := False;
      Bad_Cert_Policy      : Boolean       := False;
      Bad_AKID             : Boolean       := False;
      Bad_Subject_Encoding : Boolean       := False;
      Bad_EKU_Content      : Boolean       := False;
      Ext_Has_EKU          : Boolean       := False;
      EKU_Has_Any          : Boolean       := False;
      EKU_Has_Server_Auth  : Boolean       := False;
      EKU_Is_Critical      : Boolean       := False;
      Bad_CRL_DP           : Boolean       := False;
      SAN_Critical_With_Subject : Boolean  := False;
      V3_UniqueID_NoExts   : Boolean       := False;
   end record;

end X509;
