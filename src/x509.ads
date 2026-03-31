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
   --  Parser
   --================================================================

   procedure Parse
     (DER  : in     Byte_Seq;
      Cert :    out Certificate;
      OK   :    out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last;

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

   function SAN_Count (Cert : Certificate) return Natural;
   function SAN_DNS   (Cert : Certificate; Index : Positive) return Span
   with Pre => Index >= 1 and Index <= SAN_Count (Cert)
               and SAN_Count (Cert) <= Max_SANs;

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
   with Pre => DER'First = 0 and DER'Last < N32'Last;

   --  True if the cert contains a critical extension we don't understand.
   --  RFC 5280: MUST reject certs with unrecognized critical extensions.
   function Has_Unknown_Critical_Extension (Cert : Certificate) return Boolean;
   function Has_Duplicate_Extension (Cert : Certificate) return Boolean;
   function Has_Extensions (Cert : Certificate) return Boolean;
   function Sig_Algorithm_2 (Cert : Certificate) return Algorithm_ID;
   function Is_Key_Usage_Critical (Cert : Certificate) return Boolean;

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
        --  RFC 5280 4.1.1.2: TBS sig algo must match outer sig algo
        --  (when both are recognized)
        and (Sig_Algorithm_2 (Cert) = Algo_Unknown
             or else Sig_Algorithm (Cert) = Sig_Algorithm_2 (Cert))
        --  RFC 5280 4.2.1.3: Key Usage must be critical when present
        and (not Has_Key_Usage (Cert)
             or else Is_Key_Usage_Critical (Cert)));

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
      Ext_Unknown_Critical : Boolean       := False;
      Ext_Duplicate        : Boolean       := False;
      Has_Extensions       : Boolean       := False;

      --  Second signature algorithm (after TBS, must match first)
      Sig_Algo_2           : Algorithm_ID  := Algo_Unknown;
      S_Auth_Key_ID        : Span;
      S_Subject_Key_ID     : Span;

      --  Subject Alternative Names
      SANs                 : SAN_Array     := (others => (0, 0, False));
      SAN_Num              : Natural       := 0;
   end record;

end X509;
