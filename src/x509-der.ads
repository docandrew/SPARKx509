--  X509.DER — Low-level ASN.1 DER parsing primitives
--
--  Tag constants, length parsing, OID matching, and skip helpers.
--  Used by X509.Parse and X509.Names.

package X509.DER with
   SPARK_Mode => On
is
   --================================================================
   --  ASN.1 DER tag constants
   --================================================================
   TAG_BOOLEAN     : constant Byte := 16#01#;
   TAG_INTEGER     : constant Byte := 16#02#;
   TAG_BITSTRING   : constant Byte := 16#03#;
   TAG_OCTETSTRING : constant Byte := 16#04#;
   TAG_NULL        : constant Byte := 16#05#;
   TAG_OID         : constant Byte := 16#06#;
   TAG_UTF8STRING  : constant Byte := 16#0C#;
   TAG_T61STRING   : constant Byte := 16#14#;
   TAG_PRINTSTRING : constant Byte := 16#13#;
   TAG_UTCTIME     : constant Byte := 16#17#;
   TAG_GENTIME     : constant Byte := 16#18#;
   TAG_SEQUENCE    : constant Byte := 16#30#;
   TAG_SET         : constant Byte := 16#31#;
   TAG_VERSION     : constant Byte := 16#A0#;
   TAG_EXTENSIONS  : constant Byte := 16#A3#;
   TAG_IA5STRING   : constant Byte := 16#86#;

   --================================================================
   --  Bounds checking
   --================================================================

   function Can_Read
     (DER : Byte_Seq; Pos : N32; N : N32) return Boolean
   is (Pos <= DER'Last and then N <= DER'Last - Pos + 1);

   --================================================================
   --  DER length and structure parsing
   --================================================================

   procedure Parse_Length
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then Pos > Pos'Old);

   procedure Parse_Sequence
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last
               and DER'Last < N32'Last;

   procedure Enter_Sequence
     (DER : in     Byte_Seq;
      Pos : in out N32;
      OK  : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last
               and DER'Last < N32'Last;

   procedure Parse_Explicit_Tag
     (DER      : in     Byte_Seq;
      Pos      : in out N32;
      Expected : in     Byte;
      Len      :    out N32;
      Found    :    out Boolean;
      OK       : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last
               and DER'Last < N32'Last;

   procedure Skip
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len : in     N32;
      OK  : in out Boolean)
   with Pre => OK;

   procedure Skip_TLV
     (DER : in     Byte_Seq;
      Pos : in out N32;
      OK  : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last
               and DER'Last < N32'Last;

   --================================================================
   --  Byte copying
   --================================================================

   procedure Copy_Bytes
     (DER    : in     Byte_Seq;
      Start  : in     N32;
      Len    : in     N32;
      Buf    :    out Byte_Seq;
      Copied :    out N32)
   with Pre => DER'First = 0 and Buf'First = 0 and Buf'Last < N32'Last;

   --================================================================
   --  OID constants
   --================================================================

   --  Public key algorithms
   OID_RSA     : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#01#);
   OID_EC      : constant Byte_Seq (0 .. 5) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#);
   OID_P256    : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);
   OID_P384    : constant Byte_Seq (0 .. 4) :=
     (16#2B#, 16#81#, 16#04#, 16#00#, 16#22#);
   OID_Ed25519 : constant Byte_Seq (0 .. 2) :=
     (16#2B#, 16#65#, 16#70#);

   --  Signature algorithms
   OID_SHA1_RSA     : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#05#);
   OID_SHA256_RSA   : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0B#);
   OID_SHA384_RSA   : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0C#);
   OID_SHA512_RSA   : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0D#);
   OID_RSA_PSS      : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0A#);
   OID_ECDSA_SHA256 : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#);
   OID_ECDSA_SHA384 : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#03#);

   --  Name attributes
   OID_CN      : constant Byte_Seq (0 .. 2) := (16#55#, 16#04#, 16#03#);
   OID_ORG     : constant Byte_Seq (0 .. 2) := (16#55#, 16#04#, 16#0A#);
   OID_COUNTRY : constant Byte_Seq (0 .. 2) := (16#55#, 16#04#, 16#06#);

   --  Extensions
   OID_SAN          : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#11#);
   OID_BASIC        : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#13#);
   OID_KEY_USAGE    : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#0F#);
   OID_SKID         : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#0E#);
   OID_AKID         : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#23#);
   OID_INHIBIT      : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#36#);
   OID_NAME_CONS    : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#1E#);
   OID_POLICY_CONS  : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#24#);
   OID_POLICY_MAP   : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#21#);
   OID_CERT_POLICIES : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#20#);
   OID_EKU          : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#25#);
   OID_CRL_DP       : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#1F#);
   OID_CT_SCT_V     : constant Byte_Seq (0 .. 9) :=
     (16#2B#, 16#06#, 16#01#, 16#04#, 16#01#, 16#D6#, 16#79#,
      16#02#, 16#04#, 16#02#);
   OID_ANY_EKU      : constant Byte_Seq (0 .. 3) :=
     (16#55#, 16#1D#, 16#25#, 16#00#);
   OID_KP_SERVER_AUTH : constant Byte_Seq (0 .. 7) :=
     (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#03#, 16#01#);
   OID_AIA          : constant Byte_Seq (0 .. 7) :=
     (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#01#, 16#01#);
   OID_SIA          : constant Byte_Seq (0 .. 7) :=
     (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#01#, 16#0B#);
   OID_SUBJ_DIR_ATTR : constant Byte_Seq (0 .. 2) :=
     (16#55#, 16#1D#, 16#09#);
   OID_ANY_POLICY   : constant Byte_Seq (0 .. 3) :=
     (16#55#, 16#1D#, 16#20#, 16#00#);
   OID_QT_CPS       : constant Byte_Seq (0 .. 7) :=
     (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#02#, 16#01#);
   OID_QT_UNOTICE   : constant Byte_Seq (0 .. 7) :=
     (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#02#, 16#02#);

   --================================================================
   --  OID matching
   --================================================================

   function OID_Match
     (DER    : Byte_Seq;
      Start  : N32;
      Len    : N32;
      Target : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and Target'First = 0
               and Target'Last < N32'Last;

   function OID_Prefix_Match
     (DER    : Byte_Seq;
      Start  : N32;
      Len    : N32;
      Prefix : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and Prefix'First = 0
               and Prefix'Last < N32'Last;

   procedure Parse_Algorithm_OID
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      Algo :    out Algorithm_ID;
      OK   : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last
               and DER'Last < N32'Last;

   --================================================================
   --  GeneralName tags (context-specific, RFC 5280 §4.2.1.6)
   --================================================================
   GN_OTHER_NAME   : constant Byte := 16#A0#;  --  [0] constructed
   GN_RFC822_NAME  : constant Byte := 16#81#;  --  [1] IA5String (email)
   GN_DNS_NAME     : constant Byte := 16#82#;  --  [2] IA5String
   GN_X400_ADDRESS : constant Byte := 16#83#;  --  [3]
   GN_DIR_NAME     : constant Byte := 16#A4#;  --  [4] constructed
   GN_EDI_NAME     : constant Byte := 16#A5#;  --  [5] constructed
   GN_URI          : constant Byte := 16#86#;  --  [6] IA5String
   GN_IP_ADDRESS   : constant Byte := 16#87#;  --  [7] OCTET STRING
   GN_REGISTERED_ID : constant Byte := 16#88#; --  [8] OID

   --================================================================
   --  NameConstraints tags (RFC 5280 §4.2.1.10)
   --================================================================
   NC_PERMITTED     : constant Byte := 16#A0#;  --  [0] permittedSubtrees
   NC_EXCLUDED      : constant Byte := 16#A1#;  --  [1] excludedSubtrees

   --================================================================
   --  AKID tags (context-specific, RFC 5280 §4.2.1.1)
   --================================================================
   AKID_TAG_KEY_ID  : constant Byte := 16#80#;  --  [0] keyIdentifier
   AKID_TAG_ISSUER  : constant Byte := 16#A1#;  --  [1] authorityCertIssuer
   AKID_TAG_SERIAL  : constant Byte := 16#82#;  --  [2] authorityCertSerialNumber

   --================================================================
   --  Character / byte helpers
   --================================================================

   function Is_PrintableString_Char (B : Byte) return Boolean is
     (B in 16#20# | 16#27# | 16#28# .. 16#29# | 16#2B# .. 16#2F# |
          16#30# .. 16#39# | 16#3A# | 16#3D# | 16#3F# |
          16#41# .. 16#5A# | 16#61# .. 16#7A#);

   --  Case-insensitive lower-case for a DER byte (A-Z → a-z)
   function To_Lower (B : Byte) return Byte is
     (if B in 16#41# .. 16#5A# then B + 16#20# else B);

   --  Case-insensitive lower-case for a Character → Byte
   function Char_To_Lower (Ch : Character) return Byte is
     (if Ch in 'A' .. 'Z'
      then Byte (Character'Pos (Ch) - Character'Pos ('A') + 16#61#)
      else Byte (Character'Pos (Ch)));

   --================================================================
   --  Span comparison
   --================================================================

   --  Compare two spans in the same DER buffer byte-for-byte.
   --  Returns True if both present, same length, and identical content.
   function Spans_Equal
     (DER : Byte_Seq;
      A   : Span;
      B   : Span) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last;

   --================================================================
   --  Subtree walking
   --================================================================

   --  Walk GeneralSubtree entries in a NameConstraints subtrees span.
   --  For each entry, calls Match with the GeneralName tag and the
   --  position/length of the GeneralName value.
   --  Returns True if Match returns True for any entry.
   --  Tag_Filter: only call Match for entries with this tag (0 = all).
   function Walk_Subtrees_Has_Tag
     (DER      : Byte_Seq;
      Subtrees : Span;
      Tag      : Byte) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last;

end X509.DER;
