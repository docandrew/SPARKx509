package body X509 with
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
   --  Low-level DER parsing helpers
   --================================================================

   --  Check if we can read N bytes from Pos
   function Can_Read
     (DER : Byte_Seq; Pos : N32; N : N32) return Boolean
   is (Pos <= DER'Last and then N <= DER'Last - Pos + 1);

   --  Parse a DER length field. Returns the content length and
   --  advances Pos past the length bytes.
   procedure Parse_Length
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last and DER'Last < N32'Last
   is
      B : Byte;
   begin
      B := DER (Pos);
      Pos := Pos + 1;

      if B <= 16#7F# then
         --  Short form: length in one byte
         Len := N32 (B);
      elsif B = 16#81# then
         --  Long form: 1 byte length
         if Pos > DER'Last then OK := False; Len := 0; return; end if;
         Len := N32 (DER (Pos));
         Pos := Pos + 1;
      elsif B = 16#82# then
         --  Long form: 2 byte length
         if not Can_Read (DER, Pos, 2) then OK := False; Len := 0; return; end if;
         Len := N32 (DER (Pos)) * 256 + N32 (DER (Pos + 1));
         Pos := Pos + 2;
      elsif B = 16#83# then
         --  Long form: 3 byte length
         if not Can_Read (DER, Pos, 3) then OK := False; Len := 0; return; end if;
         Len := N32 (DER (Pos)) * 65536 + N32 (DER (Pos + 1)) * 256 +
                N32 (DER (Pos + 2));
         Pos := Pos + 3;
      else
         --  4+ byte lengths or indefinite — not supported
         OK := False;
         Len := 0;
      end if;
   end Parse_Length;

   --  Parse a SEQUENCE tag + length, return content length
   procedure Parse_Sequence
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last and DER'Last < N32'Last
   is
   begin
      if DER (Pos) /= TAG_SEQUENCE then
         OK := False; Len := 0; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; Len := 0; return; end if;
      Parse_Length (DER, Pos, Len, OK);
   end Parse_Sequence;

   --  Parse an explicit tag + length (e.g., [0] EXPLICIT, [3] EXPLICIT)
   procedure Parse_Explicit_Tag
     (DER      : in     Byte_Seq;
      Pos      : in out N32;
      Expected : in     Byte;
      Len      :    out N32;
      Found    :    out Boolean;
      OK       : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last and DER'Last < N32'Last
   is
   begin
      if DER (Pos) = Expected then
         Found := True;
         Pos := Pos + 1;
         if Pos > DER'Last then OK := False; Len := 0; return; end if;
         Parse_Length (DER, Pos, Len, OK);
      else
         Found := False;
         Len := 0;
      end if;
   end Parse_Explicit_Tag;

   --  Skip past Len bytes
   procedure Skip
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len : in     N32;
      OK  : in out Boolean)
   with Pre => OK
   is
   begin
      if Len > 0 and then not Can_Read (DER, Pos, Len) then
         OK := False;
      elsif Len > 0 then
         Pos := Pos + Len;
      end if;
   end Skip;

   --  Parse a tag + length and skip the value (any type)
   procedure Skip_TLV
     (DER : in     Byte_Seq;
      Pos : in out N32;
      OK  : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last and DER'Last < N32'Last
   is
      Len : N32;
   begin
      Pos := Pos + 1;  --  skip tag
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Len, OK);
      if OK then Skip (DER, Pos, Len, OK); end if;
   end Skip_TLV;

   --================================================================
   --  OID matching
   --================================================================

   --  Well-known OID byte patterns (after tag + length)
   --  RSA: 1.2.840.113549.1.1.1
   OID_RSA : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#01#);
   --  EC Public Key: 1.2.840.10045.2.1
   OID_EC  : constant Byte_Seq (0 .. 5) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#);  --  prefix, curve follows
   --  P-256: 1.2.840.10045.3.1.7
   OID_P256 : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);
   --  P-384: 1.3.132.0.34
   OID_P384 : constant Byte_Seq (0 .. 4) :=
     (16#2B#, 16#81#, 16#04#, 16#00#, 16#22#);
   --  Ed25519: 1.3.101.112
   OID_Ed25519 : constant Byte_Seq (0 .. 2) :=
     (16#2B#, 16#65#, 16#70#);

   --  SHA1WithRSA: 1.2.840.113549.1.1.5
   OID_SHA1_RSA : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#05#);
   --  SHA256WithRSA: 1.2.840.113549.1.1.11
   OID_SHA256_RSA : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0B#);
   --  SHA384WithRSA: 1.2.840.113549.1.1.12
   OID_SHA384_RSA : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0C#);
   --  SHA512WithRSA: 1.2.840.113549.1.1.13
   OID_SHA512_RSA : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0D#);
   --  RSA-PSS: 1.2.840.113549.1.1.10
   OID_RSA_PSS : constant Byte_Seq (0 .. 8) :=
     (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#0A#);
   --  ECDSA-SHA256: 1.2.840.10045.4.3.2
   OID_ECDSA_SHA256 : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#);
   --  ECDSA-SHA384: 1.2.840.10045.4.3.3
   OID_ECDSA_SHA384 : constant Byte_Seq (0 .. 7) :=
     (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#03#);

   --  Common Name: 2.5.4.3
   OID_CN : constant Byte_Seq (0 .. 2) := (16#55#, 16#04#, 16#03#);
   --  Organization: 2.5.4.10
   OID_ORG : constant Byte_Seq (0 .. 2) := (16#55#, 16#04#, 16#0A#);
   --  Country: 2.5.4.6
   OID_COUNTRY : constant Byte_Seq (0 .. 2) := (16#55#, 16#04#, 16#06#);

   --  SAN extension: 2.5.29.17
   OID_SAN : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#11#);
   --  Basic Constraints: 2.5.29.19
   OID_BASIC : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#13#);
   --  Key Usage: 2.5.29.15
   OID_KEY_USAGE : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#0F#);
   --  Subject Key ID: 2.5.29.14
   OID_SKID : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#0E#);
   --  Authority Key ID: 2.5.29.35
   OID_AKID : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#23#);
   --  InhibitAnyPolicy: 2.5.29.54
   OID_INHIBIT : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#36#);
   --  NameConstraints: 2.5.29.30
   OID_NAME_CONS : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#1E#);
   --  PolicyConstraints: 2.5.29.36
   OID_POLICY_CONS : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#24#);
   --  PolicyMappings: 2.5.29.33
   OID_POLICY_MAP : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#21#);
   --  Certificate Policies: 2.5.29.32
   OID_CERT_POLICIES : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#20#);
   --  Extended Key Usage: 2.5.29.37
   OID_EKU : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#25#);
   --  CRL Distribution Points: 2.5.29.31
   OID_CRL_DP : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#1F#);
   --  CT SCT List: 1.3.6.1.4.1.11129.2.4.2
   OID_CT_SCT_V : constant Byte_Seq (0 .. 9) :=
     (16#2B#, 16#06#, 16#01#, 16#04#, 16#01#, 16#D6#, 16#79#,
      16#02#, 16#04#, 16#02#);
   --  anyExtendedKeyUsage: 2.5.29.37.0
   OID_ANY_EKU : constant Byte_Seq (0 .. 3) :=
     (16#55#, 16#1D#, 16#25#, 16#00#);

   function OID_Match
     (DER    : Byte_Seq;
      Start  : N32;
      Len    : N32;
      Target : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and Target'First = 0
               and Target'Last < N32'Last
   is
   begin
      if Len /= N32 (Target'Length) then
         return False;
      end if;
      if Len = 0 then
         return True;
      end if;
      if not Can_Read (DER, Start, Len) then
         return False;
      end if;
      for I in N32 range 0 .. Len - 1 loop
         pragma Loop_Invariant (Start + I <= DER'Last);
         pragma Loop_Invariant (Target'First + I <= Target'Last);
         if DER (Start + I) /= Target (Target'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end OID_Match;

   function OID_Prefix_Match
     (DER    : Byte_Seq;
      Start  : N32;
      Len    : N32;
      Prefix : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and Prefix'First = 0
               and Prefix'Last < N32'Last
   is
      PLen : constant N32 := N32 (Prefix'Length);
   begin
      if Len < PLen then
         return False;
      end if;
      if PLen = 0 then
         return True;
      end if;
      if not Can_Read (DER, Start, PLen) then
         return False;
      end if;
      for I in N32 range 0 .. PLen - 1 loop
         pragma Loop_Invariant (Start + I <= DER'Last);
         pragma Loop_Invariant (Prefix'First + I <= Prefix'Last);
         if DER (Start + I) /= Prefix (Prefix'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end OID_Prefix_Match;

   --  Parse an OID tag+length, match against known OIDs
   procedure Parse_Algorithm_OID
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      Algo :    out Algorithm_ID;
      OK   : in out Boolean)
   with Pre => OK and DER'First = 0 and Pos <= DER'Last and DER'Last < N32'Last
   is
      Len   : N32;
      Start : N32;
   begin
      Algo := Algo_Unknown;
      if DER (Pos) /= TAG_OID then OK := False; return; end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Len, OK);
      if not OK then return; end if;
      Start := Pos;

      --  Signature algorithms
      if OID_Match (DER, Start, Len, OID_SHA1_RSA) then
         Algo := Algo_RSA_PKCS1_SHA1;
      elsif OID_Match (DER, Start, Len, OID_SHA256_RSA) then
         Algo := Algo_RSA_PKCS1_SHA256;
      elsif OID_Match (DER, Start, Len, OID_SHA384_RSA) then
         Algo := Algo_RSA_PKCS1_SHA384;
      elsif OID_Match (DER, Start, Len, OID_SHA512_RSA) then
         Algo := Algo_RSA_PKCS1_SHA512;
      elsif OID_Match (DER, Start, Len, OID_RSA_PSS) then
         Algo := Algo_RSA_PSS;
      elsif OID_Match (DER, Start, Len, OID_ECDSA_SHA256) then
         Algo := Algo_ECDSA_P256_SHA256;
      elsif OID_Match (DER, Start, Len, OID_ECDSA_SHA384) then
         Algo := Algo_ECDSA_P384_SHA384;
      elsif OID_Match (DER, Start, Len, OID_Ed25519) then
         Algo := Algo_Ed25519;
      --  Public key algorithms
      elsif OID_Match (DER, Start, Len, OID_RSA) then
         Algo := Algo_RSA;
      elsif OID_Match (DER, Start, Len, OID_P256) then
         Algo := Algo_EC_P256;
      elsif OID_Match (DER, Start, Len, OID_P384) then
         Algo := Algo_EC_P384;
      elsif OID_Prefix_Match (DER, Start, Len, OID_EC) then
         --  EC key with unknown curve
         Algo := Algo_Unknown;
      end if;

      Skip (DER, Pos, Len, OK);
   end Parse_Algorithm_OID;

   --================================================================
   --  Name (RDN) parsing — extracts CN, Org, Country as Spans
   --================================================================

   --  Helper: check if a byte is valid PrintableString
   function Is_PrintableString_Char (B : Byte) return Boolean is
     (B in 16#41# .. 16#5A#   --  A-Z
      | 16#61# .. 16#7A#      --  a-z
      | 16#30# .. 16#39#      --  0-9
      | 16#20#                 --  space
      | 16#27#                 --  '
      | 16#28#                 --  (
      | 16#29#                 --  )
      | 16#2B#                 --  +
      | 16#2C#                 --  ,
      | 16#2D#                 --  -
      | 16#2E#                 --  .
      | 16#2F#                 --  /
      | 16#3A#                 --  :
      | 16#3D#                 --  =
      | 16#3F#);               --  ?

   procedure Parse_Name
     (DER          : in     Byte_Seq;
      Pos          : in out N32;
      Name_Len     : in     N32;
      CN           :    out Span;
      Org          :    out Span;
      Country      :    out Span;
      Bad_Encoding : in out Boolean;
      OK           : in out Boolean)
   with Pre => OK and DER'First = 0 and DER'Last < N32'Last
   is
      End_Pos  : N32;
      Set_Len  : N32;
      Seq_Len  : N32;
      OID_Len  : N32;
      OID_Start : N32;
      Val_Len  : N32;
      Str_Tag  : Byte;
   begin
      CN      := (0, 0, False);
      Org     := (0, 0, False);
      Country := (0, 0, False);

      if Name_Len = 0 or else not Can_Read (DER, Pos, Name_Len) then
         return;
      end if;

      End_Pos := Pos + Name_Len;

      while OK and then Pos < End_Pos and then Pos <= DER'Last loop
         --  Each RDN is a SET { SEQUENCE { OID, value } }
         if DER (Pos) /= TAG_SET then Skip (DER, Pos, End_Pos - Pos, OK); exit; end if;
         Pos := Pos + 1;
         if Pos > DER'Last then OK := False; return; end if;
         Parse_Length (DER, Pos, Set_Len, OK);
         if not OK then return; end if;

         --  Inside SET: SEQUENCE
         if Pos > DER'Last then
            OK := False; return;
         end if;
         if DER (Pos) /= TAG_SEQUENCE then
            Skip (DER, Pos, Set_Len, OK);
            if not OK then return; end if;
         else
            Pos := Pos + 1;
            if Pos > DER'Last then OK := False; return; end if;
            Parse_Length (DER, Pos, Seq_Len, OK);
            if not OK then return; end if;

            --  OID
            if Pos > DER'Last then
               OK := False; return;
            end if;
            if DER (Pos) /= TAG_OID then
               Skip (DER, Pos, Seq_Len, OK);
               if not OK then return; end if;
            else
               Pos := Pos + 1;
               if Pos > DER'Last then OK := False; return; end if;
               Parse_Length (DER, Pos, OID_Len, OK);
               if not OK then return; end if;
               OID_Start := Pos;
               Skip (DER, Pos, OID_Len, OK);
               if not OK then return; end if;

               --  Value (string type tag + length + value)
               if Pos > DER'Last then OK := False; return; end if;
               Str_Tag := DER (Pos);
               Pos := Pos + 1;  --  skip string type tag

               --  Check for T61String (0x14)
               if Str_Tag = 16#14# then
                  Bad_Encoding := True;
               end if;

               if Pos > DER'Last then OK := False; return; end if;
               Parse_Length (DER, Pos, Val_Len, OK);
               if not OK then return; end if;

               --  Validate PrintableString charset
               if Str_Tag = 16#13# and then Val_Len > 0
                  and then Can_Read (DER, Pos, Val_Len)
               then
                  for J in N32 range 0 .. Val_Len - 1 loop
                     pragma Loop_Invariant (Pos + J <= DER'Last);
                     if not Is_PrintableString_Char (DER (Pos + J)) then
                        Bad_Encoding := True;
                     end if;
                  end loop;
               end if;

               --  Match OID and record the span
               if Can_Read (DER, Pos, Val_Len) then
                  if OID_Match (DER, OID_Start, OID_Len, OID_CN) then
                     CN := (First => Pos, Last => Pos + Val_Len - 1, Present => True);
                  elsif OID_Match (DER, OID_Start, OID_Len, OID_ORG) then
                     Org := (First => Pos, Last => Pos + Val_Len - 1, Present => True);
                  elsif OID_Match (DER, OID_Start, OID_Len, OID_COUNTRY) then
                     Country := (First => Pos, Last => Pos + Val_Len - 1, Present => True);
                  end if;
               end if;

               Skip (DER, Pos, Val_Len, OK);
            end if;
         end if;
      end loop;
   end Parse_Name;

   --================================================================
   --  Time parsing (UTCTime / GeneralizedTime)
   --================================================================

   --  No forward declaration needed — Parse_Time_Value is fully SPARK

   function Digit (B : Byte) return Natural is (Natural (B) - 48)
   with Pre => B in 16#30# .. 16#39#;

   function Two_Digits (DER : Byte_Seq; Pos : N32) return Natural is
     (Digit (DER (Pos)) * 10 + Digit (DER (Pos + 1)))
   with Pre => DER'First = 0
               and then Pos < N32'Last
               and then Pos + 1 <= DER'Last
               and then DER (Pos) in 16#30# .. 16#39#
               and then DER (Pos + 1) in 16#30# .. 16#39#;

   --  Safe digit: 0..9 if ASCII digit, sets Bad if not
   procedure Safe_Digit
     (B : in Byte; Val : out Natural; Bad : in out Boolean)
   is
   begin
      if B in 16#30# .. 16#39# then
         Val := Natural (B) - 48;
      else
         Val := 0;
         Bad := True;
      end if;
   end Safe_Digit;

   procedure Safe_Two
     (B1, B2 : in Byte; Val : out Natural; Bad : in out Boolean)
   is
      D1, D2 : Natural;
   begin
      Safe_Digit (B1, D1, Bad);
      Safe_Digit (B2, D2, Bad);
      Val := D1 * 10 + D2;
   end Safe_Two;

   procedure Parse_Time_Value
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      Len  : in     N32;
      T    :    out Date_Time;
      OK   : in out Boolean)
   is
      Y, M, D, Hr, Mn, Sc : Natural := 0;
      Bad : Boolean := False;

      type Month_Days is array (1 .. 12) of Natural;
      Max_Days : constant Month_Days :=
        (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
   begin
      T := (others => 0);

      if DER'First /= 0 or else (Len < 15 and then Len < 13) then
         OK := False; return;
      end if;
      if Pos > N32'Last - 15 then
         OK := False; return;
      end if;
      --  Now Pos + 15 won't overflow
      if Len >= 15 then
         if Pos + 14 > DER'Last then OK := False; return; end if;
      else
         if Pos + 12 > DER'Last then OK := False; return; end if;
      end if;
      --  Now: Pos + Len - 1 <= DER'Last, Len >= 13, Off = 0
      --  So Pos + Off + 12 <= DER'Last throughout

      if Len >= 15 then
         --  GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes)
         declare
            YH, YL : Natural;
         begin
            Safe_Two (DER (Pos + 0), DER (Pos + 1), YH, Bad);
            Safe_Two (DER (Pos + 2), DER (Pos + 3), YL, Bad);
            Y := YH * 100 + YL;
         end;
         Safe_Two (DER (Pos + 4),  DER (Pos + 5),  M, Bad);
         Safe_Two (DER (Pos + 6),  DER (Pos + 7),  D, Bad);
         Safe_Two (DER (Pos + 8),  DER (Pos + 9),  Hr, Bad);
         Safe_Two (DER (Pos + 10), DER (Pos + 11), Mn, Bad);
         Safe_Two (DER (Pos + 12), DER (Pos + 13), Sc, Bad);
      else
         --  UTCTime: YYMMDDHHMMSSZ (13 bytes)
         Safe_Two (DER (Pos + 0),  DER (Pos + 1),  Y, Bad);
         if Y >= 50 then Y := 1900 + Y; else Y := 2000 + Y; end if;
         Safe_Two (DER (Pos + 2),  DER (Pos + 3),  M, Bad);
         Safe_Two (DER (Pos + 4),  DER (Pos + 5),  D, Bad);
         Safe_Two (DER (Pos + 6),  DER (Pos + 7),  Hr, Bad);
         Safe_Two (DER (Pos + 8),  DER (Pos + 9),  Mn, Bad);
         Safe_Two (DER (Pos + 10), DER (Pos + 11), Sc, Bad);
      end if;

      Pos := Pos + Len;

      if Bad then return; end if;
      if M not in 1 .. 12 then return; end if;
      if D < 1 or else D > Max_Days (M) then return; end if;
      if Hr > 23 then return; end if;
      if Mn > 59 then return; end if;
      if Sc > 59 then return; end if;

      T := (Year => Y, Month => M, Day => D,
            Hour => Hr, Minute => Mn, Second => Sc);
   end Parse_Time_Value;

   --================================================================
   --  Copy bytes into a fixed buffer
   --================================================================

   procedure Copy_Bytes
     (DER    : in     Byte_Seq;
      Start  : in     N32;
      Len    : in     N32;
      Buf    :    out Byte_Seq;
      Copied :    out N32)
   with Pre => DER'First = 0 and Buf'First = 0 and Buf'Last < N32'Last
   is
      Max : constant N32 := N32'Min (Len, N32 (Buf'Length));
   begin
      Buf := (others => 0);
      Copied := 0;
      if Max = 0 or else not Can_Read (DER, Start, Max) then
         return;
      end if;
      for I in N32 range 0 .. Max - 1 loop
         Buf (I) := DER (Start + I);
      end loop;
      Copied := Max;
   end Copy_Bytes;

   --================================================================
   --  Sub-procedures for certificate parsing
   --================================================================

   --  1. Parse version [0] EXPLICIT + serial INTEGER
   procedure Parse_Version_Serial
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      Len   : N32;
      Found : Boolean;
   begin
      if not Valid then return; end if;

      --  Version [0] EXPLICIT (optional, default v1)
      if Pos <= DER'Last then
         Parse_Explicit_Tag (DER, Pos, TAG_VERSION, Len, Found, Valid);
         if not Valid then return; end if;
         if Found then
            --  INTEGER inside the version tag
            if Pos <= DER'Last and then DER (Pos) = TAG_INTEGER then
               Pos := Pos + 1;
               if Pos <= DER'Last then
                  Parse_Length (DER, Pos, Len, Valid);
                  if Valid and then Len = 1 and then Pos <= DER'Last then
                     C.Cert_Version := Natural (DER (Pos)) + 1;
                     Pos := Pos + 1;
                  end if;
               end if;
            end if;
         else
            C.Cert_Version := 1;
         end if;
      end if;

      --  Serial Number (INTEGER)
      if not Valid or else Pos > DER'Last or else DER (Pos) /= TAG_INTEGER then
         Valid := False; return;
      end if;
      declare
         Serial_Start : N32;
      begin
         Pos := Pos + 1;
         if Pos > DER'Last then Valid := False; return; end if;
         Parse_Length (DER, Pos, Len, Valid);
         if not Valid then return; end if;
         Serial_Start := Pos;
         C.S_Serial := (First => Serial_Start, Last => Serial_Start + Len - 1,
                         Present => Len > 0);

         --  RFC 5280 §4.1.2.2: Serial must be positive (high bit clear)
         --  and must not be all zeros.
         if Len > 0 and then Can_Read (DER, Serial_Start, Len) then
            --  Negative check: first byte >= 0x80
            if DER (Serial_Start) >= 16#80# then
               C.Bad_Serial := True;
            end if;
            --  All-zeros check
            declare
               All_Zero : Boolean := True;
            begin
               for I in N32 range 0 .. Len - 1 loop
                  pragma Loop_Invariant (Serial_Start + I <= DER'Last);
                  if DER (Serial_Start + I) /= 0 then
                     All_Zero := False;
                  end if;
               end loop;
               if All_Zero then
                  C.Bad_Serial := True;
               end if;
            end;
            --  DER non-minimal integer check (X.690 §8.3.2):
            --  Leading 0x00 only allowed if next byte >= 0x80
            --  Leading 0xFF only allowed if next byte < 0x80
            if Len > 1 and then Serial_Start + 1 <= DER'Last then
               if DER (Serial_Start) = 16#00#
                  and then DER (Serial_Start + 1) < 16#80#
               then
                  C.Bad_DER := True;
               end if;
               if DER (Serial_Start) = 16#FF#
                  and then DER (Serial_Start + 1) >= 16#80#
               then
                  C.Bad_DER := True;
               end if;
            end if;
         end if;

         Skip (DER, Pos, Len, Valid);
      end;
   end Parse_Version_Serial;

   --  2. Parse TBS signature algorithm SEQUENCE { OID, params }
   procedure Parse_TBS_Sig_Algorithm
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      Sig_Seq_Len : N32;
      Sig_Seq_End : N32;
   begin
      if not Valid then return; end if;
      if Pos > DER'Last then Valid := False; return; end if;
      Parse_Sequence (DER, Pos, Sig_Seq_Len, Valid);
      if not Valid then return; end if;
      Sig_Seq_End := Pos + Sig_Seq_Len;
      if Pos <= DER'Last then
         Parse_Algorithm_OID (DER, Pos, C.Sig_Algo, Valid);
      end if;
      Pos := Sig_Seq_End;  --  skip any parameters
   end Parse_TBS_Sig_Algorithm;

   --  3. Parse Validity SEQUENCE { notBefore, notAfter }
   procedure Parse_Validity
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      Val_Len : N32;
      T_Tag   : Byte;
      T_Len   : N32;

      --  RFC 5280 §4.1.2.5 time format checks on a single time field.
      procedure Check_Time_Format
        (Tag     : Byte;
         T_Start : N32;
         T_Ln    : N32;
         DT      : Date_Time)
      is
      begin
         if T_Ln = 0 or else DER'First /= 0
            or else T_Start > DER'Last
            or else DER'Last - T_Start < T_Ln - 1
         then
            return;
         end if;
         --  Now: T_Start + T_Ln - 1 <= DER'Last
         --  Must end in 'Z' (0x5A)
         if DER (T_Start + T_Ln - 1) /= 16#5A# then
            C.Bad_Time_Format := True;
         end if;
         --  GeneralizedTime must NOT have fractional seconds ('.' = 0x2E)
         if Tag = TAG_GENTIME and then T_Ln > 14 then
            for I in N32 range 14 .. T_Ln - 1 loop
               pragma Loop_Invariant (T_Start + I <= DER'Last);
               if DER (T_Start + I) = 16#2E# then
                  C.Bad_Time_Format := True;
               end if;
            end loop;
         end if;
         --  Dates with year >= 2050 must use GeneralizedTime
         if Tag = TAG_UTCTIME and then DT.Year >= 2050 then
            C.Bad_Time_Format := True;
         end if;
         --  Dates with year <= 2049 must use UTCTime (not GeneralizedTime)
         if Tag = TAG_GENTIME and then DT.Year <= 2049 then
            C.Bad_Time_Format := True;
         end if;
      end Check_Time_Format;

   begin
      if not Valid then return; end if;
      if Pos > DER'Last then Valid := False; return; end if;

      Parse_Sequence (DER, Pos, Val_Len, Valid);
      if not Valid then return; end if;

      --  notBefore
      if Pos <= DER'Last then
         T_Tag := DER (Pos);
         if T_Tag = TAG_UTCTIME or T_Tag = TAG_GENTIME then
            Pos := Pos + 1;
            if Pos <= DER'Last then
               Parse_Length (DER, Pos, T_Len, Valid);
               if Valid then
                  declare
                     Time_Start : constant N32 := Pos;
                     Time_Len   : constant N32 := T_Len;
                     Saved_Tag  : constant Byte := T_Tag;
                  begin
                     Parse_Time_Value (DER, Pos, T_Len,
                                       C.Validity_Not_Before, Valid);
                     if Valid then
                        Check_Time_Format (Saved_Tag, Time_Start,
                                           Time_Len,
                                           C.Validity_Not_Before);
                     end if;
                  end;
               end if;
            end if;
         end if;
      end if;

      --  notAfter
      if Valid and then Pos <= DER'Last then
         T_Tag := DER (Pos);
         if T_Tag = TAG_UTCTIME or T_Tag = TAG_GENTIME then
            Pos := Pos + 1;
            if Pos <= DER'Last then
               Parse_Length (DER, Pos, T_Len, Valid);
               if Valid then
                  declare
                     Time_Start : constant N32 := Pos;
                     Time_Len   : constant N32 := T_Len;
                     Saved_Tag  : constant Byte := T_Tag;
                  begin
                     Parse_Time_Value (DER, Pos, T_Len,
                                       C.Validity_Not_After, Valid);
                     if Valid then
                        Check_Time_Format (Saved_Tag, Time_Start,
                                           Time_Len,
                                           C.Validity_Not_After);
                     end if;
                  end;
               end if;
            end if;
         end if;
      end if;
   end Parse_Validity;

   --  4. Parse SubjectPublicKeyInfo SEQUENCE { algorithm, publicKey }
   procedure Parse_SPKI
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      SPKI_Len    : N32;
      SPKI_End    : N32;
      Algo_Len    : N32;
      Algo_End    : N32;
      PK_Algo_ID  : Algorithm_ID := Algo_Unknown;
      Curve_Algo  : Algorithm_ID := Algo_Unknown;
      BStr_Len    : N32;
      Unused_Bits : Byte;
   begin
      if not Valid then return; end if;
      if Pos > DER'Last then Valid := False; return; end if;

      Parse_Sequence (DER, Pos, SPKI_Len, Valid);
      if not Valid then return; end if;
      SPKI_End := Pos + SPKI_Len;

      --  Algorithm SEQUENCE { OID [, parameters] }
      if Pos > DER'Last then Valid := False; return; end if;
      Parse_Sequence (DER, Pos, Algo_Len, Valid);
      if not Valid then return; end if;
      Algo_End := Pos + Algo_Len;
      if Pos <= DER'Last then
         Parse_Algorithm_OID (DER, Pos, PK_Algo_ID, Valid);
      end if;

      --  For EC keys, the curve OID follows
      if Valid and then PK_Algo_ID = Algo_Unknown and then Pos < Algo_End
         and then Pos <= DER'Last and then DER (Pos) = TAG_OID
      then
         Parse_Algorithm_OID (DER, Pos, Curve_Algo, Valid);
         if Curve_Algo in Algo_EC_P256 | Algo_EC_P384 then
            PK_Algo_ID := Curve_Algo;
         end if;
      end if;

      --  RFC 5280: RSA AlgorithmIdentifier parameters must be NULL
      if Valid and then PK_Algo_ID = Algo_RSA
         and then Pos < Algo_End
         and then Pos + 1 <= DER'Last
      then
         if DER (Pos) /= TAG_NULL
            or else DER (Pos + 1) /= 16#00#
         then
            C.Bad_PubKey := True;
         end if;
      end if;

      C.PK_Algo := PK_Algo_ID;
      Pos := Algo_End;

      --  Public key BIT STRING
      if not Valid or else Pos > DER'Last or else DER (Pos) /= TAG_BITSTRING then
         Valid := False; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then Valid := False; return; end if;
      Parse_Length (DER, Pos, BStr_Len, Valid);
      if not Valid or BStr_Len < 2 then Valid := False; return; end if;
      if Pos > DER'Last then Valid := False; return; end if;
      Unused_Bits := DER (Pos);
      Pos := Pos + 1;
      BStr_Len := BStr_Len - 1;  --  subtract unused bits byte

      --  DER BIT STRING check: unused_bits must be 0..7,
      --  and if no value bytes then unused_bits must be 0
      if Unused_Bits > 7 then
         C.Bad_DER := True;
      end if;
      if BStr_Len = 0 and then Unused_Bits > 0 then
         C.Bad_DER := True;
      end if;
      --  DER BIT STRING: unused bits in last byte must be zero
      if Unused_Bits > 0 and then BStr_Len > 0
         and then Can_Read (DER, Pos, BStr_Len)
      then
         declare
            Last_Byte : constant Byte := DER (Pos + BStr_Len - 1);
            Mask      : constant Byte :=
              Shift_Left (1, Natural (Unused_Bits)) - 1;
         begin
            if (Last_Byte and Mask) /= 0 then
               C.Bad_DER := True;
            end if;
         end;
      end if;

      if PK_Algo_ID = Algo_RSA then
         --  RSA key: BIT STRING contains SEQUENCE { modulus INTEGER, exponent INTEGER }
         if Pos <= DER'Last and then DER (Pos) = TAG_SEQUENCE then
            declare
               RSA_Len : N32;
               Mod_Len : N32;
               Exp_Len : N32;
            begin
               Parse_Sequence (DER, Pos, RSA_Len, Valid);
               if Valid and then Pos <= DER'Last and then DER (Pos) = TAG_INTEGER then
                  Pos := Pos + 1;
                  if Pos <= DER'Last then
                     Parse_Length (DER, Pos, Mod_Len, Valid);
                     if Valid then
                        --  Skip leading zero byte if present
                        if Mod_Len > 0 and then Pos <= DER'Last
                           and then DER (Pos) = 0
                        then
                           Pos := Pos + 1;
                           Mod_Len := Mod_Len - 1;
                        end if;
                        Copy_Bytes (DER, Pos, Mod_Len, C.PK_Buf, C.PK_Buf_Len);
                        --  RFC 5280: RSA modulus must be positive
                        if C.PK_Buf_Len > 0
                           and then C.PK_Buf (0) >= 16#80#
                        then
                           C.Bad_PubKey := True;
                        end if;
                        Skip (DER, Pos, Mod_Len, Valid);
                     end if;
                  end if;
               end if;
               --  Exponent INTEGER
               if Valid and then Pos <= DER'Last and then DER (Pos) = TAG_INTEGER then
                  Pos := Pos + 1;
                  if Pos <= DER'Last then
                     Parse_Length (DER, Pos, Exp_Len, Valid);
                     if Valid and then Exp_Len > 0
                        and then Can_Read (DER, Pos, Exp_Len)
                     then
                        pragma Assert (Pos + Exp_Len - 1 <= DER'Last);
                        C.PK_RSA_Exp := 0;
                        declare
                           Limit : constant N32 := N32'Min (Exp_Len, 4);
                        begin
                           pragma Assert (Limit <= Exp_Len);
                           pragma Assert (Limit >= 1);
                           for I in N32 range 0 .. Limit - 1 loop
                              pragma Loop_Invariant
                                (Pos + Exp_Len - 1 <= DER'Last
                                 and then I <= Limit - 1
                                 and then Limit <= Exp_Len);
                              pragma Assert (I < Exp_Len);
                              pragma Assert (Pos + I <= Pos + Exp_Len - 1);
                              C.PK_RSA_Exp := C.PK_RSA_Exp * 256 +
                                              Unsigned_32 (DER (Pos + I));
                           end loop;
                        end;
                        Skip (DER, Pos, Exp_Len, Valid);
                     end if;
                  end if;
               end if;
            end;
         else
            Skip (DER, Pos, BStr_Len, Valid);
         end if;
      else
         --  EC / Ed25519: raw key bytes in BIT STRING
         Copy_Bytes (DER, Pos, BStr_Len, C.PK_Buf, C.PK_Buf_Len);
         Skip (DER, Pos, BStr_Len, Valid);
      end if;

      Pos := SPKI_End;
   end Parse_SPKI;

   --  5. Parse optional issuerUniqueID [1], subjectUniqueID [2]
   procedure Parse_Unique_IDs
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
   begin
      if not Valid then return; end if;

      --  issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL
      --  subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
      --  RFC 5280 §4.1.2.8: only allowed in v2 and v3
      if Pos <= DER'Last and then C.S_TBS.Present
         and then Pos <= C.S_TBS.Last
      then
         --  issuerUniqueID: tag 0xA1 (constructed) or 0x81 (primitive)
         if Pos <= DER'Last and then
            (DER (Pos) = 16#A1# or DER (Pos) = 16#81#)
         then
            C.Has_Unique_ID := True;
            --  Validate BIT STRING content
            declare
               Save_Pos : constant N32 := Pos;
               Uid_Len  : N32;
            begin
               Pos := Pos + 1;
               if Pos <= DER'Last then
                  Parse_Length (DER, Pos, Uid_Len, Valid);
                  if Valid and then Uid_Len > 0
                     and then Pos <= DER'Last
                  then
                     --  Check for SEQUENCE (invalid for BIT STRING)
                     if DER (Pos) = 16#30# then
                        C.Bad_DER := True;
                     end if;
                     --  Check BIT STRING trailing bits
                     if Uid_Len >= 2 then
                        declare
                           UB : constant Byte := DER (Pos);
                        begin
                           if UB > 0 and then UB <= 7
                              and then Can_Read (DER, Pos, Uid_Len)
                           then
                              declare
                                 Last_B : constant Byte :=
                                   DER (Pos + Uid_Len - 1);
                                 Mask2  : constant Byte :=
                                   Shift_Left (1, Natural (UB)) - 1;
                              begin
                                 if (Last_B and Mask2) /= 0 then
                                    C.Bad_DER := True;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end if;
               end if;
               Pos := Save_Pos;
               Valid := True;
            end;
            Skip_TLV (DER, Pos, Valid);
         end if;
         --  subjectUniqueID: tag 0xA2 (constructed) or 0x82 (primitive)
         if Valid and then Pos <= DER'Last
            and then Pos <= C.S_TBS.Last
            and then (DER (Pos) = 16#A2# or DER (Pos) = 16#82#)
         then
            C.Has_Unique_ID := True;
            --  Validate BIT STRING content
            declare
               Save_Pos : constant N32 := Pos;
               Uid_Len  : N32;
            begin
               Pos := Pos + 1;
               if Pos <= DER'Last then
                  Parse_Length (DER, Pos, Uid_Len, Valid);
                  if Valid and then Uid_Len > 0
                     and then Pos <= DER'Last
                  then
                     --  Check for SEQUENCE (invalid for BIT STRING)
                     if DER (Pos) = 16#30# then
                        C.Bad_DER := True;
                     end if;
                     --  Check BIT STRING trailing bits
                     if Uid_Len >= 2 then
                        declare
                           UB : constant Byte := DER (Pos);
                        begin
                           if UB > 0 and then UB <= 7
                              and then Can_Read (DER, Pos, Uid_Len)
                           then
                              declare
                                 Last_B : constant Byte :=
                                   DER (Pos + Uid_Len - 1);
                                 Mask2  : constant Byte :=
                                   Shift_Left (1, Natural (UB)) - 1;
                              begin
                                 if (Last_B and Mask2) /= 0 then
                                    C.Bad_DER := True;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end if;
               end if;
               Pos := Save_Pos;
               Valid := True;
            end;
            Skip_TLV (DER, Pos, Valid);
         end if;
      end if;
   end Parse_Unique_IDs;

   --  6. Extension sub-procedures
   --  Each handles one extension type. Pos is "in" — the outer loop
   --  advances past Ext_Seq_End regardless.

   procedure Parse_Ext_SAN
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  SAN noncrit + empty subject check
      if not Is_Critical
         and then not C.Has_Subject
      then
         C.SAN_Noncrit_Empty_Subj := True;
      end if;
      --  RFC 5280 §4.2.1.6: SAN critical with non-empty subject
      if Is_Critical and then C.Has_Subject then
         C.SAN_Critical_With_Subject := True;
      end if;
      --  SAN: SEQUENCE of GeneralName
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then
            Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            --  RFC 5280 4.2.1.6: empty SAN
            if Inner_Len = 0 then
               C.Bad_SAN := True;
            end if;
            declare
               Saw_DNS  : Boolean := False;
               Saw_Other : Boolean := False;
            begin
            while Valid and then P < Inner_End
                  and then P <= DER'Last
            loop
               declare
                  GN_Tag : constant Byte :=
                     DER (P);
                  GN_Len : N32;
               begin
                  P := P + 1;
                  if P > DER'Last then
                     Valid := False; exit;
                  end if;
                  Parse_Length
                    (DER, P, GN_Len, Valid);
                  if not Valid then exit; end if;

                  --  Tag 0x82 = dNSName (context
                  --  tag 2, primitive)
                  if GN_Tag = 16#82# then
                     Saw_DNS := True;
                     if GN_Len = 0 then
                        --  Blank DNS name
                        C.Bad_SAN := True;
                     elsif Can_Read
                        (DER, P, GN_Len)
                     then
                        --  Validate DNS chars
                        for J in N32 range
                           0 .. GN_Len - 1
                        loop
                           pragma Loop_Invariant
                             (P + J <= DER'Last);
                           declare
                              Ch : constant Byte :=
                                DER (P + J);
                           begin
                              if not (Ch in
                                 16#61# .. 16#7A#  --  a-z
                               | 16#41# .. 16#5A#  --  A-Z
                               | 16#30# .. 16#39#  --  0-9
                               | 16#2D#            --  '-'
                               | 16#2E#            --  '.'
                               | 16#2A#)           --  '*'
                              then
                                 C.Bad_SAN := True;
                              end if;
                           end;
                        end loop;
                        if C.SAN_Num < Max_SANs
                        then
                           C.SAN_Num :=
                              C.SAN_Num + 1;
                           C.SANs (C.SAN_Num) :=
                             (First   => P,
                              Last    =>
                                 P + GN_Len - 1,
                              Present => True);
                        end if;
                     end if;

                  elsif GN_Tag = 16#81# then
                     --  rfc822Name (email)
                     Saw_Other := True;
                     --  Empty GeneralName value
                     if GN_Len = 0 then
                        C.Bad_SAN := True;
                     end if;
                     if GN_Len > 0
                        and then Can_Read
                           (DER, P, GN_Len)
                     then
                        declare
                           Has_At   : Boolean :=
                             False;
                           Bad_Char : Boolean :=
                             False;
                        begin
                           for J in N32 range
                              0 .. GN_Len - 1
                           loop
                              pragma Loop_Invariant
                                (P + J <=
                                   DER'Last);
                              if DER (P + J) =
                                 16#40#
                              then
                                 Has_At := True;
                              end if;
                              --  RFC 2821 Mailbox:
                              --  no spaces, angles
                              if DER (P + J) =
                                    16#20#
                                 or DER (P + J) =
                                    16#3C#
                                 or DER (P + J) =
                                    16#3E#
                              then
                                 Bad_Char := True;
                              end if;
                           end loop;
                           if not Has_At
                              or Bad_Char
                           then
                              C.Bad_SAN := True;
                           end if;
                        end;
                     end if;

                  elsif GN_Tag = 16#86# then
                     --  uniformResourceIdentifier
                     Saw_Other := True;
                     if GN_Len = 0 then
                        C.Bad_SAN := True;
                     end if;
                     if GN_Len > 0
                        and then Can_Read
                           (DER, P, GN_Len)
                     then
                        --  Check for "://" scheme
                        declare
                           Has_Scheme : Boolean :=
                             False;
                        begin
                           if GN_Len >= 3
                              and then P <= DER'Last
                              and then DER'Last - P >= GN_Len - 1
                           then
                              for J in N32 range
                                 0 .. GN_Len - 3
                              loop
                                 pragma
                                   Loop_Invariant
                                     (P + J + 2
                                        <= DER'Last);
                                 if DER (P + J)
                                      = 16#3A#
                                    and then
                                    DER (P + J + 1)
                                      = 16#2F#
                                    and then
                                    DER (P + J + 2)
                                      = 16#2F#
                                 then
                                    Has_Scheme :=
                                      True;
                                 end if;
                              end loop;
                           end if;
                           if not Has_Scheme then
                              C.Bad_SAN := True;
                           end if;
                        end;
                     end if;

                  elsif GN_Tag = 16#87# then
                     --  iPAddress
                     Saw_Other := True;
                     if GN_Len /= 4
                        and then GN_Len /= 16
                     then
                        C.Bad_SAN := True;
                     end if;

                  elsif GN_Tag in
                     16#80# | 16#83# | 16#84#
                     | 16#85# | 16#88#
                  then
                     --  Other known tags
                     Saw_Other := True;

                  else
                     --  Unrecognized SAN tag
                     C.Bad_SAN := True;
                  end if;

                  Skip (DER, P, GN_Len, Valid);
               end;
            end loop;
            --  Note: SANs with only non-DNS names
            --  (e.g. email-only) are valid per RFC 5280
            end;
         end if;
      end if;
   end Parse_Ext_SAN;

   procedure Parse_Ext_Basic_Constraints
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      C.Ext_Basic_Crit := Is_Critical;
      --  Basic Constraints: SEQUENCE {
      --    BOOLEAN (isCA)?, INTEGER (pathLen)? }
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then Inner_Len > 0
            and then Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            --  Optional isCA BOOLEAN
            if P < Inner_End
               and then P <= DER'Last
               and then DER (P) = TAG_BOOLEAN
            then
               P := P + 1;
               if P > DER'Last then
                  Valid := False;
               else
                  declare
                     B_Len : N32;
                  begin
                     Parse_Length
                       (DER, P, B_Len, Valid);
                     if Valid and then B_Len = 1
                        and then P <= DER'Last
                     then
                        C.Ext_Is_CA :=
                          DER (P) /= 0;
                        P := P + 1;
                     elsif Valid then
                        Skip
                          (DER, P, B_Len, Valid);
                     end if;
                  end;
               end if;
            end if;
            --  Optional pathLen INTEGER
            if Valid and then P < Inner_End
               and then P <= DER'Last
               and then DER (P) = TAG_INTEGER
            then
               P := P + 1;
               if P <= DER'Last then
                  declare
                     PL_Len : N32;
                  begin
                     Parse_Length
                       (DER, P, PL_Len, Valid);
                     if Valid and then PL_Len >= 1
                        and then P <= DER'Last
                     then
                        C.Ext_Has_Path_Len := True;
                        C.Ext_Path_Len :=
                          Natural (DER (P));
                        Skip
                          (DER, P, PL_Len, Valid);
                     end if;
                  end;
               end if;
            end if;
         end if;
      end if;
   end Parse_Ext_Basic_Constraints;

   procedure Parse_Ext_Key_Usage
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P : N32 := Pos;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      C.Ext_Key_Usage_Crit := Is_Critical;
      --  Key Usage: BIT STRING
      if P <= DER'Last
         and then DER (P) = TAG_BITSTRING
      then
         P := P + 1;
         if P > DER'Last then
            Valid := False;
         else
            declare
               BS_Len      : N32;
               Unused_Bits : Byte;
            begin
               Parse_Length
                 (DER, P, BS_Len, Valid);
               if Valid and then BS_Len >= 1
                  and then P <= DER'Last
                  and then Can_Read
                     (DER, P, BS_Len)
               then
                  Unused_Bits := DER (P);
                  P := P + 1;
                  BS_Len := BS_Len - 1;
                  C.Ext_Has_Key_Usage := True;
                  if BS_Len >= 1 then
                     --  First byte of key usage bits
                     if P <= DER'Last then
                        C.Ext_Key_Usage :=
                          Unsigned_16 (DER (P))
                          * 256;
                        if BS_Len >= 2
                           and then P + 1 <=
                              DER'Last
                        then
                           C.Ext_Key_Usage :=
                             C.Ext_Key_Usage or
                             Unsigned_16
                               (DER (P + 1));
                        end if;
                     end if;
                  end if;
                  --  RFC 5280 4.2.1.3: KU with
                  --  no bits set is invalid
                  --  (includes BS_Len=0: only
                  --  unused-bits byte, no value)
                  if C.Ext_Key_Usage = 0 then
                     C.Empty_Key_Usage := True;
                  end if;
                  --  X.690 §11.2.2: DER BIT STRING
                  --  trailing zero bits check.
                  --  The unused_bits count must match
                  --  actual trailing zeros in last byte.
                  if BS_Len >= 1
                     and then Unused_Bits > 0
                  then
                     declare
                        Last_Byte : Byte;
                        Mask : Byte;
                     begin
                        if BS_Len = 1
                           and then P <= DER'Last
                        then
                           Last_Byte := DER (P);
                        elsif BS_Len >= 2
                           and then P + 1 <= DER'Last
                        then
                           Last_Byte := DER (P + 1);
                        else
                           Last_Byte := 0;
                        end if;
                        --  Mask for the unused bits
                        Mask :=
                          Shift_Left (1, Natural (Unused_Bits)) - 1;
                        if (Last_Byte and Mask) /= 0 then
                           C.Bad_DER := True;
                        end if;
                     end;
                  end if;
               end if;
            end;
         end if;
      end if;
   end Parse_Ext_Key_Usage;

   procedure Parse_Ext_SKID
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P : N32 := Pos;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280: SKID MUST NOT be critical
      if Is_Critical then
         C.Bad_Ext_Criticality := True;
      end if;
      --  Subject Key ID: OCTET STRING
      if P <= DER'Last
         and then DER (P) = TAG_OCTETSTRING
      then
         P := P + 1;
         if P > DER'Last then
            Valid := False;
         else
            declare
               SK_Len : N32;
            begin
               Parse_Length
                 (DER, P, SK_Len, Valid);
               if Valid and then SK_Len > 0
                  and then Can_Read
                     (DER, P, SK_Len)
               then
                  C.S_Subject_Key_ID :=
                    (First   => P,
                     Last    => P + SK_Len - 1,
                     Present => True);
               end if;
            end;
         end if;
      end if;
   end Parse_Ext_SKID;

   procedure Parse_Ext_AKID
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280: AKID MUST NOT be critical
      if Is_Critical then
         C.Bad_Ext_Criticality := True;
      end if;
      --  Authority Key ID: SEQUENCE {
      --    [0] keyIdentifier IMPLICIT OCTET STRING
      --    [1] authorityCertIssuer IMPLICIT GeneralNames
      --    [2] authorityCertSerialNumber IMPLICIT INTEGER
      --  }
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then Inner_Len > 0
            and then Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            declare
               Has_Key_ID  : Boolean := False;
               Has_Issuer  : Boolean := False;
               Has_Serial2 : Boolean := False;
               Scan_Pos    : N32 := P;
            begin
            --  Scan all tags in AKID SEQUENCE
            while Valid and then Scan_Pos < Inner_End
                  and then Scan_Pos <= DER'Last
            loop
               declare
                  AKID_Tag : constant Byte :=
                    DER (Scan_Pos);
                  AKID_TLen : N32;
               begin
                  if AKID_Tag = 16#80# then
                     Has_Key_ID := True;
                  elsif AKID_Tag = 16#A1# then
                     Has_Issuer := True;
                  elsif AKID_Tag = 16#82# then
                     Has_Serial2 := True;
                  end if;
                  --  Skip this element
                  Scan_Pos := Scan_Pos + 1;
                  if Scan_Pos > DER'Last then
                     exit;
                  end if;
                  Parse_Length
                    (DER, Scan_Pos, AKID_TLen, Valid);
                  if Valid then
                     --  Validate [1] authorityCertIssuer content
                     if AKID_Tag = 16#A1#
                        and then AKID_TLen > 0
                        and then Can_Read
                          (DER, Scan_Pos, AKID_TLen)
                     then
                        --  Scan GeneralNames inside [1]
                        declare
                           GN_Scan : N32 :=
                             Scan_Pos;
                           GN_End  : constant N32 :=
                             Scan_Pos + AKID_TLen;
                           GN_OK   : Boolean := True;
                        begin
                           while GN_OK
                             and then GN_Scan < GN_End
                             and then GN_Scan <= DER'Last
                           loop
                              declare
                                 GT : constant Byte :=
                                   DER (GN_Scan);
                                 GL : N32;
                              begin
                                 --  Must be valid GN tag
                                 if not (GT in
                                    16#80# .. 16#88#
                                    | 16#A0# .. 16#A8#)
                                 then
                                    C.Bad_AKID := True;
                                    exit;
                                 end if;
                                 GN_Scan := GN_Scan + 1;
                                 if GN_Scan > DER'Last
                                 then
                                    exit;
                                 end if;
                                 Parse_Length
                                   (DER, GN_Scan,
                                    GL, GN_OK);
                                 if not GN_OK then
                                    exit;
                                 end if;
                                 --  iPAddress must be
                                 --  4 or 16 bytes
                                 if GT = 16#87#
                                    and then GL /= 4
                                    and then GL /= 16
                                 then
                                    C.Bad_AKID := True;
                                 end if;
                                 Skip (DER, GN_Scan,
                                       GL, GN_OK);
                              end;
                           end loop;
                        end;
                     end if;
                     Skip (DER, Scan_Pos,
                           AKID_TLen, Valid);
                  end if;
               end;
            end loop;

            --  Extract keyIdentifier [0]
            if Has_Key_ID
               and then P <= DER'Last
               and then DER (P) = 16#80#
            then
               declare
                  AK_Pos : N32 := P + 1;
                  AK_Len : N32;
               begin
                  if Valid and then AK_Pos <= DER'Last then
                     Parse_Length
                       (DER, AK_Pos, AK_Len, Valid);
                     if Valid and then AK_Len > 0
                        and then Can_Read
                           (DER, AK_Pos, AK_Len)
                     then
                        C.S_Auth_Key_ID :=
                          (First   => AK_Pos,
                           Last    =>
                             AK_Pos + AK_Len - 1,
                           Present => True);
                     end if;
                  end if;
               end;
            end if;

            if not Has_Key_ID then
               --  RFC 5280 4.2.1.1: AKID without
               --  keyIdentifier
               C.AKID_Missing_Key_ID := True;
            end if;

            --  RFC 5280 4.2.1.1: authorityCertIssuer
            --  and authorityCertSerialNumber MUST both
            --  be present or both absent
            if Has_Issuer /= Has_Serial2 then
               C.Bad_AKID := True;
            end if;
            end;
         end if;
      end if;
   end Parse_Ext_AKID;

   procedure Parse_Ext_Cert_Policies
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len, Is_Critical);
      --  RFC 5280 §4.2.1.4: Certificate Policies
      --  Parse SEQUENCE of PolicyInformation,
      --  check for duplicates and BMPString
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then Inner_Len > 0
            and then Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            declare
               --  Track up to 10 policy OIDs
               --  for duplicate detection
               type OID_Rec is record
                  Start : N32 := 0;
                  Len   : N32 := 0;
               end record;
               type OID_Arr is array
                 (1 .. 10) of OID_Rec;
               Seen_OIDs : OID_Arr :=
                 (others => (0, 0));
               Seen_Count : Natural := 0;
            begin
            while Valid
                  and then P < Inner_End
                  and then P <= DER'Last
            loop
               --  Each PolicyInformation is a
               --  SEQUENCE { OID, qualifiers? }
               if DER (P) /= TAG_SEQUENCE then
                  exit;
               end if;
               declare
                  PI_Len   : N32;
                  PI_End   : N32;
                  PO_Len   : N32;
                  PO_Start : N32;
               begin
                  Parse_Sequence
                    (DER, P, PI_Len, Valid);
                  if not Valid then exit; end if;
                  if not Can_Read
                    (DER, P, PI_Len)
                  then
                     exit;
                  end if;
                  PI_End := P + PI_Len;
                  --  Parse policy OID
                  if P <= DER'Last
                     and then
                     DER (P) = TAG_OID
                  then
                     P := P + 1;
                     if P > DER'Last then
                        Valid := False;
                        exit;
                     end if;
                     Parse_Length
                       (DER, P, PO_Len, Valid);
                     if not Valid then exit; end if;
                     PO_Start := P;
                     --  Check for duplicate
                     for I in 1 .. Seen_Count loop
                        if I <= 10
                           and then
                           Seen_OIDs (I).Len =
                             PO_Len
                           and then PO_Len > 0
                           and then Can_Read
                             (DER, PO_Start, PO_Len)
                           and then Can_Read
                             (DER,
                              Seen_OIDs (I).Start,
                              PO_Len)
                        then
                           declare
                              Match : Boolean :=
                                True;
                           begin
                              for J in N32 range
                                0 .. PO_Len - 1
                              loop
                                 pragma
                                   Loop_Invariant
                                     (PO_Start + J
                                        <= DER'Last
                                      and then
                                      Seen_OIDs (I)
                                        .Start + J
                                        <= DER'Last);
                                 if DER
                                   (PO_Start + J)
                                   /= DER
                                   (Seen_OIDs (I)
                                      .Start + J)
                                 then
                                    Match := False;
                                 end if;
                              end loop;
                              if Match then
                                 C.Bad_Cert_Policy
                                   := True;
                              end if;
                           end;
                        end if;
                     end loop;
                     --  Record this OID
                     if Seen_Count < 10 then
                        Seen_Count :=
                          Seen_Count + 1;
                        Seen_OIDs (Seen_Count) :=
                          (Start => PO_Start,
                           Len   => PO_Len);
                     end if;
                     Skip (DER, P, PO_Len, Valid);
                     if not Valid then exit; end if;
                  end if;
                  --  Scan remaining PI bytes for
                  --  BMPString tag (0x1E) and
                  --  control chars in UTF8String
                  while P < PI_End
                        and then P <= DER'Last
                  loop
                     if DER (P) = 16#1E# then
                        C.Bad_Cert_Policy := True;
                     end if;
                     --  Check for UTF8String (0x0C)
                     --  containing control characters
                     if DER (P) = 16#0C#
                        and then P + 1 <= DER'Last
                     then
                        declare
                           U8_Pos : N32 := P + 1;
                           U8_Len : N32;
                           U8_Valid : Boolean := True;
                        begin
                           Parse_Length
                             (DER, U8_Pos, U8_Len,
                              U8_Valid);
                           if U8_Valid
                              and then U8_Len > 0
                              and then Can_Read
                                (DER, U8_Pos, U8_Len)
                           then
                              for K in N32 range
                                0 .. U8_Len - 1
                              loop
                                 pragma Loop_Invariant
                                   (U8_Pos + K
                                      <= DER'Last);
                                 if DER (U8_Pos + K)
                                      < 16#20#
                                    and then
                                    DER (U8_Pos + K)
                                      /= 16#09#
                                    and then
                                    DER (U8_Pos + K)
                                      /= 16#0A#
                                    and then
                                    DER (U8_Pos + K)
                                      /= 16#0D#
                                 then
                                    C.Bad_Cert_Policy
                                      := True;
                                 end if;
                              end loop;
                           end if;
                        end;
                     end if;
                     P := P + 1;
                  end loop;
                  P := PI_End;
               end;
            end loop;
            end;
         end if;
      end if;
   end Parse_Ext_Cert_Policies;

   procedure Parse_Ext_EKU
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280 §4.2.1.12: Extended Key Usage
      --  SEQUENCE of OID, each must be valid
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then
            Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            --  Empty EKU SEQUENCE is invalid
            if Inner_Len = 0 then
               C.Bad_EKU_Content := True;
            end if;
            while Valid
                  and then P < Inner_End
                  and then P <= DER'Last
            loop
               if DER (P) /= TAG_OID then
                  C.Bad_EKU_Content := True;
                  exit;
               end if;
               P := P + 1;
               if P > DER'Last then
                  Valid := False; exit;
               end if;
               declare
                  EKU_OLen  : N32;
                  EKU_Start : N32;
               begin
                  Parse_Length
                    (DER, P, EKU_OLen, Valid);
                  if not Valid then exit; end if;
                  EKU_Start := P;
                  --  Zero-length OID is invalid
                  if EKU_OLen = 0 then
                     C.Bad_EKU_Content := True;
                  end if;
                  --  anyExtendedKeyUsage in critical EKU
                  if Is_Critical
                     and then OID_Match
                       (DER, EKU_Start, EKU_OLen,
                        OID_ANY_EKU)
                  then
                     C.Bad_EKU_Content := True;
                  end if;
                  Skip (DER, P, EKU_OLen, Valid);
               end;
            end loop;
         end if;
      end if;
   end Parse_Ext_EKU;

   procedure Parse_Ext_CRL_DP
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280 §4.2.1.13: CRL Distribution Points
      --  SHOULD be non-critical
      if Is_Critical then
         C.Bad_CRL_DP := True;
      end if;
      --  DistributionPoint MUST NOT consist of only
      --  the reasons field
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then
            Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            while Valid
                  and then P < Inner_End
                  and then P <= DER'Last
            loop
               --  Each DistributionPoint SEQUENCE
               if DER (P) /= TAG_SEQUENCE then
                  exit;
               end if;
               declare
                  DP_Len : N32;
                  DP_End : N32;
                  Has_DP_Name  : Boolean := False;
                  Has_Reasons  : Boolean := False;
                  Has_Issuer2  : Boolean := False;
                  DP_Scan      : N32;
               begin
                  Parse_Sequence
                    (DER, P, DP_Len, Valid);
                  if not Valid then exit; end if;
                  if not Can_Read
                    (DER, P, DP_Len)
                  then
                     exit;
                  end if;
                  DP_End := P + DP_Len;
                  DP_Scan := P;
                  while DP_Scan < DP_End
                        and then
                        DP_Scan <= DER'Last
                  loop
                     declare
                        DPT : constant Byte :=
                          DER (DP_Scan);
                        DPT_Len : N32;
                     begin
                        --  [0] distributionPoint
                        if DPT = 16#A0# then
                           Has_DP_Name := True;
                        --  [1] reasons
                        elsif DPT = 16#81# then
                           Has_Reasons := True;
                        --  [2] cRLIssuer
                        elsif DPT = 16#A2# then
                           Has_Issuer2 := True;
                        end if;
                        DP_Scan := DP_Scan + 1;
                        if not Valid
                           or else DP_Scan > DER'Last
                        then
                           exit;
                        end if;
                        Parse_Length
                          (DER, DP_Scan,
                           DPT_Len, Valid);
                        if Valid then
                           Skip (DER, DP_Scan,
                                 DPT_Len, Valid);
                        end if;
                        if not Valid then
                           exit;
                        end if;
                     end;
                  end loop;
                  --  Reasons-only check
                  if Has_Reasons
                     and then not Has_DP_Name
                     and then not Has_Issuer2
                  then
                     C.Bad_CRL_DP := True;
                  end if;
                  P := DP_End;
               end;
            end loop;
         end if;
      end if;
   end Parse_Ext_CRL_DP;

   --  Parse [3] EXPLICIT SEQUENCE of extensions (dispatcher)
   procedure Parse_Extensions
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      Ext_Tag_Len  : N32;
      Ext_Found    : Boolean;
      Exts_Seq_Len : N32;
      Exts_End     : N32;
      Ext_Seq_Len  : N32;
      Ext_Seq_End  : N32;
      OID_Len      : N32;
      OID_Start    : N32;
      Val_Len      : N32;
      --  Duplicate extension tracking
      Seen_SAN   : Boolean := False;
      Seen_Basic : Boolean := False;
      Seen_KU    : Boolean := False;
      Seen_SKID  : Boolean := False;
      Seen_AKID  : Boolean := False;
   begin
      if not Valid then return; end if;
      if not (Pos <= DER'Last and then C.S_TBS.Present
              and then Pos <= C.S_TBS.Last)
      then
         return;
      end if;

      Parse_Explicit_Tag (DER, Pos, TAG_EXTENSIONS, Ext_Tag_Len,
                           Ext_Found, Valid);
      if not (Valid and then Ext_Found) then return; end if;

      C.Has_Extensions := True;
      --  Outer SEQUENCE of extensions
      if Pos > DER'Last then return; end if;
      Parse_Sequence (DER, Pos, Exts_Seq_Len, Valid);
      if not Valid then return; end if;

      if Can_Read (DER, Pos, Exts_Seq_Len) then
         Exts_End := Pos + Exts_Seq_Len;
      else
         Exts_End := Pos;
         Valid := False;
         return;
      end if;

      --  Loop through each Extension SEQUENCE
      while Valid and then Pos < Exts_End
            and then Pos <= DER'Last
      loop
         if DER (Pos) /= TAG_SEQUENCE then
            --  Skip unexpected content to end
            Pos := Exts_End;
            exit;
         end if;
         Parse_Sequence (DER, Pos, Ext_Seq_Len, Valid);
         if not Valid then exit; end if;
         if not Can_Read (DER, Pos, Ext_Seq_Len) then
            Valid := False; exit;
         end if;
         Ext_Seq_End := Pos + Ext_Seq_Len;

         --  OID
         if Pos > DER'Last or else DER (Pos) /= TAG_OID then
            Pos := Ext_Seq_End;
         else
            Pos := Pos + 1;
            if Pos > DER'Last then Valid := False; exit; end if;
            Parse_Length (DER, Pos, OID_Len, Valid);
            if not Valid then exit; end if;
            OID_Start := Pos;
            Skip (DER, Pos, OID_Len, Valid);
            if not Valid then exit; end if;

            --  Optional critical BOOLEAN
            declare
               Is_Critical : Boolean := False;
            begin
            if Pos < Ext_Seq_End and then Pos <= DER'Last
               and then DER (Pos) = TAG_BOOLEAN
            then
               --  Parse boolean: tag(1) + len(1) + value(1)
               if Can_Read (DER, Pos, 3) then
                  Is_Critical := DER (Pos + 2) /= 0;
               end if;
               Skip_TLV (DER, Pos, Valid);
               if not Valid then exit; end if;
            end if;

            --  OCTET STRING wrapping the extension value
            if Pos < Ext_Seq_End and then Pos <= DER'Last
               and then DER (Pos) = TAG_OCTETSTRING
            then
               Pos := Pos + 1;
               if Pos > DER'Last then Valid := False; exit; end if;
               Parse_Length (DER, Pos, Val_Len, Valid);
               if not Valid then exit; end if;

               --  RFC 5280: extension value must not be empty
               --  Also catch OCTET STRING wrapping an empty SEQUENCE
               --  (e.g., 3000 = SEQUENCE length 0)
               if Val_Len = 0 then
                  C.Bad_Ext_Content := True;
               elsif Val_Len >= 2
                  and then Pos <= DER'Last
                  and then Pos + 1 <= DER'Last
                  and then DER (Pos) = 16#30#
                  and then DER (Pos + 1) = 0
               then
                  C.Bad_Ext_Content := True;
               end if;

               --  Dispatch based on the OID
               if OID_Match (DER, OID_Start, OID_Len, OID_SAN)
               then
                  if Seen_SAN then
                     C.Ext_Duplicate := True;
                  end if;
                  Seen_SAN := True;
                  Parse_Ext_SAN
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_BASIC)
               then
                  if Seen_Basic then
                     C.Ext_Duplicate := True;
                  end if;
                  Seen_Basic := True;
                  Parse_Ext_Basic_Constraints
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_KEY_USAGE)
               then
                  if Seen_KU then
                     C.Ext_Duplicate := True;
                  end if;
                  Seen_KU := True;
                  Parse_Ext_Key_Usage
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_SKID)
               then
                  if Seen_SKID then
                     C.Ext_Duplicate := True;
                  end if;
                  Seen_SKID := True;
                  Parse_Ext_SKID
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_AKID)
               then
                  if Seen_AKID then
                     C.Ext_Duplicate := True;
                  end if;
                  Seen_AKID := True;
                  Parse_Ext_AKID
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_INHIBIT)
               then
                  --  RFC 5280: MUST be critical
                  if not Is_Critical then
                     C.Bad_Ext_Criticality := True;
                  end if;
                  --  RFC 5280 §4.2.1.14: value is INTEGER,
                  --  must not be negative (high bit set)
                  if Pos <= DER'Last
                     and then DER (Pos) = TAG_INTEGER
                  then
                     declare
                        Int_Len : N32;
                        Int_Pos : N32 := Pos + 1;
                     begin
                        if Int_Pos <= DER'Last then
                           Parse_Length
                             (DER, Int_Pos, Int_Len, Valid);
                           if Valid and then Int_Len >= 1
                              and then Int_Pos <= DER'Last
                              and then DER (Int_Pos) >= 16#80#
                           then
                              C.Bad_Inhibit_Value := True;
                           end if;
                        end if;
                     end;
                  end if;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_NAME_CONS)
               then
                  --  RFC 5280: MUST be critical
                  if not Is_Critical then
                     C.Bad_Ext_Criticality := True;
                  end if;
                  --  RFC 5280 §4.2.1.10: only on CA certs
                  C.Has_Name_Constraints := True;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_POLICY_CONS)
                  or else OID_Match
                  (DER, OID_Start, OID_Len, OID_POLICY_MAP)
               then
                  --  RFC 5280: these MUST be critical
                  if not Is_Critical then
                     C.Bad_Ext_Criticality := True;
                  end if;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_CERT_POLICIES)
               then
                  Parse_Ext_Cert_Policies
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_EKU)
               then
                  Parse_Ext_EKU
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_CRL_DP)
               then
                  Parse_Ext_CRL_DP
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_CT_SCT_V)
               then
                  --  RFC 6962 §3.3: SCT extension
                  --  Value must be nested OCTET STRING (0x04)
                  if Val_Len > 0
                     and then Pos <= DER'Last
                  then
                     if DER (Pos) /= 16#04# then
                        C.Bad_Ext_Content := True;
                     else
                        --  Check for trailing data: parse inner
                        --  OCTET STRING and verify it consumes
                        --  all of Val_Len
                        if Pos + 1 <= DER'Last then
                           declare
                              SCT_Pos : N32 := Pos + 1;
                              SCT_Len : N32;
                              SCT_OK  : Boolean := True;
                           begin
                              Parse_Length
                                (DER, SCT_Pos, SCT_Len, SCT_OK);
                              if SCT_OK then
                                 --  Inner tag(1) + length bytes
                                 --  + SCT_Len should equal Val_Len
                                 if SCT_Pos + SCT_Len /=
                                    Pos + Val_Len
                                 then
                                    C.Bad_Ext_Content := True;
                                 end if;
                              end if;
                           end;
                        end if;
                     end if;
                  end if;

               else
                  --  Unknown extension
                  if Is_Critical then
                     C.Ext_Unknown_Critical := True;
                  end if;
               end if;
            end if;
            end;  --  Is_Critical declare block

            --  Advance to next extension regardless
            Pos := Ext_Seq_End;
         end if;
      end loop;
   end Parse_Extensions;

   --  7. Parse outer signature algorithm SEQUENCE + signature BIT STRING
   procedure Parse_Outer_Sig_And_Value
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
   begin
      if not Valid then return; end if;

      --  Signature Algorithm (again, should match first one)
      if Pos <= DER'Last then
         declare
            SA2_Len : N32;
            SA2_End : N32;
            SA2_Algo : Algorithm_ID;
         begin
            Parse_Sequence (DER, Pos, SA2_Len, Valid);
            if Valid then
               SA2_End := Pos + SA2_Len;
               if Pos <= DER'Last then
                  Parse_Algorithm_OID (DER, Pos, SA2_Algo, Valid);
                  C.Sig_Algo_2 := SA2_Algo;
               end if;
               Pos := SA2_End;  --  skip past entire algo sequence
            end if;
         end;
      end if;

      --  Signature Value (BIT STRING)
      if Valid and then Pos <= DER'Last and then DER (Pos) = TAG_BITSTRING then
         declare
            Sig_Len     : N32;
            Sig_Unused  : Byte;
         begin
            Pos := Pos + 1;
            if Pos <= DER'Last then
               Parse_Length (DER, Pos, Sig_Len, Valid);
               if Valid and then Sig_Len > 1 and then Pos <= DER'Last then
                  Sig_Unused := DER (Pos);
                  Pos := Pos + 1;
                  Sig_Len := Sig_Len - 1;
                  Copy_Bytes (DER, Pos, Sig_Len, C.Sig_Buf, C.Sig_Buf_Len);
               end if;
            end if;
         end;
      end if;
   end Parse_Outer_Sig_And_Value;

   --================================================================
   --  Main certificate parser (thin orchestrator)
   --================================================================

   procedure Parse
     (DER  : in     Byte_Seq;
      Cert :    out Certificate;
      OK   :    out Boolean)
   is
      Pos       : N32 := 0;
      Len       : N32;
      TBS_Start : N32;
      TBS_Len   : N32;
      Valid     : Boolean := True;

      --  Fields we'll populate
      C : Certificate;
   begin
      --  Initialize
      C := Certificate'(Valid_Flag          => False,
                         Cert_Version        => 0,
                         S_Issuer_CN         => (0, 0, False),
                         S_Issuer_Org        => (0, 0, False),
                         S_Issuer_Country    => (0, 0, False),
                         S_Subject_CN        => (0, 0, False),
                         S_Subject_Org       => (0, 0, False),
                         S_Subject_Country   => (0, 0, False),
                         S_Serial            => (0, 0, False),
                         S_TBS               => (0, 0, False),
                         Validity_Not_Before => (others => 0),
                         Validity_Not_After  => (others => 0),
                         PK_Algo             => Algo_Unknown,
                         PK_Buf              => (others => 0),
                         PK_Buf_Len          => 0,
                         PK_RSA_Exp          => 0,
                         Sig_Algo            => Algo_Unknown,
                         Sig_Buf             => (others => 0),
                         Sig_Buf_Len         => 0,
                         Ext_Is_CA           => False,
                         Ext_Has_Path_Len    => False,
                         Ext_Path_Len        => 0,
                         Ext_Key_Usage       => 0,
                         Ext_Has_Key_Usage   => False,
                         Ext_Key_Usage_Crit   => False,
                         Ext_Basic_Crit       => False,
                         Ext_Unknown_Critical => False,
                         Ext_Duplicate        => False,
                         Has_Extensions       => False,
                         Sig_Algo_2           => Algo_Unknown,
                         S_Auth_Key_ID       => (0, 0, False),
                         S_Subject_Key_ID    => (0, 0, False),
                         SANs                => (others => (0, 0, False)),
                         SAN_Num             => 0,
                         Bad_Ext_Criticality => False,
                         Bad_Serial          => False,
                         Bad_Time_Format     => False,
                         Bad_SAN             => False,
                         Empty_Key_Usage     => False,
                         Has_Subject         => False,
                         Has_Unique_ID       => False,
                         SAN_Noncrit_Empty_Subj => False,
                         Bad_Ext_Content     => False,
                         Bad_PubKey          => False,
                         AKID_Missing_Key_ID => False,
                         Has_Name_Constraints => False,
                         Bad_Inhibit_Value   => False,
                         Bad_DER             => False,
                         Bad_Cert_Policy     => False,
                         Bad_AKID            => False,
                         Bad_Subject_Encoding => False,
                         Bad_EKU_Content     => False,
                         Bad_CRL_DP          => False,
                         SAN_Critical_With_Subject => False,
                         V3_UniqueID_NoExts  => False);

      --  Outer SEQUENCE (Certificate)
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      Parse_Sequence (DER, Pos, Len, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  TBS Certificate SEQUENCE
      TBS_Start := Pos;
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      Parse_Sequence (DER, Pos, TBS_Len, Valid);
      if not Valid then Cert := C; OK := False; return; end if;
      C.S_TBS := (First => TBS_Start, Last => Pos + TBS_Len - 1, Present => True);

      --  Version + Serial
      Parse_Version_Serial (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  TBS Signature Algorithm
      Parse_TBS_Sig_Algorithm (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  Issuer (SEQUENCE of RDN SETs)
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      declare
         Issuer_Len : N32;
         Dummy_Enc  : Boolean := False;
      begin
         Parse_Sequence (DER, Pos, Issuer_Len, Valid);
         if not Valid then Cert := C; OK := False; return; end if;
         Parse_Name (DER, Pos, Issuer_Len,
                     C.S_Issuer_CN, C.S_Issuer_Org, C.S_Issuer_Country,
                     Dummy_Enc, Valid);
      end;

      --  Validity
      Parse_Validity (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  Subject (SEQUENCE of RDN SETs)
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      declare
         Subject_Len   : N32;
         Subject_Start : N32;
      begin
         Parse_Sequence (DER, Pos, Subject_Len, Valid);
         if not Valid then Cert := C; OK := False; return; end if;
         C.Has_Subject := (Subject_Len > 0);
         Subject_Start := Pos;
         Parse_Name (DER, Pos, Subject_Len,
                     C.S_Subject_CN, C.S_Subject_Org, C.S_Subject_Country,
                     C.Bad_Subject_Encoding, Valid);
      end;

      --  SubjectPublicKeyInfo
      Parse_SPKI (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  Optional Unique IDs
      Parse_Unique_IDs (DER, Pos, C, Valid);

      --  Extensions
      Parse_Extensions (DER, Pos, C, Valid);

      --  RFC 5280 §4.1.2.1: v3 with UniqueID but no extensions
      if C.Cert_Version = 3
         and then C.Has_Unique_ID
         and then not C.Has_Extensions
      then
         C.V3_UniqueID_NoExts := True;
      end if;

      --  Skip any remaining TBS bytes
      if Valid and then C.S_TBS.Present and then Pos <= C.S_TBS.Last then
         Pos := C.S_TBS.Last + 1;
      end if;

      --  Outer Signature Algorithm + Signature Value
      Parse_Outer_Sig_And_Value (DER, Pos, C, Valid);

      C.Valid_Flag := Valid;
      Cert := C;
      OK := Valid;
   end Parse;

   --================================================================
   --  Getter implementations (expression functions)
   --================================================================

   function Is_Valid   (Cert : Certificate) return Boolean is (Cert.Valid_Flag);
   function Version    (Cert : Certificate) return Natural is (Cert.Cert_Version);

   function Issuer_CN       (Cert : Certificate) return Span is (Cert.S_Issuer_CN);
   function Issuer_Org      (Cert : Certificate) return Span is (Cert.S_Issuer_Org);
   function Issuer_Country  (Cert : Certificate) return Span is (Cert.S_Issuer_Country);

   function Subject_CN      (Cert : Certificate) return Span is (Cert.S_Subject_CN);
   function Subject_Org     (Cert : Certificate) return Span is (Cert.S_Subject_Org);
   function Subject_Country (Cert : Certificate) return Span is (Cert.S_Subject_Country);

   function Has_Issuer_CN   (Cert : Certificate) return Boolean is (Cert.S_Issuer_CN.Present);
   function Has_Subject_CN  (Cert : Certificate) return Boolean is (Cert.S_Subject_CN.Present);

   function SAN_Count (Cert : Certificate) return Natural is (Cert.SAN_Num);
   function SAN_DNS   (Cert : Certificate; Index : Positive) return Span is
     (Cert.SANs (Index));

   function PK_Algorithm  (Cert : Certificate) return Algorithm_ID is (Cert.PK_Algo);
   function PK_Length      (Cert : Certificate) return N32 is (Cert.PK_Buf_Len);
   function PK_Data        (Cert : Certificate) return Byte_Seq is
     (Cert.PK_Buf (0 .. Cert.PK_Buf_Len - 1));
   function RSA_Exponent   (Cert : Certificate) return Unsigned_32 is (Cert.PK_RSA_Exp);

   function Sig_Algorithm  (Cert : Certificate) return Algorithm_ID is (Cert.Sig_Algo);
   function Sig_Length      (Cert : Certificate) return N32 is (Cert.Sig_Buf_Len);
   function Sig_Data        (Cert : Certificate) return Byte_Seq is
     (Cert.Sig_Buf (0 .. Cert.Sig_Buf_Len - 1));

   function TBS (Cert : Certificate) return Span is (Cert.S_TBS);

   function Not_Before (Cert : Certificate) return Date_Time is (Cert.Validity_Not_Before);
   function Not_After  (Cert : Certificate) return Date_Time is (Cert.Validity_Not_After);

   function Is_CA         (Cert : Certificate) return Boolean is (Cert.Ext_Is_CA);
   function Has_Path_Len_Constraint (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_Path_Len);
   function Path_Len_Constraint (Cert : Certificate) return Natural is
     (Cert.Ext_Path_Len);
   function Has_Key_Usage (Cert : Certificate) return Boolean is (Cert.Ext_Has_Key_Usage);

   function KU_Digital_Signature (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#8000#) /= 0);
   function KU_Key_Encipherment  (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#2000#) /= 0);
   function KU_Key_Cert_Sign     (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#0400#) /= 0);
   function KU_CRL_Sign          (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#0200#) /= 0);

   function Authority_Key_ID (Cert : Certificate) return Span is (Cert.S_Auth_Key_ID);
   function Subject_Key_ID   (Cert : Certificate) return Span is (Cert.S_Subject_Key_ID);

   function Serial (Cert : Certificate) return Span is (Cert.S_Serial);

   --================================================================
   --  Validation functions
   --================================================================

   function Is_Date_Valid
     (Cert : Certificate;
      Now  : Date_Time) return Boolean
   is
   begin
      if not Cert.Valid_Flag then
         return False;
      end if;
      return DT_Before_Or_Equal (Cert.Validity_Not_Before, Now)
         and then DT_Before_Or_Equal (Now, Cert.Validity_Not_After);
   end Is_Date_Valid;

   function Matches_Hostname
     (Cert     : Certificate;
      DER      : Byte_Seq;
      Hostname : String) return Boolean
   is
      --  Case-insensitive lower-case conversion for a Byte
      function To_Lower_B (B : Byte) return Byte is
        (if B in 16#41# .. 16#5A# then B + 16#20# else B);

      --  Case-insensitive lower-case conversion for a Character
      function To_Lower_C (Ch : Character) return Byte is
        (if Ch in 'A' .. 'Z'
         then Byte (Character'Pos (Ch) - Character'Pos ('A') + 16#61#)
         else Byte (Character'Pos (Ch)));

      --  Check if DER span matches Hostname exactly (case-insensitive)
      function Exact_Match (S : Span) return Boolean
      with Pre => DER'First = 0 and DER'Last < N32'Last
      is
         Len : N32;
      begin
         if not S.Present or else S.Last < S.First then
            return False;
         end if;
         Len := S.Last - S.First + 1;
         if Hostname'Length = 0 or else Len /= N32 (Hostname'Length) then
            return False;
         end if;
         if not Can_Read (DER, S.First, Len) then
            return False;
         end if;
         for I in 0 .. Natural (Len) - 1 loop
            pragma Loop_Invariant (S.First + N32 (I) <= DER'Last);
            pragma Loop_Invariant (Hostname'First + I <= Hostname'Last);
            if To_Lower_B (DER (S.First + N32 (I))) /=
               To_Lower_C (Hostname (Hostname'First + I))
            then
               return False;
            end if;
         end loop;
         return True;
      end Exact_Match;

      --  Check if DER span matches Hostname with wildcard support.
      --  A leading "*." in the DER span matches exactly one label in
      --  Hostname (e.g. *.example.com matches foo.example.com but
      --  not foo.bar.example.com).
      function Span_Matches (S : Span) return Boolean
      with Pre => DER'First = 0 and DER'Last < N32'Last
      is
         Len : N32;
      begin
         if not S.Present or else S.Last < S.First then
            return False;
         end if;
         Len := S.Last - S.First + 1;
         if not Can_Read (DER, S.First, Len) then
            return False;
         end if;

         --  Check for wildcard pattern "*."
         if Len >= 3 and then DER (S.First) = 16#2A#    --  '*'
            and then DER (S.First + 1) = 16#2E#          --  '.'
         then
            --  Find the first '.' in Hostname
            declare
               Dot_Pos : Natural := 0;
            begin
               for J in Hostname'Range loop
                  if Hostname (J) = '.' then
                     Dot_Pos := J;
                     exit;
                  end if;
               end loop;

               --  Must have a dot, and it must not be the first or last char
               if Dot_Pos = 0
                  or else Dot_Pos = Hostname'First
                  or else Dot_Pos = Hostname'Last
               then
                  return False;
               end if;

               --  The part after the dot in Hostname must match
               --  the part after "*." in the DER span
               declare
                  Wild_Rest_First : constant N32 := S.First + 2;
                  Wild_Rest_Len   : constant N32 := Len - 2;
                  Host_Rest_First : constant Natural := Dot_Pos + 1;
                  Host_Rest_Len   : constant Natural :=
                     Hostname'Last - Host_Rest_First + 1;
               begin
                  if N32 (Host_Rest_Len) /= Wild_Rest_Len then
                     return False;
                  end if;
                  if Wild_Rest_Len = 0 then
                     return False;
                  end if;
                  if not Can_Read (DER, Wild_Rest_First, Wild_Rest_Len) then
                     return False;
                  end if;
                  for I in N32 range 0 .. Wild_Rest_Len - 1 loop
                     pragma Loop_Invariant
                       (Wild_Rest_First + I <= DER'Last);
                     if To_Lower_B (DER (Wild_Rest_First + I)) /=
                        To_Lower_C
                          (Hostname (Host_Rest_First + Natural (I)))
                     then
                        return False;
                     end if;
                  end loop;
                  return True;
               end;
            end;
         else
            --  No wildcard: exact match
            return Exact_Match (S);
         end if;
      end Span_Matches;

   begin  --  Matches_Hostname
      if not Cert.Valid_Flag then
         return False;
      end if;

      --  First check SANs (preferred per RFC 6125)
      for I in 1 .. Cert.SAN_Num loop
         if I <= Max_SANs and then Span_Matches (Cert.SANs (I)) then
            return True;
         end if;
      end loop;

      --  Fall back to Subject CN only if no SANs present
      if Cert.SAN_Num = 0 and then Cert.S_Subject_CN.Present then
         return Span_Matches (Cert.S_Subject_CN);
      end if;

      return False;
   end Matches_Hostname;

   function Has_Unknown_Critical_Extension (Cert : Certificate) return Boolean is
     (Cert.Ext_Unknown_Critical);

   function Has_Duplicate_Extension (Cert : Certificate) return Boolean is
     (Cert.Ext_Duplicate);

   function Has_Extensions (Cert : Certificate) return Boolean is
     (Cert.Has_Extensions);

   function Sig_Algorithm_2 (Cert : Certificate) return Algorithm_ID is
     (Cert.Sig_Algo_2);

   function Is_Key_Usage_Critical (Cert : Certificate) return Boolean is
     (Cert.Ext_Key_Usage_Crit);

   function Is_Basic_Constraints_Critical (Cert : Certificate) return Boolean is
     (Cert.Ext_Basic_Crit);

   function Has_Key_Cert_Sign_Without_CA (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_Key_Usage
      and then (Cert.Ext_Key_Usage and 16#0400#) /= 0
      and then not Cert.Ext_Is_CA);

   function Has_Bad_Extension_Criticality (Cert : Certificate) return Boolean is
     (Cert.Bad_Ext_Criticality);

   function Has_Bad_Serial (Cert : Certificate) return Boolean is
     (Cert.Bad_Serial);

   function Has_Bad_Time_Format (Cert : Certificate) return Boolean is
     (Cert.Bad_Time_Format);

   function Has_Bad_SAN (Cert : Certificate) return Boolean is
     (Cert.Bad_SAN);

   function Has_Empty_Key_Usage_Value (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_Key_Usage and then Cert.Empty_Key_Usage);

   function CA_Missing_Subject_Key_ID (Cert : Certificate) return Boolean is
     (Cert.Ext_Is_CA and then not Cert.S_Subject_Key_ID.Present);

   function Has_Unique_ID_Version_Error (Cert : Certificate) return Boolean is
     (Cert.Has_Unique_ID and then Cert.Cert_Version < 2);

   function Has_SAN_Subject_Error (Cert : Certificate) return Boolean is
     (Cert.SAN_Noncrit_Empty_Subj);

   function Has_Bad_Ext_Content (Cert : Certificate) return Boolean is
     (Cert.Bad_Ext_Content);

   function Has_Bad_PubKey (Cert : Certificate) return Boolean is
     (Cert.Bad_PubKey);

   function Has_AKID_Missing_Key_ID (Cert : Certificate) return Boolean is
     (Cert.AKID_Missing_Key_ID);

   function Has_Name_Constraints_NonCA (Cert : Certificate) return Boolean is
     (Cert.Has_Name_Constraints and then not Cert.Ext_Is_CA);

   function Has_Bad_Inhibit_Value (Cert : Certificate) return Boolean is
     (Cert.Bad_Inhibit_Value);

   function Has_Bad_DER (Cert : Certificate) return Boolean is
     (Cert.Bad_DER);

   function Has_Bad_Cert_Policy (Cert : Certificate) return Boolean is
     (Cert.Bad_Cert_Policy);

   function Has_Bad_AKID (Cert : Certificate) return Boolean is
     (Cert.Bad_AKID);

   function Has_Bad_Subject_Encoding (Cert : Certificate) return Boolean is
     (Cert.Bad_Subject_Encoding);

   function Has_Bad_EKU_Content (Cert : Certificate) return Boolean is
     (Cert.Bad_EKU_Content);

   function Has_Bad_CRL_DP (Cert : Certificate) return Boolean is
     (Cert.Bad_CRL_DP);

   function Has_SAN_Critical_With_Subject (Cert : Certificate) return Boolean is
     (Cert.SAN_Critical_With_Subject);

   function Has_V3_UniqueID_NoExts (Cert : Certificate) return Boolean is
     (Cert.V3_UniqueID_NoExts);

   function Is_Structurally_Valid
     (Cert : Certificate;
      Now  : Date_Time) return Boolean
   is
   begin
      --  Must have parsed successfully
      if not Cert.Valid_Flag then
         return False;
      end if;

      --  Must not have unrecognized critical extensions
      if Cert.Ext_Unknown_Critical then
         return False;
      end if;

      --  Must be within validity period
      if not Is_Date_Valid (Cert, Now) then
         return False;
      end if;

      --  Must have a known signature algorithm
      if Cert.Sig_Algo = Algo_Unknown then
         return False;
      end if;

      --  Must have a known public key algorithm
      if Cert.PK_Algo = Algo_Unknown then
         return False;
      end if;

      --  Must have TBS data for signature verification
      if not Cert.S_TBS.Present then
         return False;
      end if;

      --  Version/extension consistency (RFC 5280 Section 4.1.2.1)
      --  v1 and v2 certs MUST NOT have extensions
      if Cert.Cert_Version < 3 and then Cert.Has_Extensions then
         return False;
      end if;

      --  Duplicate extensions (RFC 5280 Section 4.2)
      if Cert.Ext_Duplicate then
         return False;
      end if;

      --  Signature algorithm mismatch (RFC 5280 Section 4.1.1.2)
      --  If both are recognized, they must match
      if Cert.Sig_Algo_2 /= Algo_Unknown
         and then Cert.Sig_Algo /= Cert.Sig_Algo_2
      then
         return False;
      end if;

      --  Key Usage must be critical when present (RFC 5280 Section 4.2.1.3)
      if Cert.Ext_Has_Key_Usage and then not Cert.Ext_Key_Usage_Crit then
         return False;
      end if;

      --  Basic Constraints must be critical for CAs (RFC 5280 Section 4.2.1.9)
      if Cert.Ext_Is_CA and then not Cert.Ext_Basic_Crit then
         return False;
      end if;

      --  keyCertSign in Key Usage requires CA (RFC 5280 Section 4.2.1.3)
      if Has_Key_Cert_Sign_Without_CA (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2: Extension criticality enforcement
      if Cert.Bad_Ext_Criticality then
         return False;
      end if;

      --  RFC 5280 §4.1.2.2: Serial number validation
      if Cert.Bad_Serial then
         return False;
      end if;

      --  RFC 5280 §4.1.2.5: Time format validation
      if Cert.Bad_Time_Format then
         return False;
      end if;

      --  RFC 5280 §4.2.1.6: SAN must not be malformed
      if Cert.Bad_SAN then
         return False;
      end if;

      --  RFC 5280 §4.2.1.3: Key Usage must have at least one bit set
      if Cert.Ext_Has_Key_Usage and then Cert.Empty_Key_Usage then
         return False;
      end if;

      --  RFC 5280 §4.2.1.2: CA certs should have Subject Key ID
      if Cert.Ext_Is_CA and then not Cert.S_Subject_Key_ID.Present then
         return False;
      end if;

      --  RFC 5280 §4.1.2.8: uniqueIDs only in v2 and v3
      if Has_Unique_ID_Version_Error (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2.1.6: SAN must be critical if subject is empty
      if Has_SAN_Subject_Error (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2: Extension value must not be empty
      if Cert.Bad_Ext_Content then
         return False;
      end if;

      --  RFC 5280 §4.2.1.1: Public key must be structurally valid
      if Cert.Bad_PubKey then
         return False;
      end if;

      --  RFC 5280 §4.2.1.1: AKID must contain keyIdentifier
      if Cert.AKID_Missing_Key_ID then
         return False;
      end if;

      --  RFC 5280 §4.2.1.10: NameConstraints only on CA certs
      if Has_Name_Constraints_NonCA (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2.1.14: InhibitAnyPolicy must not be negative
      if Cert.Bad_Inhibit_Value then
         return False;
      end if;

      --  RFC 5280 Appendix A / X.690: Valid DER encoding
      if Cert.Bad_DER then
         return False;
      end if;

      --  RFC 5280 §4.2.1.4: Certificate policies
      if Cert.Bad_Cert_Policy then
         return False;
      end if;

      --  RFC 5280 §4.2.1.1: AuthKeyID issuer/serial both or neither
      if Cert.Bad_AKID then
         return False;
      end if;

      --  RFC 5280 §4.1.2.6: Subject encoding
      if Cert.Bad_Subject_Encoding then
         return False;
      end if;

      --  RFC 5280 §4.2.1.12: EKU valid OIDs
      if Cert.Bad_EKU_Content then
         return False;
      end if;

      --  RFC 5280 §4.2.1.13: CRL DP not reasons-only
      if Cert.Bad_CRL_DP then
         return False;
      end if;

      --  RFC 5280 §4.2.1.6: SAN critical with non-empty subject
      if Cert.SAN_Critical_With_Subject then
         return False;
      end if;

      --  RFC 5280 §4.1.2.1: v3 UniqueID without extensions
      if Cert.V3_UniqueID_NoExts then
         return False;
      end if;

      return True;
   end Is_Structurally_Valid;

end X509;
