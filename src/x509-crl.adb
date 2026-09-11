with X509.DER;     use X509.DER;
with X509.DER_Ext; use X509.DER_Ext;

package body X509.CRL with
   SPARK_Mode => On
is
   ----------------------------------------------------------------------------
   --  OIDs local to CRLs (RFC 5280 5.2 / 5.3)
   ----------------------------------------------------------------------------

   OID_CRL_NUMBER      : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#14#);  --  2.5.29.20
   OID_REASON_CODE     : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#15#);  --  2.5.29.21
   OID_INVALIDITY_DATE : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#18#);  --  2.5.29.24
   OID_DELTA_CRL       : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#1B#);  --  2.5.29.27
   OID_IDP             : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#1C#);  --  2.5.29.28
   OID_FRESHEST_CRL    : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#2E#);  --  2.5.29.46
   OID_ISSUER_ALT_NAME : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#12#);  --  2.5.29.18
   OID_EXPIRED_ON_CRL  : constant Byte_Seq (0 .. 2) := (16#55#, 16#1D#, 16#3C#);  --  2.5.29.60

   TAG_CRL_EXTENSIONS  : constant Byte := 16#A0#;  --  [0] EXPLICIT
   TAG_ENUMERATED      : constant Byte := 16#0A#;

   ----------------------------------------------------------------------------
   --  Getters
   ----------------------------------------------------------------------------

   function Version         (V : CRL_View) return Natural      is (V.CRL_Version);
   function TBS             (V : CRL_View) return Span         is (V.S_TBS);
   function Issuer_Raw      (V : CRL_View) return Span         is (V.S_Issuer_Raw);
   function This_Update     (V : CRL_View) return Date_Time    is (V.This_Upd);
   function Has_Next_Update (V : CRL_View) return Boolean      is (V.Has_Next);
   function Next_Update     (V : CRL_View) return Date_Time    is (V.Next_Upd);
   function Sig_Algorithm   (V : CRL_View) return Algorithm_ID is (V.Sig_Algo);
   function Sig_Algorithm_2 (V : CRL_View) return Algorithm_ID is (V.Sig_Algo_2);
   function Sig_Length      (V : CRL_View) return N32          is (V.Sig_Buf_Len);
   function Revoked_Count   (V : CRL_View) return N32          is (V.Revoked_Num);

   function Sig_Data (V : CRL_View) return Byte_Seq is
     (V.Sig_Buf (0 .. V.Sig_Buf_Len - 1));

   function Authority_Key_ID (V : CRL_View) return Span    is (V.S_AKID);
   function Has_CRL_Number   (V : CRL_View) return Boolean is (V.Has_Number);
   function CRL_Number       (V : CRL_View) return Span    is (V.S_CRL_Number);
   function Is_Delta_CRL     (V : CRL_View) return Boolean is (V.Is_Delta);

   function Has_IDP                    (V : CRL_View) return Boolean is (V.IDP_Present);
   function IDP_Has_Distribution_Point (V : CRL_View) return Boolean is (V.IDP_DP);
   function IDP_Distribution_Point     (V : CRL_View) return Span    is (V.S_IDP_DP);
   function IDP_Only_User_Certs        (V : CRL_View) return Boolean is (V.IDP_User);
   function IDP_Only_CA_Certs          (V : CRL_View) return Boolean is (V.IDP_CA);
   function IDP_Only_Some_Reasons      (V : CRL_View) return Boolean is (V.IDP_Reasons);
   function IDP_Indirect_CRL           (V : CRL_View) return Boolean is (V.IDP_Indirect);
   function IDP_Only_Attribute_Certs   (V : CRL_View) return Boolean is (V.IDP_Attr);

   function Has_Unknown_Critical_Extension (V : CRL_View) return Boolean is
     (V.Unknown_Crit);
   function Has_Bad_Extension (V : CRL_View) return Boolean is (V.Bad_Ext);
   function Has_Critical_Entry_Extension (V : CRL_View) return Boolean is
     (V.Crit_Entry_Ext);

   ----------------------------------------------------------------------------
   --  One revokedCertificates entry
   --
   --  RevokedCertificate ::= SEQUENCE {
   --     userCertificate    CertificateSerialNumber,
   --     revocationDate     Time,
   --     crlEntryExtensions Extensions OPTIONAL }
   --
   --  Parses the entry at Pos and advances Pos past it. Serial is the
   --  INTEGER content span (never empty on success).
   ----------------------------------------------------------------------------

   procedure Parse_Entry
     (DER        : in     Byte_Seq;
      Pos        : in out N32;
      Serial     :    out Span;
      Rev_Date   :    out Date_Time;
      Has_Reason :    out Boolean;
      Reason     :    out Natural;
      Crit_Ext   :    out Boolean;
      OK         : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then
                   Pos > Pos'Old and Pos <= DER'Last + 1
                   and Serial.Present
                   and Span_In_Range (Serial, DER'Last))
   is
      Entry_Len : N32;
      Entry_End : N32;
      Ser_Len   : N32;
   begin
      Serial     := (0, 0, False);
      Rev_Date   := (others => 0);
      Has_Reason := False;
      Reason     := 0;
      Crit_Ext   := False;

      Parse_Sequence_Hdr (DER, Pos, Entry_Len, OK);
      if not OK then return; end if;
      Entry_End := Pos + Entry_Len;

      --  userCertificate INTEGER
      if Pos >= Entry_End or else DER (Pos) /= TAG_INTEGER then
         OK := False; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Ser_Len, OK);
      if not OK then return; end if;
      if Ser_Len = 0 or else not Can_Read (DER, Pos, Ser_Len) then
         OK := False; return;
      end if;
      Serial := (First => Pos, Last => Pos + Ser_Len - 1, Present => True);
      Pos := Pos + Ser_Len;
      if Pos > Entry_End then OK := False; return; end if;

      --  revocationDate Time
      if Pos >= Entry_End then OK := False; return; end if;
      Parse_Time_TLV (DER, Pos, Rev_Date, OK);
      if not OK then return; end if;
      if Pos > Entry_End then OK := False; return; end if;

      --  crlEntryExtensions Extensions OPTIONAL
      if Pos < Entry_End then
         declare
            Exts_Len : N32;
            Exts_End : N32;
         begin
            Parse_Sequence_Hdr (DER, Pos, Exts_Len, OK);
            if not OK then return; end if;
            Exts_End := Pos + Exts_Len;
            if Exts_End /= Entry_End then OK := False; return; end if;

            while OK and then Pos < Exts_End loop
               pragma Loop_Invariant (Pos <= DER'Last);
               pragma Loop_Invariant (Pos > Pos'Loop_Entry - 1);
               pragma Loop_Invariant (Exts_End = Entry_End);
               pragma Loop_Variant (Increases => Pos);
               declare
                  OID_Start, OID_Len : N32;
                  Val_Start, Val_Len : N32;
                  Critical           : Boolean;
               begin
                  Next_Extension (DER, Pos, OID_Start, OID_Len, Critical,
                                  Val_Start, Val_Len, OK);
                  if not OK then return; end if;
                  if Pos > Exts_End then OK := False; return; end if;

                  if OID_Match (DER, OID_Start, OID_Len, OID_REASON_CODE) then
                     --  CRLReason ::= ENUMERATED, single octet value
                     if Val_Len = 3
                       and then DER (Val_Start) = TAG_ENUMERATED
                       and then DER (Val_Start + 1) = 1
                     then
                        Has_Reason := True;
                        Reason := Natural (DER (Val_Start + 2));
                     end if;
                  elsif OID_Match (DER, OID_Start, OID_Len, OID_INVALIDITY_DATE) then
                     null;
                  elsif Critical then
                     --  certificateIssuer (5.3.3) or anything else critical
                     Crit_Ext := True;
                  end if;
               end;
            end loop;
         end;
      end if;

      if Pos /= Entry_End then OK := False; return; end if;
   end Parse_Entry;

   ----------------------------------------------------------------------------
   --  issuingDistributionPoint (5.2.5)
   --
   --  IssuingDistributionPoint ::= SEQUENCE {
   --     distributionPoint          [0] DistributionPointName OPTIONAL,
   --     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
   --     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
   --     onlySomeReasons            [3] ReasonFlags OPTIONAL,
   --     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
   --     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
   ----------------------------------------------------------------------------

   procedure Parse_IDP
     (DER       : in     Byte_Seq;
      Val_Start : in     N32;
      Val_Len   : in     N32;
      Has_DP    :    out Boolean;
      DP_Name   :    out Span;
      Only_User :    out Boolean;
      Only_CA   :    out Boolean;
      Reasons   :    out Boolean;
      Indirect  :    out Boolean;
      Only_Attr :    out Boolean;
      OK        : in out Boolean)
   with Pre  => OK and DER'First = 0 and DER'Last < N32'Last
                and Val_Len > 0 and Can_Read (DER, Val_Start, Val_Len),
        Post => Span_In_Range (DP_Name, DER'Last)
   is
      P       : N32 := Val_Start;
      Seq_Len : N32;
      Seq_End : N32;
   begin
      Has_DP := False; Only_User := False; Only_CA := False;
      Reasons := False; Indirect := False; Only_Attr := False;
      DP_Name := (0, 0, False);

      Parse_Sequence_Hdr (DER, P, Seq_Len, OK);
      if not OK then return; end if;
      Seq_End := P + Seq_Len;
      if Seq_End /= Val_Start + Val_Len then OK := False; return; end if;

      while OK and then P < Seq_End loop
         pragma Loop_Invariant (P <= DER'Last);
         pragma Loop_Invariant (Seq_End <= DER'Last + 1);
         pragma Loop_Invariant (Span_In_Range (DP_Name, DER'Last));
         pragma Loop_Variant (Increases => P);
         declare
            Tag  : constant Byte := DER (P);
            Len  : N32;
            Flag : Boolean := False;
         begin
            P := P + 1;
            if P > DER'Last then OK := False; return; end if;
            Parse_Length (DER, P, Len, OK);
            if not OK then return; end if;
            if not Can_Read (DER, P, Len) then OK := False; return; end if;
            if Len = 1 then
               Flag := DER (P) /= 0;
            end if;
            case Tag is
               when 16#A0# =>
                  --  [0] EXPLICIT DistributionPointName: keep its TLV
                  Has_DP := True;
                  if Len > 0 then
                     DP_Name := (First => P, Last => P + Len - 1, Present => True);
                  end if;
               when 16#81# => Only_User := Flag;
               when 16#82# => Only_CA := Flag;
               when 16#83# => Reasons := True;
               when 16#84# => Indirect := Flag;
               when 16#85# => Only_Attr := Flag;
               when others => OK := False; return;
            end case;
            P := P + Len;
            if P > Seq_End then OK := False; return; end if;
         end;
      end loop;
   end Parse_IDP;

   ----------------------------------------------------------------------------
   --  crlExtensions [0] EXPLICIT Extensions (5.2)
   ----------------------------------------------------------------------------

   procedure Parse_CRL_Extensions
     (DER : in     Byte_Seq;
      Pos : in out N32;
      V   : in out CRL_View;
      OK  : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last
                and Span_In_Range (V.S_AKID, DER'Last)
                and Span_In_Range (V.S_CRL_Number, DER'Last)
                and Span_In_Range (V.S_IDP_DP, DER'Last),
        Post => (if OK then Pos <= DER'Last + 1)
                and V.S_TBS = V'Old.S_TBS
                and V.S_Issuer_Raw = V'Old.S_Issuer_Raw
                and V.S_Revoked = V'Old.S_Revoked
                and Span_In_Range (V.S_AKID, DER'Last)
                and Span_In_Range (V.S_CRL_Number, DER'Last)
                and Span_In_Range (V.S_IDP_DP, DER'Last)
   is
      Wrap_End : N32;
      Exts_Len : N32;
      Exts_End : N32;
   begin
      Enter_Explicit (DER, Pos, TAG_CRL_EXTENSIONS, Wrap_End, OK);
      if not OK then return; end if;

      if Pos >= Wrap_End then OK := False; return; end if;
      Parse_Sequence_Hdr (DER, Pos, Exts_Len, OK);
      if not OK then return; end if;
      Exts_End := Pos + Exts_Len;
      if Exts_End /= Wrap_End then OK := False; return; end if;

      while OK and then Pos < Exts_End loop
         pragma Loop_Invariant (Pos <= DER'Last);
         pragma Loop_Invariant (Span_In_Range (V.S_AKID, DER'Last));
         pragma Loop_Invariant (Span_In_Range (V.S_CRL_Number, DER'Last));
         pragma Loop_Invariant (Span_In_Range (V.S_IDP_DP, DER'Last));
         pragma Loop_Invariant (V.S_TBS = V'Loop_Entry.S_TBS);
         pragma Loop_Invariant (V.S_Issuer_Raw = V'Loop_Entry.S_Issuer_Raw);
         pragma Loop_Invariant (V.S_Revoked = V'Loop_Entry.S_Revoked);
         pragma Loop_Variant (Increases => Pos);
         declare
            OID_Start, OID_Len : N32;
            Val_Start, Val_Len : N32;
            Critical           : Boolean;
         begin
            Next_Extension (DER, Pos, OID_Start, OID_Len, Critical,
                            Val_Start, Val_Len, OK);
            if not OK then return; end if;
            if Pos > Exts_End then OK := False; return; end if;

            if OID_Match (DER, OID_Start, OID_Len, OID_AKID) then
               --  AuthorityKeyIdentifier ::= SEQUENCE { [0] keyIdentifier ... }
               declare
                  P       : N32 := Val_Start;
                  A_Len   : N32;
                  A_End   : N32;
               begin
                  Parse_Sequence_Hdr (DER, P, A_Len, OK);
                  if not OK then return; end if;
                  A_End := P + A_Len;
                  if P < A_End and then DER (P) = AKID_TAG_KEY_ID then
                     declare
                        K_Len : N32;
                     begin
                        P := P + 1;
                        if P > DER'Last then OK := False; return; end if;
                        Parse_Length (DER, P, K_Len, OK);
                        if not OK then return; end if;
                        if K_Len > 0 and then Can_Read (DER, P, K_Len)
                          and then P + K_Len <= A_End
                        then
                           V.S_AKID := (First => P, Last => P + K_Len - 1,
                                        Present => True);
                        end if;
                     end;
                  end if;
               end;

            elsif OID_Match (DER, OID_Start, OID_Len, OID_CRL_NUMBER) then
               declare
                  P     : N32 := Val_Start;
                  N_Len : N32;
               begin
                  if DER (P) /= TAG_INTEGER then OK := False; return; end if;
                  P := P + 1;
                  if P > DER'Last then OK := False; return; end if;
                  Parse_Length (DER, P, N_Len, OK);
                  if not OK then return; end if;
                  if N_Len = 0 or else not Can_Read (DER, P, N_Len)
                    or else P + N_Len /= Val_Start + Val_Len
                  then
                     OK := False; return;
                  end if;
                  V.Has_Number := True;
                  V.S_CRL_Number := (First => P, Last => P + N_Len - 1,
                                     Present => True);
                  --  RFC 5280 5.2.3: cRLNumber MUST be non-critical
                  if Critical then
                     V.Bad_Ext := True;
                  end if;
               end;

            elsif OID_Match (DER, OID_Start, OID_Len, OID_IDP) then
               V.IDP_Present := True;
               Parse_IDP (DER, Val_Start, Val_Len,
                          V.IDP_DP, V.S_IDP_DP, V.IDP_User, V.IDP_CA, V.IDP_Reasons,
                          V.IDP_Indirect, V.IDP_Attr, OK);
               if not OK then return; end if;

            elsif OID_Match (DER, OID_Start, OID_Len, OID_DELTA_CRL) then
               V.Is_Delta := True;

            elsif OID_Match (DER, OID_Start, OID_Len, OID_FRESHEST_CRL)
              or else OID_Match (DER, OID_Start, OID_Len, OID_ISSUER_ALT_NAME)
              or else OID_Match (DER, OID_Start, OID_Len, OID_AIA)
              or else OID_Match (DER, OID_Start, OID_Len, OID_EXPIRED_ON_CRL)
            then
               --  Recognized, informational, MUST be non-critical
               if Critical then
                  V.Unknown_Crit := True;
               end if;

            elsif Critical then
               V.Unknown_Crit := True;
            end if;
         end;
      end loop;
   end Parse_CRL_Extensions;

   ----------------------------------------------------------------------------
   --  Parse
   ----------------------------------------------------------------------------

   procedure Parse
     (DER : in     Byte_Seq;
      V   :    out CRL_View;
      OK  :    out Boolean)
   is
      Pos       : N32 := 0;
      Valid     : Boolean := True;
      TBS_Start : N32;
      TBS_Len   : N32;
      TBS_End   : N32;
      C         : CRL_View;
   begin
      C := (Valid_Flag => False, CRL_Version => 1,
            S_TBS => (0, 0, False), S_Issuer_Raw => (0, 0, False),
            S_Revoked => (0, 0, False), S_AKID => (0, 0, False),
            S_CRL_Number => (0, 0, False), S_IDP_DP => (0, 0, False),
            This_Upd => (others => 0), Next_Upd => (others => 0),
            Has_Next => False,
            Sig_Algo => Algo_Unknown, Sig_Algo_2 => Algo_Unknown,
            Sig_Buf => (others => 0), Sig_Buf_Len => 0,
            Revoked_Num => 0, Has_Number => False, Is_Delta => False,
            IDP_Present => False, IDP_DP => False, IDP_User => False,
            IDP_CA => False, IDP_Reasons => False, IDP_Indirect => False,
            IDP_Attr => False, Unknown_Crit => False, Bad_Ext => False,
            Crit_Entry_Ext => False);
      V  := C;
      OK := False;

      --  CertificateList ::= SEQUENCE, must consume the whole buffer
      if Pos > DER'Last then return; end if;
      declare
         Outer_Len : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, Outer_Len, Valid);
         if not Valid then return; end if;
         if Pos + Outer_Len /= DER'Last + 1 then return; end if;
      end;

      --  TBSCertList ::= SEQUENCE
      TBS_Start := Pos;
      if Pos > DER'Last then return; end if;
      Parse_Sequence_Hdr (DER, Pos, TBS_Len, Valid);
      if not Valid then return; end if;
      TBS_End := Pos + TBS_Len;
      C.S_TBS := (First => TBS_Start, Last => TBS_End - 1, Present => True);

      --  version INTEGER OPTIONAL (must be v2 = 1 when present)
      if Pos < TBS_End and then DER (Pos) = TAG_INTEGER then
         declare
            V_Len : N32;
         begin
            Pos := Pos + 1;
            if Pos > DER'Last then return; end if;
            Parse_Length (DER, Pos, V_Len, Valid);
            if not Valid then return; end if;
            if V_Len /= 1 or else Pos > DER'Last or else DER (Pos) /= 1 then
               return;
            end if;
            C.CRL_Version := 2;
            Pos := Pos + 1;
         end;
      end if;

      --  signature AlgorithmIdentifier
      if Pos >= TBS_End then return; end if;
      declare
         Alg_Len : N32;
         Alg_End : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, Alg_Len, Valid);
         if not Valid then return; end if;
         Alg_End := Pos + Alg_Len;
         if Pos >= Alg_End then return; end if;
         Parse_Algorithm_OID (DER, Pos, C.Sig_Algo, Valid);
         if not Valid then return; end if;
         Pos := Alg_End;  --  skip parameters
         if Pos > TBS_End then return; end if;
      end;

      --  issuer Name
      if Pos >= TBS_End then return; end if;
      declare
         Iss_Len : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, Iss_Len, Valid);
         if not Valid then return; end if;
         if Iss_Len = 0 or else not Can_Read (DER, Pos, Iss_Len) then return; end if;
         C.S_Issuer_Raw := (First => Pos, Last => Pos + Iss_Len - 1, Present => True);
         Pos := Pos + Iss_Len;
         if Pos > TBS_End then return; end if;
      end;

      --  thisUpdate Time
      if Pos >= TBS_End then return; end if;
      Parse_Time_TLV (DER, Pos, C.This_Upd, Valid);
      if not Valid then return; end if;
      if Pos > TBS_End then return; end if;

      --  nextUpdate Time OPTIONAL
      if Pos < TBS_End
        and then (DER (Pos) = TAG_UTCTIME or else DER (Pos) = TAG_GENTIME)
      then
         Parse_Time_TLV (DER, Pos, C.Next_Upd, Valid);
         if not Valid then return; end if;
         if Pos > TBS_End then return; end if;
         C.Has_Next := True;
      end if;

      --  revokedCertificates SEQUENCE OF RevokedCertificate OPTIONAL
      if Pos < TBS_End and then DER (Pos) = TAG_SEQUENCE then
         declare
            R_Len : N32;
            R_End : N32;
            Count : N32 := 0;
         begin
            Parse_Sequence_Hdr (DER, Pos, R_Len, Valid);
            if not Valid then return; end if;
            R_End := Pos + R_Len;
            if R_End > TBS_End then return; end if;
            --  RFC 5280 5.1.2.6: when present the list MUST be non-empty
            if R_Len = 0 then return; end if;
            C.S_Revoked := (First => Pos, Last => R_End - 1, Present => True);

            --  Validate every entry now so Lookup can trust the shape
            while Valid and then Pos < R_End loop
               pragma Loop_Invariant (Pos <= DER'Last);
               pragma Loop_Invariant (R_End <= DER'Last + 1);
               pragma Loop_Variant (Increases => Pos);
               declare
                  Serial     : Span;
                  Rev_Date   : Date_Time;
                  Has_Reason : Boolean;
                  Reason     : Natural;
                  Crit_Ext   : Boolean;
               begin
                  Parse_Entry (DER, Pos, Serial, Rev_Date, Has_Reason,
                               Reason, Crit_Ext, Valid);
                  if not Valid then return; end if;
                  if Pos > R_End then return; end if;
                  if Crit_Ext then C.Crit_Entry_Ext := True; end if;
                  if Count < N32'Last then Count := Count + 1; end if;
               end;
            end loop;
            C.Revoked_Num := Count;
         end;
      end if;

      --  crlExtensions [0] EXPLICIT Extensions OPTIONAL
      if Pos < TBS_End then
         if DER (Pos) /= TAG_CRL_EXTENSIONS then return; end if;
         Parse_CRL_Extensions (DER, Pos, C, Valid);
         if not Valid then return; end if;
         if Pos /= TBS_End then return; end if;
      end if;

      --  RFC 5280 5.1.2.1: extensions require v2
      if Pos /= TBS_End then return; end if;
      Pos := TBS_End;
      --  RFC 5280 5.2.3: a conforming (v2) CRL MUST carry cRLNumber
      if C.CRL_Version = 2 and then not C.Has_Number then
         C.Bad_Ext := True;
      end if;

      --  signatureAlgorithm AlgorithmIdentifier (outer)
      if Pos > DER'Last then return; end if;
      declare
         Alg_Len : N32;
         Alg_End : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, Alg_Len, Valid);
         if not Valid then return; end if;
         Alg_End := Pos + Alg_Len;
         if Pos >= Alg_End then return; end if;
         Parse_Algorithm_OID (DER, Pos, C.Sig_Algo_2, Valid);
         if not Valid then return; end if;
         Pos := Alg_End;
      end;

      --  signatureValue BIT STRING
      if Pos > DER'Last or else DER (Pos) /= TAG_BITSTRING then return; end if;
      declare
         Sig_Len : N32;
      begin
         Pos := Pos + 1;
         if Pos > DER'Last then return; end if;
         Parse_Length (DER, Pos, Sig_Len, Valid);
         if not Valid then return; end if;
         if Sig_Len < 2 or else not Can_Read (DER, Pos, Sig_Len) then return; end if;
         --  unused-bits octet must be zero for a signature
         if DER (Pos) /= 0 then return; end if;
         Pos := Pos + 1;
         Sig_Len := Sig_Len - 1;
         if Sig_Len > Max_Sig_Bytes then return; end if;
         Copy_Bytes (DER, Pos, Sig_Len, C.Sig_Buf, C.Sig_Buf_Len);
         if C.Sig_Buf_Len /= Sig_Len then return; end if;
         Pos := Pos + Sig_Len;
         if Pos /= DER'Last + 1 then return; end if;
      end;

      C.Valid_Flag := True;
      if not Spans_Valid (C, DER'Last) then
         C.Valid_Flag := False;
         return;
      end if;
      V  := C;
      OK := True;
   end Parse;

   ----------------------------------------------------------------------------
   --  Lookup
   ----------------------------------------------------------------------------

   procedure Lookup
     (DER             : in     Byte_Seq;
      V               : in     CRL_View;
      Serial          : in     Byte_Seq;
      Found           :    out Boolean;
      Revocation_Date :    out Date_Time;
      Has_Reason      :    out Boolean;
      Reason          :    out Natural)
   is
      Pos   : N32;
      R_End : N32;
      OK    : Boolean := True;
      S_Len : constant N32 := N32 (Serial'Length);
   begin
      Found           := False;
      Revocation_Date := (others => 0);
      Has_Reason      := False;
      Reason          := 0;

      if not V.S_Revoked.Present then return; end if;
      Pos   := V.S_Revoked.First;
      R_End := V.S_Revoked.Last + 1;

      while OK and then Pos < R_End loop
         pragma Loop_Invariant (Pos <= DER'Last);
         pragma Loop_Invariant (R_End <= DER'Last + 1);
         pragma Loop_Variant (Increases => Pos);
         declare
            E_Serial : Span;
            E_Date   : Date_Time;
            E_HasR   : Boolean;
            E_Reason : Natural;
            E_Crit   : Boolean;
         begin
            Parse_Entry (DER, Pos, E_Serial, E_Date, E_HasR, E_Reason,
                         E_Crit, OK);
            if not OK then return; end if;
            if Pos > R_End then return; end if;

            if Span_Length (E_Serial) = S_Len then
               declare
                  Same : Boolean := True;
               begin
                  for I in N32 range 0 .. S_Len - 1 loop
                     pragma Loop_Invariant (I < S_Len);
                     if DER (E_Serial.First + I) /= Serial (Serial'First + I) then
                        Same := False;
                        exit;
                     end if;
                  end loop;
                  if Same then
                     Found           := True;
                     Revocation_Date := E_Date;
                     Has_Reason      := E_HasR;
                     Reason          := E_Reason;
                     return;
                  end if;
               end;
            end if;
         end;
      end loop;
   end Lookup;

end X509.CRL;
