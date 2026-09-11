with X509.DER;     use X509.DER;
with X509.DER_Ext; use X509.DER_Ext;

package body X509.OCSP with
   SPARK_Mode => On
is
   ----------------------------------------------------------------------------
   --  OIDs and tags local to OCSP (RFC 6960 appendix B)
   ----------------------------------------------------------------------------

   --  id-pkix-ocsp-basic  1.3.6.1.5.5.7.48.1.1
   OID_OCSP_BASIC : constant Byte_Seq (0 .. 8) :=
     (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#30#, 16#01#, 16#01#);
   --  id-pkix-ocsp-nonce  1.3.6.1.5.5.7.48.1.2
   OID_OCSP_NONCE : constant Byte_Seq (0 .. 8) :=
     (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#07#, 16#30#, 16#01#, 16#02#);

   --  Digest algorithm OIDs for CertID.hashAlgorithm
   OID_SHA1   : constant Byte_Seq (0 .. 4) :=
     (16#2B#, 16#0E#, 16#03#, 16#02#, 16#1A#);                      --  1.3.14.3.2.26
   OID_SHA256 : constant Byte_Seq (0 .. 8) :=
     (16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#01#);
   OID_SHA384 : constant Byte_Seq (0 .. 8) :=
     (16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#02#);
   OID_SHA512 : constant Byte_Seq (0 .. 8) :=
     (16#60#, 16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#03#);

   TAG_ENUMERATED        : constant Byte := 16#0A#;
   TAG_RESPONSE_BYTES    : constant Byte := 16#A0#;  --  [0] EXPLICIT
   TAG_RD_VERSION        : constant Byte := 16#A0#;  --  [0] EXPLICIT
   TAG_RID_BY_NAME       : constant Byte := 16#A1#;  --  [1] EXPLICIT Name
   TAG_RID_BY_KEY        : constant Byte := 16#A2#;  --  [2] EXPLICIT KeyHash
   TAG_RD_EXTENSIONS     : constant Byte := 16#A1#;  --  [1] EXPLICIT
   TAG_STATUS_GOOD       : constant Byte := 16#80#;  --  [0] IMPLICIT NULL
   TAG_STATUS_REVOKED    : constant Byte := 16#A1#;  --  [1] IMPLICIT RevokedInfo
   TAG_STATUS_UNKNOWN    : constant Byte := 16#82#;  --  [2] IMPLICIT NULL
   TAG_REVOCATION_REASON : constant Byte := 16#A0#;  --  [0] EXPLICIT CRLReason
   TAG_NEXT_UPDATE       : constant Byte := 16#A0#;  --  [0] EXPLICIT
   TAG_SINGLE_EXTENSIONS : constant Byte := 16#A1#;  --  [1] EXPLICIT
   TAG_CERTS             : constant Byte := 16#A0#;  --  [0] EXPLICIT

   Empty_Response : constant Single_Response :=
     (Hash_Algo          => Hash_Unknown,
      S_Issuer_Name_Hash => (0, 0, False),
      S_Issuer_Key_Hash  => (0, 0, False),
      S_Serial           => (0, 0, False),
      Status             => Status_Unknown,
      This_Update        => (others => 0),
      Has_Next_Update    => False,
      Next_Update        => (others => 0),
      Revocation_Time    => (others => 0),
      Has_Reason         => False,
      Reason             => 0,
      Unknown_Critical   => False);

   ----------------------------------------------------------------------------
   --  Getters
   ----------------------------------------------------------------------------

   function Status             (V : OCSP_View) return Response_Status   is (V.Resp_Status);
   function Has_Basic_Response (V : OCSP_View) return Boolean           is (V.Has_Basic);
   function TBS                (V : OCSP_View) return Span              is (V.S_TBS);
   function Version            (V : OCSP_View) return Natural           is (V.Resp_Version);
   function Responder_Kind     (V : OCSP_View) return Responder_ID_Kind is (V.Resp_Kind);
   function Responder_ID       (V : OCSP_View) return Span              is (V.S_Responder);
   function Produced_At        (V : OCSP_View) return Date_Time         is (V.Produced);
   function Sig_Algorithm      (V : OCSP_View) return Algorithm_ID      is (V.Sig_Algo);
   function Sig_Length         (V : OCSP_View) return N32               is (V.Sig_Buf_Len);

   function Sig_Data (V : OCSP_View) return Byte_Seq is
     (V.Sig_Buf (0 .. V.Sig_Buf_Len - 1));

   function Response_Count       (V : OCSP_View) return Natural is (V.Resp_Num);
   function Total_Response_Count (V : OCSP_View) return N32     is (V.Resp_Total);

   function Get_Response
     (V : OCSP_View; Index : Positive) return Single_Response
   is (V.Responses (Index));

   function Embedded_Cert_Count (V : OCSP_View) return Natural is (V.Cert_Num);

   function Embedded_Cert
     (V : OCSP_View; Index : Positive) return Span
   is (V.Certs (Index));

   function Has_Nonce (V : OCSP_View) return Boolean is (V.S_Nonce.Present);
   function Nonce     (V : OCSP_View) return Span    is (V.S_Nonce);

   function Has_Unknown_Critical_Extension (V : OCSP_View) return Boolean is
     (V.Unknown_Crit);

   ----------------------------------------------------------------------------
   --  Helpers
   ----------------------------------------------------------------------------

   --  Walk an Extensions SEQUENCE whose content ends at Exts_End and
   --  report a critical extension that is not id-pkix-ocsp-nonce.
   --  Nonce, when present, is returned as its extnValue span.
   procedure Walk_Extensions
     (DER          : in     Byte_Seq;
      Pos          : in out N32;
      Exts_End     : in     N32;
      Nonce_Span   : in out Span;
      Unknown_Crit : in out Boolean;
      OK           : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last and Exts_End <= DER'Last + 1
                and Span_In_Range (Nonce_Span, DER'Last),
        Post => (if OK then Pos = Exts_End
                 and Span_In_Range (Nonce_Span, DER'Last))
   is
   begin
      while OK and then Pos < Exts_End loop
         pragma Loop_Invariant (Pos <= DER'Last);
         pragma Loop_Invariant (Span_In_Range (Nonce_Span, DER'Last));
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
            if OID_Match (DER, OID_Start, OID_Len, OID_OCSP_NONCE) then
               Nonce_Span := (First => Val_Start, Last => Val_Start + Val_Len - 1,
                              Present => True);
            elsif Critical then
               Unknown_Crit := True;
            end if;
         end;
      end loop;
      if Pos /= Exts_End then OK := False; end if;
   end Walk_Extensions;

   ----------------------------------------------------------------------------
   --  SingleResponse (4.2.2.3)
   ----------------------------------------------------------------------------

   procedure Parse_Single
     (DER : in     Byte_Seq;
      Pos : in out N32;
      R   :    out Single_Response;
      OK  : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last,
        Post => (if OK then Pos > Pos'Old and Pos <= DER'Last + 1
                 and Single_Spans_Valid (R, DER'Last))
   is
      SR_Len : N32;
      SR_End : N32;
      Dummy_Nonce : Span := (0, 0, False);
   begin
      R := Empty_Response;

      Parse_Sequence_Hdr (DER, Pos, SR_Len, OK);
      if not OK then return; end if;
      SR_End := Pos + SR_Len;

      --  CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
      if Pos >= SR_End then OK := False; return; end if;
      declare
         ID_Len : N32;
         ID_End : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, ID_Len, OK);
         if not OK then return; end if;
         ID_End := Pos + ID_Len;
         if ID_End > SR_End then OK := False; return; end if;

         --  hashAlgorithm AlgorithmIdentifier
         if Pos >= ID_End then OK := False; return; end if;
         declare
            Alg_Len   : N32;
            Alg_End   : N32;
            OID_Len   : N32;
            OID_Start : N32;
         begin
            Parse_Sequence_Hdr (DER, Pos, Alg_Len, OK);
            if not OK then return; end if;
            Alg_End := Pos + Alg_Len;
            if Alg_End > ID_End then OK := False; return; end if;
            if Pos >= Alg_End or else DER (Pos) /= TAG_OID then
               OK := False; return;
            end if;
            Pos := Pos + 1;
            if Pos > DER'Last then OK := False; return; end if;
            Parse_Length (DER, Pos, OID_Len, OK);
            if not OK then return; end if;
            if not Can_Read (DER, Pos, OID_Len) then OK := False; return; end if;
            OID_Start := Pos;
            if OID_Match (DER, OID_Start, OID_Len, OID_SHA1) then
               R.Hash_Algo := Hash_SHA1;
            elsif OID_Match (DER, OID_Start, OID_Len, OID_SHA256) then
               R.Hash_Algo := Hash_SHA256;
            elsif OID_Match (DER, OID_Start, OID_Len, OID_SHA384) then
               R.Hash_Algo := Hash_SHA384;
            elsif OID_Match (DER, OID_Start, OID_Len, OID_SHA512) then
               R.Hash_Algo := Hash_SHA512;
            end if;
            Pos := Alg_End;  --  skip optional NULL parameters
         end;

         --  issuerNameHash OCTET STRING
         if Pos >= ID_End then OK := False; return; end if;
         declare
            H_End : N32;
         begin
            Enter_Octet_String (DER, Pos, H_End, OK);
            if not OK then return; end if;
            if H_End > ID_End or else H_End = Pos then OK := False; return; end if;
            R.S_Issuer_Name_Hash := (First => Pos, Last => H_End - 1, Present => True);
            Pos := H_End;
         end;

         --  issuerKeyHash OCTET STRING
         if Pos >= ID_End then OK := False; return; end if;
         declare
            H_End : N32;
         begin
            Enter_Octet_String (DER, Pos, H_End, OK);
            if not OK then return; end if;
            if H_End > ID_End or else H_End = Pos then OK := False; return; end if;
            R.S_Issuer_Key_Hash := (First => Pos, Last => H_End - 1, Present => True);
            Pos := H_End;
         end;

         --  serialNumber INTEGER
         if Pos >= ID_End or else DER (Pos) /= TAG_INTEGER then
            OK := False; return;
         end if;
         declare
            S_Len : N32;
         begin
            Pos := Pos + 1;
            if Pos > DER'Last then OK := False; return; end if;
            Parse_Length (DER, Pos, S_Len, OK);
            if not OK then return; end if;
            if S_Len = 0 or else not Can_Read (DER, Pos, S_Len) then
               OK := False; return;
            end if;
            R.S_Serial := (First => Pos, Last => Pos + S_Len - 1, Present => True);
            Pos := Pos + S_Len;
            if Pos /= ID_End then OK := False; return; end if;
         end;
      end;

      --  certStatus CHOICE
      if Pos >= SR_End then OK := False; return; end if;
      declare
         Tag   : constant Byte := DER (Pos);
         S_End : N32;
      begin
         if Tag = TAG_STATUS_GOOD or else Tag = TAG_STATUS_UNKNOWN then
            --  [0] / [2] IMPLICIT NULL: tag + zero length
            if not Can_Read (DER, Pos, 2) or else DER (Pos + 1) /= 0 then
               OK := False; return;
            end if;
            R.Status := (if Tag = TAG_STATUS_GOOD then Status_Good else Status_Unknown);
            Pos := Pos + 2;
         elsif Tag = TAG_STATUS_REVOKED then
            --  [1] IMPLICIT RevokedInfo ::= SEQUENCE { revocationTime, [0] reason OPTIONAL }
            Enter_Explicit (DER, Pos, TAG_STATUS_REVOKED, S_End, OK);
            if not OK then return; end if;
            if S_End > SR_End then OK := False; return; end if;
            if Pos >= S_End then OK := False; return; end if;
            Parse_Time_TLV (DER, Pos, R.Revocation_Time, OK);
            if not OK then return; end if;
            if Pos > S_End then OK := False; return; end if;
            if Pos < S_End then
               declare
                  RR_End : N32;
               begin
                  Enter_Explicit (DER, Pos, TAG_REVOCATION_REASON, RR_End, OK);
                  if not OK then return; end if;
                  if RR_End /= S_End then OK := False; return; end if;
                  --  CRLReason ENUMERATED, one octet
                  if not Can_Read (DER, Pos, 3)
                    or else DER (Pos) /= TAG_ENUMERATED
                    or else DER (Pos + 1) /= 1
                    or else Pos + 3 /= RR_End
                  then
                     OK := False; return;
                  end if;
                  R.Has_Reason := True;
                  R.Reason := Natural (DER (Pos + 2));
                  Pos := Pos + 3;
               end;
            end if;
            R.Status := Status_Revoked;
         else
            OK := False; return;
         end if;
      end;

      --  thisUpdate GeneralizedTime
      if Pos >= SR_End then OK := False; return; end if;
      Parse_Time_TLV (DER, Pos, R.This_Update, OK);
      if not OK then return; end if;
      if Pos > SR_End then OK := False; return; end if;

      --  nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
      if Pos < SR_End and then DER (Pos) = TAG_NEXT_UPDATE then
         declare
            NU_End : N32;
         begin
            Enter_Explicit (DER, Pos, TAG_NEXT_UPDATE, NU_End, OK);
            if not OK then return; end if;
            if NU_End > SR_End or else Pos >= NU_End then OK := False; return; end if;
            Parse_Time_TLV (DER, Pos, R.Next_Update, OK);
            if not OK then return; end if;
            if Pos /= NU_End then OK := False; return; end if;
            R.Has_Next_Update := True;
         end;
      end if;

      --  singleExtensions [1] EXPLICIT Extensions OPTIONAL
      if Pos < SR_End then
         declare
            SE_End   : N32;
            Exts_Len : N32;
            Exts_End : N32;
         begin
            Enter_Explicit (DER, Pos, TAG_SINGLE_EXTENSIONS, SE_End, OK);
            if not OK then return; end if;
            if SE_End /= SR_End or else Pos >= SE_End then OK := False; return; end if;
            Parse_Sequence_Hdr (DER, Pos, Exts_Len, OK);
            if not OK then return; end if;
            Exts_End := Pos + Exts_Len;
            if Exts_End /= SE_End then OK := False; return; end if;
            Walk_Extensions (DER, Pos, Exts_End, Dummy_Nonce,
                             R.Unknown_Critical, OK);
            if not OK then return; end if;
         end;
      end if;

      if Pos /= SR_End then OK := False; return; end if;
   end Parse_Single;

   ----------------------------------------------------------------------------
   --  ResponseData (4.2.2.2)
   ----------------------------------------------------------------------------

   procedure Parse_Response_Data
     (DER : in     Byte_Seq;
      Pos : in out N32;
      C   : in out OCSP_View;
      OK  : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last and Spans_Valid (C, DER'Last),
        Post => (if OK then Pos > Pos'Old and Pos <= DER'Last + 1
                 and Spans_Valid (C, DER'Last))
   is
      RD_Start : constant N32 := Pos;
      RD_Len   : N32;
      RD_End   : N32;
   begin
      Parse_Sequence_Hdr (DER, Pos, RD_Len, OK);
      if not OK then return; end if;
      RD_End := Pos + RD_Len;
      C.S_TBS := (First => RD_Start, Last => RD_End - 1, Present => True);

      --  version [0] EXPLICIT Version DEFAULT v1
      if Pos < RD_End and then DER (Pos) = TAG_RD_VERSION then
         declare
            V_End : N32;
            V_Len : N32;
         begin
            Enter_Explicit (DER, Pos, TAG_RD_VERSION, V_End, OK);
            if not OK then return; end if;
            if V_End > RD_End then OK := False; return; end if;
            if Pos >= V_End or else DER (Pos) /= TAG_INTEGER then
               OK := False; return;
            end if;
            Pos := Pos + 1;
            if Pos > DER'Last then OK := False; return; end if;
            Parse_Length (DER, Pos, V_Len, OK);
            if not OK then return; end if;
            if V_Len /= 1 or else Pos > DER'Last or else Pos + 1 /= V_End then
               OK := False; return;
            end if;
            C.Resp_Version := Natural (DER (Pos)) + 1;
            Pos := V_End;
         end;
      end if;

      --  responderID CHOICE { byName [1] Name, byKey [2] KeyHash }
      if Pos >= RD_End then OK := False; return; end if;
      declare
         Tag    : constant Byte := DER (Pos);
         ID_End : N32;
         In_Len : N32;
      begin
         if Tag = TAG_RID_BY_NAME then
            Enter_Explicit (DER, Pos, TAG_RID_BY_NAME, ID_End, OK);
            if not OK then return; end if;
            if ID_End > RD_End or else Pos >= ID_End then OK := False; return; end if;
            Parse_Sequence_Hdr (DER, Pos, In_Len, OK);
            if not OK then return; end if;
            if In_Len = 0 or else not Can_Read (DER, Pos, In_Len)
              or else Pos + In_Len /= ID_End
            then
               OK := False; return;
            end if;
            C.Resp_Kind := Responder_By_Name;
            C.S_Responder := (First => Pos, Last => ID_End - 1, Present => True);
            Pos := ID_End;
         elsif Tag = TAG_RID_BY_KEY then
            Enter_Explicit (DER, Pos, TAG_RID_BY_KEY, ID_End, OK);
            if not OK then return; end if;
            if ID_End > RD_End or else Pos >= ID_End then OK := False; return; end if;
            declare
               K_End : N32;
            begin
               Enter_Octet_String (DER, Pos, K_End, OK);
               if not OK then return; end if;
               --  KeyHash is a SHA-1 digest: exactly 20 octets
               if K_End /= ID_End or else K_End - Pos /= 20 then
                  OK := False; return;
               end if;
               C.Resp_Kind := Responder_By_Key;
               C.S_Responder := (First => Pos, Last => K_End - 1, Present => True);
               Pos := K_End;
            end;
         else
            OK := False; return;
         end if;
      end;

      --  producedAt GeneralizedTime
      if Pos >= RD_End then OK := False; return; end if;
      Parse_Time_TLV (DER, Pos, C.Produced, OK);
      if not OK then return; end if;
      if Pos > RD_End then OK := False; return; end if;

      --  responses SEQUENCE OF SingleResponse
      if Pos >= RD_End then OK := False; return; end if;
      declare
         RS_Len : N32;
         RS_End : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, RS_Len, OK);
         if not OK then return; end if;
         RS_End := Pos + RS_Len;
         if RS_End > RD_End then OK := False; return; end if;

         while OK and then Pos < RS_End loop
            pragma Loop_Invariant (Pos <= DER'Last);
            pragma Loop_Invariant (RS_End <= DER'Last + 1);
            pragma Loop_Invariant (Spans_Valid (C, DER'Last));
            pragma Loop_Invariant (C.Resp_Num <= Max_Single_Responses);
            pragma Loop_Variant (Increases => Pos);
            declare
               R : Single_Response;
            begin
               Parse_Single (DER, Pos, R, OK);
               if not OK then return; end if;
               if Pos > RS_End then OK := False; return; end if;
               if C.Resp_Num < Max_Single_Responses then
                  C.Resp_Num := C.Resp_Num + 1;
                  C.Responses (C.Resp_Num) := R;
               end if;
               if C.Resp_Total < N32'Last then
                  C.Resp_Total := C.Resp_Total + 1;
               end if;
            end;
         end loop;
         if Pos /= RS_End then OK := False; return; end if;
      end;

      --  responseExtensions [1] EXPLICIT Extensions OPTIONAL
      if Pos < RD_End then
         declare
            RE_End   : N32;
            Exts_Len : N32;
            Exts_End : N32;
         begin
            Enter_Explicit (DER, Pos, TAG_RD_EXTENSIONS, RE_End, OK);
            if not OK then return; end if;
            if RE_End /= RD_End or else Pos >= RE_End then OK := False; return; end if;
            Parse_Sequence_Hdr (DER, Pos, Exts_Len, OK);
            if not OK then return; end if;
            Exts_End := Pos + Exts_Len;
            if Exts_End /= RE_End then OK := False; return; end if;
            Walk_Extensions (DER, Pos, Exts_End, C.S_Nonce, C.Unknown_Crit, OK);
            if not OK then return; end if;
         end;
      end if;

      if Pos /= RD_End then OK := False; return; end if;
   end Parse_Response_Data;

   ----------------------------------------------------------------------------
   --  BasicOCSPResponse (4.2.2) -- occupies DER (Pos .. Basic_End - 1)
   ----------------------------------------------------------------------------

   procedure Parse_Basic
     (DER       : in     Byte_Seq;
      Pos       : in out N32;
      Basic_End : in     N32;
      C         : in out OCSP_View;
      OK        : in out Boolean)
   with Pre  => OK and DER'First = 0 and Pos <= DER'Last
                and DER'Last < N32'Last and Basic_End <= DER'Last + 1
                and Spans_Valid (C, DER'Last),
        Post => (if OK then Pos = Basic_End and Spans_Valid (C, DER'Last))
   is
      B_Len : N32;
      B_End : N32;
   begin
      Parse_Sequence_Hdr (DER, Pos, B_Len, OK);
      if not OK then return; end if;
      B_End := Pos + B_Len;
      if B_End /= Basic_End then OK := False; return; end if;

      --  tbsResponseData
      if Pos >= B_End then OK := False; return; end if;
      Parse_Response_Data (DER, Pos, C, OK);
      if not OK then return; end if;
      if Pos > B_End then OK := False; return; end if;

      --  signatureAlgorithm
      if Pos >= B_End then OK := False; return; end if;
      declare
         Alg_Len : N32;
         Alg_End : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, Alg_Len, OK);
         if not OK then return; end if;
         Alg_End := Pos + Alg_Len;
         if Alg_End > B_End or else Pos >= Alg_End then OK := False; return; end if;
         Parse_Algorithm_OID (DER, Pos, C.Sig_Algo, OK);
         if not OK then return; end if;
         Pos := Alg_End;
      end;

      --  signature BIT STRING
      if Pos >= B_End or else DER (Pos) /= TAG_BITSTRING then OK := False; return; end if;
      declare
         Sig_Len : N32;
      begin
         Pos := Pos + 1;
         if Pos > DER'Last then OK := False; return; end if;
         Parse_Length (DER, Pos, Sig_Len, OK);
         if not OK then return; end if;
         if Sig_Len < 2 or else not Can_Read (DER, Pos, Sig_Len) then OK := False; return; end if;
         if DER (Pos) /= 0 then OK := False; return; end if;
         Pos := Pos + 1;
         Sig_Len := Sig_Len - 1;
         if Sig_Len > Max_Sig_Bytes then OK := False; return; end if;
         Copy_Bytes (DER, Pos, Sig_Len, C.Sig_Buf, C.Sig_Buf_Len);
         if C.Sig_Buf_Len /= Sig_Len then OK := False; return; end if;
         Pos := Pos + Sig_Len;
         if Pos > B_End then OK := False; return; end if;
      end;

      --  certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
      if Pos < B_End then
         declare
            CW_End : N32;
            CS_Len : N32;
            CS_End : N32;
         begin
            Enter_Explicit (DER, Pos, TAG_CERTS, CW_End, OK);
            if not OK then return; end if;
            if CW_End /= B_End or else Pos >= CW_End then OK := False; return; end if;
            Parse_Sequence_Hdr (DER, Pos, CS_Len, OK);
            if not OK then return; end if;
            CS_End := Pos + CS_Len;
            if CS_End /= CW_End then OK := False; return; end if;

            while OK and then Pos < CS_End loop
               pragma Loop_Invariant (Pos <= DER'Last);
               pragma Loop_Invariant (CS_End <= DER'Last + 1);
               pragma Loop_Invariant (Spans_Valid (C, DER'Last));
               pragma Loop_Invariant (C.Cert_Num <= Max_Embedded_Certs);
               pragma Loop_Variant (Increases => Pos);
               declare
                  Cert_Start : constant N32 := Pos;
                  Cert_Len   : N32;
               begin
                  Parse_Sequence_Hdr (DER, Pos, Cert_Len, OK);
                  if not OK then return; end if;
                  Pos := Pos + Cert_Len;
                  if Pos > CS_End then OK := False; return; end if;
                  if C.Cert_Num < Max_Embedded_Certs then
                     C.Cert_Num := C.Cert_Num + 1;
                     C.Certs (C.Cert_Num) :=
                       (First => Cert_Start, Last => Pos - 1, Present => True);
                  end if;
               end;
            end loop;
            if Pos /= CS_End then OK := False; return; end if;
         end;
      end if;

      if Pos /= B_End then OK := False; return; end if;
   end Parse_Basic;

   ----------------------------------------------------------------------------
   --  Parse
   ----------------------------------------------------------------------------

   procedure Parse
     (DER : in     Byte_Seq;
      V   :    out OCSP_View;
      OK  :    out Boolean)
   is
      Pos   : N32 := 0;
      Valid : Boolean := True;
      C     : OCSP_View;
      O_End : N32;
   begin
      C := (Valid_Flag => False, Resp_Status => Unknown_Status,
            Has_Basic => False, Resp_Version => 1,
            S_TBS => (0, 0, False), Resp_Kind => Responder_None,
            S_Responder => (0, 0, False), Produced => (others => 0),
            Sig_Algo => Algo_Unknown, Sig_Buf => (others => 0),
            Sig_Buf_Len => 0,
            Responses => (others => Empty_Response), Resp_Num => 0,
            Resp_Total => 0,
            Certs => (others => (0, 0, False)), Cert_Num => 0,
            S_Nonce => (0, 0, False), Unknown_Crit => False);
      V  := C;
      OK := False;

      --  OCSPResponse ::= SEQUENCE, must consume the whole buffer
      if Pos > DER'Last then return; end if;
      declare
         Outer_Len : N32;
      begin
         Parse_Sequence_Hdr (DER, Pos, Outer_Len, Valid);
         if not Valid then return; end if;
         O_End := Pos + Outer_Len;
         if O_End /= DER'Last + 1 then return; end if;
      end;

      --  responseStatus ENUMERATED
      if Pos >= O_End or else DER (Pos) /= TAG_ENUMERATED then return; end if;
      if not Can_Read (DER, Pos, 3) or else DER (Pos + 1) /= 1 then return; end if;
      case DER (Pos + 2) is
         when 0      => C.Resp_Status := Successful;
         when 1      => C.Resp_Status := Malformed_Request;
         when 2      => C.Resp_Status := Internal_Error;
         when 3      => C.Resp_Status := Try_Later;
         when 5      => C.Resp_Status := Sig_Required;
         when 6      => C.Resp_Status := Unauthorized;
         when others => C.Resp_Status := Unknown_Status;
      end case;
      Pos := Pos + 3;

      --  responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
      if Pos < O_End then
         declare
            RB_End   : N32;
            RB_Len   : N32;
            RB_SEnd  : N32;
            OID_Len  : N32;
            OID_Start : N32;
            Basic_End : N32;
         begin
            Enter_Explicit (DER, Pos, TAG_RESPONSE_BYTES, RB_End, Valid);
            if not Valid then return; end if;
            if RB_End /= O_End or else Pos >= RB_End then return; end if;

            --  ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
            Parse_Sequence_Hdr (DER, Pos, RB_Len, Valid);
            if not Valid then return; end if;
            RB_SEnd := Pos + RB_Len;
            if RB_SEnd /= RB_End then return; end if;

            if Pos >= RB_SEnd or else DER (Pos) /= TAG_OID then return; end if;
            Pos := Pos + 1;
            if Pos > DER'Last then return; end if;
            Parse_Length (DER, Pos, OID_Len, Valid);
            if not Valid then return; end if;
            if not Can_Read (DER, Pos, OID_Len) then return; end if;
            OID_Start := Pos;
            Pos := Pos + OID_Len;
            if not OID_Match (DER, OID_Start, OID_Len, OID_OCSP_BASIC) then
               return;
            end if;

            if Pos >= RB_SEnd then return; end if;
            Enter_Octet_String (DER, Pos, Basic_End, Valid);
            if not Valid then return; end if;
            if Basic_End /= RB_SEnd or else Pos >= Basic_End then return; end if;

            Parse_Basic (DER, Pos, Basic_End, C, Valid);
            if not Valid then return; end if;
            C.Has_Basic := True;
         end;
      end if;

      if Pos /= O_End then return; end if;

      --  A successful status must carry a basic response; a failure
      --  status carries none (4.2.1).
      if (C.Resp_Status = Successful) /= C.Has_Basic then return; end if;

      C.Valid_Flag := True;
      if not Spans_Valid (C, DER'Last) then
         C.Valid_Flag := False;
         return;
      end if;
      V  := C;
      OK := True;
   end Parse;

end X509.OCSP;
