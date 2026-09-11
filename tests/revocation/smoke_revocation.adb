--  Smoke test for X509.CRL and X509.OCSP against OpenSSL-generated
--  fixtures (see gen.sh). Usage: smoke_revocation <fixture-dir>

with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with Interfaces;
with X509;
with X509.CRL;
with X509.OCSP;

procedure Smoke_Revocation is
   package CLI renames Ada.Command_Line;
   package SIO renames Ada.Streams.Stream_IO;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_8;
   use type X509.Algorithm_ID;
   use type X509.Byte_Seq;
   use type X509.OCSP.Response_Status;
   use type X509.OCSP.Cert_Status;
   use type X509.OCSP.Hash_Algorithm;
   use type X509.OCSP.Responder_ID_Kind;

   Failures : Natural := 0;

   procedure Check (Condition : Boolean; Name : String) is
   begin
      if Condition then
         Ada.Text_IO.Put_Line ("PASS: " & Name);
      else
         Ada.Text_IO.Put_Line ("FAIL: " & Name);
         Failures := Failures + 1;
      end if;
   end Check;

   Dir : constant String :=
     (if CLI.Argument_Count >= 1 then CLI.Argument (1) else "/tmp/sparkx509-revocation");

   function Load (Name : String) return X509.Byte_Seq is
      Path : constant String := Dir & "/" & Name;
      File : SIO.File_Type;
   begin
      SIO.Open (File, SIO.In_File, Path);
      declare
         Size : constant Natural := Natural (SIO.Size (File));
         Raw  : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Size));
         Last : Ada.Streams.Stream_Element_Offset;
         DER  : X509.Byte_Seq (0 .. X509.N32 (Size - 1));
      begin
         SIO.Read (File, Raw, Last);
         SIO.Close (File);
         for I in DER'Range loop
            DER (I) := X509.Byte (Raw (Ada.Streams.Stream_Element_Offset (I + 1)));
         end loop;
         return DER;
      end;
   end Load;

   --  Bytes of a span, as a zero-based sequence
   function Bytes (DER : X509.Byte_Seq; S : X509.Span) return X509.Byte_Seq is
      R : X509.Byte_Seq (0 .. X509.Span_Length (S) - 1);
   begin
      for I in R'Range loop
         R (I) := DER (S.First + I);
      end loop;
      return R;
   end Bytes;

   Serial_Good    : constant X509.Byte_Seq (0 .. 1) := (16#10#, 16#00#);
   Serial_Revoked : constant X509.Byte_Seq (0 .. 1) := (16#10#, 16#01#);

   ----------------------------------------------------------------------------
   --  Certificates: the new getters
   ----------------------------------------------------------------------------
   procedure Test_Certs is
      CA_DER  : constant X509.Byte_Seq := Load ("ca.der");
      Good    : constant X509.Byte_Seq := Load ("good.der");
      Staple  : constant X509.Byte_Seq := Load ("staple.der");
      Resp    : constant X509.Byte_Seq := Load ("ocsp.der");
      Revoked : constant X509.Byte_Seq := Load ("revoked.der");
      CA, G, S, R, RV : X509.Certificate;
      OK : Boolean;
   begin
      X509.Parse (CA_DER, CA, OK);  Check (OK, "cert: ca parses");
      X509.Parse (Good, G, OK);     Check (OK, "cert: good parses");
      X509.Parse (Staple, S, OK);   Check (OK, "cert: staple parses");
      X509.Parse (Resp, R, OK);     Check (OK, "cert: ocsp responder parses");
      X509.Parse (Revoked, RV, OK); Check (OK, "cert: revoked parses");

      Check (X509.Must_Staple (S), "cert: TLS Feature status_request => Must_Staple");
      Check (not X509.Must_Staple (G), "cert: plain leaf is not Must_Staple");
      Check (X509.Has_EKU_OCSP_Signing (R), "cert: responder has id-kp-OCSPSigning");
      Check (not X509.Has_EKU_OCSP_Signing (G), "cert: leaf lacks id-kp-OCSPSigning");
      Check (not X509.Has_EKU_OCSP_Signing (CA), "cert: CA lacks id-kp-OCSPSigning");

      declare
         B : constant X509.Span := X509.Subject_Public_Key_Bits (CA);
      begin
         Check (B.Present and then B.Last <= CA_DER'Last, "cert: SPKI bits span present");
         --  RSA: BIT STRING content is the RSAPublicKey SEQUENCE
         Check (B.Present and then CA_DER (B.First) = 16#30#, "cert: RSA SPKI bits start with SEQUENCE");
         Check (X509.Span_Length (B) > 256, "cert: RSA-2048 SPKI bits > 256 bytes");
      end;
      declare
         B : constant X509.Span := X509.Subject_Public_Key_Bits (S);
      begin
         --  EC P-256: uncompressed point 04 || X || Y = 65 bytes
         Check (B.Present and then X509.Span_Length (B) = 65
                and then Staple (B.First) = 16#04#, "cert: EC SPKI bits are the 65-byte point");
      end;
      Check (X509.Subject_Raw (CA).Present and X509.Issuer_Raw (G).Present, "cert: raw name spans present");
      Check (Bytes (CA_DER, X509.Subject_Raw (CA)) = Bytes (Good, X509.Issuer_Raw (G)),
             "cert: leaf issuer raw == CA subject raw");
      Check (Bytes (Good, X509.Serial (G)) = Serial_Good, "cert: good serial = 0x1000");
      Check (Bytes (Revoked, X509.Serial (RV)) = Serial_Revoked, "cert: revoked serial = 0x1001");
   end Test_Certs;

   ----------------------------------------------------------------------------
   --  CRL
   ----------------------------------------------------------------------------
   procedure Test_CRL is
      DER : constant X509.Byte_Seq := Load ("crl.der");
      V   : X509.CRL.CRL_View;
      OK  : Boolean;
   begin
      X509.CRL.Parse (DER, V, OK);
      Check (OK, "crl: parses");
      if not OK then return; end if;
      Check (X509.CRL.Version (V) = 2, "crl: version 2");
      Check (X509.CRL.TBS (V).Present and then DER (X509.CRL.TBS (V).First) = 16#30#, "crl: TBS span at SEQUENCE");
      Check (X509.CRL.Issuer_Raw (V).Present, "crl: issuer raw present");
      Check (X509.CRL.This_Update (V).Year = 2026, "crl: thisUpdate year");
      Check (X509.CRL.Has_Next_Update (V), "crl: has nextUpdate");
      Check (X509.DT_Before (X509.CRL.This_Update (V), X509.CRL.Next_Update (V)), "crl: thisUpdate < nextUpdate");
      Check (X509.CRL.Sig_Algorithm (V) = X509.Algo_RSA_PKCS1_SHA256, "crl: inner sig algo sha256WithRSA");
      Check (X509.CRL.Sig_Algorithm_2 (V) = X509.CRL.Sig_Algorithm (V), "crl: outer sig algo matches");
      Check (X509.CRL.Sig_Length (V) = 256, "crl: RSA-2048 signature length");
      Check (X509.CRL.Revoked_Count (V) = 1, "crl: one revoked entry");
      Check (X509.Span_Length (X509.CRL.Authority_Key_ID (V)) = 20, "crl: AKID keyIdentifier 20 bytes");
      Check (X509.CRL.Has_CRL_Number (V), "crl: has cRLNumber");
      Check (not X509.CRL.Is_Delta_CRL (V), "crl: not delta");
      Check (not X509.CRL.Has_IDP (V), "crl: no IDP");
      Check (not X509.CRL.Has_Unknown_Critical_Extension (V), "crl: no unknown critical ext");
      Check (not X509.CRL.Has_Critical_Entry_Extension (V), "crl: no critical entry ext");

      declare
         Found : Boolean; When_R : X509.Date_Time; Has_R : Boolean; Reason : Natural;
      begin
         X509.CRL.Lookup (DER, V, Serial_Revoked, Found, When_R, Has_R, Reason);
         Check (Found, "crl: lookup 0x1001 found");
         Check (Found and then When_R.Year = 2026, "crl: revocation date parsed");
         Check (Has_R and then Reason = 1, "crl: reasonCode keyCompromise (1)");
         X509.CRL.Lookup (DER, V, Serial_Good, Found, When_R, Has_R, Reason);
         Check (not Found, "crl: lookup 0x1000 not found");
      end;

      --  Truncated / corrupted input must fail cleanly
      declare
         T  : constant X509.Byte_Seq := DER (0 .. DER'Last - 1);
         V2 : X509.CRL.CRL_View;
      begin
         X509.CRL.Parse (T, V2, OK);
         Check (not OK, "crl: truncated by one byte rejected");
      end;
      declare
         C  : X509.Byte_Seq := DER;
         V2 : X509.CRL.CRL_View;
      begin
         C (C'Last) := C (C'Last) xor 16#FF#;  --  signature byte: still parses
         X509.CRL.Parse (C, V2, OK);
         Check (OK, "crl: flipped signature byte still parses (verify is the TLS layer's job)");
         C (1) := 16#84#;  --  nonsense length form
         X509.CRL.Parse (C, V2, OK);
         Check (not OK, "crl: bad length form rejected");
      end;
   end Test_CRL;

   procedure Test_Empty_CRL is
      DER : constant X509.Byte_Seq := Load ("crl_empty.der");
      V   : X509.CRL.CRL_View;
      OK  : Boolean;
      Found : Boolean; When_R : X509.Date_Time; Has_R : Boolean; Reason : Natural;
   begin
      X509.CRL.Parse (DER, V, OK);
      Check (OK, "crl_empty: parses");
      if not OK then return; end if;
      Check (X509.CRL.Revoked_Count (V) = 0, "crl_empty: zero entries");
      X509.CRL.Lookup (DER, V, Serial_Revoked, Found, When_R, Has_R, Reason);
      Check (not Found, "crl_empty: lookup not found");
   end Test_Empty_CRL;

   ----------------------------------------------------------------------------
   --  OCSP
   ----------------------------------------------------------------------------
   procedure Test_OCSP
     (Name      : String;
      Expect    : X509.OCSP.Cert_Status;
      Hash      : X509.OCSP.Hash_Algorithm;
      Serial    : X509.Byte_Seq;
      By_Key    : Boolean;
      Delegated : Boolean;
      Nonce     : Boolean)
   is
      DER : constant X509.Byte_Seq := Load (Name);
      V   : X509.OCSP.OCSP_View;
      OK  : Boolean;
   begin
      X509.OCSP.Parse (DER, V, OK);
      Check (OK, Name & ": parses");
      if not OK then return; end if;
      Check (X509.OCSP.Status (V) = X509.OCSP.Successful, Name & ": status successful");
      Check (X509.OCSP.Has_Basic_Response (V), Name & ": has basic response");
      Check (X509.OCSP.TBS (V).Present and then DER (X509.OCSP.TBS (V).First) = 16#30#,
             Name & ": TBS span at SEQUENCE");
      Check (X509.OCSP.Version (V) = 1, Name & ": version 1");
      Check (X509.OCSP.Responder_Kind (V) =
               (if By_Key then X509.OCSP.Responder_By_Key else X509.OCSP.Responder_By_Name),
             Name & ": responder id kind");
      Check (X509.OCSP.Responder_ID (V).Present, Name & ": responder id present");
      if By_Key then
         Check (X509.Span_Length (X509.OCSP.Responder_ID (V)) = 20, Name & ": byKey is 20 bytes");
      end if;
      Check (X509.OCSP.Produced_At (V).Year = 2026, Name & ": producedAt");
      Check (X509.OCSP.Sig_Algorithm (V) = X509.Algo_RSA_PKCS1_SHA256, Name & ": sig algo");
      Check (X509.OCSP.Sig_Length (V) = 256, Name & ": sig length 256");
      Check (X509.OCSP.Response_Count (V) = 1 and X509.OCSP.Total_Response_Count (V) = 1,
             Name & ": one single response");
      Check (X509.OCSP.Has_Nonce (V) = Nonce, Name & ": nonce presence");
      Check (not X509.OCSP.Has_Unknown_Critical_Extension (V), Name & ": no unknown critical");
      if X509.OCSP.Response_Count (V) >= 1 then
         declare
            R : constant X509.OCSP.Single_Response := X509.OCSP.Get_Response (V, 1);
         begin
            Check (R.Hash_Algo = Hash, Name & ": certid hash algo");
            Check (X509.Span_Length (R.S_Issuer_Name_Hash) = (if Hash = X509.OCSP.Hash_SHA1 then 20 else 32),
                   Name & ": issuerNameHash length");
            Check (X509.Span_Length (R.S_Issuer_Key_Hash) = (if Hash = X509.OCSP.Hash_SHA1 then 20 else 32),
                   Name & ": issuerKeyHash length");
            Check (Bytes (DER, R.S_Serial) = Serial, Name & ": serial");
            Check (R.Status = Expect, Name & ": cert status");
            Check (R.This_Update.Year = 2026, Name & ": thisUpdate");
            Check (R.Has_Next_Update and then X509.DT_Before (R.This_Update, R.Next_Update),
                   Name & ": nextUpdate after thisUpdate");
            if Expect = X509.OCSP.Status_Revoked then
               Check (R.Revocation_Time.Year = 2026, Name & ": revocationTime");
               Check (R.Has_Reason and then R.Reason = 1, Name & ": reason keyCompromise");
            end if;
            Check (not R.Unknown_Critical, Name & ": no unknown critical single ext");
         end;
      end if;
      --  OpenSSL embeds the signer cert; the delegated one must parse and carry the EKU
      Check (X509.OCSP.Embedded_Cert_Count (V) >= 1, Name & ": embedded cert present");
      if X509.OCSP.Embedded_Cert_Count (V) >= 1 then
         declare
            Sp : constant X509.Span := X509.OCSP.Embedded_Cert (V, 1);
            CD : constant X509.Byte_Seq := Bytes (DER, Sp);
            C  : X509.Certificate;
         begin
            X509.Parse (CD, C, OK);
            Check (OK, Name & ": embedded cert parses");
            Check (OK and then X509.Has_EKU_OCSP_Signing (C) = Delegated,
                   Name & ": embedded cert OCSPSigning EKU matches delegation");
         end;
      end if;
      declare
         T  : constant X509.Byte_Seq := DER (0 .. DER'Last - 1);
         V2 : X509.OCSP.OCSP_View;
      begin
         X509.OCSP.Parse (T, V2, OK);
         Check (not OK, Name & ": truncated rejected");
      end;
   end Test_OCSP;

   procedure Test_OCSP_Failure_Status is
      --  OCSPResponse { responseStatus unauthorized(6) }
      DER : constant X509.Byte_Seq (0 .. 4) := (16#30#, 16#03#, 16#0A#, 16#01#, 16#06#);
      V   : X509.OCSP.OCSP_View;
      OK  : Boolean;
   begin
      X509.OCSP.Parse (DER, V, OK);
      Check (OK, "ocsp unauthorized: parses");
      Check (OK and then X509.OCSP.Status (V) = X509.OCSP.Unauthorized, "ocsp unauthorized: status");
      Check (OK and then not X509.OCSP.Has_Basic_Response (V), "ocsp unauthorized: no basic response");
      --  successful(0) without responseBytes is inconsistent -> rejected
      declare
         Bad : constant X509.Byte_Seq (0 .. 4) := (16#30#, 16#03#, 16#0A#, 16#01#, 16#00#);
      begin
         X509.OCSP.Parse (Bad, V, OK);
         Check (not OK, "ocsp successful-without-body: rejected");
      end;
   end Test_OCSP_Failure_Status;

begin
   if not Ada.Directories.Exists (Dir & "/crl.der") then
      Ada.Text_IO.Put_Line ("usage: smoke_revocation <fixture-dir>  (run gen.sh first)");
      CLI.Set_Exit_Status (CLI.Failure);
      return;
   end if;

   Test_Certs;
   Test_CRL;
   Test_Empty_CRL;
   Test_OCSP ("ocsp_good_ca.der",          X509.OCSP.Status_Good,    X509.OCSP.Hash_SHA1,   Serial_Good,    False, False, False);
   Test_OCSP ("ocsp_good_ca_keyid.der",    X509.OCSP.Status_Good,    X509.OCSP.Hash_SHA1,   Serial_Good,    True,  False, False);
   Test_OCSP ("ocsp_revoked_ca.der",       X509.OCSP.Status_Revoked, X509.OCSP.Hash_SHA1,   Serial_Revoked, False, False, False);
   Test_OCSP ("ocsp_good_delegated.der",   X509.OCSP.Status_Good,    X509.OCSP.Hash_SHA1,   Serial_Good,    False, True,  False);
   Test_OCSP ("ocsp_revoked_delegated.der", X509.OCSP.Status_Revoked, X509.OCSP.Hash_SHA1,  Serial_Revoked, False, True,  False);
   Test_OCSP ("ocsp_good_sha256_nonce.der", X509.OCSP.Status_Good,   X509.OCSP.Hash_SHA256, Serial_Good,    False, False, True);
   Test_OCSP_Failure_Status;

   if Failures = 0 then
      Ada.Text_IO.Put_Line ("smoke_revocation: all checks passed");
   else
      Ada.Text_IO.Put_Line ("smoke_revocation:" & Failures'Image & " check(s) failed");
      CLI.Set_Exit_Status (CLI.Failure);
   end if;
end Smoke_Revocation;
