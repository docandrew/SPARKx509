with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;

with Test_Cases; use Test_Cases;
with Base64; use Base64;
with PEM;

with X509; use X509;
with X509.Certificates; use X509.Certificates;

procedure PEM_Tests is

   --  A full PEM certificate (same as PEM2 from x509_tests, but with
   --  proper PEM header/footer and line breaks)
   Cert_PEM : constant String :=
      "-----BEGIN CERTIFICATE-----" & ASCII.LF &
      "MIIBBDCBtwIUNQSp7e6Vc+EkRLPJ1TvKUoahZUMwBQYDK2VwMCUxCzAJBgNVBAYT" & ASCII.LF &
      "AlVTMRYwFAYDVQQDDA10bHNjaXBoZXIubGFuMB4XDTIyMDQyMDE1MzcyMFoXDTI0" & ASCII.LF &
      "MDMyMDE1MzcyMFowJTELMAkGA1UEBhMCVVMxFjAUBgNVBAMMDXRsc2NpcGhlci5s" & ASCII.LF &
      "YW4wKjAFBgMrZXADIQCZmzb/QWdJtKXjSSN36sECqrLZo1RwsiBUvsk32FKVBTAF" & ASCII.LF &
      "BgMrZXADQQCDx3H9QLeHxYLJRGRb7c4FOjxGaHNcAqf21yAnPs8qGpYPMIKxwkJW" & ASCII.LF &
      "6AlL3uavNgMRMQ1Ec3ciD36lz5ZZ6LoG" & ASCII.LF &
      "-----END CERTIFICATE-----" & ASCII.LF;

   --  A PEM private key
   Key_PEM : constant String :=
      "-----BEGIN PRIVATE KEY-----" & ASCII.LF &
      "MC4CAQAwBQYDK2VwBCIEIOPnqpIiMEeGpsEyiNRJaVMjCWhKYTWSq59kVLLPEKqr" & ASCII.LF &
      "-----END PRIVATE KEY-----" & ASCII.LF;

   R    : PEM.Decode_Result;
   Cert : Certificate;
begin

   Put_Line ("###########################");
   Put_Line ("##### PEM Decode Tests ####");
   Put_Line ("###########################");
   New_Line;

   --  Test 1: Decode a PEM certificate
   PEM.Decode (Cert_PEM, R);

   Test_Assert (R.OK, "PEM certificate decode succeeds");

   Test_Case (R.Label (1 .. R.Label_Len), "CERTIFICATE",
              "PEM label is CERTIFICATE");

   Test_Assert (R.DER_Len > 0, "PEM certificate has non-zero DER length");

   --  Parse the decoded DER as an X.509 certificate
   Parse_Certificate (R.DER (1 .. R.DER_Len), Cert);

   Test_Assert (Cert.Valid, "Decoded PEM cert parses as valid X.509");

   --  Test 2: Decode a PEM private key
   PEM.Decode (Key_PEM, R);

   Test_Assert (R.OK, "PEM private key decode succeeds");

   Test_Case (R.Label (1 .. R.Label_Len), "PRIVATE KEY",
              "PEM label is PRIVATE KEY");

   Test_Assert (R.DER_Len = 48, "Ed25519 PKCS#8 DER is 48 bytes");

   --  Verify the Ed25519 seed is at offset 16 (PKCS#8 structure)
   Test_Assert (Character'Pos (R.DER (17)) = 16#E3#,
                "Ed25519 seed first byte matches");

   --  Test 3: Invalid PEM (no header)
   PEM.Decode ("not a pem file", R);
   Test_Assert (not R.OK, "Invalid PEM returns OK = False");

   --  Test 4: PEM with CRLF line endings
   declare
      CRLF_PEM : constant String :=
         "-----BEGIN PRIVATE KEY-----" & ASCII.CR & ASCII.LF &
         "MC4CAQAwBQYDK2VwBCIEIOPnqpIiMEeGpsEyiNRJaVMjCWhKYTWSq59kVLLPEKqr" &
         ASCII.CR & ASCII.LF &
         "-----END PRIVATE KEY-----" & ASCII.CR & ASCII.LF;
   begin
      PEM.Decode (CRLF_PEM, R);
      Test_Assert (R.OK, "PEM with CRLF line endings decodes");
      Test_Assert (R.DER_Len = 48, "CRLF PEM produces same DER length");
   end;

end PEM_Tests;
