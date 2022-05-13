with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;

with Test_Cases; use Test_Cases;
with Base64; use Base64;
with ASN1; use ASN1;

procedure ASN1_Tests is
   PEM1 : constant String := 
      "MIIBfzCCATGgAwIBAgIUfI5kSdcO2S0+LkpdL3b2VUJG10YwBQYDK2VwMDUxCzAJ" &
      "BgNVBAYTAklUMQ8wDQYDVQQHDAZNaWxhbm8xFTATBgNVBAMMDFRlc3QgZWQyNTUx" &
      "OTAeFw0yMDA5MDIxMzI1MjZaFw0zMDA5MDIxMzI1MjZaMDUxCzAJBgNVBAYTAklU" &
      "MQ8wDQYDVQQHDAZNaWxhbm8xFTATBgNVBAMMDFRlc3QgZWQyNTUxOTAqMAUGAytl" &
      "cAMhADupL/3LF2beQKKS95PeMPgKI6gxIV3QB9hjJC7/aCGFo1MwUTAdBgNVHQ4E" &
      "FgQUa6W9z536I1l4EmQXrh5y2JqASugwHwYDVR0jBBgwFoAUa6W9z536I1l4EmQX" &
      "rh5y2JqASugwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBvc3e+KJZaMzbX5TT9" &
      "kPP9QH8fAvkAV/IWDxZrBL9lhLaY0tDSv0zWbw624uidBKPgmVD5wm3ec60dNVeF" &
      "ZYYG";

   PEM2 : constant String :=
      "MIIBBDCBtwIUNQSp7e6Vc+EkRLPJ1TvKUoahZUMwBQYDK2VwMCUxCzAJBgNVBAYT" &
      "AlVTMRYwFAYDVQQDDA10bHNjaXBoZXIubGFuMB4XDTIyMDQyMDE1MzcyMFoXDTI0" &
      "MDMyMDE1MzcyMFowJTELMAkGA1UEBhMCVVMxFjAUBgNVBAMMDXRsc2NpcGhlci5s" &
      "YW4wKjAFBgMrZXADIQCZmzb/QWdJtKXjSSN36sECqrLZo1RwsiBUvsk32FKVBTAF" &
      "BgMrZXADQQCDx3H9QLeHxYLJRGRb7c4FOjxGaHNcAqf21yAnPs8qGpYPMIKxwkJW" &
      "6AlL3uavNgMRMQ1Ec3ciD36lz5ZZ6LoG";

   Cert : ASN1.Certificate;

begin
   Parse_Certificate (Decode (Construct (PEM1)), Cert);
   Parse_Certificate (Decode (Construct (PEM2)), Cert);
end ASN1_Tests;