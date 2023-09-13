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
   
   PEM3 : constant String :=
      "MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/" &
      "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT" &
      "DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow" &
      "SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT" &
      "GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC" &
      "AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF" &
      "q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8" &
      "SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0" &
      "Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA" &
      "a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj" &
      "/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T" &
      "AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG" &
      "CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv" &
      "bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k" &
      "c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw" &
      "VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC" &
      "ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz" &
      "MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu" &
      "Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF" &
      "AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo" &
      "uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/" &
      "wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu" &
      "X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG" &
      "PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6" &
      "KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==";

   Cert1 : ASN1.Certificate;
   Cert2 : ASN1.Certificate;
   Cert3 : ASN1.Certificate;

begin

   Put_Line ("#########################");
   Put_Line ("##### Certificate 1 #####");
   Put_Line ("#########################");
   New_Line;
   Parse_Certificate (Decode (Construct (PEM1)), Cert1);
   
   New_Line;
   Put_Line ("#########################");
   Put_Line ("##### Certificate 2 #####");
   Put_Line ("#########################");
   New_Line;
   Parse_Certificate (Decode (Construct (PEM2)), Cert2);

   New_Line;
   Put_Line ("#########################");
   Put_Line ("##### Certificate 2 #####");
   Put_Line ("#########################");
   New_Line;
   Parse_Certificate (Decode (Construct (PEM3)), Cert3);
end ASN1_Tests;