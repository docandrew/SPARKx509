with Ada.Command_Line;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with Interfaces;
with X509;

procedure Smoke_X509 is
   package CLI renames Ada.Command_Line;
   package SIO renames Ada.Streams.Stream_IO;
   use type Interfaces.Unsigned_32;
   use type X509.Algorithm_ID;

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

   function Load_DER (Path : String) return X509.Byte_Seq is
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
            DER (I) :=
              X509.Byte
                (Raw (Ada.Streams.Stream_Element_Offset (I + 1)));
         end loop;
         return DER;
      end;
   end Load_DER;

begin
   if CLI.Argument_Count /= 1 then
      Ada.Text_IO.Put_Line ("usage: smoke_x509 CERT.der");
      CLI.Set_Exit_Status (CLI.Failure);
      return;
   end if;

   declare
      DER  : constant X509.Byte_Seq := Load_DER (CLI.Argument (1));
      Cert : X509.Certificate;
      OK   : Boolean;
   begin
      X509.Parse (DER, Cert, OK);

      Check (OK, "parse generated DER certificate");
      if OK then
         Check (X509.Is_Valid (Cert), "certificate marked valid");
         Check (X509.Spans_Valid (Cert, DER'Last), "spans valid");
         Check (X509.Version (Cert) = 3, "version is v3");
         Check (X509.Has_Subject_CN (Cert), "subject CN present");
         Check (X509.Has_Issuer_CN (Cert), "issuer CN present");
         Check (X509.SAN_Count (Cert) >= 1, "DNS SAN present");
         Check (X509.IP_SAN_Count (Cert) >= 1, "IP SAN present");
         Check (X509.Matches_Hostname (Cert, DER, "localhost"),
                "hostname localhost matches SAN");
         Check (X509.Matches_Hostname (Cert, DER, "127.0.0.1"),
                "IPv4 address matches IP SAN");
         Check (X509.Matches_Hostname (Cert, DER, "::1"),
                "IPv6 address matches IP SAN");
         Check (not X509.Matches_Hostname (Cert, DER, "example.com"),
                "unrelated hostname rejected");
         Check (not X509.Matches_Hostname (Cert, DER, "2001:db8::1"),
                "unrelated IPv6 address rejected");
         Check (X509.CN_In_SAN (Cert, DER), "CN is represented in SAN");
         Check (X509.PK_Algorithm (Cert) = X509.Algo_RSA,
                "RSA public key algorithm");
         Check (X509.PK_Length (Cert) > 0, "public key bytes present");
         Check (X509.RSA_Exponent (Cert) = 65_537, "RSA exponent parsed");
         Check (X509.Sig_Algorithm (Cert) = X509.Algo_RSA_PKCS1_SHA256,
                "SHA-256 RSA signature algorithm");
         Check (X509.Sig_Length (Cert) > 0, "signature bytes present");
         Check (X509.Is_Date_Valid
                  (Cert, X509.Not_Before (Cert)),
                "date inside validity window accepted");
         Check (not X509.Is_Date_Valid
                  (Cert,
                   (Year => 2000, Month => 1, Day => 1,
                    Hour => 0, Minute => 0, Second => 0)),
                "date outside validity window rejected");
      end if;

      if DER'Length > 16 then
         declare
            Trunc_Last : constant X509.N32 := DER'Last - X509.N32 (16);
            Trunc      : X509.Byte_Seq (0 .. Trunc_Last);
            Trunc_Cert : X509.Certificate;
            Trunc_OK   : Boolean;
         begin
            Trunc := DER (0 .. Trunc_Last);
            X509.Parse (Trunc, Trunc_Cert, Trunc_OK);
            Check (not Trunc_OK, "truncated DER rejected");
         end;
      else
         Check (False, "test certificate long enough for truncation check");
      end if;
   end;

   if Failures = 0 then
      Ada.Text_IO.Put_Line ("SPARKx509 smoke: all checks passed");
      CLI.Set_Exit_Status (CLI.Success);
   else
      Ada.Text_IO.Put_Line
        ("SPARKx509 smoke:" & Natural'Image (Failures) & " failures");
      CLI.Set_Exit_Status (CLI.Failure);
   end if;
end Smoke_X509;
