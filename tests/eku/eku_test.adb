--  Extended key usage regression tests. Driven by run.sh, which
--  generates the fixtures; argument 1 is the fixture directory.

with Ada.Command_Line;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with X509;

procedure EKU_Test is
   package CLI renames Ada.Command_Line;
   package SIO renames Ada.Streams.Stream_IO;
   use type Ada.Streams.Stream_Element_Offset;

   Failures : Natural := 0;
   Total    : Natural := 0;

   procedure Check (Condition : Boolean; Name : String) is
   begin
      Total := Total + 1;
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
            DER (I) := X509.Byte
              (Raw (Ada.Streams.Stream_Element_Offset (I) + 1));
         end loop;
         return DER;
      end;
   end Load_DER;

   Dir : constant String := CLI.Argument (1);

   type Verdicts is record
      Has_EKU      : Boolean;
      Code_Signing : Boolean;
      Server_Auth  : Boolean;
      Any_Purpose  : Boolean;
   end record;

   type Allowed is array (X509.EKU_Purpose) of Boolean;

   --  Parse Name and compare its EKU getters and, for every purpose,
   --  Issuer_EKU_Allows_Signing against the expected values.
   procedure Case_EKU
     (Name : String; Expect : Verdicts; Allows : Allowed)
   is
      DER  : constant X509.Byte_Seq := Load_DER (Dir & "/" & Name & ".der");
      Cert : X509.Certificate;
      OK   : Boolean;
   begin
      X509.Parse (DER, Cert, OK);
      Check (OK and then X509.Is_Valid (Cert), Name & ": parses and is valid");
      if not OK then
         return;
      end if;
      Check (X509.Has_EKU (Cert) = Expect.Has_EKU, Name & ": Has_EKU");
      Check (X509.Has_EKU_Code_Signing (Cert) = Expect.Code_Signing,
             Name & ": Has_EKU_Code_Signing");
      Check (X509.Has_EKU_Server_Auth (Cert) = Expect.Server_Auth,
             Name & ": Has_EKU_Server_Auth");
      Check (X509.Has_EKU_Any_Purpose (Cert) = Expect.Any_Purpose,
             Name & ": Has_EKU_Any_Purpose");
      for P in X509.EKU_Purpose loop
         Check (X509.Issuer_EKU_Allows_Signing (Cert, P) = Allows (P),
                Name & ": Issuer_EKU_Allows_Signing " & P'Image);
      end loop;
   end Case_EKU;

   --  Purpose order: Server_Auth, Client_Auth, Any_Purpose, Code_Signing.
   Everything  : constant Allowed := (others => True);
   Code_Only   : constant Allowed := (X509.EKU_Code_Signing => True,
                                      others => False);
   Server_Only : constant Allowed := (X509.EKU_Server_Auth => True,
                                      X509.EKU_Any_Purpose => True,
                                      others => False);
   TLS_Both    : constant Allowed := (X509.EKU_Code_Signing => False,
                                      others => True);
   Nothing     : constant Allowed := (others => False);
begin
   if CLI.Argument_Count /= 1 then
      Ada.Text_IO.Put_Line ("usage: eku_test FIXTURE_DIR");
      CLI.Set_Exit_Status (CLI.Failure);
      return;
   end if;

   Case_EKU ("leaf_code", (True, True, False, False), Code_Only);
   Case_EKU ("leaf_code_crit", (True, True, False, False), Code_Only);
   Case_EKU ("leaf_server", (True, False, True, False), Server_Only);
   Case_EKU ("leaf_mixed", (True, True, True, False), Everything);
   --  id-kp-OCSPSigning and id-kp-timeStamping differ from
   --  id-kp-codeSigning only in the last arc.
   Case_EKU ("leaf_ocsp", (True, False, False, False), Nothing);
   Case_EKU ("leaf_timestamp", (True, False, False, False), Nothing);
   --  anyExtendedKeyUsage is not id-kp-codeSigning: a leaf check that
   --  needs code signing must ask Has_EKU_Code_Signing.
   Case_EKU ("leaf_any", (True, False, False, True), Everything);
   Case_EKU ("leaf_none", (False, False, False, False), Everything);
   Case_EKU ("ca_code", (True, True, False, False), Code_Only);
   Case_EKU ("ca_server", (True, False, True, False), TLS_Both);
   Case_EKU ("ca_any", (True, False, False, True), Everything);
   Case_EKU ("ca_none", (False, False, False, False), Everything);

   Ada.Text_IO.Put_Line
     ("eku:" & Natural'Image (Total - Failures) & " /" & Natural'Image (Total)
      & " passed");
   if Failures = 0 then
      CLI.Set_Exit_Status (CLI.Success);
   else
      CLI.Set_Exit_Status (CLI.Failure);
   end if;
end EKU_Test;
