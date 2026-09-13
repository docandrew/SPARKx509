--  Name-constraint regression tests. Driven by run.sh, which generates
--  the fixtures; argument 1 is the fixture directory.

with Ada.Command_Line;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with X509;

procedure NC_Test is
   package CLI renames Ada.Command_Line;
   package SIO renames Ada.Streams.Stream_IO;
   use type X509.N32;
   use type X509.Byte;
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

   --  Expected verdict of Satisfies_Name_Constraints (Leaf under CA).
   procedure Case_NC (Leaf, CA : String; Expect : Boolean; Why : String) is
      CA_DER   : constant X509.Byte_Seq := Load_DER (Dir & "/" & CA & ".der");
      Leaf_DER : constant X509.Byte_Seq := Load_DER (Dir & "/" & Leaf & ".der");
      CA_Cert, Leaf_Cert : X509.Certificate;
      OK1, OK2 : Boolean;
   begin
      X509.Parse (CA_DER, CA_Cert, OK1);
      X509.Parse (Leaf_DER, Leaf_Cert, OK2);
      Check (OK1 and OK2, Leaf & "/" & CA & " parses");
      if OK1 and OK2 then
         Check (X509.Satisfies_Name_Constraints
                  (Leaf_Cert, Leaf_DER, CA_Cert, CA_DER) = Expect,
                Leaf & " under " & CA & ": " & Why);
      end if;
   end Case_NC;

   --  Malformed subtree: flip the first GeneralSubtree SEQUENCE tag in
   --  the CA's permitted subtrees to a non-SEQUENCE. A walker that stops
   --  silently would then see "no constraints" (fail-open); the
   --  certificate must be rejected instead.
   procedure Case_Malformed (Leaf, CA : String) is
      CA_DER   : X509.Byte_Seq := Load_DER (Dir & "/" & CA & ".der");
      Leaf_DER : constant X509.Byte_Seq := Load_DER (Dir & "/" & Leaf & ".der");
      CA_Cert, Leaf_Cert : X509.Certificate;
      OK1, OK2 : Boolean;
      Patched  : Boolean := False;
   begin
      --  Find "30 LL 82 ..": a GeneralSubtree SEQUENCE whose base is a
      --  dNSName, and turn the SEQUENCE tag into SET (0x31).
      for I in CA_DER'First .. CA_DER'Last - 2 loop
         if not Patched and then CA_DER (I) = 16#30#
           and then CA_DER (I + 2) = 16#82#
         then
            CA_DER (I) := 16#31#;
            Patched := True;
         end if;
      end loop;
      Check (Patched, CA & ": found a dNSName GeneralSubtree to corrupt");
      X509.Parse (CA_DER, CA_Cert, OK1);
      X509.Parse (Leaf_DER, Leaf_Cert, OK2);
      if not OK1 then
         Check (True, CA & " (corrupted): parser rejects the certificate outright");
      elsif OK2 then
         Check (not X509.Satisfies_Name_Constraints
                      (Leaf_Cert, Leaf_DER, CA_Cert, CA_DER),
                Leaf & " under corrupted " & CA & ": undecodable subtrees reject");
      end if;
   end Case_Malformed;
begin
   Ada.Text_IO.Put_Line ("--- X509.Satisfies_Name_Constraints ---");
   --  ca_plain: permitted example.com, excluded bad.example.com
   Case_NC ("san_ok",       "ca_plain", True,  "SAN subdomain of permitted");
   Case_NC ("san_apex",     "ca_plain", True,  "SAN equal to permitted apex");
   Case_NC ("san_bad",      "ca_plain", False, "SAN outside permitted");
   Case_NC ("san_excl",     "ca_plain", False, "SAN equal to excluded");
   Case_NC ("san_excl_sub", "ca_plain", False, "SAN below excluded");
   Case_NC ("cn_ok",        "ca_plain", True,  "CN-only inside permitted");
   Case_NC ("cn_bad",       "ca_plain", False, "CN-only outside permitted (SR-09)");
   Case_NC ("cn_excl",      "ca_plain", False, "CN-only equal to excluded");
   --  ca_dot: permitted .example.com -- a malformed dNSName constraint
   --  (RFC 5280 4.2.1.10); nothing validates under it, whatever the name.
   Case_NC ("dot_sub",      "ca_dot",   False, "leading-dot constraint is malformed: subdomain rejected");
   Case_NC ("dot_apex",     "ca_dot",   False, "leading-dot constraint is malformed: apex rejected");
   Case_NC ("dot_wild",     "ca_dot",   False, "leading-dot constraint is malformed: wildcard rejected");
   Case_NC ("dot_other",    "ca_dot",   False, "leading-dot constraint is malformed: other domain rejected");
   Case_NC ("dot_cn_sub",   "ca_dot",   False, "leading-dot constraint is malformed: CN-only rejected");
   Case_NC ("dot_cn_apex",  "ca_dot",   False, "leading-dot constraint is malformed: CN-only apex rejected");
   --  fail-closed on undecodable subtrees
   Case_Malformed ("san_excl", "ca_plain");
   Case_Malformed ("san_bad",  "ca_plain");
   Ada.Text_IO.New_Line;
   Ada.Text_IO.Put_Line ("=== Results:" & Natural'Image (Total - Failures) & " /" & Total'Image
                         & " passed," & Failures'Image & " failed ===");
   if Failures > 0 then
      CLI.Set_Exit_Status (1);
   end if;
end NC_Test;
