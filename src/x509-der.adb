package body X509.DER with
   SPARK_Mode => On
is

   --================================================================
   --  DER length and structure parsing
   --================================================================

   procedure Parse_Length
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   is
      B : Byte;
   begin
      B := DER (Pos);
      Pos := Pos + 1;

      if B <= 16#7F# then
         --  Short form
         Len := N32 (B);
      elsif B = 16#81# then
         --  Long form, 1 byte
         if Pos > DER'Last then OK := False; Len := 0; return; end if;
         Len := N32 (DER (Pos));
         Pos := Pos + 1;
      elsif B = 16#82# then
         --  Long form, 2 bytes
         if not Can_Read (DER, Pos, 2) then OK := False; Len := 0; return; end if;
         Len := N32 (DER (Pos)) * 256 + N32 (DER (Pos + 1));
         Pos := Pos + 2;
      elsif B = 16#83# then
         --  Long form, 3 bytes
         if not Can_Read (DER, Pos, 3) then OK := False; Len := 0; return; end if;
         Len := N32 (DER (Pos)) * 65536 + N32 (DER (Pos + 1)) * 256 +
                N32 (DER (Pos + 2));
         Pos := Pos + 3;
      else
         --  4+ byte lengths, indefinite form, or 0x80 — not valid DER
         OK := False;
         Len := 0;
      end if;
   end Parse_Length;

   procedure Parse_Sequence
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   is
   begin
      if DER (Pos) /= TAG_SEQUENCE then
         OK := False; Len := 0; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; Len := 0; return; end if;
      Parse_Length (DER, Pos, Len, OK);
   end Parse_Sequence;

   procedure Enter_Sequence
     (DER : in     Byte_Seq;
      Pos : in out N32;
      OK  : in out Boolean)
   is
      pragma Warnings (Off, """Len"" is set by ""Parse_Sequence"" but not used");
      Len : N32;
   begin
      Parse_Sequence (DER, Pos, Len, OK);
   end Enter_Sequence;

   procedure Parse_Explicit_Tag
     (DER      : in     Byte_Seq;
      Pos      : in out N32;
      Expected : in     Byte;
      Len      :    out N32;
      Found    :    out Boolean;
      OK       : in out Boolean)
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

   procedure Skip
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len : in     N32;
      OK  : in out Boolean)
   is
   begin
      if Len > 0 and then not Can_Read (DER, Pos, Len) then
         OK := False;
      elsif Len > 0 then
         Pos := Pos + Len;
      end if;
   end Skip;

   procedure Skip_TLV
     (DER : in     Byte_Seq;
      Pos : in out N32;
      OK  : in out Boolean)
   is
      Len : N32;
   begin
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Len, OK);
      if OK then Skip (DER, Pos, Len, OK); end if;
   end Skip_TLV;

   --================================================================
   --  Byte copying
   --================================================================

   procedure Copy_Bytes
     (DER    : in     Byte_Seq;
      Start  : in     N32;
      Len    : in     N32;
      Buf    :    out Byte_Seq;
      Copied :    out N32)
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
   --  OID matching
   --================================================================

   function OID_Match
     (DER    : Byte_Seq;
      Start  : N32;
      Len    : N32;
      Target : Byte_Seq) return Boolean
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

   procedure Parse_Algorithm_OID
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      Algo :    out Algorithm_ID;
      OK   : in out Boolean)
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
      elsif OID_Match (DER, Start, Len, OID_RSA) then
         Algo := Algo_RSA;
      elsif OID_Match (DER, Start, Len, OID_P256) then
         Algo := Algo_EC_P256;
      elsif OID_Match (DER, Start, Len, OID_P384) then
         Algo := Algo_EC_P384;
      elsif OID_Prefix_Match (DER, Start, Len, OID_EC) then
         Algo := Algo_Unknown;
      end if;

      Skip (DER, Pos, Len, OK);
   end Parse_Algorithm_OID;

   --================================================================
   --  Span comparison
   --================================================================

   function Spans_Equal
     (DER : Byte_Seq;
      A   : Span;
      B   : Span) return Boolean
   is
      Len : N32;
   begin
      if not A.Present or not B.Present then
         return False;
      end if;
      Len := Span_Length (A);
      if Len /= Span_Length (B) then
         return False;
      end if;
      if Len = 0 then
         return True;
      end if;
      if A.Last > DER'Last or B.Last > DER'Last then
         return False;
      end if;
      for I in N32 range 0 .. Len - 1 loop
         if DER (A.First + I) /= DER (B.First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Spans_Equal;

   --================================================================
   --  Subtree walking
   --================================================================

   function Walk_Subtrees_Has_Tag
     (DER      : Byte_Seq;
      Subtrees : Span;
      Tag      : Byte) return Boolean
   is
      P     : N32;
      S_End : N32;
      OK    : Boolean := True;
   begin
      if not Subtrees.Present then
         return False;
      end if;
      P := Subtrees.First;
      S_End := Subtrees.Last + 1;
      while OK and then P < S_End and then P <= DER'Last loop
         pragma Loop_Invariant (DER'First = 0 and DER'Last < N32'Last);
         pragma Loop_Invariant (P >= DER'First and P < S_End);
         pragma Loop_Variant (Decreases => S_End - P);
         if DER (P) /= TAG_SEQUENCE then
            exit;
         end if;
         declare
            GS_Len : N32;
            GS_OK  : Boolean := True;
            GS_P   : N32;
            Old_P  : constant N32 := P with Ghost;
         begin
            GS_P := P + 1;
            if GS_P > DER'Last then exit; end if;
            Parse_Length (DER, GS_P, GS_Len, GS_OK);
            if not GS_OK or else not Can_Read (DER, GS_P, GS_Len) then
               exit;
            end if;
            if GS_P + GS_Len <= P then exit; end if;
            pragma Assert (GS_P + GS_Len > Old_P);
            if GS_P <= DER'Last and then DER (GS_P) = Tag then
               return True;
            end if;
            P := GS_P + GS_Len;
         end;
      end loop;
      return False;
   end Walk_Subtrees_Has_Tag;

end X509.DER;
