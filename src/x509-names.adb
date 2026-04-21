with X509.DER; use X509.DER;

package body X509.Names with
   SPARK_Mode => On
is

   function Matches_Hostname
     (Cert     : Certificate;
      DER      : Byte_Seq;
      Hostname : String) return Boolean
   is
      --  Check if DER span matches Hostname exactly (case-insensitive)
      function Exact_Match (S : Span) return Boolean
      with Pre => DER'First = 0 and DER'Last < N32'Last
      is
         Len : N32;
      begin
         if not S.Present or else S.Last < S.First then
            return False;
         end if;
         Len := S.Last - S.First + 1;
         if Hostname'Length = 0 or else Len /= N32 (Hostname'Length) then
            return False;
         end if;
         if not Can_Read (DER, S.First, Len) then
            return False;
         end if;
         --  Now: S.First + Len - 1 <= DER'Last
         --  and  Len = N32(Hostname'Length), so Natural(Len) - 1 < Hostname'Length
         if Len > N32 (Natural'Last) then return False; end if;
         --  Len > 0 and Len = Hostname'Length, so Hostname is non-empty
         pragma Assert (Hostname'Length > 0);
         pragma Assert (Hostname'First <= Hostname'Last);
         declare
            H_Idx : Natural := Hostname'First;
         begin
            for I in N32 range 0 .. Len - 1 loop
               pragma Loop_Invariant (S.First + Len - 1 <= DER'Last);
               pragma Loop_Invariant
                 (H_Idx in Hostname'First .. Hostname'Last);
               pragma Loop_Invariant (I <= Len - 1);
               if To_Lower (DER (S.First + I)) /=
                  Char_To_Lower (Hostname (H_Idx))
               then
                  return False;
               end if;
               if H_Idx < Hostname'Last then
                  H_Idx := H_Idx + 1;
               end if;
            end loop;
         end;
         return True;
      end Exact_Match;

      --  Check if DER span matches Hostname with wildcard support.
      --  A leading "*." in the DER span matches exactly one label in
      --  Hostname (e.g. *.example.com matches foo.example.com but
      --  not foo.bar.example.com).
      function Span_Matches (S : Span) return Boolean
      with Pre => DER'First = 0 and DER'Last < N32'Last
      is
         Len : N32;
      begin
         if not S.Present or else S.Last < S.First then
            return False;
         end if;
         Len := S.Last - S.First + 1;
         if not Can_Read (DER, S.First, Len) then
            return False;
         end if;

         --  Check for wildcard pattern "*."
         if Len >= 3 and then DER (S.First) = 16#2A#    --  '*'
            and then DER (S.First + 1) = 16#2E#          --  '.'
         then
            --  Find the first '.' in Hostname
            declare
               Dot_Pos : Natural := 0;
            begin
               for J in Hostname'Range loop
                  if Hostname (J) = '.' then
                     Dot_Pos := J;
                     exit;
                  end if;
               end loop;

               --  Must have a dot, and it must not be the first or last char
               if Dot_Pos = 0
                  or else Dot_Pos = Hostname'First
                  or else Dot_Pos = Hostname'Last
               then
                  return False;
               end if;

               --  The part after the dot in Hostname must match
               --  the part after "*." in the DER span
               declare
                  Wild_Rest_First : constant N32 := S.First + 2;
                  Wild_Rest_Len   : constant N32 := Len - 2;
                  Host_Rest_First : constant Natural := Dot_Pos + 1;
                  Host_Rest_Len   : constant Natural :=
                     Hostname'Last - Host_Rest_First + 1;
               begin
                  if N32 (Host_Rest_Len) /= Wild_Rest_Len then
                     return False;
                  end if;
                  if Wild_Rest_Len = 0 then
                     return False;
                  end if;
                  if not Can_Read (DER, Wild_Rest_First, Wild_Rest_Len) then
                     return False;
                  end if;
                  pragma Assert (Host_Rest_First <= Hostname'Last);
                  declare
                     H_Idx : Natural := Host_Rest_First;
                  begin
                     for I in N32 range 0 .. Wild_Rest_Len - 1 loop
                        pragma Loop_Invariant
                          (Wild_Rest_First + Wild_Rest_Len - 1 <= DER'Last);
                        pragma Loop_Invariant
                          (H_Idx in Host_Rest_First .. Hostname'Last);
                        pragma Loop_Invariant (I <= Wild_Rest_Len - 1);
                        if To_Lower (DER (Wild_Rest_First + I)) /=
                           Char_To_Lower (Hostname (H_Idx))
                        then
                           return False;
                        end if;
                        if H_Idx < Hostname'Last then
                           H_Idx := H_Idx + 1;
                        end if;
                     end loop;
                  end;
                  return True;
               end;
            end;
         else
            --  No wildcard: exact match
            return Exact_Match (S);
         end if;
      end Span_Matches;

      --  Check if Hostname looks like an IPv4 address (digits and dots only)
      function Is_IPv4_String return Boolean is
      begin
         if Hostname'Length < 7 or Hostname'Length > 15 then
            return False;
         end if;
         for I in Hostname'Range loop
            if Hostname (I) not in '0' .. '9' | '.' then
               return False;
            end if;
         end loop;
         return True;
      end Is_IPv4_String;

      --  Parse IPv4 string "a.b.c.d" to 4 bytes.
      --  Returns True on success with IP_Bytes filled.
      procedure Parse_IPv4
        (IP_Bytes : out Byte_Seq;
         OK       : out Boolean)
      with Pre => IP_Bytes'First = 0 and IP_Bytes'Length = 4
      is
         Octet : Natural := 0;
         B_Idx : N32 := 0;
      begin
         IP_Bytes := (others => 0);
         OK := False;
         for I in Hostname'Range loop
            pragma Loop_Invariant (Octet <= 255);
            pragma Loop_Invariant (B_Idx <= 3);
            if Hostname (I) = '.' then
               if Octet > 255 then return; end if;
               if B_Idx > 2 then return; end if;
               IP_Bytes (B_Idx) := Byte (Octet);
               B_Idx := B_Idx + 1;
               Octet := 0;
            elsif Hostname (I) in '0' .. '9' then
               Octet := Octet * 10 +
                  (Character'Pos (Hostname (I)) - Character'Pos ('0'));
               if Octet > 255 then return; end if;
            else
               return;
            end if;
         end loop;
         if Octet > 255 or B_Idx /= 3 then return; end if;
         IP_Bytes (3) := Byte (Octet);
         OK := True;
      end Parse_IPv4;

      --  Check if Hostname looks like an IPv6 address (hex digits and colons)
      function Is_IPv6_String return Boolean
      with Post => (if Is_IPv6_String'Result then
                       Hostname'Length >= 2 and Hostname'Length <= 39)
      is
      begin
         if Hostname'Length < 2 or Hostname'Length > 39 then
            return False;
         end if;
         --  Must contain at least one colon
         declare
            Has_Colon : Boolean := False;
         begin
            for I in Hostname'Range loop
               if Hostname (I) = ':' then
                  Has_Colon := True;
               elsif Hostname (I) not in '0' .. '9' | 'a' .. 'f'
                                        | 'A' .. 'F'
               then
                  return False;
               end if;
            end loop;
            return Has_Colon;
         end;
      end Is_IPv6_String;

      --  Parse IPv6 string to 16 bytes.
      --  Supports full form (1:2:3:4:5:6:7:8) and :: compression.
      --  Hostname must be 2..39 chars (checked by Is_IPv6_String).
      procedure Parse_IPv6
        (IP_Bytes : out Byte_Seq;
         OK       : out Boolean)
      with Pre => IP_Bytes'First = 0 and IP_Bytes'Length = 16
                  and Hostname'Length >= 2 and Hostname'Length <= 39
      is
         subtype Group_Idx is Natural range 0 .. 7;
         subtype Hex_Group is Natural range 0 .. 65535;

         function Hex_Val (Ch : Character) return Natural is
           (if Ch in '0' .. '9' then Character'Pos (Ch) - Character'Pos ('0')
            elsif Ch in 'a' .. 'f' then Character'Pos (Ch) - Character'Pos ('a') + 10
            elsif Ch in 'A' .. 'F' then Character'Pos (Ch) - Character'Pos ('A') + 10
            else 0)
         with Post => Hex_Val'Result <= 15;

         Groups  : array (Group_Idx) of Hex_Group := (others => 0);
         G_Count : Natural range 0 .. 8 := 0;
         DC_Idx  : Integer range -1 .. 8 := -1;
         Val     : Natural range 0 .. 65535 := 0;
         Chars   : Natural range 0 .. 4 := 0;
         I       : Positive := Hostname'First;
         Prev_Colon : Boolean := False;
      begin
         IP_Bytes := (others => 0);
         OK := False;

         while I <= Hostname'Last loop
            pragma Loop_Invariant (I >= Hostname'First);
            pragma Loop_Invariant (G_Count <= 8);
            pragma Loop_Invariant (Val <= 65535);
            pragma Loop_Invariant (Chars <= 4);
            pragma Loop_Invariant (DC_Idx in -1 .. 8);
            pragma Loop_Variant (Increases => I);

            if Hostname (I) = ':' then
               if Prev_Colon then
                  --  This is the second ':' of '::'
                  if DC_Idx >= 0 then return; end if;  --  duplicate ::
                  DC_Idx := G_Count;
                  Prev_Colon := False;
               else
                  --  First colon — store pending group if any
                  if Chars > 0 then
                     if G_Count > 7 then return; end if;
                     Groups (G_Count) := Val;
                     G_Count := G_Count + 1;
                     Val := 0; Chars := 0;
                  elsif I = Hostname'First then
                     --  Leading ':' — could be start of '::'
                     null;
                  else
                     --  Empty group (e.g. "1::2:") — invalid
                     return;
                  end if;
                  Prev_Colon := True;
               end if;
            elsif Hostname (I) in '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' then
               Prev_Colon := False;
               if Chars >= 4 then return; end if;
               declare
                  H   : constant Natural := Hex_Val (Hostname (I));
                  New_Val : constant Natural := Val * 16 + H;
               begin
                  if New_Val > 65535 then return; end if;
                  Val := New_Val;
               end;
               Chars := Chars + 1;
            else
               return;
            end if;
            if I = Hostname'Last then exit; end if;
            I := I + 1;
         end loop;

         --  Final group
         if Chars > 0 then
            if G_Count > 7 then return; end if;
            Groups (G_Count) := Val;
            G_Count := G_Count + 1;
         end if;

         if DC_Idx < 0 then
            if G_Count /= 8 then return; end if;
         else
            if G_Count > 8 then return; end if;
         end if;

         --  Expand groups into 16 bytes
         if DC_Idx < 0 then
            --  No compression: exactly 8 groups
            for J in Group_Idx loop
               pragma Loop_Invariant (J <= 7);
               IP_Bytes (N32 (J) * 2)     := Byte (Groups (J) / 256);
               IP_Bytes (N32 (J) * 2 + 1) := Byte (Groups (J) mod 256);
            end loop;
         else
            --  Left groups go at start (indices 0 .. DC_Idx-1)
            if DC_Idx > 0 then
               for J in 0 .. DC_Idx - 1 loop
                  pragma Loop_Invariant (J <= 7);
                  IP_Bytes (N32 (J) * 2)     := Byte (Groups (J) / 256);
                  IP_Bytes (N32 (J) * 2 + 1) := Byte (Groups (J) mod 256);
               end loop;
            end if;
            --  Right groups go at end
            if G_Count < DC_Idx then return; end if;
            declare
               RC   : constant Natural := G_Count - DC_Idx;
               Base : constant Natural := 8 - RC;
            begin
               if RC > 0 and then Base + RC <= 8
                  and then DC_Idx + RC <= 8
               then
                  for J in 0 .. RC - 1 loop
                     pragma Loop_Invariant (J < RC);
                     pragma Loop_Invariant (Base + J <= 7);
                     pragma Loop_Invariant (DC_Idx + J <= 7);
                     IP_Bytes (N32 (Base + J) * 2)     :=
                        Byte (Groups (DC_Idx + J) / 256);
                     IP_Bytes (N32 (Base + J) * 2 + 1) :=
                        Byte (Groups (DC_Idx + J) mod 256);
                  end loop;
               end if;
            end;
         end if;
         OK := True;
      end Parse_IPv6;

      --  Match an IP SAN span (4 bytes for IPv4) against parsed IP
      function IP_SAN_Matches (S : Span; Expected : Byte_Seq) return Boolean
      with Pre => DER'First = 0 and DER'Last < N32'Last
                  and Expected'First = 0 and Expected'Length = 4
      is
         Len : constant N32 := Span_Length (S);
      begin
         if not S.Present or Len /= 4 then
            return False;
         end if;
         if not Can_Read (DER, S.First, 4) then
            return False;
         end if;
         for I in N32 range 0 .. 3 loop
            pragma Loop_Invariant (S.First + I <= DER'Last);
            if DER (S.First + I) /= Expected (I) then
               return False;
            end if;
         end loop;
         return True;
      end IP_SAN_Matches;

      function IP6_SAN_Matches (S : Span; Expected : Byte_Seq) return Boolean
      with Pre => DER'First = 0 and DER'Last < N32'Last
                  and Expected'First = 0 and Expected'Length = 16
      is
         Len : constant N32 := Span_Length (S);
      begin
         if not S.Present or Len /= 16 then
            return False;
         end if;
         if not Can_Read (DER, S.First, 16) then
            return False;
         end if;
         for I in N32 range 0 .. 15 loop
            pragma Loop_Invariant (S.First + I <= DER'Last);
            if DER (S.First + I) /= Expected (I) then
               return False;
            end if;
         end loop;
         return True;
      end IP6_SAN_Matches;

   begin  --  Matches_Hostname
      if not Cert.Valid_Flag then
         return False;
      end if;

      --  If hostname is an IPv4 address, match against IP SANs only
      if Is_IPv4_String then
         declare
            IP4 : Byte_Seq (0 .. 3);
            Parse_OK : Boolean;
         begin
            Parse_IPv4 (IP4, Parse_OK);
            if not Parse_OK then
               return False;
            end if;
            for I in 1 .. Cert.IP_SAN_Num loop
               if I <= Max_SANs
                  and then IP_SAN_Matches (Cert.IP_SANs (I), IP4)
               then
                  return True;
               end if;
            end loop;
            return False;
         end;
      end if;

      --  If hostname is an IPv6 address, match against IP SANs only
      if Is_IPv6_String then
         pragma Assert (Hostname'Length >= 2 and Hostname'Length <= 39);
         declare
            IP6 : Byte_Seq (0 .. 15);
            Parse_OK : Boolean;
         begin
            Parse_IPv6 (IP6, Parse_OK);
            if not Parse_OK then
               return False;
            end if;
            for I in 1 .. Cert.IP_SAN_Num loop
               if I <= Max_SANs
                  and then IP6_SAN_Matches (Cert.IP_SANs (I), IP6)
               then
                  return True;
               end if;
            end loop;
            return False;
         end;
      end if;

      --  DNS hostname: check stored SANs first (fast path)
      for I in 1 .. Cert.SAN_Num loop
         if I <= Max_SANs and then Span_Matches (Cert.SANs (I)) then
            return True;
         end if;
      end loop;

      --  If we have more SANs than Max_SANs, walk the raw DER
      --  extension to find all dNSName entries.
      if Cert.SAN_Num >= Max_SANs
         and then Cert.SAN_Ext_Value.Present
         and then Can_Read (DER, Cert.SAN_Ext_Value.First,
                            Cert.SAN_Ext_Value.Last -
                               Cert.SAN_Ext_Value.First + 1)
      then
         declare
            P   : N32 := Cert.SAN_Ext_Value.First;
            E   : constant N32 := Cert.SAN_Ext_Value.Last;
         begin
            while P < E and then P <= DER'Last loop
               pragma Loop_Variant (Increases => P);
               pragma Loop_Invariant (P <= DER'Last);
               pragma Loop_Invariant (DER'Last < N32'Last);
               pragma Loop_Invariant (P < N32'Last);
               declare
                  Tag      : constant Byte := DER (P);
                  GN_Len   : N32;
                  Len_OK   : Boolean := True;
                  Saved_P  : constant N32 := P with Ghost;
               begin
                  P := P + 1;
                  if P > DER'Last then exit; end if;
                  Parse_Length (DER, P, GN_Len, Len_OK);
                  if not Len_OK then exit; end if;
                  if not Can_Read (DER, P, GN_Len) then exit; end if;
                  pragma Assert (P > Saved_P);

                  if Tag = GN_DNS_NAME and then GN_Len > 0 then
                     if Span_Matches ((First   => P,
                                       Last    => P + GN_Len - 1,
                                       Present => True))
                     then
                        return True;
                     end if;
                  end if;

                  P := P + GN_Len;
               end;
            end loop;
         end;
      end if;

      --  Fall back to Subject CN only if NO SANs at all (DNS or IP)
      if Cert.SAN_Num = 0
         and then Cert.IP_SAN_Num = 0
         and then Cert.S_Subject_CN.Present
      then
         return Span_Matches (Cert.S_Subject_CN);
      end if;

      return False;
   end Matches_Hostname;

   function Is_Self_Issued
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   is (Issuer_Matches (Cert, DER, Cert, DER));

   function AKI_Matches_SKI
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   is
      AKI : constant Span := Cert.S_Auth_Key_ID;
      SKI : constant Span := Cert.S_Subject_Key_ID;
   begin
      --  If either is absent, nothing to compare — vacuously true
      if not AKI.Present or not SKI.Present then
         return True;
      end if;
      return Spans_Equal (DER, AKI, SKI);
   end AKI_Matches_SKI;

   function CN_In_SAN
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   is


      --  Case-insensitive comparison of CN span against a SAN span
      function CI_Match (SAN_First : N32; SAN_Len : N32;
                         CN_First : N32; CN_Len : N32) return Boolean
      with Pre => DER'First = 0 and DER'Last < N32'Last
      is
      begin
         if SAN_Len = 0 or CN_Len = 0 then return False; end if;
         if SAN_Len /= CN_Len then return False; end if;
         if not Can_Read (DER, SAN_First, SAN_Len) then return False; end if;
         if not Can_Read (DER, CN_First, CN_Len) then return False; end if;
         --  Now: SAN_First + SAN_Len - 1 <= DER'Last
         --  and  CN_First  + CN_Len  - 1 <= DER'Last
         --  and  SAN_Len = CN_Len
         for J in N32 range 0 .. CN_Len - 1 loop
            pragma Loop_Invariant (J <= CN_Len - 1);
            pragma Loop_Invariant (CN_First + CN_Len - 1 <= DER'Last);
            pragma Loop_Invariant (SAN_First + SAN_Len - 1 <= DER'Last);
            if To_Lower (DER (CN_First + J)) /=
               To_Lower (DER (SAN_First + J))
            then
               return False;
            end if;
         end loop;
         return True;
      end CI_Match;

      CN : constant Span := Cert.S_Subject_CN;
   begin
      --  No CN => trivially satisfied (CABF BR 7.1.4.3)
      if not CN.Present or else CN.Last < CN.First then
         return True;
      end if;

      declare
         CN_Len : constant N32 := Span_Length (CN);
      begin
         if CN_Len = 0 then
            return True;
         end if;
         if not Can_Read (DER, CN.First, CN_Len) then
            return True;  --  can't read CN, don't enforce
         end if;

         --  Check stored DNS SANs first (fast path)
         for I in 1 .. Cert.SAN_Num loop
            if I <= Max_SANs and then Cert.SANs (I).Present then
               if CI_Match (Cert.SANs (I).First,
                            Span_Length (Cert.SANs (I)),
                            CN.First, CN_Len)
               then
                  return True;
               end if;
            end if;
         end loop;

         --  Walk raw DER SAN extension for overflow SANs (>Max_SANs)
         if Cert.SAN_Num >= Max_SANs
            and then Cert.SAN_Ext_Value.Present
            and then Can_Read (DER, Cert.SAN_Ext_Value.First,
                               Cert.SAN_Ext_Value.Last -
                                  Cert.SAN_Ext_Value.First + 1)
         then
            declare
               P   : N32 := Cert.SAN_Ext_Value.First;
               E   : constant N32 := Cert.SAN_Ext_Value.Last;
            begin
               while P < E and then P <= DER'Last loop
                  pragma Loop_Variant (Increases => P);
                  pragma Loop_Invariant (P <= DER'Last);
                  pragma Loop_Invariant (DER'Last < N32'Last);
                  pragma Loop_Invariant (P < N32'Last);
                  declare
                     Tag     : constant Byte := DER (P);
                     GN_Len  : N32;
                     Len_OK  : Boolean := True;
                     Saved_P : constant N32 := P with Ghost;
                  begin
                     P := P + 1;
                     if P > DER'Last then exit; end if;
                     Parse_Length (DER, P, GN_Len, Len_OK);
                     if not Len_OK then exit; end if;
                     if not Can_Read (DER, P, GN_Len) then exit; end if;
                     pragma Assert (P > Saved_P);
                     if Tag = GN_DNS_NAME and then GN_Len > 0 then
                        if CI_Match (P, GN_Len, CN.First, CN_Len) then
                           return True;
                        end if;
                     end if;
                     P := P + GN_Len;
                  end;
               end loop;
            end;
         end if;

         --  No SAN matched
         return False;
      end;
   end CN_In_SAN;

   function Issuer_Matches
     (Cert       : Certificate;
      Cert_DER   : Byte_Seq;
      Issuer     : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   is
      Cert_Issuer : constant Span := Cert.S_Issuer_Raw;
      Issuer_Subj : constant Span := Issuer.S_Subject_Raw;

      --  RFC 5280 §7.1: case fold a single byte (A-Z -> a-z)


      --  RFC 5280 §7.1: Compare two string values with normalization.
      --  - Case-insensitive for PrintableString (tag 0x13) and
      --    UTF8String (tag 0x0C)
      --  - Collapse internal whitespace runs to single space
      --  - Strip leading and trailing whitespace
      --  Returns True if values are equal after normalization.
      function Normalized_String_Equal
        (D1 : Byte_Seq; S1 : N32; L1 : N32;
         D2 : Byte_Seq; S2 : N32; L2 : N32) return Boolean
      with Pre => D1'First = 0 and D1'Last < N32'Last
                  and D2'First = 0 and D2'Last < N32'Last
                  and Can_Read (D1, S1, L1)
                  and Can_Read (D2, S2, L2)
      is
         P1 : N32 := S1;
         P2 : N32 := S2;
         E1 : constant N32 := S1 + L1;
         E2 : constant N32 := S2 + L2;
         C1, C2 : Byte;

         --  Skip whitespace (0x20, 0x09)
         procedure Skip_WS (D : Byte_Seq; P : in out N32; E : N32)
         with Pre => D'First = 0 and D'Last < N32'Last
                     and E <= D'Last + 1
         is
         begin
            while P < E and then P <= D'Last
                  and then (D (P) = 16#20# or D (P) = 16#09#)
            loop
               pragma Loop_Invariant (P >= D'First and P < E);
               pragma Loop_Variant (Decreases => E - P);
               P := P + 1;
            end loop;
         end Skip_WS;

         --  Advance past a whitespace run, consuming exactly one
         --  logical space. Returns False if no WS to consume.
         procedure Consume_WS
           (D     : Byte_Seq;
            P     : in out N32;
            E     : N32;
            Found : out Boolean)
         with Pre => D'First = 0 and D'Last < N32'Last
                     and E <= D'Last + 1
         is
         begin
            Found := False;
            if P < E and then P <= D'Last
               and then (D (P) = 16#20# or D (P) = 16#09#)
            then
               Found := True;
               while P < E and then P <= D'Last
                     and then (D (P) = 16#20# or D (P) = 16#09#)
               loop
                  pragma Loop_Invariant (P >= D'First and P < E);
                  pragma Loop_Variant (Decreases => E - P);
                  P := P + 1;
               end loop;
            end if;
         end Consume_WS;

         WS1, WS2 : Boolean;
         Fuel : N32;
      begin
         --  Strip leading whitespace
         Skip_WS (D1, P1, E1);
         Skip_WS (D2, P2, E2);
         Fuel := L1 + L2;

         --  Compare character by character with normalization
         while P1 < E1 and then P2 < E2 loop
            pragma Loop_Variant (Decreases => Fuel);
            pragma Loop_Invariant
              (P1 >= D1'First and P2 >= D2'First);
            --  Strip trailing whitespace (check if remaining is all WS)
            declare
               T1 : N32 := P1;
               T2 : N32 := P2;
            begin
               Skip_WS (D1, T1, E1);
               Skip_WS (D2, T2, E2);
               --  Both at end after stripping trailing WS?
               if T1 >= E1 and T2 >= E2 then
                  return True;
               end if;
               --  One at end but not the other?
               if T1 >= E1 or T2 >= E2 then
                  return False;
               end if;
            end;

            --  Both have non-WS content remaining
            if P1 >= E1 or P2 >= E2
               or P1 > D1'Last or P2 > D2'Last
            then
               return P1 >= E1 and P2 >= E2;
            end if;

            --  Check for whitespace runs — collapse to single match
            Consume_WS (D1, P1, E1, WS1);
            Consume_WS (D2, P2, E2, WS2);
            if WS1 /= WS2 then
               return False;
            end if;
            if WS1 then
               --  Both consumed WS, continue to next non-WS char
               null;
            else
               --  Compare next character (case-insensitive)
               if P1 > D1'Last or P2 > D2'Last then
                  return False;
               end if;
               C1 := To_Lower (D1 (P1));
               C2 := To_Lower (D2 (P2));
               if C1 /= C2 then
                  return False;
               end if;
               P1 := P1 + 1;
               P2 := P2 + 1;
            end if;
            if Fuel = 0 then
               return False;
            end if;
            Fuel := Fuel - 1;
         end loop;
         --  If we get here, at least one pointer reached the end.
         --  Check if both are at/past end (after trimming trailing WS).
         declare
            T1 : N32 := P1;
            T2 : N32 := P2;
         begin
            Skip_WS (D1, T1, E1);
            Skip_WS (D2, T2, E2);
            return T1 >= E1 and T2 >= E2;
         end;
      end Normalized_String_Equal;

      --  Compare two attribute values.  For PrintableString (0x13) and
      --  UTF8String (0x0C), use normalized comparison.  For everything
      --  else, use byte-exact.
      function Attr_Value_Equal
        (D1 : Byte_Seq; Tag1 : Byte; S1 : N32; L1 : N32;
         D2 : Byte_Seq; Tag2 : Byte; S2 : N32; L2 : N32) return Boolean
      with Pre => D1'First = 0 and D1'Last < N32'Last
                  and D2'First = 0 and D2'Last < N32'Last
                  and (L1 = 0 or else Can_Read (D1, S1, L1))
                  and (L2 = 0 or else Can_Read (D2, S2, L2))
      is
      begin
         --  Both must be string types for normalized comparison
         if (Tag1 = 16#13# or Tag1 = 16#0C#)
            and (Tag2 = 16#13# or Tag2 = 16#0C#)
         then
            if L1 = 0 and L2 = 0 then return True; end if;
            if L1 = 0 or L2 = 0 then return False; end if;
            return Normalized_String_Equal (D1, S1, L1, D2, S2, L2);
         end if;

         --  Non-string: byte-exact comparison
         if L1 /= L2 then return False; end if;
         if L1 = 0 then return True; end if;
         if not Can_Read (D1, S1, L1) then return False; end if;
         if not Can_Read (D2, S2, L2) then return False; end if;
         for I in N32 range 0 .. L1 - 1 loop
            pragma Loop_Invariant (S1 + I <= D1'Last);
            pragma Loop_Invariant (S2 + I <= D2'Last);
            if D1 (S1 + I) /= D2 (S2 + I) then
               return False;
            end if;
         end loop;
         return True;
      end Attr_Value_Equal;

      --  Walk a Name SEQUENCE and extract the next RDN's first ATV.
      --  P advances past the entire SET (RDN).
      --  Set_End is set so the caller can advance past multi-valued RDNs.
      procedure Next_ATV
        (DER     : in     Byte_Seq;
         P       : in out N32;
         E       : in     N32;
         OID_S   :    out N32;
         OID_L   :    out N32;
         Val_Tag :    out Byte;
         Val_S   :    out N32;
         Val_L   :    out N32;
         Set_End :    out N32;
         OK      :    out Boolean)
      with Pre => DER'First = 0 and DER'Last < N32'Last
                  and E <= DER'Last + 1
      is
         Set_Len, Seq_Len, OL, VL : N32;
         Loc_OK : Boolean := True;
      begin
         OID_S := 0; OID_L := 0;
         Val_Tag := 0; Val_S := 0; Val_L := 0;
         Set_End := P; OK := False;
         if P >= E or P > DER'Last then return; end if;
         --  SET { SEQUENCE { OID, value } }
         if DER (P) /= TAG_SET then return; end if;
         P := P + 1;
         if P > DER'Last then return; end if;
         Parse_Length (DER, P, Set_Len, Loc_OK);
         if not Loc_OK or else not Can_Read (DER, P, Set_Len) then
            return;
         end if;
         Set_End := P + Set_Len;
         --  SEQUENCE inside SET
         if P > DER'Last or else DER (P) /= TAG_SEQUENCE then return; end if;
         P := P + 1;
         if P > DER'Last then return; end if;
         Parse_Length (DER, P, Seq_Len, Loc_OK);
         if not Loc_OK or else Seq_Len = 0 then return; end if;
         if not Can_Read (DER, P, Seq_Len) then return; end if;
         --  OID
         if P > DER'Last or else DER (P) /= TAG_OID then return; end if;
         P := P + 1;
         if P > DER'Last then return; end if;
         Parse_Length (DER, P, OL, Loc_OK);
         if not Loc_OK then return; end if;
         OID_S := P;
         OID_L := OL;
         Skip (DER, P, OL, Loc_OK);
         if not Loc_OK then return; end if;
         --  Value (any tag)
         if P > DER'Last then return; end if;
         Val_Tag := DER (P);
         P := P + 1;
         if P > DER'Last then return; end if;
         Parse_Length (DER, P, VL, Loc_OK);
         if not Loc_OK then return; end if;
         Val_S := P;
         Val_L := VL;
         --  Advance P to end of SET (skip entire RDN)
         P := Set_End;
         OK := True;
      end Next_ATV;

      CI_Len : N32;
      IS_Len : N32;
   begin  --  Issuer_Matches
      if not Cert_Issuer.Present or not Issuer_Subj.Present then
         return False;
      end if;
      CI_Len := Span_Length (Cert_Issuer);
      IS_Len := Span_Length (Issuer_Subj);

      --  Fast path: byte-exact match
      if CI_Len = IS_Len and then CI_Len > 0
         and then Can_Read (Cert_DER, Cert_Issuer.First, CI_Len)
         and then Can_Read (Issuer_DER, Issuer_Subj.First, IS_Len)
      then
         declare
            Exact : Boolean := True;
         begin
            for I in N32 range 0 .. CI_Len - 1 loop
               pragma Loop_Invariant
                 (Cert_Issuer.First + I <= Cert_DER'Last);
               pragma Loop_Invariant
                 (Issuer_Subj.First + I <= Issuer_DER'Last);
               if Cert_DER (Cert_Issuer.First + I) /=
                  Issuer_DER (Issuer_Subj.First + I)
               then
                  Exact := False;
                  exit;
               end if;
            end loop;
            if Exact then
               return True;
            end if;
         end;
      end if;

      --  Both empty = match
      if CI_Len = 0 and IS_Len = 0 then
         return True;
      end if;
      if CI_Len = 0 or IS_Len = 0 then
         return False;
      end if;
      if not Can_Read (Cert_DER, Cert_Issuer.First, CI_Len) then
         return False;
      end if;
      if not Can_Read (Issuer_DER, Issuer_Subj.First, IS_Len) then
         return False;
      end if;

      --  Semantic comparison: walk RDNs in parallel
      declare
         P1 : N32 := Cert_Issuer.First;
         P2 : N32 := Issuer_Subj.First;
         E1 : constant N32 := Cert_Issuer.First + CI_Len;
         E2 : constant N32 := Issuer_Subj.First + IS_Len;
         OID_S1, OID_S2 : N32;
         OID_L1, OID_L2 : N32;
         VT1, VT2       : Byte;
         VS1, VS2       : N32;
         VL1, VL2       : N32;
         SE1, SE2       : N32;
         OK1, OK2       : Boolean;
         Fuel           : N32 := CI_Len + IS_Len;
      begin
         while P1 < E1 and then P2 < E2 loop
            pragma Loop_Variant (Decreases => Fuel);
            pragma Loop_Invariant
              (P1 >= Cert_DER'First and P2 >= Issuer_DER'First);

            declare
               Old_P1 : constant N32 := P1;
               Old_P2 : constant N32 := P2;
            begin
               pragma Warnings (Off, """SE1"" is set by ""Next_ATV"" but not used");
               Next_ATV (Cert_DER, P1, E1,
                         OID_S1, OID_L1, VT1, VS1, VL1, SE1, OK1);
               pragma Warnings (On, """SE1"" is set by ""Next_ATV"" but not used");
               pragma Warnings (Off, """SE2"" is set by ""Next_ATV"" but not used");
               Next_ATV (Issuer_DER, P2, E2,
                         OID_S2, OID_L2, VT2, VS2, VL2, SE2, OK2);
               pragma Warnings (On, """SE2"" is set by ""Next_ATV"" but not used");

               if not OK1 or not OK2 then
                  return False;
               end if;

               --  Ensure forward progress
               if P1 <= Old_P1 or P2 <= Old_P2 then
                  return False;
               end if;
            end;
            if Fuel = 0 then
               return False;
            end if;
            Fuel := Fuel - 1;

            --  OIDs must match exactly
            if OID_L1 /= OID_L2 then
               return False;
            end if;
            if OID_L1 > 0
               and then Can_Read (Cert_DER, OID_S1, OID_L1)
               and then Can_Read (Issuer_DER, OID_S2, OID_L2)
            then
               for I in N32 range 0 .. OID_L1 - 1 loop
                  pragma Loop_Invariant (OID_S1 + I <= Cert_DER'Last);
                  pragma Loop_Invariant (OID_S2 + I <= Issuer_DER'Last);
                  if Cert_DER (OID_S1 + I) /= Issuer_DER (OID_S2 + I) then
                     return False;
                  end if;
               end loop;
            end if;

            --  Values must match (with normalization for strings)
            if (VL1 > 0 and then not Can_Read (Cert_DER, VS1, VL1))
               or (VL2 > 0 and then not Can_Read (Issuer_DER, VS2, VL2))
            then
               return False;
            end if;
            if not Attr_Value_Equal
              (Cert_DER, VT1, VS1, VL1,
               Issuer_DER, VT2, VS2, VL2)
            then
               return False;
            end if;
         end loop;
         --  Both exhausted = match; one exhausted = mismatch
         return P1 >= E1 and P2 >= E2;
      end;
   end Issuer_Matches;

   function Satisfies_Name_Constraints
     (Cert       : Certificate;
      Cert_DER   : Byte_Seq;
      Issuer     : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   is
      --  Case-insensitive lower-case conversion for a Byte


      --  Check if a cert DNS name (in Cert_DER) ends with a constraint
      --  DNS name (in Issuer_DER).  Per RFC 5280, "example.com" matches
      --  "example.com" exactly, and "foo.example.com" matches because
      --  it ends with ".example.com".
      --  Also handles wildcard SANs: "*.example.com" matches constraint
      --  "example.com" and any constraint that is a subdomain of
      --  "example.com" (e.g. "bar.example.com"), because the wildcard
      --  could expand to match such names.
      function DNS_Matches_Constraint
        (DNS_Span   : Span;
         Cons_First : N32;
         Cons_Len   : N32) return Boolean
      with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
                  and Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last,
           Subprogram_Variant => (Decreases => Span_Length (DNS_Span))
      is
         DNS_Len : constant N32 := Span_Length (DNS_Span);
      begin
         if DNS_Len = 0 or Cons_Len = 0 then
            return False;
         end if;
         if not Can_Read (Cert_DER, DNS_Span.First, DNS_Len) then
            return False;
         end if;
         if not Can_Read (Issuer_DER, Cons_First, Cons_Len) then
            return False;
         end if;

         --  Handle wildcard SANs: "*.example.com"
         --  The wildcard base domain is "example.com" (after "*.")
         --  It matches:
         --    - constraint "example.com" (exact base)
         --    - constraint "foo.example.com" (subdomain of base)
         --    - constraint "example.com" as a suffix (base is under
         --      the constraint)
         if DNS_Len >= 3
            and then Cert_DER (DNS_Span.First) = 16#2A#      --  '*'
            and then Cert_DER (DNS_Span.First + 1) = 16#2E#  --  '.'
         then
            declare
               --  Base = everything after "*."
               Base_First : constant N32 := DNS_Span.First + 2;
               Base_Len   : constant N32 := DNS_Len - 2;
               Base_Span  : constant Span :=
                  (First => Base_First, Last => Base_First + Base_Len - 1,
                   Present => True);
            begin
               --  Recursively check: does "example.com" match the constraint?
               --  This handles both "example.com" == constraint and
               --  "example.com" as subdomain of constraint.
               if DNS_Matches_Constraint (Base_Span, Cons_First, Cons_Len) then
                  return True;
               end if;
               --  Also check reverse: is the constraint a subdomain of the
               --  base?  E.g. constraint "bar.example.com" ends with
               --  ".example.com" — meaning the wildcard could expand to it.
               if Cons_Len > Base_Len and then Base_Len > 0 then
                  declare
                     Suffix_Start : constant N32 :=
                        Cons_First + Cons_Len - Base_Len;
                     Dot_Pos      : constant N32 := Suffix_Start - 1;
                  begin
                     if Dot_Pos >= Issuer_DER'First
                        and then Dot_Pos <= Issuer_DER'Last
                        and then Issuer_DER (Dot_Pos) = 16#2E#
                     then
                        declare
                           Match : Boolean := True;
                        begin
                           for I in N32 range 0 .. Base_Len - 1 loop
                              pragma Loop_Invariant
                                (Suffix_Start + I <= Issuer_DER'Last);
                              pragma Loop_Invariant
                                (Base_First + I <= Cert_DER'Last);
                              if To_Lower (Issuer_DER (Suffix_Start + I)) /=
                                 To_Lower (Cert_DER (Base_First + I))
                              then
                                 Match := False;
                                 exit;
                              end if;
                           end loop;
                           if Match then
                              return True;
                           end if;
                        end;
                     end if;
                  end;
               end if;
            end;
            return False;
         end if;

         --  Exact length match: compare directly
         if DNS_Len = Cons_Len then
            for I in N32 range 0 .. DNS_Len - 1 loop
               pragma Loop_Invariant (DNS_Span.First + I <= Cert_DER'Last);
               pragma Loop_Invariant (Cons_First + I <= Issuer_DER'Last);
               if To_Lower (Cert_DER (DNS_Span.First + I)) /=
                  To_Lower (Issuer_DER (Cons_First + I))
               then
                  return False;
               end if;
            end loop;
            return True;
         end if;

         --  DNS name must be longer than constraint and end with
         --  "." + constraint.  E.g. DNS="foo.example.com", constraint=
         --  "example.com" => check DNS ends with ".example.com".
         if DNS_Len <= Cons_Len then
            return False;
         end if;
         --  The byte just before the suffix must be '.'
         declare
            Suffix_Start : constant N32 := DNS_Span.First + DNS_Len - Cons_Len;
            Dot_Pos      : constant N32 := Suffix_Start - 1;
         begin
            if Dot_Pos < Cert_DER'First or Dot_Pos > Cert_DER'Last then
               return False;
            end if;
            if Cert_DER (Dot_Pos) /= 16#2E# then  --  '.'
               return False;
            end if;
            --  Compare suffix
            for I in N32 range 0 .. Cons_Len - 1 loop
               pragma Loop_Invariant (Suffix_Start + I <= Cert_DER'Last);
               pragma Loop_Invariant (Cons_First + I <= Issuer_DER'Last);
               if To_Lower (Cert_DER (Suffix_Start + I)) /=
                  To_Lower (Issuer_DER (Cons_First + I))
               then
                  return False;
               end if;
            end loop;
            return True;
         end;
      end DNS_Matches_Constraint;

      --  Walk a subtrees span in Issuer_DER and check if any dNSName
      --  entry matches the given cert DNS SAN entry.
      --  Returns True if at least one dNSName constraint in the subtrees
      --  matches the cert DNS name.
      function Any_DNS_Constraint_Matches
        (Subtrees : Span;
         DNS_Span : Span) return Boolean
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
                  and Cert_DER'First = 0 and Cert_DER'Last < N32'Last
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
         --  Walk GeneralSubtree SEQUENCE entries
         while OK and then P < S_End and then P <= Issuer_DER'Last loop
            pragma Loop_Invariant
              (Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last);
            pragma Loop_Invariant (P >= Issuer_DER'First and P < S_End);
            pragma Loop_Variant (Decreases => S_End - P);
            --  Each GeneralSubtree is a SEQUENCE
            if Issuer_DER (P) /= TAG_SEQUENCE then
               exit;
            end if;
            declare
               GS_Len  : N32;
               GS_End  : N32;
               GS_OK   : Boolean := True;
               GS_P    : N32;
            begin
               GS_P := P + 1;
               if GS_P > Issuer_DER'Last then exit; end if;
               Parse_Length (Issuer_DER, GS_P, GS_Len, GS_OK);
               if not GS_OK or else not Can_Read (Issuer_DER, GS_P, GS_Len)
               then
                  exit;
               end if;
               GS_End := GS_P + GS_Len;
               --  Ensure forward progress
               if GS_End <= P then exit; end if;
               --  First element is GeneralName base.
               --  dNSName (GN_DNS_NAME, context tag 2, primitive).
               if GS_P <= Issuer_DER'Last
                  and then Issuer_DER (GS_P) = GN_DNS_NAME
               then
                  declare
                     DN_Len : N32;
                     DN_OK  : Boolean := True;
                     DN_P   : N32 := GS_P + 1;
                  begin
                     if DN_P <= Issuer_DER'Last then
                        Parse_Length (Issuer_DER, DN_P, DN_Len, DN_OK);
                        if DN_OK and then DN_Len > 0
                           and then Can_Read (Issuer_DER, DN_P, DN_Len)
                        then
                           if DNS_Matches_Constraint
                                (DNS_Span, DN_P, DN_Len)
                           then
                              return True;
                           end if;
                        end if;
                     end if;
                  end;
               end if;
               --  Advance past this GeneralSubtree
               P := GS_End;
            end;
         end loop;
         return False;
      end Any_DNS_Constraint_Matches;

      --  Check if a subtrees span contains any dNSName entries at all
      function Has_DNS_Constraints (Subtrees : Span) return Boolean
      is (Walk_Subtrees_Has_Tag (Issuer_DER, Subtrees, GN_DNS_NAME))
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last;

      --  Check if an IP SAN (4 or 16 bytes) matches an IP name constraint
      --  (8 or 32 bytes: IP address || network mask).
      --  Match: (SAN_IP[i] AND mask[i]) == (constraint_IP[i] AND mask[i])
      function IP_Matches_Constraint
        (IP_Span    : Span;
         Cons_First : N32;
         Cons_Len   : N32) return Boolean
      with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
                  and Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
      is
         IP_Len : constant N32 := Span_Length (IP_Span);
      begin
         --  IPv4 SAN (4) matches IPv4 constraint (8)
         --  IPv6 SAN (16) matches IPv6 constraint (32)
         if not ((IP_Len = 4 and Cons_Len = 8)
                 or (IP_Len = 16 and Cons_Len = 32))
         then
            return False;
         end if;
         if not Can_Read (Cert_DER, IP_Span.First, IP_Len) then
            return False;
         end if;
         if not Can_Read (Issuer_DER, Cons_First, Cons_Len) then
            return False;
         end if;
         --  Compare: (SAN[i] & mask[i]) == (constraint[i] & mask[i])
         for I in N32 range 0 .. IP_Len - 1 loop
            pragma Loop_Invariant (IP_Span.First + I <= Cert_DER'Last);
            pragma Loop_Invariant (Cons_First + I <= Issuer_DER'Last);
            pragma Loop_Invariant (Cons_First + IP_Len + I <= Issuer_DER'Last);
            declare
               Mask : constant Byte :=
                  Issuer_DER (Cons_First + IP_Len + I);
            begin
               if (Cert_DER (IP_Span.First + I) and Mask) /=
                  (Issuer_DER (Cons_First + I) and Mask)
               then
                  return False;
               end if;
            end;
         end loop;
         return True;
      end IP_Matches_Constraint;

      --  Walk subtrees and check if any iPAddress constraint matches
      --  the given cert IP SAN.
      function Any_IP_Constraint_Matches
        (Subtrees : Span;
         IP_Span  : Span) return Boolean
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
                  and Cert_DER'First = 0 and Cert_DER'Last < N32'Last
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
         while OK and then P < S_End and then P <= Issuer_DER'Last loop
            pragma Loop_Invariant
              (Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last);
            pragma Loop_Invariant
              (Cert_DER'First = 0 and Cert_DER'Last < N32'Last);
            pragma Loop_Invariant (P >= Issuer_DER'First and P < S_End);
            pragma Loop_Variant (Decreases => S_End - P);
            if Issuer_DER (P) /= TAG_SEQUENCE then
               exit;
            end if;
            declare
               GS_Len : N32;
               GS_OK  : Boolean := True;
               GS_P   : N32;
               Old_P  : constant N32 := P with Ghost;
            begin
               GS_P := P + 1;
               if GS_P > Issuer_DER'Last then exit; end if;
               Parse_Length (Issuer_DER, GS_P, GS_Len, GS_OK);
               if not GS_OK or else not Can_Read (Issuer_DER, GS_P, GS_Len)
               then
                  exit;
               end if;
               if GS_P + GS_Len <= P then exit; end if;
               pragma Assert (GS_P + GS_Len > Old_P);
               --  iPAddress (GN_IP_ADDRESS, context tag 7, primitive)
               if GS_P <= Issuer_DER'Last
                  and then Issuer_DER (GS_P) = GN_IP_ADDRESS
               then
                  declare
                     IP_Len_Val : N32;
                     IP_OK  : Boolean := True;
                     IP_P   : N32 := GS_P + 1;
                  begin
                     if IP_P <= Issuer_DER'Last then
                        Parse_Length (Issuer_DER, IP_P, IP_Len_Val, IP_OK);
                        if IP_OK and then IP_Len_Val > 0
                           and then Can_Read (Issuer_DER, IP_P, IP_Len_Val)
                        then
                           if IP_Matches_Constraint
                                (IP_Span, IP_P, IP_Len_Val)
                           then
                              return True;
                           end if;
                        end if;
                     end if;
                  end;
               end if;
               P := GS_P + GS_Len;
            end;
         end loop;
         return False;
      end Any_IP_Constraint_Matches;

      --  Check if subtrees contain any iPAddress constraints
      function Has_IP_Constraints (Subtrees : Span) return Boolean
      is (Walk_Subtrees_Has_Tag (Issuer_DER, Subtrees, GN_IP_ADDRESS))
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last;

      function Has_Tag_In_Subtrees
        (Subtrees : Span; Tag : Byte) return Boolean
      is (Walk_Subtrees_Has_Tag (Issuer_DER, Subtrees, Tag))
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last;

      --  Check if a directoryName SAN in Cert_DER matches a
      --  directoryName constraint in the NC subtrees (Issuer_DER).
      --  Matching: the constraint DN content must byte-equal the
      --  SAN DN content (or be a prefix for subtree matching).
      function DirName_Matches_Constraint
        (DN_First  : N32;   --  SAN dirName content start in Cert_DER
         DN_Len    : N32;   --  SAN dirName content length
         Cons_First : N32;  --  constraint dirName content start in Issuer_DER
         Cons_Len   : N32)  --  constraint dirName content length
        return Boolean
      with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
                  and Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
      is
      begin
         --  RFC 5280: constraint DN must be equal to or a prefix of SAN DN.
         --  For now: byte-equal comparison (covers most real-world cases).
         if DN_Len /= Cons_Len or DN_Len = 0 then
            return False;
         end if;
         if not Can_Read (Cert_DER, DN_First, DN_Len) then
            return False;
         end if;
         if not Can_Read (Issuer_DER, Cons_First, Cons_Len) then
            return False;
         end if;
         for I in N32 range 0 .. DN_Len - 1 loop
            pragma Loop_Invariant (DN_First + I <= Cert_DER'Last);
            pragma Loop_Invariant (Cons_First + I <= Issuer_DER'Last);
            if Cert_DER (DN_First + I) /= Issuer_DER (Cons_First + I) then
               return False;
            end if;
         end loop;
         return True;
      end DirName_Matches_Constraint;

      --  Walk NC subtrees for GN_DIR_NAME entries and check if any
      --  matches the given cert SAN directoryName.
      function Any_DirName_Constraint_Matches
        (Subtrees : Span;
         DN_First : N32;
         DN_Len   : N32) return Boolean
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
                  and Cert_DER'First = 0 and Cert_DER'Last < N32'Last
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
         while OK and then P < S_End and then P <= Issuer_DER'Last loop
            pragma Loop_Invariant
              (Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last);
            pragma Loop_Invariant
              (Cert_DER'First = 0 and Cert_DER'Last < N32'Last);
            pragma Loop_Invariant (P >= Issuer_DER'First and P < S_End);
            pragma Loop_Variant (Decreases => S_End - P);
            if Issuer_DER (P) /= TAG_SEQUENCE then
               exit;
            end if;
            declare
               GS_Len : N32;
               GS_OK  : Boolean := True;
               GS_P   : N32;
               Old_P  : constant N32 := P with Ghost;
            begin
               GS_P := P + 1;
               if GS_P > Issuer_DER'Last then exit; end if;
               Parse_Length (Issuer_DER, GS_P, GS_Len, GS_OK);
               if not GS_OK or else not Can_Read (Issuer_DER, GS_P, GS_Len)
               then
                  exit;
               end if;
               if GS_P + GS_Len <= P then exit; end if;
               pragma Assert (GS_P + GS_Len > Old_P);
               --  directoryName (GN_DIR_NAME)
               if GS_P <= Issuer_DER'Last
                  and then Issuer_DER (GS_P) = GN_DIR_NAME
               then
                  declare
                     DN_LenC : N32;
                     DN_OKC  : Boolean := True;
                     DN_PC   : N32 := GS_P + 1;
                  begin
                     if DN_PC <= Issuer_DER'Last then
                        Parse_Length (Issuer_DER, DN_PC, DN_LenC, DN_OKC);
                        if DN_OKC and then DN_LenC > 0
                           and then Can_Read (Issuer_DER, DN_PC, DN_LenC)
                        then
                           if DirName_Matches_Constraint
                                (DN_First, DN_Len, DN_PC, DN_LenC)
                           then
                              return True;
                           end if;
                        end if;
                     end if;
                  end;
               end if;
               P := GS_P + GS_Len;
            end;
         end loop;
         return False;
      end Any_DirName_Constraint_Matches;

      function Has_DirName_Constraints (Subtrees : Span) return Boolean
      is (Walk_Subtrees_Has_Tag (Issuer_DER, Subtrees, GN_DIR_NAME))
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last;

      --  Check if subtrees contain unsupported constraint types
      --  (email, URI — we now handle dirName separately)
      function Has_Unsupported_Constraints (Subtrees : Span) return Boolean
      with Pre => Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last
      is
      begin
         return Walk_Subtrees_Has_Tag (Issuer_DER, Subtrees, GN_RFC822_NAME)
           or else Walk_Subtrees_Has_Tag (Issuer_DER, Subtrees, GN_URI);
      end Has_Unsupported_Constraints;

      --  DoS budget: reject if NC × names exceeds this threshold.
      --  2048 constraints × 2048 SANs = 4M iterations — far too many.
      --  A reasonable real-world chain has < 100 of each.
      Max_NC_Work : constant := 100_000;

      function NC_Work_Estimate return N32 is
         NC_Size   : N32 := 0;
         Name_Size : N32 := 0;
      begin
         if Issuer.S_Permitted_Subtrees.Present then
            NC_Size := NC_Size + Span_Length (Issuer.S_Permitted_Subtrees);
         end if;
         if Issuer.S_Excluded_Subtrees.Present then
            NC_Size := NC_Size + Span_Length (Issuer.S_Excluded_Subtrees);
         end if;
         Name_Size := N32 (Cert.SAN_Num) + N32 (Cert.IP_SAN_Num);
         if Cert.SAN_Ext_Value.Present then
            Name_Size := Name_Size + Span_Length (Cert.SAN_Ext_Value);
         end if;
         --  Saturating multiply
         if NC_Size > 0 and then Name_Size > Max_NC_Work / NC_Size then
            return Max_NC_Work + 1;
         end if;
         return NC_Size * Name_Size;
      end NC_Work_Estimate;

   begin  --  Satisfies_Name_Constraints
      --  If issuer has no name constraints, everything is allowed
      if not Issuer.S_Permitted_Subtrees.Present
         and not Issuer.S_Excluded_Subtrees.Present
      then
         return True;
      end if;

      --  DoS mitigation: reject pathologically large NC × name products
      if NC_Work_Estimate > Max_NC_Work then
         return False;
      end if;

      --  RFC 5280 §4.2.1.10: if the cert has otherName SANs and
      --  the NC has otherName constraints, conservatively reject
      --  (we can't match otherName values).
      if Cert.SAN_Has_Other_Name then
         if (Issuer.S_Excluded_Subtrees.Present
               and then Has_Tag_In_Subtrees
                 (Issuer.S_Excluded_Subtrees, GN_OTHER_NAME))
            or (Issuer.S_Permitted_Subtrees.Present
                  and then Has_Tag_In_Subtrees
                    (Issuer.S_Permitted_Subtrees, GN_OTHER_NAME))
         then
            return False;
         end if;
      end if;

      --  RFC 5280 §4.2.1.10: if excluded subtrees contain types
      --  we don't fully check (email, URI, dirName),
      --  conservatively reject.
      if Issuer.S_Excluded_Subtrees.Present
         and then Has_Unsupported_Constraints (Issuer.S_Excluded_Subtrees)
      then
         return False;
      end if;

      --  Likewise for permitted subtrees with unsupported types
      if Issuer.S_Permitted_Subtrees.Present
         and then Has_Unsupported_Constraints (Issuer.S_Permitted_Subtrees)
      then
         return False;
      end if;

      --  Check excluded subtrees: cert DNS names must NOT match any
      if Issuer.S_Excluded_Subtrees.Present then
         for I in 1 .. Cert.SAN_Num loop
            if I <= Max_SANs and then Cert.SANs (I).Present then
               if Any_DNS_Constraint_Matches
                    (Issuer.S_Excluded_Subtrees, Cert.SANs (I))
               then
                  return False;
               end if;
            end if;
         end loop;
         --  Check Subject CN against excluded DNS only when no SANs
         --  (modern WebPKI: when SAN exists, CN is ignored for NC)
         if Cert.SAN_Num = 0
            and then Cert.IP_SAN_Num = 0
            and then Cert.S_Subject_CN.Present
         then
            if Any_DNS_Constraint_Matches
                 (Issuer.S_Excluded_Subtrees, Cert.S_Subject_CN)
            then
               return False;
            end if;
         end if;
         --  Check IP SANs against excluded IP constraints
         for I in 1 .. Cert.IP_SAN_Num loop
            if I <= Max_SANs and then Cert.IP_SANs (I).Present then
               if Any_IP_Constraint_Matches
                    (Issuer.S_Excluded_Subtrees, Cert.IP_SANs (I))
               then
                  return False;
               end if;
            end if;
         end loop;
      end if;

      --  Check permitted subtrees: if there are DNS constraints AND
      --  the cert has DNS names, EVERY DNS name must match at least
      --  one permitted constraint.
      --  (RFC 5280 §4.2.1.10: all names of the constrained type must
      --  fall within the permitted subtrees.)
      if Issuer.S_Permitted_Subtrees.Present
         and then Has_DNS_Constraints (Issuer.S_Permitted_Subtrees)
         and then Cert.SAN_Num > 0
      then
         for I in 1 .. Cert.SAN_Num loop
            if I <= Max_SANs and then Cert.SANs (I).Present then
               if not Any_DNS_Constraint_Matches
                    (Issuer.S_Permitted_Subtrees, Cert.SANs (I))
               then
                  return False;
               end if;
            end if;
         end loop;
      end if;

      --  Check permitted subtrees: if there are IP constraints AND
      --  the cert has IP SANs, EVERY IP SAN must match at least one
      --  permitted constraint.
      if Issuer.S_Permitted_Subtrees.Present
         and then Has_IP_Constraints (Issuer.S_Permitted_Subtrees)
         and then Cert.IP_SAN_Num > 0
      then
         for I in 1 .. Cert.IP_SAN_Num loop
            if I <= Max_SANs and then Cert.IP_SANs (I).Present then
               if not Any_IP_Constraint_Matches
                    (Issuer.S_Permitted_Subtrees, Cert.IP_SANs (I))
               then
                  return False;
               end if;
            end if;
         end loop;
      end if;

      --  Check directoryName constraints by walking the SAN extension DER
      if (Issuer.S_Excluded_Subtrees.Present
            and then Has_DirName_Constraints (Issuer.S_Excluded_Subtrees))
         or (Issuer.S_Permitted_Subtrees.Present
               and then Has_DirName_Constraints (Issuer.S_Permitted_Subtrees))
      then
         --  Walk cert SAN extension for directoryName entries
         if Cert.SAN_Ext_Value.Present
            and then Can_Read (Cert_DER, Cert.SAN_Ext_Value.First,
                               Span_Length (Cert.SAN_Ext_Value))
         then
            declare
               SP    : N32 := Cert.SAN_Ext_Value.First;
               SE    : constant N32 := Cert.SAN_Ext_Value.Last;
               S_OK  : Boolean := True;
               Found_DirName : Boolean := False;
            begin
               while S_OK and then SP < SE and then SP <= Cert_DER'Last loop
                  pragma Loop_Variant (Increases => SP);
                  pragma Loop_Invariant (SP <= Cert_DER'Last);
                  pragma Loop_Invariant (Cert_DER'Last < N32'Last);
                  declare
                     ST     : constant Byte := Cert_DER (SP);
                     SL     : N32;
                     SL_OK  : Boolean := True;
                     SL_P   : N32 := SP + 1;
                  begin
                     if SL_P > Cert_DER'Last then exit; end if;
                     Parse_Length (Cert_DER, SL_P, SL, SL_OK);
                     if not SL_OK or SL = 0 then exit; end if;
                     if not Can_Read (Cert_DER, SL_P, SL) then exit; end if;
                     if SL_P + SL <= SP then exit; end if;

                     if ST = GN_DIR_NAME then
                        Found_DirName := True;
                        --  Check excluded
                        if Issuer.S_Excluded_Subtrees.Present
                           and then Any_DirName_Constraint_Matches
                             (Issuer.S_Excluded_Subtrees, SL_P, SL)
                        then
                           return False;
                        end if;
                        --  Check permitted
                        if Issuer.S_Permitted_Subtrees.Present
                           and then Has_DirName_Constraints
                             (Issuer.S_Permitted_Subtrees)
                           and then not Any_DirName_Constraint_Matches
                             (Issuer.S_Permitted_Subtrees, SL_P, SL)
                        then
                           return False;
                        end if;
                     end if;

                     SP := SL_P + SL;
                  end;
               end loop;
            end;
         end if;
      end if;

      return True;
   end Satisfies_Name_Constraints;

end X509.Names;
