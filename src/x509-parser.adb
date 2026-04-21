with X509.DER; use X509.DER;

package body X509.Parser with
   SPARK_Mode => On
is

   procedure Parse_Name
     (DER          : in     Byte_Seq;
      Pos          : in out N32;
      Name_Len     : in     N32;
      CN           :    out Span;
      Org          :    out Span;
      Country      :    out Span;
      Bad_Encoding : in out Boolean;
      OK           : in out Boolean)
   with Pre => OK and DER'First = 0 and DER'Last < N32'Last
   is
      End_Pos  : N32;
      Set_Len  : N32;
      Seq_Len  : N32;
      OID_Len  : N32;
      OID_Start : N32;
      Val_Len  : N32;
      Str_Tag  : Byte;
   begin
      CN      := (0, 0, False);
      Org     := (0, 0, False);
      Country := (0, 0, False);

      if Name_Len = 0 or else not Can_Read (DER, Pos, Name_Len) then
         return;
      end if;

      End_Pos := Pos + Name_Len;

      while OK and then Pos < End_Pos and then Pos <= DER'Last loop
         --  Each RDN is a SET { SEQUENCE { OID, value } }
         if DER (Pos) /= TAG_SET then Skip (DER, Pos, End_Pos - Pos, OK); exit; end if;
         Pos := Pos + 1;
         if Pos > DER'Last then OK := False; return; end if;
         Parse_Length (DER, Pos, Set_Len, OK);
         if not OK then return; end if;

         --  Inside SET: SEQUENCE
         if Pos > DER'Last then
            OK := False; return;
         end if;
         if DER (Pos) /= TAG_SEQUENCE then
            Skip (DER, Pos, Set_Len, OK);
            if not OK then return; end if;
         else
            Pos := Pos + 1;
            if Pos > DER'Last then OK := False; return; end if;
            Parse_Length (DER, Pos, Seq_Len, OK);
            if not OK then return; end if;

            --  OID
            if Pos > DER'Last then
               OK := False; return;
            end if;
            if DER (Pos) /= TAG_OID then
               Skip (DER, Pos, Seq_Len, OK);
               if not OK then return; end if;
            else
               Pos := Pos + 1;
               if Pos > DER'Last then OK := False; return; end if;
               Parse_Length (DER, Pos, OID_Len, OK);
               if not OK then return; end if;
               OID_Start := Pos;
               Skip (DER, Pos, OID_Len, OK);
               if not OK then return; end if;

               --  Value (string type tag + length + value)
               if Pos > DER'Last then OK := False; return; end if;
               Str_Tag := DER (Pos);
               Pos := Pos + 1;  --  skip string type tag

               --  Check for T61String (0x14)
               if Str_Tag = 16#14# then
                  Bad_Encoding := True;
               end if;

               if Pos > DER'Last then OK := False; return; end if;
               Parse_Length (DER, Pos, Val_Len, OK);
               if not OK then return; end if;

               --  Validate PrintableString charset
               if Str_Tag = 16#13# and then Val_Len > 0
                  and then Can_Read (DER, Pos, Val_Len)
               then
                  for J in N32 range 0 .. Val_Len - 1 loop
                     pragma Loop_Invariant (Pos + J <= DER'Last);
                     if not Is_PrintableString_Char (DER (Pos + J)) then
                        Bad_Encoding := True;
                     end if;
                  end loop;
               end if;

               --  Match OID and record the span
               if Can_Read (DER, Pos, Val_Len) then
                  if OID_Match (DER, OID_Start, OID_Len, OID_CN) then
                     CN := (First => Pos, Last => Pos + Val_Len - 1, Present => True);
                  elsif OID_Match (DER, OID_Start, OID_Len, OID_ORG) then
                     Org := (First => Pos, Last => Pos + Val_Len - 1, Present => True);
                  elsif OID_Match (DER, OID_Start, OID_Len, OID_COUNTRY) then
                     Country := (First => Pos, Last => Pos + Val_Len - 1, Present => True);
                  end if;
               end if;

               Skip (DER, Pos, Val_Len, OK);
            end if;
         end if;
      end loop;
   end Parse_Name;

   --================================================================
   --  Time parsing (UTCTime / GeneralizedTime)
   --================================================================

   --  No forward declaration needed — Parse_Time_Value is fully SPARK

   function Digit (B : Byte) return Natural is (Natural (B) - 48)
   with Pre => B in 16#30# .. 16#39#;

   function Two_Digits (DER : Byte_Seq; Pos : N32) return Natural is
     (Digit (DER (Pos)) * 10 + Digit (DER (Pos + 1)))
   with Pre => DER'First = 0
               and then Pos < N32'Last
               and then Pos + 1 <= DER'Last
               and then DER (Pos) in 16#30# .. 16#39#
               and then DER (Pos + 1) in 16#30# .. 16#39#;

   --  Safe digit: 0..9 if ASCII digit, sets Bad if not
   procedure Safe_Digit
     (B : in Byte; Val : out Natural; Bad : in out Boolean)
   is
   begin
      if B in 16#30# .. 16#39# then
         Val := Natural (B) - 48;
      else
         Val := 0;
         Bad := True;
      end if;
   end Safe_Digit;

   procedure Safe_Two
     (B1, B2 : in Byte; Val : out Natural; Bad : in out Boolean)
   is
      D1, D2 : Natural;
   begin
      Safe_Digit (B1, D1, Bad);
      Safe_Digit (B2, D2, Bad);
      Val := D1 * 10 + D2;
   end Safe_Two;

   procedure Parse_Time_Value
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      Len  : in     N32;
      T    :    out Date_Time;
      OK   : in out Boolean)
   is
      Y, M, D, Hr, Mn, Sc : Natural;
      Bad : Boolean := False;

      type Month_Days is array (1 .. 12) of Natural;
      Max_Days : constant Month_Days :=
        (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
   begin
      T := (others => 0);

      if DER'First /= 0 or else (Len < 15 and then Len < 13) then
         OK := False; return;
      end if;
      if Pos > N32'Last - 15 then
         OK := False; return;
      end if;
      --  Now Pos + 15 won't overflow
      if Len >= 15 then
         if Pos + 14 > DER'Last then OK := False; return; end if;
      else
         if Pos + 12 > DER'Last then OK := False; return; end if;
      end if;
      --  Now: Pos + Len - 1 <= DER'Last, Len >= 13, Off = 0
      --  So Pos + Off + 12 <= DER'Last throughout

      if Len >= 15 then
         --  GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes)
         declare
            YH, YL : Natural;
         begin
            Safe_Two (DER (Pos + 0), DER (Pos + 1), YH, Bad);
            Safe_Two (DER (Pos + 2), DER (Pos + 3), YL, Bad);
            Y := YH * 100 + YL;
         end;
         Safe_Two (DER (Pos + 4),  DER (Pos + 5),  M, Bad);
         Safe_Two (DER (Pos + 6),  DER (Pos + 7),  D, Bad);
         Safe_Two (DER (Pos + 8),  DER (Pos + 9),  Hr, Bad);
         Safe_Two (DER (Pos + 10), DER (Pos + 11), Mn, Bad);
         Safe_Two (DER (Pos + 12), DER (Pos + 13), Sc, Bad);
      else
         --  UTCTime: YYMMDDHHMMSSZ (13 bytes)
         Safe_Two (DER (Pos + 0),  DER (Pos + 1),  Y, Bad);
         if Y >= 50 then Y := 1900 + Y; else Y := 2000 + Y; end if;
         Safe_Two (DER (Pos + 2),  DER (Pos + 3),  M, Bad);
         Safe_Two (DER (Pos + 4),  DER (Pos + 5),  D, Bad);
         Safe_Two (DER (Pos + 6),  DER (Pos + 7),  Hr, Bad);
         Safe_Two (DER (Pos + 8),  DER (Pos + 9),  Mn, Bad);
         Safe_Two (DER (Pos + 10), DER (Pos + 11), Sc, Bad);
      end if;

      Pos := Pos + Len;

      if Bad then return; end if;
      if M not in 1 .. 12 then return; end if;
      if D < 1 or else D > Max_Days (M) then return; end if;
      if Hr > 23 then return; end if;
      if Mn > 59 then return; end if;
      if Sc > 59 then return; end if;

      T := (Year => Y, Month => M, Day => D,
            Hour => Hr, Minute => Mn, Second => Sc);
   end Parse_Time_Value;

   --================================================================
   --  Sub-procedures for certificate parsing
   --================================================================

   --  1. Parse version [0] EXPLICIT + serial INTEGER
   procedure Parse_Version_Serial
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      Len   : N32;
      Found : Boolean;
      pragma Warnings (Off, Len);
   begin
      if not Valid then return; end if;

      --  Version [0] EXPLICIT (optional, default v1)
      if Pos <= DER'Last then
         Parse_Explicit_Tag (DER, Pos, TAG_VERSION, Len, Found, Valid);
         if not Valid then return; end if;
         if Found then
            --  INTEGER inside the version tag
            if Pos <= DER'Last and then DER (Pos) = TAG_INTEGER then
               Pos := Pos + 1;
               if Pos <= DER'Last then
                  Parse_Length (DER, Pos, Len, Valid);
                  if Valid and then Len = 1 and then Pos <= DER'Last then
                     C.Cert_Version := Natural (DER (Pos)) + 1;
                     Pos := Pos + 1;
                  end if;
               end if;
            end if;
         else
            C.Cert_Version := 1;
         end if;
      end if;

      --  Serial Number (INTEGER)
      if not Valid or else Pos > DER'Last or else DER (Pos) /= TAG_INTEGER then
         Valid := False; return;
      end if;
      declare
         Serial_Start : N32;
      begin
         Pos := Pos + 1;
         if Pos > DER'Last then Valid := False; return; end if;
         Parse_Length (DER, Pos, Len, Valid);
         if not Valid then return; end if;
         Serial_Start := Pos;
         if Len > 0 and then not Can_Read (DER, Pos, Len) then
            Valid := False; return;
         end if;
         C.S_Serial := (First => Serial_Start, Last => Serial_Start + Len - 1,
                         Present => Len > 0);

         --  RFC 5280 §4.1.2.2: Serial must be positive (high bit clear)
         --  and must not be all zeros.
         if Len > 0 and then Can_Read (DER, Serial_Start, Len) then
            --  RFC 5280 §4.1.2.2: serial must be at most 20 octets
            if Len > 20 then
               C.Bad_Serial := True;
            end if;
            --  Negative check: first byte >= 0x80
            if DER (Serial_Start) >= 16#80# then
               C.Bad_Serial := True;
            end if;
            --  All-zeros check
            declare
               All_Zero : Boolean := True;
            begin
               for I in N32 range 0 .. Len - 1 loop
                  pragma Loop_Invariant (Serial_Start + I <= DER'Last);
                  if DER (Serial_Start + I) /= 0 then
                     All_Zero := False;
                  end if;
               end loop;
               if All_Zero then
                  C.Bad_Serial := True;
               end if;
            end;
            --  DER non-minimal integer check (X.690 §8.3.2):
            --  Leading 0x00 only allowed if next byte >= 0x80
            --  Leading 0xFF only allowed if next byte < 0x80
            if Len > 1 and then Serial_Start + 1 <= DER'Last then
               if DER (Serial_Start) = 16#00#
                  and then DER (Serial_Start + 1) < 16#80#
               then
                  C.Bad_DER := True;
               end if;
               if DER (Serial_Start) = 16#FF#
                  and then DER (Serial_Start + 1) >= 16#80#
               then
                  C.Bad_DER := True;
               end if;
            end if;
         end if;

         Skip (DER, Pos, Len, Valid);
      end;
   end Parse_Version_Serial;

   --  2. Parse TBS signature algorithm SEQUENCE { OID, params }
   procedure Parse_TBS_Sig_Algorithm
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      Sig_Seq_Len : N32;
      Sig_Seq_End : N32;
   begin
      if not Valid then return; end if;
      if Pos > DER'Last then Valid := False; return; end if;
      Parse_Sequence (DER, Pos, Sig_Seq_Len, Valid);
      if not Valid then return; end if;
      if not Can_Read (DER, Pos, Sig_Seq_Len) then
         Valid := False; return;
      end if;
      Sig_Seq_End := Pos + Sig_Seq_Len;
      if Pos <= DER'Last then
         pragma Warnings (Off, """Pos"" is set by ""Parse_Algorithm_OID"" but not used after the call");
         Parse_Algorithm_OID (DER, Pos, C.Sig_Algo, Valid);
         pragma Warnings (On, """Pos"" is set by ""Parse_Algorithm_OID"" but not used after the call");
      end if;
      Pos := Sig_Seq_End;  --  skip any parameters
   end Parse_TBS_Sig_Algorithm;

   --  3. Parse Validity SEQUENCE { notBefore, notAfter }
   procedure Parse_Validity
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      T_Tag   : Byte;
      T_Len   : N32;

      --  RFC 5280 §4.1.2.5 time format checks on a single time field.
      procedure Check_Time_Format
        (Tag     : Byte;
         T_Start : N32;
         T_Ln    : N32;
         DT      : Date_Time)
      is
      begin
         if T_Ln = 0 or else DER'First /= 0
            or else T_Start > DER'Last
            or else DER'Last - T_Start < T_Ln - 1
         then
            return;
         end if;
         --  Now: T_Start + T_Ln - 1 <= DER'Last
         --  Must end in 'Z' (0x5A)
         if DER (T_Start + T_Ln - 1) /= 16#5A# then
            C.Bad_Time_Format := True;
         end if;
         --  GeneralizedTime must NOT have fractional seconds ('.' = 0x2E)
         if Tag = TAG_GENTIME and then T_Ln > 14 then
            for I in N32 range 14 .. T_Ln - 1 loop
               pragma Loop_Invariant (T_Start + I <= DER'Last);
               if DER (T_Start + I) = 16#2E# then
                  C.Bad_Time_Format := True;
               end if;
            end loop;
         end if;
         --  Dates with year >= 2050 must use GeneralizedTime
         if Tag = TAG_UTCTIME and then DT.Year >= 2050 then
            C.Bad_Time_Format := True;
         end if;
         --  Dates with year <= 2049 must use UTCTime (not GeneralizedTime)
         if Tag = TAG_GENTIME and then DT.Year <= 2049 then
            C.Bad_Time_Format := True;
         end if;
      end Check_Time_Format;

   begin
      if not Valid then return; end if;
      if Pos > DER'Last then Valid := False; return; end if;

      Enter_Sequence (DER, Pos, Valid);
      if not Valid then return; end if;

      --  notBefore
      if Pos <= DER'Last then
         T_Tag := DER (Pos);
         if T_Tag = TAG_UTCTIME or T_Tag = TAG_GENTIME then
            Pos := Pos + 1;
            if Pos <= DER'Last then
               Parse_Length (DER, Pos, T_Len, Valid);
               if Valid then
                  declare
                     Time_Start : constant N32 := Pos;
                     Time_Len   : constant N32 := T_Len;
                     Saved_Tag  : constant Byte := T_Tag;
                  begin
                     Parse_Time_Value (DER, Pos, T_Len,
                                       C.Validity_Not_Before, Valid);
                     if Valid then
                        declare
                           DT_Copy : constant Date_Time :=
                             C.Validity_Not_Before;
                        begin
                           Check_Time_Format (Saved_Tag, Time_Start,
                                              Time_Len, DT_Copy);
                        end;
                     end if;
                  end;
               end if;
            end if;
         end if;
      end if;

      --  notAfter
      if Valid and then Pos <= DER'Last then
         T_Tag := DER (Pos);
         if T_Tag = TAG_UTCTIME or T_Tag = TAG_GENTIME then
            Pos := Pos + 1;
            if Pos <= DER'Last then
               Parse_Length (DER, Pos, T_Len, Valid);
               if Valid then
                  declare
                     Time_Start : constant N32 := Pos;
                     Time_Len   : constant N32 := T_Len;
                     Saved_Tag  : constant Byte := T_Tag;
                  begin
                     Parse_Time_Value (DER, Pos, T_Len,
                                       C.Validity_Not_After, Valid);
                     if Valid then
                        declare
                           DT_Copy : constant Date_Time :=
                             C.Validity_Not_After;
                        begin
                           Check_Time_Format (Saved_Tag, Time_Start,
                                              Time_Len, DT_Copy);
                        end;
                     end if;
                  end;
               end if;
            end if;
         end if;
      end if;
   end Parse_Validity;

   --  4. Parse SubjectPublicKeyInfo SEQUENCE { algorithm, publicKey }
   procedure Parse_SPKI
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      SPKI_Len    : N32;
      SPKI_End    : N32;
      Algo_Len    : N32;
      Algo_End    : N32;
      PK_Algo_ID  : Algorithm_ID := Algo_Unknown;
      Curve_Algo  : Algorithm_ID;
      BStr_Len    : N32;
      Unused_Bits : Byte;
   begin
      if not Valid then return; end if;
      if Pos > DER'Last then Valid := False; return; end if;

      Parse_Sequence (DER, Pos, SPKI_Len, Valid);
      if not Valid then return; end if;
      if not Can_Read (DER, Pos, SPKI_Len) then
         Valid := False; return;
      end if;
      SPKI_End := Pos + SPKI_Len;

      --  Algorithm SEQUENCE { OID [, parameters] }
      if Pos > DER'Last then Valid := False; return; end if;
      Parse_Sequence (DER, Pos, Algo_Len, Valid);
      if not Valid then return; end if;
      if not Can_Read (DER, Pos, Algo_Len) then
         Valid := False; return;
      end if;
      Algo_End := Pos + Algo_Len;
      if Pos <= DER'Last then
         Parse_Algorithm_OID (DER, Pos, PK_Algo_ID, Valid);
      end if;

      --  For EC keys, the curve OID follows
      if Valid and then PK_Algo_ID = Algo_Unknown and then Pos < Algo_End
         and then Pos <= DER'Last and then DER (Pos) = TAG_OID
      then
         Parse_Algorithm_OID (DER, Pos, Curve_Algo, Valid);
         if Curve_Algo in Algo_EC_P256 | Algo_EC_P384 then
            PK_Algo_ID := Curve_Algo;
         end if;
      end if;

      --  RFC 5280: RSA AlgorithmIdentifier parameters must be NULL
      if Valid and then PK_Algo_ID = Algo_RSA
         and then Pos < Algo_End
         and then Pos + 1 <= DER'Last
      then
         if DER (Pos) /= TAG_NULL
            or else DER (Pos + 1) /= 16#00#
         then
            C.Bad_PubKey := True;
         end if;
      end if;

      C.PK_Algo := PK_Algo_ID;
      Pos := Algo_End;

      --  Public key BIT STRING
      if not Valid or else Pos > DER'Last or else DER (Pos) /= TAG_BITSTRING then
         Valid := False; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then Valid := False; return; end if;
      Parse_Length (DER, Pos, BStr_Len, Valid);
      if not Valid or BStr_Len < 2 then Valid := False; return; end if;
      if Pos > DER'Last then Valid := False; return; end if;
      Unused_Bits := DER (Pos);
      Pos := Pos + 1;
      BStr_Len := BStr_Len - 1;  --  subtract unused bits byte

      --  DER BIT STRING check: unused_bits must be 0..7,
      --  and if no value bytes then unused_bits must be 0
      if Unused_Bits > 7 then
         C.Bad_DER := True;
      end if;
      if BStr_Len = 0 and then Unused_Bits > 0 then
         C.Bad_DER := True;
      end if;
      --  DER BIT STRING: unused bits in last byte must be zero
      if Unused_Bits > 0 and then BStr_Len > 0
         and then Can_Read (DER, Pos, BStr_Len)
      then
         declare
            Last_Byte : constant Byte := DER (Pos + BStr_Len - 1);
            Mask      : constant Byte :=
              Shift_Left (1, Natural (Unused_Bits)) - 1;
         begin
            if (Last_Byte and Mask) /= 0 then
               C.Bad_DER := True;
            end if;
         end;
      end if;

      if PK_Algo_ID = Algo_RSA then
         --  RSA key: BIT STRING contains SEQUENCE { modulus INTEGER, exponent INTEGER }
         if Pos <= DER'Last and then DER (Pos) = TAG_SEQUENCE then
            declare
               Mod_Len : N32;
               Exp_Len : N32;
            begin
               Enter_Sequence (DER, Pos, Valid);
               if Valid and then Pos <= DER'Last and then DER (Pos) = TAG_INTEGER then
                  Pos := Pos + 1;
                  if Pos <= DER'Last then
                     Parse_Length (DER, Pos, Mod_Len, Valid);
                     if Valid then
                        --  RFC 5280: RSA modulus must be positive
                        --  Check before stripping the leading zero byte
                        if Mod_Len > 0 and then Pos <= DER'Last
                           and then DER (Pos) >= 16#80#
                        then
                           C.Bad_PubKey := True;
                        end if;
                        --  DER: no unnecessary leading zero
                        if Mod_Len >= 2 and then Pos <= DER'Last
                           and then DER (Pos) = 0
                           and then Pos + 1 <= DER'Last
                           and then DER (Pos + 1) < 16#80#
                        then
                           C.Bad_DER := True;
                        end if;
                        --  Skip leading zero byte if present
                        if Mod_Len > 0 and then Pos <= DER'Last
                           and then DER (Pos) = 0
                        then
                           Pos := Pos + 1;
                           Mod_Len := Mod_Len - 1;
                        end if;
                        Copy_Bytes (DER, Pos, Mod_Len, C.PK_Buf, C.PK_Buf_Len);
                        Skip (DER, Pos, Mod_Len, Valid);
                     end if;
                  end if;
               end if;
               --  Exponent INTEGER
               if Valid and then Pos <= DER'Last and then DER (Pos) = TAG_INTEGER then
                  Pos := Pos + 1;
                  if Pos <= DER'Last then
                     Parse_Length (DER, Pos, Exp_Len, Valid);
                     if Valid and then Exp_Len > 0
                        and then Can_Read (DER, Pos, Exp_Len)
                     then
                        pragma Assert (Pos + Exp_Len - 1 <= DER'Last);
                        --  RFC 3279: exponent must be positive
                        if DER (Pos) >= 16#80# then
                           C.Bad_PubKey := True;
                        end if;
                        --  DER: no unnecessary leading zero
                        if Exp_Len >= 2
                           and then DER (Pos) = 0
                           and then Pos + 1 <= DER'Last
                           and then DER (Pos + 1) < 16#80#
                        then
                           C.Bad_DER := True;
                        end if;
                        C.PK_RSA_Exp := 0;
                        declare
                           Limit : constant N32 := N32'Min (Exp_Len, 4);
                        begin
                           pragma Assert (Limit <= Exp_Len);
                           pragma Assert (Limit >= 1);
                           for I in N32 range 0 .. Limit - 1 loop
                              pragma Loop_Invariant
                                (Pos + Exp_Len - 1 <= DER'Last
                                 and then I <= Limit - 1
                                 and then Limit <= Exp_Len);
                              pragma Assert (I < Exp_Len);
                              pragma Assert (Pos + I <= Pos + Exp_Len - 1);
                              C.PK_RSA_Exp := C.PK_RSA_Exp * 256 +
                                              Unsigned_32 (DER (Pos + I));
                           end loop;
                        end;
                        pragma Warnings (Off, """Pos"" is set by ""Skip"" but not used");
                        Skip (DER, Pos, Exp_Len, Valid);
                        pragma Warnings (On, """Pos"" is set by ""Skip"" but not used");
                     end if;
                  end if;
               end if;
            end;
         else
            pragma Warnings (Off, """Pos"" is set by ""Skip"" but not used");
            Skip (DER, Pos, BStr_Len, Valid);
            pragma Warnings (On, """Pos"" is set by ""Skip"" but not used");
         end if;
      else
         --  EC / Ed25519: raw key bytes in BIT STRING
         Copy_Bytes (DER, Pos, BStr_Len, C.PK_Buf, C.PK_Buf_Len);
         pragma Warnings (Off, """Pos"" is set by ""Skip"" but not used");
         Skip (DER, Pos, BStr_Len, Valid);
         pragma Warnings (On, """Pos"" is set by ""Skip"" but not used");
      end if;

      Pos := SPKI_End;
   end Parse_SPKI;

   --  5. Parse optional issuerUniqueID [1], subjectUniqueID [2]
   procedure Parse_Unique_IDs
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
   begin
      if not Valid then return; end if;

      --  issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL
      --  subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
      --  RFC 5280 §4.1.2.8: only allowed in v2 and v3
      if Pos <= DER'Last and then C.S_TBS.Present
         and then Pos <= C.S_TBS.Last
      then
         --  issuerUniqueID: tag 0xA1 (constructed) or 0x81 (primitive)
         if Pos <= DER'Last and then
            (DER (Pos) = 16#A1# or DER (Pos) = 16#81#)
         then
            C.Has_Unique_ID := True;
            --  Validate BIT STRING content
            declare
               Save_Pos : constant N32 := Pos;
               Uid_Len  : N32;
            begin
               Pos := Pos + 1;
               if Pos <= DER'Last then
                  Parse_Length (DER, Pos, Uid_Len, Valid);
                  if Valid and then Uid_Len > 0
                     and then Pos <= DER'Last
                  then
                     --  Check for SEQUENCE (invalid for BIT STRING)
                     if DER (Pos) = 16#30# then
                        C.Bad_DER := True;
                     end if;
                     --  Check BIT STRING trailing bits
                     if Uid_Len >= 2 then
                        declare
                           UB : constant Byte := DER (Pos);
                        begin
                           if UB > 0 and then UB <= 7
                              and then Can_Read (DER, Pos, Uid_Len)
                           then
                              declare
                                 Last_B : constant Byte :=
                                   DER (Pos + Uid_Len - 1);
                                 Mask2  : constant Byte :=
                                   Shift_Left (1, Natural (UB)) - 1;
                              begin
                                 if (Last_B and Mask2) /= 0 then
                                    C.Bad_DER := True;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end if;
               end if;
               Pos := Save_Pos;
               Valid := True;
            end;
            Skip_TLV (DER, Pos, Valid);
         end if;
         --  subjectUniqueID: tag 0xA2 (constructed) or 0x82 (primitive)
         if Valid and then Pos <= DER'Last
            and then Pos <= C.S_TBS.Last
            and then (DER (Pos) = 16#A2# or DER (Pos) = 16#82#)
         then
            C.Has_Unique_ID := True;
            --  Validate BIT STRING content
            declare
               Save_Pos : constant N32 := Pos;
               Uid_Len  : N32;
            begin
               Pos := Pos + 1;
               if Pos <= DER'Last then
                  Parse_Length (DER, Pos, Uid_Len, Valid);
                  if Valid and then Uid_Len > 0
                     and then Pos <= DER'Last
                  then
                     --  Check for SEQUENCE (invalid for BIT STRING)
                     if DER (Pos) = 16#30# then
                        C.Bad_DER := True;
                     end if;
                     --  Check BIT STRING trailing bits
                     if Uid_Len >= 2 then
                        declare
                           UB : constant Byte := DER (Pos);
                        begin
                           if UB > 0 and then UB <= 7
                              and then Can_Read (DER, Pos, Uid_Len)
                           then
                              declare
                                 Last_B : constant Byte :=
                                   DER (Pos + Uid_Len - 1);
                                 Mask2  : constant Byte :=
                                   Shift_Left (1, Natural (UB)) - 1;
                              begin
                                 if (Last_B and Mask2) /= 0 then
                                    C.Bad_DER := True;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end if;
               end if;
               Pos := Save_Pos;
               Valid := True;
            end;
            Skip_TLV (DER, Pos, Valid);
         end if;
      end if;
   end Parse_Unique_IDs;

   --  6. Extension sub-procedures
   --  Each handles one extension type. Pos is "in" — the outer loop
   --  advances past Ext_Seq_End regardless.

   procedure Parse_Ext_SAN
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  SAN noncrit + empty subject check
      if not Is_Critical
         and then not C.Has_Subject
      then
         C.SAN_Noncrit_Empty_Subj := True;
      end if;
      --  RFC 5280 §4.2.1.6: SAN critical with non-empty subject
      if Is_Critical and then C.Has_Subject then
         C.SAN_Critical_With_Subject := True;
      end if;
      --  SAN: SEQUENCE of GeneralName
      if P > DER'Last or else DER (P) /= TAG_SEQUENCE then
         --  SAN extension present but not a valid SEQUENCE
         C.Bad_SAN := True;
         return;
      end if;
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then
            Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            --  Store the full SAN extension value span for
            --  Matches_Hostname to iterate all SANs from DER
            --  (handles certs with > Max_SANs entries).
            C.SAN_Ext_Value := (First => P, Last => Inner_End - 1,
                                Present => Inner_Len > 0);
            --  RFC 5280 4.2.1.6: empty SAN
            if Inner_Len = 0 then
               C.Bad_SAN := True;
            end if;
            declare
            begin
            while Valid and then P < Inner_End
                  and then P <= DER'Last
            loop
               declare
                  GN_Tag : constant Byte :=
                     DER (P);
                  GN_Len : N32;
               begin
                  P := P + 1;
                  if P > DER'Last then
                     Valid := False; exit;
                  end if;
                  Parse_Length
                    (DER, P, GN_Len, Valid);
                  if not Valid then exit; end if;

                  --  Tag 0x82 = dNSName (context
                  --  tag 2, primitive)
                  if GN_Tag = GN_DNS_NAME then

                     if GN_Len = 0 then
                        --  Blank DNS name
                        C.Bad_SAN := True;
                     elsif Can_Read
                        (DER, P, GN_Len)
                     then
                        --  Leading dot is invalid
                        if DER (P) = 16#2E# then
                           C.Bad_SAN := True;
                        end if;
                        --  Validate DNS chars
                        for J in N32 range
                           0 .. GN_Len - 1
                        loop
                           pragma Loop_Invariant
                             (P + J <= DER'Last);
                           declare
                              Ch : constant Byte :=
                                DER (P + J);
                           begin
                              if not (Ch in
                                 16#61# .. 16#7A#  --  a-z
                               | 16#41# .. 16#5A#  --  A-Z
                               | 16#30# .. 16#39#  --  0-9
                               | 16#2D#            --  '-'
                               | 16#2E#            --  '.'
                               | 16#2A#)           --  '*'
                              then
                                 C.Bad_SAN := True;
                              end if;
                           end;
                        end loop;
                        if C.SAN_Num < Max_SANs
                        then
                           C.SAN_Num :=
                              C.SAN_Num + 1;
                           C.SANs (C.SAN_Num) :=
                             (First   => P,
                              Last    =>
                                 P + GN_Len - 1,
                              Present => True);
                        end if;
                     end if;

                  elsif GN_Tag = GN_RFC822_NAME then
                     --  rfc822Name (email)

                     C.SAN_Has_Email := True;
                     --  Empty GeneralName value
                     if GN_Len = 0 then
                        C.Bad_SAN := True;
                     end if;
                     if GN_Len > 0
                        and then Can_Read
                           (DER, P, GN_Len)
                     then
                        declare
                           Has_At   : Boolean :=
                             False;
                           Bad_Char : Boolean :=
                             False;
                        begin
                           for J in N32 range
                              0 .. GN_Len - 1
                           loop
                              pragma Loop_Invariant
                                (P + J <=
                                   DER'Last);
                              if DER (P + J) =
                                 16#40#
                              then
                                 Has_At := True;
                              end if;
                              --  RFC 2821 Mailbox:
                              --  no spaces, angles
                              if DER (P + J) =
                                    16#20#
                                 or DER (P + J) =
                                    16#3C#
                                 or DER (P + J) =
                                    16#3E#
                              then
                                 Bad_Char := True;
                              end if;
                           end loop;
                           if not Has_At
                              or Bad_Char
                           then
                              C.Bad_SAN := True;
                           end if;
                        end;
                     end if;

                  elsif GN_Tag = GN_URI then
                     --  uniformResourceIdentifier

                     if GN_Len = 0 then
                        C.Bad_SAN := True;
                     end if;
                     if GN_Len > 0
                        and then Can_Read
                           (DER, P, GN_Len)
                     then
                        --  Check for "://" scheme
                        declare
                           Has_Scheme : Boolean :=
                             False;
                        begin
                           if GN_Len >= 3
                              and then P <= DER'Last
                              and then DER'Last - P >= GN_Len - 1
                           then
                              for J in N32 range
                                 0 .. GN_Len - 3
                              loop
                                 pragma
                                   Loop_Invariant
                                     (P + J + 2
                                        <= DER'Last);
                                 if DER (P + J)
                                      = 16#3A#
                                    and then
                                    DER (P + J + 1)
                                      = 16#2F#
                                    and then
                                    DER (P + J + 2)
                                      = 16#2F#
                                 then
                                    Has_Scheme :=
                                      True;
                                 end if;
                              end loop;
                           end if;
                           if not Has_Scheme then
                              C.Bad_SAN := True;
                           end if;
                        end;
                     end if;

                  elsif GN_Tag = GN_IP_ADDRESS then
                     --  iPAddress

                     if GN_Len /= 4
                        and then GN_Len /= 16
                     then
                        C.Bad_SAN := True;
                     elsif Can_Read (DER, P, GN_Len)
                        and then C.IP_SAN_Num < Max_SANs
                     then
                        C.IP_SAN_Num :=
                           C.IP_SAN_Num + 1;
                        C.IP_SANs (C.IP_SAN_Num) :=
                          (First   => P,
                           Last    =>
                              P + GN_Len - 1,
                           Present => True);
                     end if;

                  elsif GN_Tag = GN_OTHER_NAME then
                     --  otherName
                     C.SAN_Has_Other_Name := True;

                  elsif GN_Tag in
                     GN_X400_ADDRESS
                     | GN_DIR_NAME     --  directoryName
                     | GN_EDI_NAME     --  ediPartyName
                     | GN_REGISTERED_ID
                  then
                     --  Other known tags
                     null;

                  else
                     --  Unrecognized SAN tag
                     C.Bad_SAN := True;
                  end if;

                  Skip (DER, P, GN_Len, Valid);
               end;
            end loop;
            --  Note: SANs with only non-DNS names
            --  (e.g. email-only) are valid per RFC 5280
            end;
         end if;
      end if;
   end Parse_Ext_SAN;

   procedure Parse_Ext_Basic_Constraints
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      C.Ext_Basic_Crit := Is_Critical;
      --  Basic Constraints: SEQUENCE {
      --    BOOLEAN (isCA)?, INTEGER (pathLen)? }
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then Inner_Len > 0
            and then Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            --  Optional isCA BOOLEAN
            if P < Inner_End
               and then P <= DER'Last
               and then DER (P) = TAG_BOOLEAN
            then
               P := P + 1;
               if P > DER'Last then
                  Valid := False;
               else
                  declare
                     B_Len : N32;
                  begin
                     Parse_Length
                       (DER, P, B_Len, Valid);
                     if Valid and then B_Len = 1
                        and then P <= DER'Last
                     then
                        C.Ext_Is_CA :=
                          DER (P) /= 0;
                        P := P + 1;
                     elsif Valid then
                        Skip
                          (DER, P, B_Len, Valid);
                     end if;
                  end;
               end if;
            end if;
            --  Optional pathLen INTEGER
            if Valid and then P < Inner_End
               and then P <= DER'Last
               and then DER (P) = TAG_INTEGER
            then
               P := P + 1;
               if P <= DER'Last then
                  declare
                     PL_Len : N32;
                  begin
                     Parse_Length
                       (DER, P, PL_Len, Valid);
                     if Valid and then PL_Len >= 1
                        and then P <= DER'Last
                     then
                        C.Ext_Has_Path_Len := True;
                        C.Ext_Path_Len :=
                          Natural (DER (P));
                        pragma Warnings (Off, """P"" is set by ""Skip"" but not used");
                        Skip
                          (DER, P, PL_Len, Valid);
                        pragma Warnings (On, """P"" is set by ""Skip"" but not used");
                     end if;
                  end;
               end if;
            end if;
         end if;
      end if;
   end Parse_Ext_Basic_Constraints;

   procedure Parse_Ext_Key_Usage
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P : N32 := Pos;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      C.Ext_Key_Usage_Crit := Is_Critical;
      --  Key Usage: BIT STRING
      if P <= DER'Last
         and then DER (P) = TAG_BITSTRING
      then
         P := P + 1;
         if P > DER'Last then
            Valid := False;
         else
            declare
               BS_Len      : N32;
               Unused_Bits : Byte;
            begin
               Parse_Length
                 (DER, P, BS_Len, Valid);
               if Valid and then BS_Len >= 1
                  and then P <= DER'Last
                  and then Can_Read
                     (DER, P, BS_Len)
               then
                  Unused_Bits := DER (P);
                  P := P + 1;
                  BS_Len := BS_Len - 1;
                  C.Ext_Has_Key_Usage := True;
                  if BS_Len >= 1 then
                     --  First byte of key usage bits
                     if P <= DER'Last then
                        C.Ext_Key_Usage :=
                          Unsigned_16 (DER (P))
                          * 256;
                        if BS_Len >= 2
                           and then P + 1 <=
                              DER'Last
                        then
                           C.Ext_Key_Usage :=
                             C.Ext_Key_Usage or
                             Unsigned_16
                               (DER (P + 1));
                        end if;
                     end if;
                  end if;
                  --  RFC 5280 4.2.1.3: KU with
                  --  no bits set is invalid
                  --  (includes BS_Len=0: only
                  --  unused-bits byte, no value)
                  if C.Ext_Key_Usage = 0 then
                     C.Empty_Key_Usage := True;
                  end if;
                  --  X.690 §11.2.2: DER BIT STRING
                  --  trailing zero bits must be removed.
                  if BS_Len >= 1 then
                     declare
                        Last_Byte : Byte := 0;
                     begin
                        if BS_Len = 1
                           and then P <= DER'Last
                        then
                           Last_Byte := DER (P);
                        elsif BS_Len >= 2
                           and then P + BS_Len - 1 <=
                              DER'Last
                        then
                           Last_Byte :=
                             DER (P + BS_Len - 1);
                        end if;
                        --  Non-minimal: last byte is
                        --  all zero (could be removed)
                        if BS_Len >= 2
                           and then Last_Byte = 0
                        then
                           C.Bad_DER := True;
                        end if;
                        --  Unused bits must be zero
                        if Unused_Bits > 0 then
                           declare
                              Mask : constant Byte :=
                                Shift_Left
                                  (1, Natural
                                     (Unused_Bits))
                                  - 1;
                           begin
                              if (Last_Byte and Mask)
                                    /= 0
                              then
                                 C.Bad_DER := True;
                              end if;
                           end;
                        end if;
                     end;
                  end if;
               end if;
            end;
         end if;
      end if;
   end Parse_Ext_Key_Usage;

   procedure Parse_Ext_SKID
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P : N32 := Pos;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280: SKID MUST NOT be critical
      if Is_Critical then
         C.Bad_Ext_Criticality := True;
      end if;
      --  Subject Key ID: OCTET STRING
      if P <= DER'Last
         and then DER (P) = TAG_OCTETSTRING
      then
         P := P + 1;
         if P > DER'Last then
            Valid := False;
         else
            declare
               SK_Len : N32;
            begin
               Parse_Length
                 (DER, P, SK_Len, Valid);
               if Valid and then SK_Len > 0
                  and then Can_Read
                     (DER, P, SK_Len)
               then
                  C.S_Subject_Key_ID :=
                    (First   => P,
                     Last    => P + SK_Len - 1,
                     Present => True);
               end if;
            end;
         end if;
      end if;
   end Parse_Ext_SKID;

   procedure Parse_Ext_AKID
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280: AKID MUST NOT be critical
      if Is_Critical then
         C.Bad_Ext_Criticality := True;
      end if;
      --  Authority Key ID: SEQUENCE {
      --    [0] keyIdentifier IMPLICIT OCTET STRING
      --    [1] authorityCertIssuer IMPLICIT GeneralNames
      --    [2] authorityCertSerialNumber IMPLICIT INTEGER
      --  }
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid then
            if Inner_Len = 0 then
               --  Empty AKID SEQUENCE: missing keyIdentifier
               C.AKID_Missing_Key_ID := True;
            elsif Can_Read (DER, P, Inner_Len) then
            Inner_End := P + Inner_Len;
            declare
               Has_Key_ID  : Boolean := False;
               Has_Issuer  : Boolean := False;
               Has_Serial2 : Boolean := False;
               Scan_Pos    : N32 := P;
            begin
            --  Scan all tags in AKID SEQUENCE
            while Valid and then Scan_Pos < Inner_End
                  and then Scan_Pos <= DER'Last
            loop
               declare
                  AKID_Tag : constant Byte :=
                    DER (Scan_Pos);
                  AKID_TLen : N32;
               begin
                  if AKID_Tag = AKID_TAG_KEY_ID then
                     Has_Key_ID := True;
                  elsif AKID_Tag = AKID_TAG_ISSUER then
                     Has_Issuer := True;
                  elsif AKID_Tag = AKID_TAG_SERIAL then
                     Has_Serial2 := True;
                  end if;
                  --  Skip this element
                  Scan_Pos := Scan_Pos + 1;
                  if Scan_Pos > DER'Last then
                     exit;
                  end if;
                  Parse_Length
                    (DER, Scan_Pos, AKID_TLen, Valid);
                  if Valid then
                     --  Save AKID serial span
                     if AKID_Tag = AKID_TAG_SERIAL
                        and then AKID_TLen > 0
                        and then Can_Read
                          (DER, Scan_Pos, AKID_TLen)
                     then
                        C.S_AKID_Serial :=
                          (First   => Scan_Pos,
                           Last    => Scan_Pos + AKID_TLen - 1,
                           Present => True);
                     end if;
                     --  Validate [1] authorityCertIssuer content
                     if AKID_Tag = AKID_TAG_ISSUER
                        and then AKID_TLen > 0
                        and then Can_Read
                          (DER, Scan_Pos, AKID_TLen)
                     then
                        --  Scan GeneralNames inside [1]
                        declare
                           GN_Scan : N32 :=
                             Scan_Pos;
                           GN_End  : constant N32 :=
                             Scan_Pos + AKID_TLen;
                           GN_OK   : Boolean := True;
                        begin
                           while GN_OK
                             and then GN_Scan < GN_End
                             and then GN_Scan <= DER'Last
                           loop
                              declare
                                 GT : constant Byte :=
                                   DER (GN_Scan);
                                 GL : N32;
                              begin
                                 --  Must be valid GN tag
                                 if not (GT in
                                    16#80# .. 16#88#
                                    | 16#A0# .. 16#A8#)
                                 then
                                    C.Bad_AKID := True;
                                    exit;
                                 end if;
                                 GN_Scan := GN_Scan + 1;
                                 if GN_Scan > DER'Last
                                 then
                                    exit;
                                 end if;
                                 Parse_Length
                                   (DER, GN_Scan,
                                    GL, GN_OK);
                                 if not GN_OK then
                                    exit;
                                 end if;
                                 --  iPAddress must be
                                 --  4 or 16 bytes
                                 if GT = GN_IP_ADDRESS
                                    and then GL /= 4
                                    and then GL /= 16
                                 then
                                    C.Bad_AKID := True;
                                 end if;
                                 Skip (DER, GN_Scan,
                                       GL, GN_OK);
                              end;
                           end loop;
                        end;
                     end if;
                     Skip (DER, Scan_Pos,
                           AKID_TLen, Valid);
                  end if;
               end;
            end loop;

            --  Extract keyIdentifier [0]
            if Has_Key_ID
               and then P <= DER'Last
               and then DER (P) = AKID_TAG_KEY_ID
            then
               declare
                  AK_Pos : N32 := P + 1;
                  AK_Len : N32;
               begin
                  if Valid and then AK_Pos <= DER'Last then
                     Parse_Length
                       (DER, AK_Pos, AK_Len, Valid);
                     if Valid and then AK_Len > 0
                        and then Can_Read
                           (DER, AK_Pos, AK_Len)
                     then
                        C.S_Auth_Key_ID :=
                          (First   => AK_Pos,
                           Last    =>
                             AK_Pos + AK_Len - 1,
                           Present => True);
                     end if;
                  end if;
               end;
            end if;

            if not Has_Key_ID then
               --  RFC 5280 4.2.1.1: AKID without
               --  keyIdentifier
               C.AKID_Missing_Key_ID := True;
            end if;

            --  RFC 5280 4.2.1.1: authorityCertIssuer
            --  and authorityCertSerialNumber MUST both
            --  be present or both absent
            if Has_Issuer /= Has_Serial2 then
               C.Bad_AKID := True;
            end if;
            --  Store authorityCertIssuer presence for CABF checks
            C.AKID_Has_Issuer := Has_Issuer;
            end;
            end if;  --  elsif Can_Read
         end if;  --  if Valid
      end if;
   end Parse_Ext_AKID;

   --  Check a userNotice qualifier for BMPString or control chars.
   --  P should point at the UserNotice SEQUENCE.
   procedure Check_User_Notice
     (DER : in     Byte_Seq;
      P   : in     N32;
      Lim : in     N32;
      Bad : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      UP     : N32;
      UL     : N32;
      UE     : N32;
      OK     : Boolean := True;
   begin
      if P > DER'Last or else DER (P) /= TAG_SEQUENCE then
         return;
      end if;
      UP := P;
      Parse_Sequence (DER, UP, UL, OK);
      if not OK or else UL = 0 or else not Can_Read (DER, UP, UL) then
         return;
      end if;
      UE := UP + UL;
      if UE > Lim then
         UE := Lim;
      end if;

      --  Walk elements inside UserNotice SEQUENCE
      while OK and then UP < UE and then UP <= DER'Last loop
         declare
            Tag : constant Byte := DER (UP);
            TL  : N32;
         begin
            UP := UP + 1;
            if UP > DER'Last then exit; end if;
            Parse_Length (DER, UP, TL, OK);
            if not OK then exit; end if;

            --  RFC 5280: explicitText MUST NOT use BMPString
            if Tag = 16#1E# then
               Bad := True;
            end if;

            --  RFC 5280: explicitText SHOULD NOT have control chars
            if Tag = 16#0C# and then TL > 0
               and then Can_Read (DER, UP, TL)
            then
               for K in N32 range 0 .. TL - 1 loop
                  pragma Loop_Invariant (UP + K <= DER'Last);
                  if DER (UP + K) < 16#20#
                     and then DER (UP + K) /= 16#09#
                     and then DER (UP + K) /= 16#0A#
                     and then DER (UP + K) /= 16#0D#
                  then
                     Bad := True;
                  end if;
               end loop;
            end if;

            Skip (DER, UP, TL, OK);
            if not OK then exit; end if;
         end;
      end loop;
   end Check_User_Notice;

   procedure Parse_Ext_Cert_Policies
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len, Is_Critical);
      --  RFC 5280 §4.2.1.4: Certificate Policies
      --  Parse SEQUENCE of PolicyInformation,
      --  check for duplicates and BMPString
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then Inner_Len > 0
            and then Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            declare
               --  Track up to 10 policy OIDs
               --  for duplicate detection
               type OID_Rec is record
                  Start : N32 := 0;
                  Len   : N32 := 0;
               end record;
               type OID_Arr is array
                 (1 .. 10) of OID_Rec;
               Seen_OIDs : OID_Arr :=
                 (others => (0, 0));
               Seen_Count : Natural := 0;
            begin
            while Valid
                  and then P < Inner_End
                  and then P <= DER'Last
            loop
               --  Each PolicyInformation is a
               --  SEQUENCE { OID, qualifiers? }
               if DER (P) /= TAG_SEQUENCE then
                  exit;
               end if;
               declare
                  PI_Len   : N32;
                  PI_End   : N32;
                  PO_Len   : N32 := 0;
                  PO_Start : N32 := 0;
               begin
                  Parse_Sequence
                    (DER, P, PI_Len, Valid);
                  if not Valid then exit; end if;
                  if not Can_Read
                    (DER, P, PI_Len)
                  then
                     exit;
                  end if;
                  PI_End := P + PI_Len;
                  --  Parse policy OID
                  if P <= DER'Last
                     and then
                     DER (P) = TAG_OID
                  then
                     P := P + 1;
                     if P > DER'Last then
                        Valid := False;
                        exit;
                     end if;
                     Parse_Length
                       (DER, P, PO_Len, Valid);
                     if not Valid then exit; end if;
                     PO_Start := P;
                     --  Check for duplicate
                     for I in 1 .. Seen_Count loop
                        if I <= 10
                           and then
                           Seen_OIDs (I).Len =
                             PO_Len
                           and then PO_Len > 0
                           and then Can_Read
                             (DER, PO_Start, PO_Len)
                           and then Can_Read
                             (DER,
                              Seen_OIDs (I).Start,
                              PO_Len)
                        then
                           declare
                              Match : Boolean :=
                                True;
                           begin
                              for J in N32 range
                                0 .. PO_Len - 1
                              loop
                                 pragma
                                   Loop_Invariant
                                     (PO_Start + J
                                        <= DER'Last
                                      and then
                                      Seen_OIDs (I)
                                        .Start + J
                                        <= DER'Last);
                                 if DER
                                   (PO_Start + J)
                                   /= DER
                                   (Seen_OIDs (I)
                                      .Start + J)
                                 then
                                    Match := False;
                                 end if;
                              end loop;
                              if Match then
                                 C.Bad_Cert_Policy
                                   := True;
                              end if;
                           end;
                        end if;
                     end loop;
                     --  Record this OID
                     if Seen_Count < 10 then
                        Seen_Count :=
                          Seen_Count + 1;
                        Seen_OIDs (Seen_Count) :=
                          (Start => PO_Start,
                           Len   => PO_Len);
                     end if;
                     Skip (DER, P, PO_Len, Valid);
                     if not Valid then exit; end if;
                  end if;
                  --  Check policy qualifiers if present
                  declare
                     Is_Any : constant Boolean :=
                       PO_Len > 0
                       and then Can_Read
                         (DER, PO_Start, PO_Len)
                       and then OID_Match
                         (DER, PO_Start, PO_Len,
                          OID_ANY_POLICY);
                  begin
                  --  Walk qualifiers SEQUENCE if present
                  if P < PI_End and then P <= DER'Last
                     and then DER (P) = TAG_SEQUENCE
                  then
                     declare
                        QS_Len : N32;
                        QS_End : N32;
                     begin
                        Parse_Sequence
                          (DER, P, QS_Len, Valid);
                        if Valid and then QS_Len > 0
                           and then Can_Read
                             (DER, P, QS_Len)
                        then
                           QS_End := P + QS_Len;
                           --  Each PolicyQualifierInfo
                           while Valid
                                 and then P < QS_End
                                 and then P <= DER'Last
                                 and then DER (P) =
                                    TAG_SEQUENCE
                           loop
                              declare
                                 PQ_Len : N32;
                                 PQ_End : N32;
                                 QOL    : N32;
                                 QOS    : N32;
                                 Is_CPS : Boolean :=
                                   False;
                                 Is_UNot : Boolean :=
                                   False;
                              begin
                                 Parse_Sequence
                                   (DER, P, PQ_Len,
                                    Valid);
                                 if not Valid then
                                    exit;
                                 end if;
                                 if not Can_Read
                                   (DER, P, PQ_Len)
                                 then
                                    exit;
                                 end if;
                                 PQ_End := P + PQ_Len;
                                 --  Qualifier OID
                                 if P <= DER'Last
                                    and then DER (P) =
                                       TAG_OID
                                 then
                                    P := P + 1;
                                    if P > DER'Last
                                    then
                                       exit;
                                    end if;
                                    Parse_Length
                                      (DER, P, QOL,
                                       Valid);
                                    if not Valid then
                                       exit;
                                    end if;
                                    QOS := P;
                                    if Can_Read
                                      (DER, QOS, QOL)
                                    then
                                       Is_CPS :=
                                         OID_Match
                                           (DER, QOS,
                                            QOL,
                                            OID_QT_CPS);
                                       Is_UNot :=
                                         OID_Match
                                           (DER, QOS,
                                            QOL,
                                            OID_QT_UNOTICE);
                                    end if;
                                    Skip
                                      (DER, P, QOL,
                                       Valid);
                                    if not Valid then
                                       exit;
                                    end if;
                                 end if;
                                 --  anyPolicy: only
                                 --  CPS and unotice
                                 if Is_Any
                                    and then
                                    not Is_CPS
                                    and then
                                    not Is_UNot
                                 then
                                    C.Bad_Cert_Policy
                                      := True;
                                 end if;
                                 --  Check userNotice for
                                 --  BMPString / ctrl chars
                                 if Is_UNot
                                    and then P < PQ_End
                                    and then P <=
                                       DER'Last
                                 then
                                    Check_User_Notice
                                      (DER, P, PQ_End,
                                       C.Bad_Cert_Policy);
                                 end if;
                                 P := PQ_End;
                              end;
                           end loop;
                        end if;
                     end;
                  end if;
                  end;
                  P := PI_End;
               end;
            end loop;
            end;
         end if;
      end if;
   end Parse_Ext_Cert_Policies;

   procedure Parse_Ext_EKU
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280 §4.2.1.12: Extended Key Usage
      --  SEQUENCE of OID, each must be valid
      C.Ext_Has_EKU := True;
      C.EKU_Is_Critical := Is_Critical;
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then
            Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            --  Empty EKU SEQUENCE is invalid
            if Inner_Len = 0 then
               C.Bad_EKU_Content := True;
            end if;
            while Valid
                  and then P < Inner_End
                  and then P <= DER'Last
            loop
               if DER (P) /= TAG_OID then
                  C.Bad_EKU_Content := True;
                  exit;
               end if;
               P := P + 1;
               if P > DER'Last then
                  Valid := False; exit;
               end if;
               declare
                  EKU_OLen  : N32;
                  EKU_Start : N32;
               begin
                  Parse_Length
                    (DER, P, EKU_OLen, Valid);
                  if not Valid then exit; end if;
                  EKU_Start := P;
                  --  Zero-length OID is invalid
                  if EKU_OLen = 0 then
                     C.Bad_EKU_Content := True;
                  end if;
                  --  Track id-kp-serverAuth
                  if OID_Match
                       (DER, EKU_Start, EKU_OLen,
                        OID_KP_SERVER_AUTH)
                  then
                     C.EKU_Has_Server_Auth := True;
                  end if;
                  --  Track anyExtendedKeyUsage
                  if OID_Match
                       (DER, EKU_Start, EKU_OLen,
                        OID_ANY_EKU)
                  then
                     C.EKU_Has_Any := True;
                     --  anyEKU in critical EKU is invalid
                     if Is_Critical then
                        C.Bad_EKU_Content := True;
                     end if;
                  end if;
                  Skip (DER, P, EKU_OLen, Valid);
               end;
            end loop;
         end if;
      end if;
   end Parse_Ext_EKU;

   procedure Parse_Ext_CRL_DP
     (DER         : in     Byte_Seq;
      Pos         : in     N32;
      Val_Len     : in     N32;
      Is_Critical : in     Boolean;
      C           : in out Certificate;
      Valid       : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      P         : N32 := Pos;
      Inner_Len : N32;
      Inner_End : N32;
   begin
      if not Valid then return; end if;
      pragma Unreferenced (Val_Len);
      --  RFC 5280 §4.2.1.13: CRL Distribution Points
      --  SHOULD be non-critical
      if Is_Critical then
         C.Bad_CRL_DP := True;
      end if;
      --  DistributionPoint MUST NOT consist of only
      --  the reasons field
      if P <= DER'Last
         and then DER (P) = TAG_SEQUENCE
      then
         Parse_Sequence (DER, P, Inner_Len, Valid);
         if Valid and then
            Can_Read (DER, P, Inner_Len)
         then
            Inner_End := P + Inner_Len;
            while Valid
                  and then P < Inner_End
                  and then P <= DER'Last
            loop
               --  Each DistributionPoint SEQUENCE
               if DER (P) /= TAG_SEQUENCE then
                  exit;
               end if;
               declare
                  DP_Len : N32;
                  DP_End : N32;
                  Has_DP_Name  : Boolean := False;
                  Has_Reasons  : Boolean := False;
                  Has_Issuer2  : Boolean := False;
                  DP_Scan      : N32;
               begin
                  Parse_Sequence
                    (DER, P, DP_Len, Valid);
                  if not Valid then exit; end if;
                  if not Can_Read
                    (DER, P, DP_Len)
                  then
                     exit;
                  end if;
                  DP_End := P + DP_Len;
                  DP_Scan := P;
                  while DP_Scan < DP_End
                        and then
                        DP_Scan <= DER'Last
                  loop
                     declare
                        DPT : constant Byte :=
                          DER (DP_Scan);
                        DPT_Len : N32;
                     begin
                        --  [0] distributionPoint
                        if DPT = 16#A0# then
                           Has_DP_Name := True;
                        --  [1] reasons
                        elsif DPT = 16#81# then
                           Has_Reasons := True;
                        --  [2] cRLIssuer
                        elsif DPT = 16#A2# then
                           Has_Issuer2 := True;
                        end if;
                        DP_Scan := DP_Scan + 1;
                        if not Valid
                           or else DP_Scan > DER'Last
                        then
                           exit;
                        end if;
                        Parse_Length
                          (DER, DP_Scan,
                           DPT_Len, Valid);
                        if Valid then
                           Skip (DER, DP_Scan,
                                 DPT_Len, Valid);
                        end if;
                        if not Valid then
                           exit;
                        end if;
                     end;
                  end loop;
                  --  Reasons-only check
                  if Has_Reasons
                     and then not Has_DP_Name
                     and then not Has_Issuer2
                  then
                     C.Bad_CRL_DP := True;
                  end if;
                  P := DP_End;
               end;
            end loop;
         end if;
      end if;
   end Parse_Ext_CRL_DP;

   --  Parse [3] EXPLICIT SEQUENCE of extensions (dispatcher)
   procedure Parse_Extensions
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
      Ext_Tag_Len  : N32;
      Ext_Found    : Boolean;
      Exts_Seq_Len : N32;
      Exts_End     : N32;
      Ext_Seq_Len  : N32;
      Ext_Seq_End  : N32;
      OID_Len      : N32;
      OID_Start    : N32;
      Val_Len      : N32;
      --  Duplicate extension tracking: store OID start+len for each
      --  extension seen, reject if any OID appears twice.
      Max_Seen_Exts : constant := 30;
      type Ext_OID_Entry is record
         Start : N32 := 0;
         Len   : N32 := 0;
      end record;
      type Ext_OID_Array is array (1 .. Max_Seen_Exts) of Ext_OID_Entry;
      Seen_Exts  : Ext_OID_Array := (others => (0, 0));
      Seen_Count : Natural := 0;
   begin
      if not Valid then return; end if;
      if not (Pos <= DER'Last and then C.S_TBS.Present
              and then Pos <= C.S_TBS.Last)
      then
         return;
      end if;

      pragma Warnings (Off, """Ext_Tag_Len"" is set by ""Parse_Explicit_Tag"" but not used");
      Parse_Explicit_Tag (DER, Pos, TAG_EXTENSIONS, Ext_Tag_Len,
                           Ext_Found, Valid);
      pragma Warnings (On, """Ext_Tag_Len"" is set by ""Parse_Explicit_Tag"" but not used");
      if not (Valid and then Ext_Found) then return; end if;

      C.Has_Extensions := True;
      --  Outer SEQUENCE of extensions
      if Pos > DER'Last then return; end if;
      Parse_Sequence (DER, Pos, Exts_Seq_Len, Valid);
      if not Valid then return; end if;

      if Can_Read (DER, Pos, Exts_Seq_Len) then
         Exts_End := Pos + Exts_Seq_Len;
      else
         Valid := False;
         return;
      end if;

      --  Loop through each Extension SEQUENCE
      while Valid and then Pos < Exts_End
            and then Pos <= DER'Last
      loop
         if DER (Pos) /= TAG_SEQUENCE then
            --  Skip unexpected content to end
            Pos := Exts_End;
            exit;
         end if;
         Parse_Sequence (DER, Pos, Ext_Seq_Len, Valid);
         if not Valid then exit; end if;
         if not Can_Read (DER, Pos, Ext_Seq_Len) then
            Valid := False; exit;
         end if;
         Ext_Seq_End := Pos + Ext_Seq_Len;

         --  OID
         if Pos > DER'Last or else DER (Pos) /= TAG_OID then
            Pos := Ext_Seq_End;
         else
            Pos := Pos + 1;
            if Pos > DER'Last then Valid := False; exit; end if;
            Parse_Length (DER, Pos, OID_Len, Valid);
            if not Valid then exit; end if;
            OID_Start := Pos;
            Skip (DER, Pos, OID_Len, Valid);
            if not Valid then exit; end if;

            --  Check for duplicate extension OID
            if OID_Len > 0 and then Can_Read (DER, OID_Start, OID_Len) then
               for J in 1 .. Seen_Count loop
                  if Seen_Exts (J).Len = OID_Len
                     and then Can_Read (DER, Seen_Exts (J).Start,
                                        Seen_Exts (J).Len)
                  then
                     declare
                        Match : Boolean := True;
                     begin
                        for K in N32 range 0 .. OID_Len - 1 loop
                           if DER (OID_Start + K) /=
                              DER (Seen_Exts (J).Start + K)
                           then
                              Match := False;
                              exit;
                           end if;
                        end loop;
                        if Match then
                           C.Ext_Duplicate := True;
                        end if;
                     end;
                  end if;
               end loop;
               if Seen_Count < Max_Seen_Exts then
                  Seen_Count := Seen_Count + 1;
                  Seen_Exts (Seen_Count) :=
                    (Start => OID_Start, Len => OID_Len);
               end if;
            end if;

            --  Optional critical BOOLEAN
            declare
               Is_Critical : Boolean := False;
            begin
            if Pos < Ext_Seq_End and then Pos <= DER'Last
               and then DER (Pos) = TAG_BOOLEAN
            then
               --  Parse boolean: tag(1) + len(1) + value(1)
               if Can_Read (DER, Pos, 3) then
                  Is_Critical := DER (Pos + 2) /= 0;
               end if;
               Skip_TLV (DER, Pos, Valid);
               if not Valid then exit; end if;
            end if;

            --  OCTET STRING wrapping the extension value
            if Pos < Ext_Seq_End and then Pos <= DER'Last
               and then DER (Pos) = TAG_OCTETSTRING
            then
               Pos := Pos + 1;
               if Pos > DER'Last then Valid := False; exit; end if;
               Parse_Length (DER, Pos, Val_Len, Valid);
               if not Valid then exit; end if;

               --  RFC 5280: extension value must not be empty
               if Val_Len = 0 then
                  C.Bad_Ext_Content := True;
               end if;

               --  Dispatch based on the OID
               if OID_Match (DER, OID_Start, OID_Len, OID_SAN)
               then
                  Parse_Ext_SAN
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_BASIC)
               then
                  Parse_Ext_Basic_Constraints
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_KEY_USAGE)
               then
                  Parse_Ext_Key_Usage
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_SKID)
               then
                  Parse_Ext_SKID
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_AKID)
               then
                  Parse_Ext_AKID
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_INHIBIT)
               then
                  --  RFC 5280: MUST be critical
                  if not Is_Critical then
                     C.Bad_Ext_Criticality := True;
                  end if;
                  --  RFC 5280 §4.2.1.14: value is INTEGER,
                  --  must not be negative (high bit set)
                  if Pos <= DER'Last
                     and then DER (Pos) = TAG_INTEGER
                  then
                     declare
                        Int_Len : N32;
                        Int_Pos : N32 := Pos + 1;
                     begin
                        if Int_Pos <= DER'Last then
                           Parse_Length
                             (DER, Int_Pos, Int_Len, Valid);
                           if Valid and then Int_Len >= 1
                              and then Int_Pos <= DER'Last
                              and then DER (Int_Pos) >= 16#80#
                           then
                              C.Bad_Inhibit_Value := True;
                           end if;
                        end if;
                     end;
                  end if;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_NAME_CONS)
               then
                  --  RFC 5280 §4.2.1.10: NC MUST be critical.
                  --  We still process non-critical NC per X.509 §8.2.2.3,
                  --  but track it so validators can reject in strict mode.
                  --  RFC 5280 §4.2.1.10: only on CA certs
                  C.Has_Name_Constraints := True;
                  if not Is_Critical then
                     C.NC_Noncritical := True;
                  end if;
                  --  Parse NameConstraints SEQUENCE for subtree spans
                  if Pos <= DER'Last
                     and then DER (Pos) = TAG_SEQUENCE
                  then
                     declare
                        NC_Len : N32;
                        NC_End : N32;
                        NC_P   : N32;
                        NC_OK  : Boolean := True;
                     begin
                        NC_P := Pos;
                        Parse_Sequence (DER, NC_P, NC_Len, NC_OK);
                        if NC_OK and then Can_Read (DER, NC_P, NC_Len) then
                           NC_End := NC_P + NC_Len;
                           --  Look for [0] permittedSubtrees
                           if NC_P < NC_End and then NC_P <= DER'Last
                              and then DER (NC_P) = NC_PERMITTED
                           then
                              declare
                                 PT_Len : N32;
                              begin
                                 NC_P := NC_P + 1;
                                 if NC_P <= DER'Last then
                                    Parse_Length (DER, NC_P, PT_Len, NC_OK);
                                    if NC_OK and then PT_Len > 0
                                       and then Can_Read (DER, NC_P, PT_Len)
                                    then
                                       C.S_Permitted_Subtrees :=
                                         (First   => NC_P,
                                          Last    => NC_P + PT_Len - 1,
                                          Present => True);
                                       NC_P := NC_P + PT_Len;
                                    end if;
                                 end if;
                              end;
                           end if;
                           --  Look for [1] excludedSubtrees
                           if NC_OK and then NC_P < NC_End
                              and then NC_P <= DER'Last
                              and then DER (NC_P) = NC_EXCLUDED
                           then
                              declare
                                 ET_Len : N32;
                              begin
                                 NC_P := NC_P + 1;
                                 if NC_P <= DER'Last then
                                    Parse_Length (DER, NC_P, ET_Len, NC_OK);
                                    if NC_OK and then ET_Len > 0
                                       and then Can_Read (DER, NC_P, ET_Len)
                                    then
                                       C.S_Excluded_Subtrees :=
                                         (First   => NC_P,
                                          Last    => NC_P + ET_Len - 1,
                                          Present => True);
                                    end if;
                                 end if;
                              end;
                           end if;
                           --  RFC 5280 §4.2.1.10: NameConstraints MUST
                           --  have at least one non-empty subtree.
                           if not C.S_Permitted_Subtrees.Present
                              and not C.S_Excluded_Subtrees.Present
                           then
                              C.Bad_Ext_Content := True;
                           end if;
                        end if;
                     end;
                  end if;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_POLICY_CONS)
               then
                  --  RFC 5280 §4.2.1.11: PolicyConstraints MUST be critical
                  if not Is_Critical then
                     C.Bad_Ext_Criticality := True;
                  end if;
                  --  RFC 5280 §4.2.1.11: MUST NOT be empty sequence
                  if Val_Len = 2
                     and then Pos <= DER'Last
                     and then Pos + 1 <= DER'Last
                     and then DER (Pos) = TAG_SEQUENCE
                     and then DER (Pos + 1) = 0
                  then
                     C.Bad_Ext_Content := True;
                  end if;
                  --  RFC 5280 §4.2.1.9: pathLen without CA
                  --  (PolicyConstraints also needs non-CA check
                  --   but that's a different field)

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_POLICY_MAP)
               then
                  --  Note: RFC 5280 says MUST be critical (issuance req).
                  null;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_CERT_POLICIES)
               then
                  Parse_Ext_Cert_Policies
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_EKU)
               then
                  Parse_Ext_EKU
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_CRL_DP)
               then
                  Parse_Ext_CRL_DP
                    (DER, Pos, Val_Len, Is_Critical, C, Valid);

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_CT_SCT_V)
               then
                  --  RFC 6962 §3.3: SCT extension
                  --  Value must be nested OCTET STRING (0x04)
                  if Val_Len > 0
                     and then Pos <= DER'Last
                  then
                     if DER (Pos) /= 16#04# then
                        C.Bad_Ext_Content := True;
                     else
                        --  Check for trailing data: parse inner
                        --  OCTET STRING and verify it consumes
                        --  all of Val_Len
                        if Pos + 1 <= DER'Last then
                           declare
                              SCT_Pos : N32 := Pos + 1;
                              SCT_Len : N32;
                              SCT_OK  : Boolean := True;
                           begin
                              Parse_Length
                                (DER, SCT_Pos, SCT_Len, SCT_OK);
                              if SCT_OK then
                                 --  Inner tag(1) + length bytes
                                 --  + SCT_Len should equal Val_Len
                                 if SCT_Pos + SCT_Len /=
                                    Pos + Val_Len
                                 then
                                    C.Bad_Ext_Content := True;
                                 end if;
                              end if;
                           end;
                        end if;
                     end if;
                  end if;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_AIA)
                  or else OID_Match
                  (DER, OID_Start, OID_Len, OID_SIA)
               then
                  --  RFC 5280 §4.2.2.1/§4.2.2.2: MUST NOT be critical
                  if Is_Critical then
                     C.Bad_Ext_Criticality := True;
                  end if;
                  --  SEQUENCE SIZE (1..MAX) of AccessDescription
                  if Val_Len > 0 and then Pos <= DER'Last then
                     if DER (Pos) /= TAG_SEQUENCE then
                        --  Value must be a SEQUENCE
                        C.Bad_Ext_Content := True;
                     elsif Val_Len = 2
                        and then Pos + 1 <= DER'Last
                        and then DER (Pos + 1) = 0
                     then
                        --  Empty SEQUENCE (no AccessDescriptions)
                        C.Bad_Ext_Content := True;
                     end if;
                  end if;

               elsif OID_Match
                  (DER, OID_Start, OID_Len, OID_SUBJ_DIR_ATTR)
               then
                  --  RFC 5280 §4.2.1.8: MUST NOT be critical
                  if Is_Critical then
                     C.Bad_Ext_Criticality := True;
                  end if;
                  --  SEQUENCE of one or more
                  if Val_Len = 2
                     and then Pos <= DER'Last
                     and then Pos + 1 <= DER'Last
                     and then DER (Pos) = TAG_SEQUENCE
                     and then DER (Pos + 1) = 0
                  then
                     C.Bad_Ext_Content := True;
                  end if;

               else
                  --  Unknown extension
                  if Is_Critical then
                     C.Ext_Unknown_Critical := True;
                  end if;
               end if;
            end if;
            end;  --  Is_Critical declare block

            --  Advance to next extension regardless
            Pos := Ext_Seq_End;
         end if;
      end loop;
   end Parse_Extensions;

   --  7. Parse outer signature algorithm SEQUENCE + signature BIT STRING
   procedure Parse_Outer_Sig_And_Value
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      C     : in out Certificate;
      Valid : in out Boolean)
   with Pre => DER'First = 0 and DER'Last < N32'Last
   is
   begin
      if not Valid then return; end if;

      --  Signature Algorithm (again, should match first one)
      if Pos <= DER'Last then
         declare
            SA2_Len : N32;
            SA2_End : N32;
            SA2_Algo : Algorithm_ID;
         begin
            Parse_Sequence (DER, Pos, SA2_Len, Valid);
            if Valid and then not Can_Read (DER, Pos, SA2_Len) then
               Valid := False;
            end if;
            if Valid then
               SA2_End := Pos + SA2_Len;
               if Pos <= DER'Last then
                  pragma Warnings (Off, """Pos"" is set by ""Parse_Algorithm_OID"" but not used");
                  Parse_Algorithm_OID (DER, Pos, SA2_Algo, Valid);
                  pragma Warnings (On, """Pos"" is set by ""Parse_Algorithm_OID"" but not used");
                  C.Sig_Algo_2 := SA2_Algo;
               end if;
               Pos := SA2_End;  --  skip past entire algo sequence
            end if;
         end;
      end if;

      --  Signature Value (BIT STRING)
      if Valid and then Pos <= DER'Last and then DER (Pos) = TAG_BITSTRING then
         declare
            Sig_Len     : N32;
            Sig_Unused  : Byte;
         begin
            Pos := Pos + 1;
            if Pos <= DER'Last then
               Parse_Length (DER, Pos, Sig_Len, Valid);
               if Valid and then Sig_Len > 1 and then Pos <= DER'Last then
                  Sig_Unused := DER (Pos);
                  Pos := Pos + 1;
                  Sig_Len := Sig_Len - 1;
                  Copy_Bytes (DER, Pos, Sig_Len, C.Sig_Buf, C.Sig_Buf_Len);
               end if;
            end if;
         end;
      end if;
   end Parse_Outer_Sig_And_Value;

   --================================================================
   --  Main certificate parser (thin orchestrator)
   --================================================================


   procedure Parse_Certificate
     (DER  : in     Byte_Seq;
      Cert :    out Certificate;
      OK   :    out Boolean)
   is
      Pos       : N32 := 0;
      TBS_Start : N32;
      TBS_Len   : N32;
      Valid     : Boolean := True;

      --  Fields we'll populate
      C : Certificate;
   begin
      --  Initialize
      C := Certificate'(Valid_Flag          => False,
                         Cert_Version        => 0,
                         S_Issuer_CN         => (0, 0, False),
                         S_Issuer_Org        => (0, 0, False),
                         S_Issuer_Country    => (0, 0, False),
                         S_Subject_CN        => (0, 0, False),
                         S_Subject_Org       => (0, 0, False),
                         S_Subject_Country   => (0, 0, False),
                         S_Issuer_Raw        => (0, 0, False),
                         S_Subject_Raw       => (0, 0, False),
                         S_Permitted_Subtrees => (0, 0, False),
                         S_Excluded_Subtrees  => (0, 0, False),
                         S_Serial            => (0, 0, False),
                         S_TBS               => (0, 0, False),
                         Validity_Not_Before => (others => 0),
                         Validity_Not_After  => (others => 0),
                         PK_Algo             => Algo_Unknown,
                         PK_Buf              => (others => 0),
                         PK_Buf_Len          => 0,
                         PK_RSA_Exp          => 0,
                         Sig_Algo            => Algo_Unknown,
                         Sig_Buf             => (others => 0),
                         Sig_Buf_Len         => 0,
                         Ext_Is_CA           => False,
                         Ext_Has_Path_Len    => False,
                         Ext_Path_Len        => 0,
                         Ext_Key_Usage       => 0,
                         Ext_Has_Key_Usage   => False,
                         Ext_Key_Usage_Crit   => False,
                         Ext_Basic_Crit       => False,
                         Ext_Unknown_Critical => False,
                         Ext_Duplicate        => False,
                         Has_Extensions       => False,
                         Sig_Algo_2           => Algo_Unknown,
                         S_Auth_Key_ID       => (0, 0, False),
                         S_AKID_Serial       => (0, 0, False),
                         S_Subject_Key_ID    => (0, 0, False),
                         SANs                => (others => (0, 0, False)),
                         SAN_Num             => 0,
                         SAN_Ext_Value       => (0, 0, False),
                         SAN_Has_Email       => False,
                         SAN_Has_Other_Name  => False,
                         IP_SANs             => (others => (0, 0, False)),
                         IP_SAN_Num          => 0,
                         Bad_Ext_Criticality => False,
                         Bad_Serial          => False,
                         Bad_Time_Format     => False,
                         Bad_SAN             => False,
                         Empty_Key_Usage     => False,
                         Has_Subject         => False,
                         Has_Unique_ID       => False,
                         SAN_Noncrit_Empty_Subj => False,
                         Bad_Ext_Content     => False,
                         Bad_PubKey          => False,
                         AKID_Missing_Key_ID => False,
                         AKID_Has_Issuer     => False,
                         Has_Name_Constraints => False,
                         NC_Noncritical      => False,
                         Bad_Inhibit_Value   => False,
                         Bad_DER             => False,
                         Bad_Cert_Policy     => False,
                         Bad_AKID            => False,
                         Bad_Subject_Encoding => False,
                         Bad_EKU_Content     => False,
                         Ext_Has_EKU         => False,
                         EKU_Has_Any         => False,
                         EKU_Has_Server_Auth => False,
                         EKU_Is_Critical     => False,
                         Bad_CRL_DP          => False,
                         SAN_Critical_With_Subject => False,
                         V3_UniqueID_NoExts  => False);

      --  Outer SEQUENCE (Certificate)
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      Enter_Sequence (DER, Pos, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  TBS Certificate SEQUENCE
      TBS_Start := Pos;
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      Parse_Sequence (DER, Pos, TBS_Len, Valid);
      if not Valid then Cert := C; OK := False; return; end if;
      --  Verify TBS content fits within DER buffer (prevents N32 overflow)
      if not Can_Read (DER, Pos, TBS_Len) then
         Cert := C; OK := False; return;
      end if;
      C.S_TBS := (First => TBS_Start, Last => Pos + TBS_Len - 1, Present => True);

      --  Version + Serial
      Parse_Version_Serial (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  TBS Signature Algorithm
      Parse_TBS_Sig_Algorithm (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  Issuer (SEQUENCE of RDN SETs)
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      declare
         Issuer_Len : N32;
         Dummy_Enc  : Boolean := False;
      begin
         Parse_Sequence (DER, Pos, Issuer_Len, Valid);
         if not Valid then Cert := C; OK := False; return; end if;
         if Issuer_Len > 0 and then not Can_Read (DER, Pos, Issuer_Len) then
            Cert := C; OK := False; return;
         end if;
         C.S_Issuer_Raw := (First   => Pos,
                            Last    => Pos + Issuer_Len - 1,
                            Present => Issuer_Len > 0);
         Parse_Name (DER, Pos, Issuer_Len,
                     C.S_Issuer_CN, C.S_Issuer_Org, C.S_Issuer_Country,
                     Dummy_Enc, Valid);
      end;

      --  Validity
      Parse_Validity (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  Subject (SEQUENCE of RDN SETs)
      if Pos > DER'Last then Cert := C; OK := False; return; end if;
      declare
         Subject_Len : N32;
      begin
         Parse_Sequence (DER, Pos, Subject_Len, Valid);
         if not Valid then Cert := C; OK := False; return; end if;
         if Subject_Len > 0 and then not Can_Read (DER, Pos, Subject_Len) then
            Cert := C; OK := False; return;
         end if;
         C.Has_Subject := (Subject_Len > 0);
         C.S_Subject_Raw := (First   => Pos,
                             Last    => Pos + Subject_Len - 1,
                             Present => Subject_Len > 0);
         Parse_Name (DER, Pos, Subject_Len,
                     C.S_Subject_CN, C.S_Subject_Org, C.S_Subject_Country,
                     C.Bad_Subject_Encoding, Valid);
      end;

      --  SubjectPublicKeyInfo
      Parse_SPKI (DER, Pos, C, Valid);
      if not Valid then Cert := C; OK := False; return; end if;

      --  Optional Unique IDs
      Parse_Unique_IDs (DER, Pos, C, Valid);

      --  Extensions
      Parse_Extensions (DER, Pos, C, Valid);

      --  RFC 5280 §4.1.2.1: v3 with UniqueID but no extensions
      if C.Cert_Version = 3
         and then C.Has_Unique_ID
         and then not C.Has_Extensions
      then
         C.V3_UniqueID_NoExts := True;
      end if;

      --  Skip any remaining TBS bytes
      if Valid and then C.S_TBS.Present and then Pos <= C.S_TBS.Last then
         Pos := C.S_TBS.Last + 1;
      end if;

      --  Outer Signature Algorithm + Signature Value
      pragma Warnings (Off, """Pos"" is set by ""Parse_Outer_Sig_And_Value"" but not used");
      Parse_Outer_Sig_And_Value (DER, Pos, C, Valid);
      pragma Warnings (On, """Pos"" is set by ""Parse_Outer_Sig_And_Value"" but not used");

      C.Valid_Flag := Valid;
      Cert := C;
      OK := Valid;
   end Parse_Certificate;

end X509.Parser;
