package body X509.DER_Ext with
   SPARK_Mode => On
is

   ----------------------------------------------------------------------------
   --  Time parsing (UTCTime / GeneralizedTime) -- copy of X509.Parser's
   ----------------------------------------------------------------------------

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

   --  NOTE: as in X509.Parser, Parse_Time_Value leaves OK True and T
   --  zeroed for an out-of-range calendar value (the certificate parser
   --  reports those through Bad_Time_Format). Parse_Time_TLV below turns
   --  that into OK = False, which is the behaviour the revocation
   --  verifiers want: a CRL or OCSP response with an unparseable time is
   --  unusable.

   procedure Parse_Time_TLV
     (DER  : in     Byte_Seq;
      Pos  : in out N32;
      T    :    out Date_Time;
      OK   : in out Boolean)
   is
      Tag     : constant Byte := DER (Pos);
      Old_Pos : constant N32  := Pos with Ghost;
      Len     : N32;
      Start   : N32;
   begin
      T := (others => 0);
      if Tag /= TAG_UTCTIME and then Tag /= TAG_GENTIME then
         OK := False; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Len, OK);
      if not OK then return; end if;
      --  Strict lengths: 13 for UTCTime, 15 for GeneralizedTime
      if (Tag = TAG_UTCTIME and then Len /= 13)
        or else (Tag = TAG_GENTIME and then Len /= 15)
      then
         OK := False; return;
      end if;
      if not Can_Read (DER, Pos, Len) then OK := False; return; end if;
      Start := Pos;
      pragma Assert (Start > Old_Pos);
      pragma Assert (Len <= DER'Last - Start + 1);
      pragma Assert (Start + Len <= DER'Last + 1);
      --  Must end in 'Z'
      if DER (Start + Len - 1) /= 16#5A# then OK := False; return; end if;
      Parse_Time_Value (DER, Pos, Len, T, OK);
      if not OK then return; end if;
      --  Parse_Time_Value reports a bad calendar field by leaving T zeroed
      if T.Month = 0 then OK := False; return; end if;
      pragma Assert (Pos = Start + Len);
      pragma Assert (Pos > Start);
      pragma Assert (Pos > Old_Pos);
   end Parse_Time_TLV;

   ----------------------------------------------------------------------------
   --  Header helpers with published advance
   ----------------------------------------------------------------------------

   procedure Parse_Sequence_Hdr
     (DER : in     Byte_Seq;
      Pos : in out N32;
      Len :    out N32;
      OK  : in out Boolean)
   is
   begin
      Len := 0;
      if DER (Pos) /= TAG_SEQUENCE then OK := False; return; end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Len, OK);
      if not OK then return; end if;
      if not Can_Read (DER, Pos, Len) then OK := False; return; end if;
   end Parse_Sequence_Hdr;

   procedure Enter_Explicit
     (DER      : in     Byte_Seq;
      Pos      : in out N32;
      Expected : in     Byte;
      Wrap_End :    out N32;
      OK       : in out Boolean)
   is
      Len : N32;
   begin
      Wrap_End := 0;
      if DER (Pos) /= Expected then OK := False; return; end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Len, OK);
      if not OK then return; end if;
      if not Can_Read (DER, Pos, Len) then OK := False; return; end if;
      Wrap_End := Pos + Len;
   end Enter_Explicit;

   procedure Enter_Octet_String
     (DER     : in     Byte_Seq;
      Pos     : in out N32;
      Str_End :    out N32;
      OK      : in out Boolean)
   is
      Len : N32;
   begin
      Str_End := 0;
      if DER (Pos) /= TAG_OCTETSTRING then OK := False; return; end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Len, OK);
      if not OK then return; end if;
      if not Can_Read (DER, Pos, Len) then OK := False; return; end if;
      Str_End := Pos + Len;
   end Enter_Octet_String;

   ----------------------------------------------------------------------------
   --  Extension walker
   ----------------------------------------------------------------------------

   procedure Next_Extension
     (DER       : in     Byte_Seq;
      Pos       : in out N32;
      OID_Start :    out N32;
      OID_Len   :    out N32;
      Critical  :    out Boolean;
      Val_Start :    out N32;
      Val_Len   :    out N32;
      OK        : in out Boolean)
   is
      Ext_Len : N32;
      Ext_End : N32;
   begin
      OID_Start := 0; OID_Len := 0; Critical := False;
      Val_Start := 0; Val_Len := 0;

      Parse_Sequence_Hdr (DER, Pos, Ext_Len, OK);
      if not OK then return; end if;
      Ext_End := Pos + Ext_Len;

      --  extnID OBJECT IDENTIFIER
      if Pos >= Ext_End or else DER (Pos) /= TAG_OID then
         OK := False; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, OID_Len, OK);
      if not OK then return; end if;
      if OID_Len = 0 or else not Can_Read (DER, Pos, OID_Len) then
         OK := False; return;
      end if;
      OID_Start := Pos;
      Pos := Pos + OID_Len;
      if Pos > Ext_End then OK := False; return; end if;

      --  critical BOOLEAN DEFAULT FALSE
      if Pos < Ext_End and then DER (Pos) = TAG_BOOLEAN then
         Parse_Boolean (DER, Pos, Critical, OK);
         if not OK then return; end if;
         if Pos > Ext_End then OK := False; return; end if;
      end if;

      --  extnValue OCTET STRING
      if Pos >= Ext_End or else DER (Pos) /= TAG_OCTETSTRING then
         OK := False; return;
      end if;
      Pos := Pos + 1;
      if Pos > DER'Last then OK := False; return; end if;
      Parse_Length (DER, Pos, Val_Len, OK);
      if not OK then return; end if;
      if Val_Len = 0 or else not Can_Read (DER, Pos, Val_Len) then
         OK := False; return;
      end if;
      Val_Start := Pos;
      Pos := Pos + Val_Len;
      --  The extension SEQUENCE must contain exactly these elements
      if Pos /= Ext_End then OK := False; return; end if;
   end Next_Extension;

   ----------------------------------------------------------------------------
   --  Distribution point name matching (RFC 5280 6.3.3)
   ----------------------------------------------------------------------------

   TAG_DPN_FULL     : constant Byte := 16#A0#;  --  [0] fullName GeneralNames
   TAG_DPN_RELATIVE : constant Byte := 16#A1#;  --  [1] nameRelativeToCRLIssuer
   TAG_DP_NAME      : constant Byte := 16#A0#;  --  DistributionPoint [0] EXPLICIT
   TAG_GN_DIRNAME   : constant Byte := 16#A4#;  --  GeneralName [4] directoryName

   --  Len bytes at A_First in A equal Len bytes at B_First in B.
   function Bytes_Equal
     (A : Byte_Seq; A_First : N32; B : Byte_Seq; B_First : N32; Len : N32)
      return Boolean
   with Pre => A'First = 0 and A'Last < N32'Last
               and B'First = 0 and B'Last < N32'Last
   is
   begin
      if Len = 0 then
         return True;
      end if;
      if not Can_Read (A, A_First, Len) or else not Can_Read (B, B_First, Len) then
         return False;
      end if;
      for I in N32 range 0 .. Len - 1 loop
         pragma Loop_Invariant (I < Len);
         if A (A_First + I) /= B (B_First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Bytes_Equal;

   --  The whole TLV at Pos (bounded by Limit): content start and length.
   --  On success Pos moves past the TLV.
   procedure Next_TLV
     (DER     : in     Byte_Seq;
      Pos     : in out N32;
      Limit   : in     N32;
      Tag     :    out Byte;
      C_Start :    out N32;
      C_Len   :    out N32;
      OK      :    out Boolean)
   with Pre  => DER'First = 0 and DER'Last < N32'Last and Limit <= DER'Last + 1,
        Post => (if OK then Pos > Pos'Old and Pos <= Limit
                 and C_Start <= DER'Last
                 and Can_Read (DER, C_Start, C_Len)
                 and C_Start + C_Len = Pos)
   is
      Len_OK : Boolean := True;
   begin
      Tag := 0; C_Start := 0; C_Len := 0; OK := False;
      if Pos >= Limit or else Pos > DER'Last then
         return;
      end if;
      Tag := DER (Pos);
      declare
         P : N32 := Pos + 1;
         L : N32;
      begin
         if P > DER'Last then
            return;
         end if;
         Parse_Length (DER, P, L, Len_OK);
         if not Len_OK then
            return;
         end if;
         if not Can_Read (DER, P, L) or else P + L > Limit then
            return;
         end if;
         C_Start := P;
         C_Len   := L;
         Pos     := P + L;
         OK      := True;
      end;
   end Next_TLV;

   --  Full = Issuer content followed by a SET TLV whose content is RDN
   --  (i.e. the DN obtained by appending the relative name to the
   --  issuer Name, RFC 5280 4.2.1.13).
   function Name_Is_Issuer_Plus_RDN
     (Full_DER   : Byte_Seq; Full_Start : N32; Full_Len : N32;
      Iss_DER    : Byte_Seq; Iss        : Span;
      RDN_DER    : Byte_Seq; RDN_Start  : N32; RDN_Len : N32) return Boolean
   with Pre => Full_DER'First = 0 and Full_DER'Last < N32'Last
               and Iss_DER'First = 0 and Iss_DER'Last < N32'Last
               and RDN_DER'First = 0 and RDN_DER'Last < N32'Last
               and Span_In_Range (Iss, Iss_DER'Last)
               and Can_Read (Full_DER, Full_Start, Full_Len)
               and Can_Read (RDN_DER, RDN_Start, RDN_Len)
   is
      IL  : constant N32 := Span_Length (Iss);
      Hdr : constant N32 :=
        (if RDN_Len < 128 then 2 elsif RDN_Len < 256 then 3 else 4);
      P   : N32;
   begin
      if RDN_Len >= 65_536 or else not Iss.Present then
         return False;
      end if;
      if Full_Len /= IL + Hdr + RDN_Len then
         return False;
      end if;
      if not Bytes_Equal (Full_DER, Full_Start, Iss_DER, Iss.First, IL) then
         return False;
      end if;
      P := Full_Start + IL;
      --  Full_Len = IL + Hdr + RDN_Len and Can_Read (Full, Full_Start,
      --  Full_Len): the header bytes P .. P + Hdr - 1 are readable.
      if not Can_Read (Full_DER, P, Hdr) then
         return False;
      end if;
      if Full_DER (P) /= TAG_SET then
         return False;
      end if;
      if Hdr = 2 then
         if Full_DER (P + 1) /= Byte (RDN_Len mod 256) then return False; end if;
      elsif Hdr = 3 then
         if Full_DER (P + 1) /= 16#81#
           or else Full_DER (P + 2) /= Byte (RDN_Len mod 256)
         then
            return False;
         end if;
      else
         if Full_DER (P + 1) /= 16#82#
           or else Full_DER (P + 2) /= Byte ((RDN_Len / 256) mod 256)
           or else Full_DER (P + 3) /= Byte (RDN_Len mod 256)
         then
            return False;
         end if;
      end if;
      return Bytes_Equal (Full_DER, P + Hdr, RDN_DER, RDN_Start, RDN_Len);
   end Name_Is_Issuer_Plus_RDN;

   --  Does GeneralName TLV (GN_Start, GN_Len = whole TLV) on side A
   --  match the DistributionPointName on side B? B is either a fullName
   --  (each of its GeneralNames must be compared) or a relative name
   --  (A must be a directoryName equal to B's issuer plus the RDN).
   function GN_Matches_DPN
     (A_DER    : Byte_Seq; GN_Start : N32; GN_Len : N32;
      B_DER    : Byte_Seq; B_Full   : Boolean;
      B_Start  : N32; B_Len : N32;      --  GeneralNames content or RDN content
      B_Issuer : Span) return Boolean
   with Pre => A_DER'First = 0 and A_DER'Last < N32'Last
               and B_DER'First = 0 and B_DER'Last < N32'Last
               and Can_Read (A_DER, GN_Start, GN_Len)
               and Can_Read (B_DER, B_Start, B_Len)
               and Span_In_Range (B_Issuer, B_DER'Last)
   is
   begin
      if B_Full then
         --  Compare against every GeneralName of B
         declare
            P     : N32 := B_Start;
            Limit : constant N32 := B_Start + B_Len;
         begin
            while P < Limit loop
               pragma Loop_Invariant (P >= B_Start and P <= B_DER'Last);
               pragma Loop_Variant (Increases => P);
               declare
                  Tag     : Byte;
                  C_Start : N32;
                  C_Len   : N32;
                  T_Start : constant N32 := P;
                  OK      : Boolean;
               begin
                  Next_TLV (B_DER, P, Limit, Tag, C_Start, C_Len, OK);
                  if not OK then
                     return False;
                  end if;
                  if P - T_Start = GN_Len
                    and then Bytes_Equal (A_DER, GN_Start, B_DER, T_Start, GN_Len)
                  then
                     return True;
                  end if;
               end;
            end loop;
            return False;
         end;
      else
         --  A must be a directoryName whose Name is B's issuer + RDN
         if GN_Len < 2 or else A_DER (GN_Start) /= TAG_GN_DIRNAME then
            return False;
         end if;
         declare
            P       : N32 := GN_Start;
            Limit   : constant N32 := GN_Start + GN_Len;
            Tag     : Byte;
            C_Start : N32;
            C_Len   : N32;
            OK      : Boolean;
            N_Start : N32;
            N_Len   : N32;
         begin
            --  [4] wrapper, then the Name SEQUENCE
            Next_TLV (A_DER, P, Limit, Tag, C_Start, C_Len, OK);
            if not OK or else P /= Limit then
               return False;
            end if;
            P := C_Start;
            Next_TLV (A_DER, P, C_Start + C_Len, Tag, N_Start, N_Len, OK);
            if not OK or else Tag /= TAG_SEQUENCE or else P /= C_Start + C_Len then
               return False;
            end if;
            return Name_Is_Issuer_Plus_RDN
                     (A_DER, N_Start, N_Len, B_DER, B_Issuer,
                      B_DER, B_Start, B_Len);
         end;
      end if;
   end GN_Matches_DPN;

   --  Match one DistributionPointName TLV (cert side) against the IDP's.
   function DPN_Matches
     (Cert_DER    : Byte_Seq; Cert_DPN : Span; Cert_Issuer : Span;
      CRL_DER     : Byte_Seq; IDP_DPN  : Span; CRL_Issuer  : Span) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
               and CRL_DER'First = 0 and CRL_DER'Last < N32'Last
               and Span_In_Range (Cert_DPN, Cert_DER'Last)
               and Span_In_Range (Cert_Issuer, Cert_DER'Last)
               and Span_In_Range (IDP_DPN, CRL_DER'Last)
               and Span_In_Range (CRL_Issuer, CRL_DER'Last)
   is
      C_Tag, I_Tag       : Byte;
      C_Start, C_Len     : N32;
      I_Start, I_Len     : N32;
      C_OK, I_OK         : Boolean;
      PC, PI             : N32;
   begin
      if not Cert_DPN.Present or else not IDP_DPN.Present then
         return False;
      end if;
      PC := Cert_DPN.First;
      Next_TLV (Cert_DER, PC, Cert_DPN.Last + 1, C_Tag, C_Start, C_Len, C_OK);
      PI := IDP_DPN.First;
      Next_TLV (CRL_DER, PI, IDP_DPN.Last + 1, I_Tag, I_Start, I_Len, I_OK);
      if not C_OK or else not I_OK then
         return False;
      end if;
      if C_Tag not in TAG_DPN_FULL | TAG_DPN_RELATIVE
        or else I_Tag not in TAG_DPN_FULL | TAG_DPN_RELATIVE
      then
         return False;
      end if;

      if C_Tag = TAG_DPN_RELATIVE and then I_Tag = TAG_DPN_RELATIVE then
         --  Both relative to (the same) issuer: the RDNs must be equal
         return C_Len = I_Len
           and then Bytes_Equal (Cert_DER, C_Start, CRL_DER, I_Start, C_Len);
      elsif C_Tag = TAG_DPN_FULL then
         --  Each of the certificate's GeneralNames against the IDP
         declare
            P     : N32 := C_Start;
            Limit : constant N32 := C_Start + C_Len;
         begin
            while P < Limit loop
               pragma Loop_Invariant (P >= C_Start and P <= Cert_DER'Last);
               pragma Loop_Variant (Increases => P);
               declare
                  Tag     : Byte;
                  G_Start : N32;
                  G_Len   : N32;
                  T_Start : constant N32 := P;
                  OK      : Boolean;
               begin
                  Next_TLV (Cert_DER, P, Limit, Tag, G_Start, G_Len, OK);
                  if not OK then
                     return False;
                  end if;
                  if GN_Matches_DPN (Cert_DER, T_Start, P - T_Start,
                                     CRL_DER, I_Tag = TAG_DPN_FULL,
                                     I_Start, I_Len, CRL_Issuer)
                  then
                     return True;
                  end if;
               end;
            end loop;
            return False;
         end;
      else
         --  Certificate relative, IDP full: some IDP directoryName must
         --  equal the certificate's issuer plus the RDN
         declare
            P     : N32 := I_Start;
            Limit : constant N32 := I_Start + I_Len;
         begin
            while P < Limit loop
               pragma Loop_Invariant (P >= I_Start and P <= CRL_DER'Last);
               pragma Loop_Variant (Increases => P);
               declare
                  Tag     : Byte;
                  G_Start : N32;
                  G_Len   : N32;
                  T_Start : constant N32 := P;
                  OK      : Boolean;
               begin
                  Next_TLV (CRL_DER, P, Limit, Tag, G_Start, G_Len, OK);
                  if not OK then
                     return False;
                  end if;
                  if GN_Matches_DPN (CRL_DER, T_Start, P - T_Start,
                                     Cert_DER, False,
                                     C_Start, C_Len, Cert_Issuer)
                  then
                     return True;
                  end if;
               end;
            end loop;
            return False;
         end;
      end if;
   end DPN_Matches;

   function DP_Name_Matches
     (Cert_DER    : Byte_Seq;
      CRL_DP_Ext  : Span;
      Cert_Issuer : Span;
      CRL_DER     : Byte_Seq;
      IDP_DPN     : Span;
      CRL_Issuer  : Span) return Boolean
   is
      P       : N32;
      Tag     : Byte;
      L_Start : N32;
      L_Len   : N32;
      OK      : Boolean;
      Limit   : N32;
   begin
      if not CRL_DP_Ext.Present or else not IDP_DPN.Present then
         return False;
      end if;
      --  SEQUENCE OF DistributionPoint
      P := CRL_DP_Ext.First;
      Next_TLV (Cert_DER, P, CRL_DP_Ext.Last + 1, Tag, L_Start, L_Len, OK);
      if not OK or else Tag /= TAG_SEQUENCE then
         return False;
      end if;
      P := L_Start;
      Limit := L_Start + L_Len;
      while P < Limit loop
         pragma Loop_Invariant (P >= L_Start and P <= Cert_DER'Last);
         pragma Loop_Variant (Increases => P);
         declare
            D_Tag   : Byte;
            D_Start : N32;
            D_Len   : N32;
            D_OK    : Boolean;
         begin
            --  DistributionPoint ::= SEQUENCE { [0] distributionPoint ... }
            Next_TLV (Cert_DER, P, Limit, D_Tag, D_Start, D_Len, D_OK);
            if not D_OK or else D_Tag /= TAG_SEQUENCE then
               return False;
            end if;
            if D_Len > 0 and then Cert_DER (D_Start) = TAG_DP_NAME then
               declare
                  Q       : N32 := D_Start;
                  W_Tag   : Byte;
                  W_Start : N32;
                  W_Len   : N32;
                  W_OK    : Boolean;
               begin
                  Next_TLV (Cert_DER, Q, D_Start + D_Len, W_Tag, W_Start, W_Len, W_OK);
                  if W_OK and then W_Len > 0
                    and then DPN_Matches
                               (Cert_DER,
                                (First => W_Start, Last => W_Start + W_Len - 1, Present => True),
                                Cert_Issuer, CRL_DER, IDP_DPN, CRL_Issuer)
                  then
                     return True;
                  end if;
               end;
            end if;
         end;
      end loop;
      return False;
   end DP_Name_Matches;

   ----------------------------------------------------------------------------
   --  BOOLEAN
   ----------------------------------------------------------------------------

   procedure Parse_Boolean
     (DER   : in     Byte_Seq;
      Pos   : in out N32;
      Value :    out Boolean;
      OK    : in out Boolean)
   is
   begin
      Value := False;
      if DER (Pos) /= TAG_BOOLEAN then OK := False; return; end if;
      if not Can_Read (DER, Pos, 3) then OK := False; return; end if;
      if DER (Pos + 1) /= 1 then OK := False; return; end if;
      Value := DER (Pos + 2) /= 0;
      Pos := Pos + 3;
   end Parse_Boolean;

end X509.DER_Ext;
