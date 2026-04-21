with X509.DER; use X509.DER;
with X509.Names;
with X509.Parser;

package body X509 with
   SPARK_Mode => On
is

   function Spans_Valid
     (Cert     : Certificate;
      DER_Last : N32) return Boolean
   is
      function OK (S : Span) return Boolean is
        (Span_In_Range (S, DER_Last));
   begin
      return OK (Cert.S_TBS)
         and then OK (Cert.S_Serial)
         and then OK (Cert.S_Issuer_CN)
         and then OK (Cert.S_Issuer_Org)
         and then OK (Cert.S_Issuer_Country)
         and then OK (Cert.S_Subject_CN)
         and then OK (Cert.S_Subject_Org)
         and then OK (Cert.S_Subject_Country)
         and then OK (Cert.S_Issuer_Raw)
         and then OK (Cert.S_Subject_Raw)
         and then OK (Cert.S_Auth_Key_ID)
         and then OK (Cert.S_AKID_Serial)
         and then OK (Cert.S_Subject_Key_ID)
         and then OK (Cert.SAN_Ext_Value)
         and then OK (Cert.S_Permitted_Subtrees)
         and then OK (Cert.S_Excluded_Subtrees)
         and then (for all I in 1 .. Max_SANs =>
                     OK (Cert.SANs (I)))
         and then (for all I in 1 .. Max_SANs =>
                     OK (Cert.IP_SANs (I)));
   end Spans_Valid;

   function Algorithms_Valid (Cert : Certificate) return Boolean is
     (Cert.Sig_Algo /= Algo_Unknown
      and then Cert.Sig_Algo_2 /= Algo_Unknown
      and then Cert.Sig_Algo = Cert.Sig_Algo_2
      and then Cert.PK_Algo /= Algo_Unknown);

   procedure Parse
     (DER  : in     Byte_Seq;
      Cert :    out Certificate;
      OK   :    out Boolean)
   is
   begin
      Parser.Parse_Certificate (DER, Cert, OK);
   end Parse;


   --================================================================
   --  Getter implementations (expression functions)
   --================================================================

   function Is_Valid   (Cert : Certificate) return Boolean is (Cert.Valid_Flag);
   function Version    (Cert : Certificate) return Natural is (Cert.Cert_Version);

   function Issuer_CN       (Cert : Certificate) return Span is (Cert.S_Issuer_CN);
   function Issuer_Org      (Cert : Certificate) return Span is (Cert.S_Issuer_Org);
   function Issuer_Country  (Cert : Certificate) return Span is (Cert.S_Issuer_Country);

   function Subject_CN      (Cert : Certificate) return Span is (Cert.S_Subject_CN);
   function Subject_Org     (Cert : Certificate) return Span is (Cert.S_Subject_Org);
   function Subject_Country (Cert : Certificate) return Span is (Cert.S_Subject_Country);

   function Has_Issuer_CN   (Cert : Certificate) return Boolean is (Cert.S_Issuer_CN.Present);
   function Has_Subject_CN  (Cert : Certificate) return Boolean is (Cert.S_Subject_CN.Present);

   function SAN_Count (Cert : Certificate) return Natural is (Cert.SAN_Num);
   function SAN_DNS   (Cert : Certificate; Index : Positive) return Span is
     (Cert.SANs (Index));

   function IP_SAN_Count (Cert : Certificate) return Natural is
     (Cert.IP_SAN_Num);
   function IP_SAN (Cert : Certificate; Index : Positive) return Span is
     (Cert.IP_SANs (Index));

   function PK_Algorithm  (Cert : Certificate) return Algorithm_ID is (Cert.PK_Algo);
   function PK_Length      (Cert : Certificate) return N32 is (Cert.PK_Buf_Len);
   function PK_Data        (Cert : Certificate) return Byte_Seq is
     (Cert.PK_Buf (0 .. Cert.PK_Buf_Len - 1));
   function RSA_Exponent   (Cert : Certificate) return Unsigned_32 is (Cert.PK_RSA_Exp);

   function Sig_Algorithm  (Cert : Certificate) return Algorithm_ID is (Cert.Sig_Algo);
   function Sig_Length      (Cert : Certificate) return N32 is (Cert.Sig_Buf_Len);
   function Sig_Data        (Cert : Certificate) return Byte_Seq is
     (Cert.Sig_Buf (0 .. Cert.Sig_Buf_Len - 1));

   function TBS (Cert : Certificate) return Span is (Cert.S_TBS);

   function Not_Before (Cert : Certificate) return Date_Time is (Cert.Validity_Not_Before);
   function Not_After  (Cert : Certificate) return Date_Time is (Cert.Validity_Not_After);

   function Is_CA         (Cert : Certificate) return Boolean is (Cert.Ext_Is_CA);
   function Has_Path_Len_Constraint (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_Path_Len);
   function Path_Len_Constraint (Cert : Certificate) return Natural is
     (Cert.Ext_Path_Len);
   function Has_Key_Usage (Cert : Certificate) return Boolean is (Cert.Ext_Has_Key_Usage);

   function KU_Digital_Signature (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#8000#) /= 0);
   function KU_Key_Encipherment  (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#2000#) /= 0);
   function KU_Key_Cert_Sign     (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#0400#) /= 0);
   function KU_CRL_Sign          (Cert : Certificate) return Boolean is
     ((Cert.Ext_Key_Usage and 16#0200#) /= 0);

   function Authority_Key_ID (Cert : Certificate) return Span is (Cert.S_Auth_Key_ID);
   function AKID_Serial (Cert : Certificate) return Span is (Cert.S_AKID_Serial);
   function Subject_Key_ID   (Cert : Certificate) return Span is (Cert.S_Subject_Key_ID);

   function Serial (Cert : Certificate) return Span is (Cert.S_Serial);

   --================================================================
   --  Validation functions
   --================================================================

   function Is_Date_Valid
     (Cert : Certificate;
      Now  : Date_Time) return Boolean
   is
   begin
      if not Cert.Valid_Flag then
         return False;
      end if;
      return DT_Before_Or_Equal (Cert.Validity_Not_Before, Now)
         and then DT_Before_Or_Equal (Now, Cert.Validity_Not_After);
   end Is_Date_Valid;


   function Matches_Hostname
     (Cert     : Certificate;
      DER      : Byte_Seq;
      Hostname : String) return Boolean
   is (Names.Matches_Hostname (Cert, DER, Hostname));

   function Is_Self_Issued
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   is (Names.Is_Self_Issued (Cert, DER));

   function AKI_Matches_SKI
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   is (Names.AKI_Matches_SKI (Cert, DER));

   function CN_In_SAN
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   is (Names.CN_In_SAN (Cert, DER));

   function Has_Unknown_Critical_Extension (Cert : Certificate) return Boolean is
     (Cert.Ext_Unknown_Critical);

   function Has_Duplicate_Extension (Cert : Certificate) return Boolean is
     (Cert.Ext_Duplicate);

   function Has_Extensions (Cert : Certificate) return Boolean is
     (Cert.Has_Extensions);

   function Sig_Algorithm_2 (Cert : Certificate) return Algorithm_ID is
     (Cert.Sig_Algo_2);

   function Is_Key_Usage_Critical (Cert : Certificate) return Boolean is
     (Cert.Ext_Key_Usage_Crit);

   function Is_Basic_Constraints_Critical (Cert : Certificate) return Boolean is
     (Cert.Ext_Basic_Crit);

   function Has_Key_Cert_Sign_Without_CA (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_Key_Usage
      and then (Cert.Ext_Key_Usage and 16#0400#) /= 0
      and then not Cert.Ext_Is_CA);

   function Has_Bad_Extension_Criticality (Cert : Certificate) return Boolean is
     (Cert.Bad_Ext_Criticality);

   function Has_Bad_Serial (Cert : Certificate) return Boolean is
     (Cert.Bad_Serial);

   function Has_Bad_Time_Format (Cert : Certificate) return Boolean is
     (Cert.Bad_Time_Format);

   function Has_Bad_SAN (Cert : Certificate) return Boolean is
     (Cert.Bad_SAN);

   function Has_Empty_Key_Usage_Value (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_Key_Usage and then Cert.Empty_Key_Usage);

   function CA_Missing_Subject_Key_ID (Cert : Certificate) return Boolean is
     (Cert.Ext_Is_CA and then not Cert.S_Subject_Key_ID.Present);

   function Has_Unique_ID_Version_Error (Cert : Certificate) return Boolean is
     (Cert.Has_Unique_ID and then Cert.Cert_Version < 2);

   function Has_SAN_Subject_Error (Cert : Certificate) return Boolean is
     (Cert.SAN_Noncrit_Empty_Subj);

   function Has_Bad_Ext_Content (Cert : Certificate) return Boolean is
     (Cert.Bad_Ext_Content);

   function Has_Bad_PubKey (Cert : Certificate) return Boolean is
     (Cert.Bad_PubKey);

   function Has_AKID_Missing_Key_ID (Cert : Certificate) return Boolean is
     (Cert.AKID_Missing_Key_ID);

   function Has_AKID_Issuer (Cert : Certificate) return Boolean is
     (Cert.AKID_Has_Issuer);

   function Has_Name_Constraints_NonCA (Cert : Certificate) return Boolean is
     (Cert.Has_Name_Constraints and then not Cert.Ext_Is_CA);

   function Has_NC_Noncritical (Cert : Certificate) return Boolean is
     (Cert.NC_Noncritical);

   function Has_Bad_Inhibit_Value (Cert : Certificate) return Boolean is
     (Cert.Bad_Inhibit_Value);

   function Has_Bad_DER (Cert : Certificate) return Boolean is
     (Cert.Bad_DER);

   function Has_Bad_Cert_Policy (Cert : Certificate) return Boolean is
     (Cert.Bad_Cert_Policy);

   function Has_Bad_AKID (Cert : Certificate) return Boolean is
     (Cert.Bad_AKID);

   function Has_Bad_Subject_Encoding (Cert : Certificate) return Boolean is
     (Cert.Bad_Subject_Encoding);

   function Has_Bad_EKU_Content (Cert : Certificate) return Boolean is
     (Cert.Bad_EKU_Content);

   function Has_Bad_CRL_DP (Cert : Certificate) return Boolean is
     (Cert.Bad_CRL_DP);

   function Has_SAN_Critical_With_Subject (Cert : Certificate) return Boolean is
     (Cert.SAN_Critical_With_Subject);

   function Has_V3_UniqueID_NoExts (Cert : Certificate) return Boolean is
     (Cert.V3_UniqueID_NoExts);

   function Has_Path_Len_Without_CA (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_Path_Len and then not Cert.Ext_Is_CA);

   function Is_Structurally_Valid
     (Cert : Certificate;
      Now  : Date_Time) return Boolean
   is
   begin
      --  Must have parsed successfully
      if not Cert.Valid_Flag then
         return False;
      end if;

      --  Must not have unrecognized critical extensions
      if Cert.Ext_Unknown_Critical then
         return False;
      end if;

      --  Must be within validity period
      if not Is_Date_Valid (Cert, Now) then
         return False;
      end if;

      --  Must have a known signature algorithm
      if Cert.Sig_Algo = Algo_Unknown then
         return False;
      end if;

      --  Must have a known public key algorithm
      if Cert.PK_Algo = Algo_Unknown then
         return False;
      end if;

      --  Must have TBS data for signature verification
      if not Cert.S_TBS.Present then
         return False;
      end if;

      --  Version/extension consistency (RFC 5280 Section 4.1.2.1)
      --  v1 and v2 certs MUST NOT have extensions
      if Cert.Cert_Version < 3 and then Cert.Has_Extensions then
         return False;
      end if;

      --  Duplicate extensions (RFC 5280 Section 4.2)
      if Cert.Ext_Duplicate then
         return False;
      end if;

      --  Signature algorithm (RFC 5280 Section 4.1.1.2)
      --  Both inner and outer must be recognized, and must match.
      --  Unknown algorithms can't be verified — reject.
      if Cert.Sig_Algo = Algo_Unknown
         or else Cert.Sig_Algo_2 = Algo_Unknown
         or else Cert.Sig_Algo /= Cert.Sig_Algo_2
      then
         return False;
      end if;

      --  Note: RFC 5280 §4.2.1.3 says conforming CAs MUST mark KU critical,
      --  but X.509 §8.2.2.3 says if non-critical and recognized, the
      --  validator SHALL still enforce the bits.  We enforce the bits
      --  (keyCertSign check below) but don't reject non-critical KU.
      --  PKITS tests 30, 33 confirm non-critical KU should be accepted.

      --  Note: RFC 5280 §4.2.1.9 says conforming CAs MUST mark BC critical,
      --  but this is a CA issuance requirement, not a validator requirement.
      --  X.509 §8.4.2.1: if BC is present with cA=true, treat as CA
      --  regardless of criticality.  PKITS test 26 confirms this.

      --  RFC 5280 §4.2.1.9: pathLen only when cA is TRUE
      if Cert.Ext_Has_Path_Len and then not Cert.Ext_Is_CA then
         return False;
      end if;

      --  RFC 5280 §4.2.1.6: if only identity is email, subject must be empty
      if Cert.SAN_Has_Email and then Cert.SAN_Num = 0
         and then Cert.Has_Subject
      then
         return False;
      end if;

      --  keyCertSign in Key Usage requires CA (RFC 5280 Section 4.2.1.3)
      if Has_Key_Cert_Sign_Without_CA (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2: Extension criticality enforcement
      if Cert.Bad_Ext_Criticality then
         return False;
      end if;

      --  RFC 5280 §4.1.2.2: Serial number validation
      if Cert.Bad_Serial then
         return False;
      end if;

      --  RFC 5280 §4.1.2.5: Time format validation
      if Cert.Bad_Time_Format then
         return False;
      end if;

      --  RFC 5280 §4.2.1.6: SAN must not be malformed
      if Cert.Bad_SAN then
         return False;
      end if;

      --  RFC 5280 §4.2.1.3: Key Usage must have at least one bit set
      if Cert.Ext_Has_Key_Usage and then Cert.Empty_Key_Usage then
         return False;
      end if;

      --  RFC 5280 §4.2.1.2: CA certs should have Subject Key ID
      if Cert.Ext_Is_CA and then not Cert.S_Subject_Key_ID.Present then
         return False;
      end if;

      --  RFC 5280 §4.1.2.8: uniqueIDs only in v2 and v3
      if Has_Unique_ID_Version_Error (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2.1.6: SAN must be critical if subject is empty
      if Has_SAN_Subject_Error (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2: Extension value must not be empty
      if Cert.Bad_Ext_Content then
         return False;
      end if;

      --  RFC 5280 §4.2.1.1: Public key must be structurally valid
      if Cert.Bad_PubKey then
         return False;
      end if;

      --  RFC 5280 §4.2.1.1: AKID must contain keyIdentifier
      if Cert.AKID_Missing_Key_ID then
         return False;
      end if;

      --  RFC 5280 §4.2.1.10: NameConstraints only on CA certs
      if Has_Name_Constraints_NonCA (Cert) then
         return False;
      end if;

      --  RFC 5280 §4.2.1.14: InhibitAnyPolicy must not be negative
      if Cert.Bad_Inhibit_Value then
         return False;
      end if;

      --  RFC 5280 Appendix A / X.690: Valid DER encoding
      if Cert.Bad_DER then
         return False;
      end if;

      --  RFC 5280 §4.2.1.4: Certificate policies
      if Cert.Bad_Cert_Policy then
         return False;
      end if;

      --  RFC 5280 §4.2.1.1: AuthKeyID issuer/serial both or neither
      if Cert.Bad_AKID then
         return False;
      end if;

      --  RFC 5280 §4.1.2.6: Subject encoding
      if Cert.Bad_Subject_Encoding then
         return False;
      end if;

      --  RFC 5280 §4.2.1.12: EKU valid OIDs
      if Cert.Bad_EKU_Content then
         return False;
      end if;

      --  RFC 5280 §4.2.1.13: CRL DP not reasons-only
      if Cert.Bad_CRL_DP then
         return False;
      end if;

      --  RFC 5280 §4.2.1.6: SAN critical with non-empty subject
      if Cert.SAN_Critical_With_Subject then
         return False;
      end if;

      --  RFC 5280 §4.1.2.1: v3 UniqueID without extensions
      if Cert.V3_UniqueID_NoExts then
         return False;
      end if;

      return True;
   end Is_Structurally_Valid;

   --================================================================
   --  Chain validation functions
   --================================================================


   function Issuer_Matches
     (Cert       : Certificate;
      Cert_DER   : Byte_Seq;
      Issuer     : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   is (Names.Issuer_Matches (Cert, Cert_DER, Issuer, Issuer_DER));


   function Issuer_May_Sign (Issuer : Certificate) return Boolean is
   begin
      --  If issuer has no Key Usage extension, signing is implicitly allowed
      if not Issuer.Ext_Has_Key_Usage then
         return True;
      end if;
      --  keyCertSign bit (bit 5 from MSB = 0x0400 in our 16-bit representation)
      return (Issuer.Ext_Key_Usage and 16#0400#) /= 0;
   end Issuer_May_Sign;

   function Issuer_EKU_Allows_Signing (Issuer : Certificate) return Boolean is
   begin
      --  No EKU means unrestricted
      if not Issuer.Ext_Has_EKU then
         return True;
      end if;
      --  anyExtendedKeyUsage allows everything
      if Issuer.EKU_Has_Any then
         return True;
      end if;
      --  RFC 5280 Section 4.2.1.12: If EKU is present on a CA cert,
      --  it constrains what the CA can sign. A CA with serverAuth
      --  or clientAuth EKU can sign TLS certs. Google, Let's Encrypt,
      --  and other major CAs commonly include these on intermediates.
      if Issuer.EKU_Has_Server_Auth then
         return True;
      end if;
      --  EKU present but no recognized signing-related purpose
      return False;
   end Issuer_EKU_Allows_Signing;

   function Has_EKU_Server_Auth (Cert : Certificate) return Boolean is
     (Cert.EKU_Has_Server_Auth);

   function Has_EKU_Any_Purpose (Cert : Certificate) return Boolean is
     (Cert.EKU_Has_Any);

   function Has_EKU (Cert : Certificate) return Boolean is
     (Cert.Ext_Has_EKU);

   function Is_EKU_Critical (Cert : Certificate) return Boolean is
     (Cert.EKU_Is_Critical);


   function Satisfies_Name_Constraints
     (Cert       : Certificate;
      Cert_DER   : Byte_Seq;
      Issuer     : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   is (Names.Satisfies_Name_Constraints (Cert, Cert_DER, Issuer, Issuer_DER));


end X509;
