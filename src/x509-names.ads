--  X509.Names — Hostname matching, issuer comparison, name constraints
--
--  All functions that compare certificate names against hostnames,
--  other certificates, or name constraint subtrees.

package X509.Names with
   SPARK_Mode => On
is
   function Matches_Hostname
     (Cert     : Certificate;
      DER      : Byte_Seq;
      Hostname : String) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last;

   --  CABF BR 7.1.4.3: if the cert has a Subject CN, it must be a
   --  byte-for-byte copy of a SAN dNSName or iPAddress value.
   --  Returns True if CN is absent, or if CN matches a SAN entry.
   function CN_In_SAN
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last;

   --  RFC 5280 §4.2.1.9: Self-issued cert (issuer == subject byte-equal).
   function Is_Self_Issued
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last;

   --  CABF 7.1.2.1.3: AKI keyIdentifier must be byte-equal to SKI.
   function AKI_Matches_SKI
     (Cert : Certificate;
      DER  : Byte_Seq) return Boolean
   with Pre => DER'First = 0 and DER'Last < N32'Last;

   --  RFC 5280 §7.1: Issuer DN matching with semantic normalization.
   function Issuer_Matches
     (Cert       : Certificate;
      Cert_DER   : Byte_Seq;
      Issuer     : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
               and Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last;

   --  RFC 5280 §4.2.1.10: Name constraints satisfaction.
   function Satisfies_Name_Constraints
     (Cert       : Certificate;
      Cert_DER   : Byte_Seq;
      Issuer     : Certificate;
      Issuer_DER : Byte_Seq) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last
               and Issuer_DER'First = 0 and Issuer_DER'Last < N32'Last;

end X509.Names;
