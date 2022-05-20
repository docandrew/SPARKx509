with X509Ada; use X509Ada;

package body OID
   with SPARK_Mode
is
   function To_String (Bytes : Byte_Seq) return String is
      Ret : String (1 .. Bytes'Length);
   begin
      for I in Ret'Range loop
         Ret (I) := Character'Val (Bytes (Bytes'First + Natural (I) - 1));
      end loop;

      return Ret;
   end To_String;

   --   packed byte representations of each of these object identifiers

   DOMAIN_COMPONENT_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F2#, 16#2C#, 16#64#,
       16#01#, 16#19#));
   A_RECORD_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F3#, 16#2C#, 16#64#,
       16#01#, 16#1A#));
   MX_RECORD_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F3#, 16#2C#, 16#64#,
       16#01#, 16#1C#));
   NS_RECORD_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F3#, 16#2C#, 16#64#,
       16#01#, 16#1D#));
   SOA_RECORD_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F3#, 16#2C#, 16#64#,
       16#01#, 16#1E#));
   CNAME_RECORD_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F3#, 16#2C#, 16#64#,
       16#01#, 16#1F#));
   ASSOCIATED_DOMAIN_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F3#, 16#2C#, 16#64#,
       16#01#, 16#25#));
   ASSOCIATED_NAME_STR : constant String := To_String (
      (16#09#, 16#92#, 16#26#, 16#89#, 16#93#, 16#F3#, 16#2C#, 16#64#,
       16#01#, 16#26#));

   RSA_ENCRYPTION_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#01#));
   MD2_WITH_RSA_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#02#));
   MD4_WITH_RSA_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#03#));
   MD5_WITH_RSA_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#04#));
   RSA_OAEP_ENCRYPTION_SET_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#06#));
   ID_RSAES_OAEP_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#07#));
   ID_MGF1_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#08#));
   ID_PSPECIFIED_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#09#));
   RSASSA_PSS_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#0A#));
   SHA256_WITH_RSA_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#0B#));
   SHA384_WITH_RSA_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#0C#));
   SHA512_WITH_RSA_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#0D#));
   SHA224_WITH_RSA_STR : constant String := To_String (
      (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 
       16#0E#));

   ID_X25519_STR : constant String := To_String (
      (16#2B#, 16#65#, 16#6E#));
   ID_X448_STR : constant String := To_String (
      (16#2B#, 16#65#, 16#6F#));
   ID_EDDSA25519_STR : constant String := To_String (
      (16#2B#, 16#65#, 16#70#));
   ID_EDDSA448_STR : constant String := To_String (
      (16#2B#, 16#65#, 16#71#));
   ID_EDDSA25519_PH_STR : constant String := To_String (
      (16#2B#, 16#65#, 16#72#));
   ID_EDDSA448_PH_STR : constant String := To_String (
      (16#2B#, 16#65#, 16#73#));

   OBJECT_CLASS_STR : constant String := To_String (
      (16#55#, 16#04#, 16#00#));
   ALIASED_ENTRY_NAME_STR : constant String := To_String (
      (16#55#, 16#04#, 16#01#));
   KNOWLEDGE_INFORMATION_STR : constant String := To_String (
      (16#55#, 16#04#, 16#02#));
   COMMON_NAME_STR : constant String := To_String (
      (16#55#, 16#04#, 16#03#));
   SURNAME_STR : constant String := To_String (
      (16#55#, 16#04#, 16#04#));
   SERIAL_NUMBER_STR : constant String := To_String (
      (16#55#, 16#04#, 16#05#));
   COUNTRY_STR : constant String := To_String (
      (16#55#, 16#04#, 16#06#));
   LOCALITY_STR : constant String := To_String (
      (16#55#, 16#04#, 16#07#));
   STATE_OR_PROVINCE_STR : constant String := To_String (
      (16#55#, 16#04#, 16#08#));
   STREET_ADDRESS_STR : constant String := To_String (
      (16#55#, 16#04#, 16#09#));
   ORG_STR : constant String := To_String (
      (16#55#, 16#04#, 16#0A#));
   ORG_UNIT_STR : constant String := To_String (
      (16#55#, 16#04#, 16#0B#));
   TITLE_STR : constant String := To_String (
      (16#55#, 16#04#, 16#0C#));
   DESCRIPTION_STR : constant String := To_String (
      (16#55#, 16#04#, 16#0D#));

   GIVEN_NAME_STR : constant String := To_String (
      (16#55#, 16#04#, 16#2A#));
   INITIALS_STR : constant String := To_String (
      (16#55#, 16#04#, 16#2B#));
   GENERATION_QUALIFIER_STR : constant String := To_String (
      (16#55#, 16#04#, 16#2C#));
   DISTINGUISHED_NAME_STR : constant String := To_String (
      (16#55#, 16#04#, 16#31#));
   SUPPORTED_ALGORITHMS_STR : constant String := To_String (
      (16#55#, 16#04#, 16#34#));
   PSEUDONYM_STR : constant String := To_String (
      (16#55#, 16#04#, 16#41#));

   CERTIFICATE_POLICIES_VERISIGN_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#03#));
   SUBJECT_DIRECTORY_ATTRIBUTES_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#09#));
   SUBJECT_KEY_IDENTIFIER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#0E#));
   KEY_USAGE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#0F#));
   PRIVATE_KEY_USAGE_PERIOD_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#10#));
   SUBJECT_ALT_NAME_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#11#));
   ISSUER_ALT_NAME_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#12#));
   BASIC_CONSTRAINTS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#13#));
   CRL_NUMBER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#14#));
   REASON_CODE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#15#));
   INSTRUCTION_CODE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#17#));
   INVALIDITY_DATE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#18#));
   CRL_INDICATOR_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#1B#));
   ISSUING_DISTRIBUTION_POINT_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#1C#));
   CERTIFICATE_ISSUER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#1D#));
   NAME_CONSTRAINTS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#1E#));
   CRL_DISTRIBUTION_POINTS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#1F#));
   CERTIFICATE_POLICIES_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#20#));
   POLICY_MAPPINGS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#21#));
   AUTHORITY_KEY_IDENTIFIER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#23#));
   POLICY_CONSTRAINTS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#24#));
   EXT_KEY_USAGE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#25#));
   AUTHORITY_ATTRIBUTE_IDENTIFIER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#26#));
   ROLE_SPEC_CERT_IDENTIFIER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#27#));
   CRL_STREAM_IDENTIFIER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#28#));
   BASIC_ATT_CONSTRAINTS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#29#));
   DELEGATED_NAME_CONSTRAINTS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#2A#));
   TIME_SPECIFICATION_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#2B#));
   CRL_SCOPE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#2C#));
   STATUS_REFERRALS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#2D#));
   FRESHEST_CRL_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#2E#));
   ORDERED_LIST_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#2F#));
   ATTRIBUTE_DESCRIPTOR_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#30#));
   USER_NOTICE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#31#));
   SOA_IDENTIFIER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#32#));
   BASE_UPDATE_TIME_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#33#));
   ACCEPTABLE_CERT_POLICIES_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#34#));
   DELTA_INFO_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#35#));
   INHIBIT_ANY_POLICY_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#36#));
   TARGET_INFORMATION_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#37#));
   NO_REV_AVAIL_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#38#));
   ACCEPTABLE_PRIVILEGE_POLICIES_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#39#));
   TO_BE_REVOKED_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#3A#));
   REVOKED_GROUPS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#3B#));
   EXPIRED_CERTS_ON_CRL_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#3C#));
   INDIRECT_ISSUER_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#3D#));
   NO_ASSERTION_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#3E#));
   AA_ISSUING_DISTRIBUTION_POINT_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#3F#));
   ISSUED_ON_BEHALF_OF_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#40#));
   SINGLE_USE_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#41#));
   GROUP_AC_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#42#));
   ALLOWED_ATT_ASS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#43#));
   ATTRIBUTE_MAPPINGS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#44#));
   HOLDER_NAME_CONSTRAINTS_STR : constant String := To_String (
      (16#55#, 16#1D#, 16#45#));

   --  Instead of gonkulating the actual object ID string, we just compare
   --  packed byte representations.
   function Lookup (Packed : String) return Object_ID is
   begin
      --  Linear search for now
      if Packed = DOMAIN_COMPONENT_STR     then return DOMAIN_COMPONENT;
      elsif Packed = A_RECORD_STR          then return A_RECORD;
      elsif Packed = MX_RECORD_STR         then return MX_RECORD;
      elsif Packed = NS_RECORD_STR         then return NS_RECORD;
      elsif Packed = SOA_RECORD_STR        then return SOA_RECORD;
      elsif Packed = CNAME_RECORD_STR      then return CNAME_RECORD;
      elsif Packed = ASSOCIATED_DOMAIN_STR then return ASSOCIATED_DOMAIN;
      elsif Packed = ASSOCIATED_NAME_STR   then return ASSOCIATED_NAME;
      elsif Packed = RSA_ENCRYPTION_STR    then return RSA_ENCRYPTION;
      elsif Packed = MD2_WITH_RSA_STR      then return MD2_WITH_RSA;
      elsif Packed = MD4_WITH_RSA_STR      then return MD4_WITH_RSA;
      elsif Packed = MD5_WITH_RSA_STR      then return MD5_WITH_RSA;
      elsif Packed = RSA_OAEP_ENCRYPTION_SET_STR then return RSA_OAEP_ENCRYPTION_SET;
      elsif Packed = ID_RSAES_OAEP_STR     then return ID_RSAES_OAEP;
      elsif Packed = ID_MGF1_STR           then return ID_MGF1;
      elsif Packed = ID_PSPECIFIED_STR     then return ID_PSPECIFIED;
      elsif Packed = RSASSA_PSS_STR        then return RSASSA_PSS;
      elsif Packed = SHA256_WITH_RSA_STR   then return SHA256_WITH_RSA;
      elsif Packed = SHA384_WITH_RSA_STR   then return SHA384_WITH_RSA;
      elsif Packed = SHA512_WITH_RSA_STR   then return SHA512_WITH_RSA;
      elsif Packed = SHA224_WITH_RSA_STR   then return SHA224_WITH_RSA;
      elsif Packed = ID_X25519_STR         then return ID_X25519;
      elsif Packed = ID_X448_STR           then return ID_X448;
      elsif Packed = ID_EDDSA25519_STR     then return ID_EDDSA25519;
      elsif Packed = ID_EDDSA448_STR       then return ID_EDDSA448;
      elsif Packed = ID_EDDSA25519_PH_STR  then return ID_EDDSA25519_PH;
      elsif Packed = ID_EDDSA448_PH_STR    then return ID_EDDSA448_PH;
      elsif Packed = OBJECT_CLASS_STR      then return OBJECT_CLASS;
      elsif Packed = ALIASED_ENTRY_NAME_STR then return ALIASED_ENTRY_NAME;
      elsif Packed = KNOWLEDGE_INFORMATION_STR then return KNOWLEDGE_INFORMATION;
      elsif Packed = COMMON_NAME_STR       then return COMMON_NAME;
      elsif Packed = SURNAME_STR           then return SURNAME;
      elsif Packed = SERIAL_NUMBER_STR     then return SERIAL_NUMBER;
      elsif Packed = COUNTRY_STR           then return COUNTRY;
      elsif Packed = LOCALITY_STR          then return LOCALITY;
      elsif Packed = STATE_OR_PROVINCE_STR then return STATE_OR_PROVINCE;
      elsif Packed = STREET_ADDRESS_STR    then return STREET_ADDRESS;
      elsif Packed = ORG_STR               then return ORG;
      elsif Packed = ORG_UNIT_STR          then return ORG_UNIT;
      elsif Packed = TITLE_STR             then return TITLE;
      elsif Packed = DESCRIPTION_STR       then return DESCRIPTION;
      elsif Packed = GIVEN_NAME_STR        then return GIVEN_NAME;
      elsif Packed = INITIALS_STR          then return INITIALS;
      elsif Packed = GENERATION_QUALIFIER_STR then return GENERATION_QUALIFIER;
      elsif Packed = DISTINGUISHED_NAME_STR then return DISTINGUISHED_NAME;
      elsif Packed = SUPPORTED_ALGORITHMS_STR then return SUPPORTED_ALGORITHMS;
      elsif Packed = PSEUDONYM_STR         then return PSEUDONYM;
      elsif Packed = CERTIFICATE_POLICIES_VERISIGN_STR then return CERTIFICATE_POLICIES_VERISIGN;
      elsif Packed = SUBJECT_DIRECTORY_ATTRIBUTES_STR then return SUBJECT_DIRECTORY_ATTRIBUTES;
      elsif Packed = SUBJECT_KEY_IDENTIFIER_STR then return SUBJECT_KEY_IDENTIFIER;
      elsif Packed = KEY_USAGE_STR         then return KEY_USAGE;
      elsif Packed = PRIVATE_KEY_USAGE_PERIOD_STR then return PRIVATE_KEY_USAGE_PERIOD;
      elsif Packed = SUBJECT_ALT_NAME_STR  then return SUBJECT_ALT_NAME;
      elsif Packed = ISSUER_ALT_NAME_STR   then return ISSUER_ALT_NAME;
      elsif Packed = BASIC_CONSTRAINTS_STR then return BASIC_CONSTRAINTS;
      elsif Packed = CRL_NUMBER_STR        then return CRL_NUMBER;
      elsif Packed = REASON_CODE_STR       then return REASON_CODE;
      elsif Packed = INSTRUCTION_CODE_STR  then return INSTRUCTION_CODE;
      elsif Packed = INVALIDITY_DATE_STR   then return INVALIDITY_DATE;
      elsif Packed = CRL_INDICATOR_STR     then return CRL_INDICATOR;
      elsif Packed = ISSUING_DISTRIBUTION_POINT_STR then return ISSUING_DISTRIBUTION_POINT;
      elsif Packed = CERTIFICATE_ISSUER_STR then return CERTIFICATE_ISSUER;
      elsif Packed = NAME_CONSTRAINTS_STR  then return NAME_CONSTRAINTS;
      elsif Packed = CRL_DISTRIBUTION_POINTS_STR then return CRL_DISTRIBUTION_POINTS;
      elsif Packed = CERTIFICATE_POLICIES_STR then return CERTIFICATE_POLICIES;
      elsif Packed = POLICY_MAPPINGS_STR then return POLICY_MAPPINGS;
      elsif Packed = AUTHORITY_KEY_IDENTIFIER_STR then return AUTHORITY_KEY_IDENTIFIER;
      elsif Packed = POLICY_CONSTRAINTS_STR then return POLICY_CONSTRAINTS;
      elsif Packed = EXT_KEY_USAGE_STR     then return EXT_KEY_USAGE;
      elsif Packed = AUTHORITY_ATTRIBUTE_IDENTIFIER_STR then return AUTHORITY_ATTRIBUTE_IDENTIFIER;
      elsif Packed = ROLE_SPEC_CERT_IDENTIFIER_STR then return ROLE_SPEC_CERT_IDENTIFIER;
      elsif Packed = CRL_STREAM_IDENTIFIER_STR then return CRL_STREAM_IDENTIFIER;
      elsif Packed = BASIC_ATT_CONSTRAINTS_STR then return BASIC_ATT_CONSTRAINTS;
      elsif Packed = DELEGATED_NAME_CONSTRAINTS_STR then return DELEGATED_NAME_CONSTRAINTS;
      elsif Packed = TIME_SPECIFICATION_STR then return TIME_SPECIFICATION;
      elsif Packed = CRL_SCOPE_STR then return CRL_SCOPE;
      elsif Packed = STATUS_REFERRALS_STR  then return STATUS_REFERRALS;
      elsif Packed = FRESHEST_CRL_STR      then return FRESHEST_CRL;
      elsif Packed = ORDERED_LIST_STR      then return ORDERED_LIST;
      elsif Packed = ATTRIBUTE_DESCRIPTOR_STR then return ATTRIBUTE_DESCRIPTOR;
      elsif Packed = USER_NOTICE_STR       then return USER_NOTICE;
      elsif Packed = SOA_IDENTIFIER_STR    then return SOA_IDENTIFIER;
      elsif Packed = BASE_UPDATE_TIME_STR  then return BASE_UPDATE_TIME;
      elsif Packed = ACCEPTABLE_CERT_POLICIES_STR then return ACCEPTABLE_CERT_POLICIES;
      elsif Packed = DELTA_INFO_STR        then return DELTA_INFO;
      elsif Packed = INHIBIT_ANY_POLICY_STR then return INHIBIT_ANY_POLICY;
      elsif Packed = TARGET_INFORMATION_STR then return TARGET_INFORMATION;
      elsif Packed = NO_REV_AVAIL_STR      then return NO_REV_AVAIL;
      elsif Packed = ACCEPTABLE_PRIVILEGE_POLICIES_STR then return ACCEPTABLE_PRIVILEGE_POLICIES;
      elsif Packed = TO_BE_REVOKED_STR     then return TO_BE_REVOKED;
      elsif Packed = REVOKED_GROUPS_STR    then return REVOKED_GROUPS;
      elsif Packed = EXPIRED_CERTS_ON_CRL_STR then return EXPIRED_CERTS_ON_CRL;
      elsif Packed = INDIRECT_ISSUER_STR then return INDIRECT_ISSUER;
      elsif Packed = NO_ASSERTION_STR      then return NO_ASSERTION;
      elsif Packed = AA_ISSUING_DISTRIBUTION_POINT_STR then return AA_ISSUING_DISTRIBUTION_POINT;
      elsif Packed = ISSUED_ON_BEHALF_OF_STR then return ISSUED_ON_BEHALF_OF;
      elsif Packed = SINGLE_USE_STR        then return SINGLE_USE;
      elsif Packed = GROUP_AC_STR          then return GROUP_AC;
      elsif Packed = ALLOWED_ATT_ASS_STR   then return ALLOWED_ATT_ASS;
      elsif Packed = ATTRIBUTE_MAPPINGS_STR then return ATTRIBUTE_MAPPINGS;
      elsif Packed = HOLDER_NAME_CONSTRAINTS_STR then return HOLDER_NAME_CONSTRAINTS;
      else return UNKNOWN; end if;
   end Lookup;
end OID;