package OID 
   with SPARK_Mode
is
   type Object_ID is (
      --  Catch-all for object IDs we don't support or recognize
      UNKNOWN,

      --  Domain Component (and other DNS fields not used in X.509)
      --  0 ITU-T -> 9 Data -> 2342 PSS/X.25 Network
      --   -> 19200300 University College London -> 100 pilot
      --   -> 1 pilot attribute type
      DOMAIN_COMPONENT,                --  0.9.2342.19200300.100.1.25
      A_RECORD,                        --  0.9.2342.19200300.100.1.26
      MX_RECORD,                       --  0.9.2342.19200300.100.1.28
      NS_RECORD,                       --  0.9.2342.19200300.100.1.29
      SOA_RECORD,                      --  0.9.2342.19200300.100.1.30
      CNAME_RECORD,                    --  0.9.2342.19200300.100.1.31
      ASSOCIATED_DOMAIN,               --  0.9.2342.19200300.100.1.37
      ASSOCIATED_NAME,                 --  0.9.2342.19200300.100.1.38

      --  Signature Algorithms
      
      --  1 ISO -> 2 Member Body -> 840 US -> 13549 RSADSI -> 1 PKCS -> 1 PKCS-1
      RSA_ENCRYPTION,                  --  1.2.840.113549.1.1.1
      MD2_WITH_RSA,                    --  1.2.840.113549.1.1.2
      MD4_WITH_RSA,                    --  1.2.840.113549.1.1.3
      MD5_WITH_RSA,                    --  1.2.840.115349.1.1.4
      RSA_OAEP_ENCRYPTION_SET,         --  1.2.840.115349.1.1.6
      ID_RSAES_OAEP,                   --  1.2.840.115349.1.1.7
      ID_MGF1,                         --  1.2.840.113549.1.1.8
      ID_PSPECIFIED,                   --  1.2.840.113549.1.1.9
      RSASSA_PSS,                      --  1.2.840.113549.1.1.10
      SHA256_WITH_RSA,                 --  1.2.840.113549.1.1.11
      SHA384_WITH_RSA,                 --  1.2.840.113549.1.1.12
      SHA512_WITH_RSA,                 --  1.2.840.113549.1.1.13
      SHA224_WITH_RSA,                 --  1.2.840.113549.1.1.14

      --  1 ISO -> 3 org -> 101 Thawte
      ID_X25519,                       --  1.3.101.110
      ID_X448,                         --  1.3.101.111
      ID_EDDSA25519,                   --  1.3.101.112
      ID_EDDSA448,                     --  1.3.101.113
      ID_EDDSA25519_PH,                --  1.3.101.114
      ID_EDDSA448_PH,                  --  1.3.101.115

      --  Distinguished Name Components
      
      --  2 Joint ISO -> 5 Directory Services -> 4 Attribute Type
      OBJECT_CLASS,                    --  2.5.4.0
      ALIASED_ENTRY_NAME,              --  2.5.4.1
      KNOWLEDGE_INFORMATION,           --  2.5.4.2

      COMMON_NAME,                     --  2.5.4.3
      SURNAME,                         --  2.5.4.4
      SERIAL_NUMBER,                   --  2.5.4.5
      COUNTRY,                         --  2.5.4.6
      LOCALITY,                        --  2.5.4.7
      STATE_OR_PROVINCE,               --  2.5.4.8
      STREET_ADDRESS,                  --  2.5.4.9
      ORG,                             --  2.5.4.10
      ORG_UNIT,                        --  2.5.4.11
      TITLE,                           --  2.5.4.12
      DESCRIPTION,                     --  2.5.4.13

      --  Other object identifiers that RFC 5280 implementations SHOULD handle
      GIVEN_NAME,                      --  2.5.4.42
      INITIALS,                        --  2.5.4.43
      GENERATION_QUALIFIER,            --  2.5.4.44
      DISTINGUISHED_NAME,              --  2.5.4.49
      SUPPORTED_ALGORITHMS,            --  2.5.4.52
      PSEUDONYM,                       --  2.5.4.65

      --  x.509 Extensions

      --  2 Joint ISO -> 5 Directory Services -> 29 Certificate Extensions
      --  authority key identifier         2.5.29.1 deprecated
      --  key attributes                   2.5.29.2 obsolete
      CERTIFICATE_POLICIES_VERISIGN,   --  2.5.29.3 (obsolete but common)
      --  key usage restriction            2.5.29.4 obsolete
      --  policy mapping                   2.5.29.5 obsolete
      --  subtrees constraint              2.5.29.6 obsolete
      --  subject alt name                 2.5.29.7 obsolete
      --  issuer alt name                  2.5.29.8 obsolete
      SUBJECT_DIRECTORY_ATTRIBUTES,    --  2.5.29.9
      --  basic constraints                2.5.29.10 deprecated
      --  11                               2.5.29.11 obsolete
      --  12                               2.5.29.12 obsolete
      --  13                               2.5.29.13 obsolete
      SUBJECT_KEY_IDENTIFIER,          --  2.5.29.14
      KEY_USAGE,                       --  2.5.29.15
      PRIVATE_KEY_USAGE_PERIOD,        --  2.5.29.16
      SUBJECT_ALT_NAME,                --  2.5.29.17
      ISSUER_ALT_NAME,                 --  2.5.29.18
      BASIC_CONSTRAINTS,               --  2.5.29.19
      CRL_NUMBER,                      --  2.5.29.20
      REASON_CODE,                     --  2.5.29.21
      --  expiration date                  2.5.29.22 obsolete
      INSTRUCTION_CODE,                --  2.5.29.23
      INVALIDITY_DATE,                 --  2.5.29.24
      --  CRL distribution points          2.5.29.25 obsolete
      --  issuing distribution point       2.5.29.26 obsolete
      CRL_INDICATOR,                   --  2.5.29.27
      ISSUING_DISTRIBUTION_POINT,      --  2.5.29.28
      CERTIFICATE_ISSUER,              --  2.5.29.29
      NAME_CONSTRAINTS,                --  2.5.29.30
      CRL_DISTRIBUTION_POINTS,         --  2.5.29.31
      CERTIFICATE_POLICIES,            --  2.5.29.32
      POLICY_MAPPINGS,                 --  2.5.29.33
      --  policy constraints               2.5.29.34 deprecated
      AUTHORITY_KEY_IDENTIFIER,        --  2.5.29.35
      POLICY_CONSTRAINTS,              --  2.5.29.36
      EXT_KEY_USAGE,                   --  2.5.29.37
      AUTHORITY_ATTRIBUTE_IDENTIFIER,  --  2.5.29.38
      ROLE_SPEC_CERT_IDENTIFIER,       --  2.5.29.39
      CRL_STREAM_IDENTIFIER,           --  2.5.29.40
      BASIC_ATT_CONSTRAINTS,           --  2.5.29.41
      DELEGATED_NAME_CONSTRAINTS,      --  2.5.29.42
      TIME_SPECIFICATION,              --  2.5.29.43
      CRL_SCOPE,                       --  2.5.29.44
      STATUS_REFERRALS,                --  2.5.29.45
      FRESHEST_CRL,                    --  2.5.29.46
      ORDERED_LIST,                    --  2.5.29.47
      ATTRIBUTE_DESCRIPTOR,            --  2.5.29.48
      USER_NOTICE,                     --  2.5.29.49
      SOA_IDENTIFIER,                  --  2.5.29.50
      BASE_UPDATE_TIME,                --  2.5.29.51
      ACCEPTABLE_CERT_POLICIES,        --  2.5.29.52
      DELTA_INFO,                      --  2.5.29.53
      INHIBIT_ANY_POLICY,              --  2.5.29.54
      TARGET_INFORMATION,              --  2.5.29.55
      NO_REV_AVAIL,                    --  2.5.29.56
      ACCEPTABLE_PRIVILEGE_POLICIES,   --  2.5.29.57
      TO_BE_REVOKED,                   --  2.5.29.58
      REVOKED_GROUPS,                  --  2.5.29.59
      EXPIRED_CERTS_ON_CRL,            --  2.5.29.60
      INDIRECT_ISSUER,                 --  2.5.29.61
      NO_ASSERTION,                    --  2.5.29.62
      AA_ISSUING_DISTRIBUTION_POINT,   --  2.5.29.63
      ISSUED_ON_BEHALF_OF,             --  2.5.29.64
      SINGLE_USE,                      --  2.5.29.65
      GROUP_AC,                        --  2.5.29.66
      ALLOWED_ATT_ASS,                 --  2.5.29.67
      ATTRIBUTE_MAPPINGS,              --  2.5.29.68
      HOLDER_NAME_CONSTRAINTS          --  2.5.29.69
   );

   ----------------------------------------------------------------------------
   --  Given the object identifier as a string of bytes, return the Object_ID
   --  constant corresponding to that identifier.
   --  @param Packed is the object identifier string slice _excluding_ the
   --  DER tag byte (06) and length byte.
   function Lookup (Packed : String) return Object_ID;
   
end OID;