package OID 
   with SPARK_Mode
is
   -- Not every object identifier is supported. Some additional ones
   -- are included here for completeness and future expansion, but only
   -- those 
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


      --  Elliptic Curve Parameters
      --  1 ISO -> 2 Member Body -> 840 US -> 10045 ANSI X9.62 -> 3 Curves -> 1 Prime
      --  TODO: CURVES
      
      --  Signature Algorithms
      UNKNOWN_ALGORITHM,               --  catch-all for erroneous object IDs when decoding
      --  1 ISO -> 2 Member Body -> 840 US -> 10045 ANSI X9.57 -> 4 Algorithms
      --  TODO: ECDSA

      --  1 ISO -> 2 Member Body -> 840 US -> 113549 RSADSI -> 1 PKCS -> 1 PKCS-1
      --RSA_DEPRECATED,                --  1.2.840.113549.1.1.0 deprecated
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

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 4 Private

      -- Reference RFC 7299 for the following object identifiers
   
      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 0 Module Identifiers
      PKIX1_EXPLICIT_88,               -- 1.3.6.1.5.5.7.0.1 RFC2459
      PKIX1_IMPLICIT_88,               -- 1.3.6.1.5.5.7.0.2 RFC2459
      PKIX1_EXPLICIT_93,               -- 1.3.6.1.5.5.7.0.3 RFC2459
      PKIX1_IMPLICIT_93,               -- 1.3.6.1.5.5.7.0.4 RFC2459
      PKIX_MOD_CRMF,                   -- 1.3.6.1.5.5.7.0.5 RFC2511
      PKIX_MOD_CMC,                    -- 1.3.6.1.5.5.7.0.6 RFC2797
      PKIX_MOD_KEA_PROFILE_88,         -- 1.3.6.1.5.5.7.0.7 RFC2528
      PKIX_MOD_KEA_PROFILE_93,         -- 1.3.6.1.5.5.7.0.8 RFC2528
      PKIX_MOD_CMP,                    -- 1.3.6.1.5.5.7.0.9 RFC2510
      PKIX_MOD_QUALIFIED_CERT_88,      -- 1.3.6.1.5.5.7.0.10 RFC3039
      PKIX_MOD_QUALIFIED_CERT_93,      -- 1.3.6.1.5.5.7.0.11 RFC3039
      PKIX_MOD_ATTRIBUTE_CERT,         -- 1.3.6.1.5.5.7.0.12 RFC3281
      PKIX_MOD_TSP,                    -- 1.3.6.1.5.5.7.0.13 RFC3161
      PKIX_MOD_OCSP,                   -- 1.3.6.1.5.5.7.0.14 RFC3029
      PKIX_MOD_DVCS,                   -- 1.3.6.1.5.5.7.0.15 RFC3029
      PKIX_MOD_CMP2000,                -- 1.3.6.1.5.5.7.0.16 RFC4210
      PKIX_MOD_PKIX1_ALGORITHMS,       -- 1.3.6.1.5.5.7.0.17 RFC3279
      PKIX_MOD_PKIX1_EXPLICIT,         -- 1.3.6.1.5.5.7.0.18 RFC3280
      PKIX_MOD_PKIX1_IMPLICIT,         -- 1.3.6.1.5.5.7.0.19 RFC3280
      -- PKIX_MOD_USER_GROUP,          -- 1.3.6.1.5.5.7.0.20 RESERVED AND OBSOLETE
      PKIX_MOD_SCVP,                   -- 1.3.6.1.5.5.7.0.21 RFC5055
      PKIX_MOD_LOGOTYPE,               -- 1.3.6.1.5.5.7.0.22 RFC3709
      PKIX_MOD_CMC2002,                -- 1.3.6.1.5.5.7.0.23 RFC5272
      PKIX_MOD_WLAN_EXTNS,             -- 1.3.6.1.5.5.7.0.24 RFC3770
      PKIX_MOD_PROXY_CERT_EXTNS,       -- 1.3.6.1.5.5.7.0.25 RFC3820
      PKIX_MOD_AC_POLICIES,            -- 1.3.6.1.5.5.7.0.26 RFC4476
      PKIX_MOD_WARRANTY_EXTN,          -- 1.3.6.1.5.5.7.0.27 RFC4059
      PKIX_MOD_PERM_ID_88,             -- 1.3.6.1.5.5.7.0.28 RFC4043
      PKIX_MOD_PERM_ID_93,             -- 1.3.6.1.5.5.7.0.29 RFC4043
      PKIX_MOD_IP_ADDR_AND_AS_IDENT,   -- 1.3.6.1.5.5.7.0.30 RFC3779
      PKIX_MOD_QUALIFIED_CERT,         -- 1.3.6.1.5.5.7.0.31 RFC3739
      -- PKIX_MOD_CRMF2003,            -- 1.3.6.1.5.5.7.0.32 RESERVED AND OBSOLETE
      PKIX_MOD_PKIX1_RSA_PKALGS,       -- 1.3.6.1.5.5.7.0.33 RFC4055
      PKIX_MOD_CERT_BUNDLE,            -- 1.3.6.1.5.5.7.0.34 RFC4306
      PKIX_MOD_QUALIFIED_CERT_97,      -- 1.3.6.1.5.5.7.0.35 RFC3739
      PKIX_MOD_CRMF2005,               -- 1.3.6.1.5.5.7.0.36 RFC4210
      PKIX_MOD_WLAN_EXTNS2005,         -- 1.3.6.1.5.5.7.0.37 RFC4334
      PKIX_MOD_SIM2005,                -- 1.3.6.1.5.5.7.0.38 RFC4683
      PKIX_MOD_DNS_SRV_NAME_88,        -- 1.3.6.1.5.5.7.0.39 RFC4985
      PKIX_MOD_DNS_SRV_NAME_93,        -- 1.3.6.1.5.5.7.0.40 RFC4985
      PKIX_MOD_CMSCONTENTCONSTR_88,    -- 1.3.6.1.5.5.7.0.41 RFC6010
      PKIX_MOD_CMSCONTENTCONSTR_93,    -- 1.3.6.1.5.5.7.0.42 RFC6010
      -- PKIX_MOD_PKIXCOMMON,          -- 1.3.6.1.5.5.7.0.43 RESERVED AND OBSOLETE
      PKIX_MOD_PKIXOTHERCERTS,         -- 1.3.6.1.5.5.7.0.44 RFC5697
      PKIX_MOD_PKIX1_ALGORITHMS2008,   -- 1.3.6.1.5.5.7.0.45 RFC5480
      PKIX_MOD_CLEARANCECONSTRAINTS,   -- 1.3.6.1.5.5.7.0.46 RFC5913
      PKIX_MOD_ATTRIBUTE_CERT_02,      -- 1.3.6.1.5.5.7.0.47 RFC5912
      PKIX_MOD_OCSP_02,                -- 1.3.6.1.5.5.7.0.48 RFC5912
      PKIX_MOD_V1ATTRCERT_02,          -- 1.3.6.1.5.5.7.0.49 RFC5912
      PKIX_MOD_CMP2000_02,             -- 1.3.6.1.5.5.7.0.50 RFC5912
      PKIX_MOD_PKIX1_EXPLICIT_02,      -- 1.3.6.1.5.5.7.0.51 RFC5912
      PKIX_MOD_SCVP_02,                -- 1.3.6.1.5.5.7.0.52 RFC5912
      PKIX_MOD_CMC2002_02,             -- 1.3.6.1.5.5.7.0.53 RFC5912
      PKIX_MOD_PKIX1_RSA_PKALGS_02,    -- 1.3.6.1.5.5.7.0.54 RFC5912
      PKIX_MOD_CRMF2005_02,            -- 1.3.6.1.5.5.7.0.55 RFC5912
      PKIX_MOD_PKIX1_ALGORITHMS2008_02,-- 1.3.6.1.5.5.7.0.56 RFC5912
      PKIX_MOD_PKIXCOMMON_02,          -- 1.3.6.1.5.5.7.0.57 RFC5912
      PKIX_MOD_ALGORITHMINFORMATION_02,-- 1.3.6.1.5.5.7.0.58 RFC5912
      PKIX_MOD_PKIX1_IMPLICIT_02,      -- 1.3.6.1.5.5.7.0.59 RFC5912
      PKIX_MOD_PKIX1_X400ADDRESS_02,   -- 1.3.6.1.5.5.7.0.60 RFC5912
      PKIX_MOD_ATTRIBUTE_CERT_V2,      -- 1.3.6.1.5.5.7.0.61 RFC5755
      PKIX_MOD_SIP_DOMAIN_EXTNS2007,   -- 1.3.6.1.5.5.7.0.62 RFC5924
      PKIX_MOD_CMS_OTHERRIS_2009_88,   -- 1.3.6.1.5.5.7.0.63 RFC5940
      PKIX_MOD_CMS_OTHERRIS_2009_93,   -- 1.3.6.1.5.5.7.0.64 RFC5940
      PKIX_MOD_ECPRIVATEKEY,           -- 1.3.6.1.5.5.7.0.65 RFC5915
      PKIX_MOD_OCSP_AGILITY_2009_93,   -- 1.3.6.1.5.5.7.0.66 RFC6277
      PKIX_MOD_OCSP_AGILITY_2009_88,   -- 1.3.6.1.5.5.7.0.67 RFC6277
      PKIX_MOD_LOGOTYPE_CERTIMAGE,     -- 1.3.6.1.5.5.7.0.68 RFC6170
      PKIX_MOD_PKCS10_2009,            -- 1.3.6.1.5.5.7.0.69 RFC5912
      PKIX_MOD_DNS_RESOURCE_RECORD,    -- 1.3.6.1.5.5.7.0.70 ABLEY DNSSEC Trust Anchor Pub for Root Zone
      PKIX_MOD_SEND_CERT_EXTNS,        -- 1.3.6.1.5.5.7.0.71 RFC6494
      PKIX_MOD_IP_ADDR_AND_PKIXENT_2,  -- 1.3.6.1.5.5.7.0.72 RFC6268
      PKIX_MOD_WLAN_EXTNS_2,           -- 1.3.6.1.5.5.7.0.73 RFC6268
      PKIX_MOD_HMAC,                   -- 1.3.6.1.5.5.7.0.74 RFC6268
      PKIX_MOD_ENROLLMSGSYNTAX_2011_88,-- 1.3.6.1.5.5.7.0.75 RFC6402 ERR3860
      PKIX_MOD_ENROLLMSGSYNTAX_2011_08,-- 1.3.6.1.5.5.7.0.76 RFC6402
      PKIX_MOD_PUBKEYSMIMECAPS_88,     -- 1.3.6.1.5.5.7.0.77 RFC6664
      PKIX_MOD_PUBKEYSMIMECAPS_08,     -- 1.3.6.1.5.5.7.0.78 RFC6664
      PKIX_MOD_DHSIGN_2012_88,         -- 1.3.6.1.5.5.7.0.79 RFC6955
      PKIX_MOD_DHSIGN_2012_08,         -- 1.3.6.1.5.5.7.0.80 RFC6955
      PKIX_MOD_OCSP_2013_88,           -- 1.3.6.1.5.5.7.0.81 RFC6960
      PKIX_MOD_OCSP_2013_08,           -- 1.3.6.1.5.5.7.0.82 RFC6960
      PKIX_MOD_TEST_CERTPOLICIES,      -- 1.3.6.1.5.5.7.0.83 RFC7229
      PKIX_MOD_BGPSEC_EKU,             -- 1.3.6.1.5.5.7.0.84 Profile for BGPSEC Router Certificates, CRLs and CRs
     
     -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 1 PKIX Extensions
     
      PKIX_AUTHORITY_INFO_ACCESS,      -- 1.3.6.1.5.5.7.1.1 CA Information Access RFC 2459
      PKIX_BIOMETRIC_INFO,             -- 1.3.6.1.5.5.7.1.2 Biometric Info RFC 3039
      PKIX_QC_STATEMENTS,              -- 1.3.6.1.5.5.7.1.3 Qualified Certificate Statements RFC 3039
      PKIX_AUDIT_IDENTITY,             -- 1.3.6.1.5.5.7.1.4 Private extension auditIdentity RFC 3281
      -- PKIX_AC_TARGETING,            -- 1.3.6.1.5.5.7.1.5 Private extention acTargeting? (OBSOLETE)
      PKIX_AA_CONTROLS,                -- 1.3.6.1.5.5.7.1.6 Attribute Authority Controls, Attribute Certificate Validation
      PKIX_IP_ADDR_BLOCKS,             -- 1.3.6.1.5.5.7.1.7 IP Address Blocks RFC 3779
      PKIX_AUTONOMOUS_SYSTEM,          -- 1.3.6.1.5.5.7.1.8 Autonomous System Identifiers RFC 3779
      -- PKIX_ROUTER_IDENTIFIER,       -- 1.3.6.1.5.5.7.1.9 Router Identifiers (OBSOLETE)
      PKIX_AC_PROXYING,                -- 1.3.6.1.5.5.7.1.10 RFC3281
      PKIX_SUBJECTINFOACCESS,          -- 1.3.6.1.5.5.7.1.11 RFC3280
      PKIX_LOGOTYPE,                   -- 1.3.6.1.5.5.7.1.12 RFC3709
      PKIX_WLANSSID,                   -- 1.3.6.1.5.5.7.1.13 RFC4334
      PKIX_PROXYCERTINFO,              -- 1.3.6.1.5.5.7.1.14 RFC3820
      PKIX_ACPOLICIES,                 -- 1.3.6.1.5.5.7.1.15 RFC4476
      PKIX_WARRANTY,                   -- 1.3.6.1.5.5.7.1.16 RFC4059
      -- PKIX_SIM,                     -- 1.3.6.1.5.5.7.1.17 RESERVED AND OBSOLETE
      PKIX_CMSCONTENTCONSTRAINTS,      -- 1.3.6.1.5.5.7.1.18 RFC6010
      PKIX_OTHERCERTS,                 -- 1.3.6.1.5.5.7.1.19 RFC5697
      PKIX_WRAPPEDAPEXCONTINKEY,       -- 1.3.6.1.5.5.7.1.20 RFC5934
      PKIX_CLEARANCECONSTRAINTS,       -- 1.3.6.1.5.5.7.1.21 RFC5913
      -- PKIX_SKISEMANTICS,            -- 1.3.6.1.5.5.7.1.22 RESERVED AND OBSOLETE
      PKIX_NSA,                        -- 1.3.6.1.5.5.7.1.23 RFC7169

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 2 PKIX Policy Qualifiers / SMI Security
      
      PKIX_CPS,                        -- 1.3.6.1.5.5.7.2.1 RFC2459
      PKIX_UNOTICE,                    -- 1.3.6.1.5.5.7.2.2 RFC2459
      PKIX_TEXTNOTICE,                 -- 1.3.6.1.5.5.7.2.3 RESERVED AND OBSOLETE
      PKIX_ACPS,                       -- 1.3.6.1.5.5.7.2.4 RFC4476
      PKIX_ACUNOTICE,                  -- 1.3.6.1.5.5.7.2.5 RFC4476


      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 3 Extended Key Purpose Identifiers

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 4 CMP Information Types

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 5 CRMF Registration

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 6 Algorithms

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 7 CMC Controls

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 8 Other name forms

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 9 Personal Data Attribute

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 10 Attribute Certificate Attributes

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 11 Qualified Certificate Statements

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 12 CMC Content Types

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 13 OIDs for Testing ONLY

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 14 Certificate Policies

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 15 CMC Error Types

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 16 Revocation Information Types

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 17 SCVP Check Type

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 18 SCVP Want Back Types

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 19 SCVP Validation Policies

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 20 Other Logotype Identifiers

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 21 Proxy Certificate Policy Languages

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 22 Matching Rules

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 23 Subject Key Identifier Semantics

      -- 1 ISO -> 3 org -> 6 DoD -> 1 Internet -> 5 Security -> 5 Mechanisms -> 7 PKIX -> 48 Access Descriptors
      PKIX_OCSP,                       --  1.3.6.1.5.5.7.48.1
      PKIX_CA_ISSUERS,                 --  1.3.6.1.5.5.7.48.2

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
