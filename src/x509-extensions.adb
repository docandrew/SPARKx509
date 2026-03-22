with Ada.Text_IO; use Ada.Text_IO;

with OID; use OID;
with X509.Basic; use X509.Basic;

with SPARKX509.Debug; use SPARKX509.Debug;
with X509.Logs; use X509.Logs;

package body X509.Extensions with
    SPARK_Mode
is
    procedure Parse_UTF8_String is new Generic_Parse_String (UB_UTF8String);

    ---------------------------------------------------------------------------
    --  Parse_Basic_Constraints
    --  Seq_Size is the sequence length for this extension. If 3, then
    --  expect Object ID, cA Boolean and pathLenConstraint Integer.
    --  RFC 5280, Section 4.2.1.9
    ---------------------------------------------------------------------------
    procedure Parse_Basic_Constraints (Cert_Slice : String;
                                       Index      : in out Natural;
                                       Cert       : in out Certificate)
        with Pre => Index in Cert_Slice'Range;

    procedure Parse_Basic_Constraints (Cert_Slice : String;
                                       Index      : in out Natural;
                                       Cert       : in out Certificate)
    is  
        CA_Flag : Boolean;  -- cA field is a BOOLEAN that indicates whether or
                            -- not the subject of the certificate is a CA.
        Seq_Size : Unsigned_32;
    begin
        if not Cert.Valid then
            return;
        end if;

        Log (TRACE, "Parse_Basic_Constraints");

        -- Basic Constraints is a SEQUENCE of the following form:
        --     BasicConstraints ::= SEQUENCE {
        --         cA                  BOOLEAN DEFAULT FALSE,
        --         pathLenConstraint   INTEGER (0..MAX) OPTIONAL
        --     }
        -- The cA field is a BOOLEAN that indicates whether or not the subject
        -- of the certificate is a CA. If the cA field is not present, the
        -- default value is FALSE. The pathLenConstraint field is an INTEGER
        -- that specifies the maximum number of non-self-issued intermediate
        -- certificates that may follow this certificate in a valid certification
        -- path. If the pathLenConstraint field is not present, no limit is
        -- imposed.
        Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);

        -- This data may not be present. Sequence size will tell us what to
        -- expect.
        if Seq_Size = 0 then
            Log (DEBUG, "No Basic Constraints Provided");
            Cert.Basic_Constraints := False;
            Cert.Path_Len_Constraint_Present := False;
            Cert.Path_Len_Constraint := 0;
        elsif Seq_Size = 3 then
            -- Boolean value only.
            Log (DEBUG, "Basic Constraint CA field only");
            Parse_Boolean (Cert_Slice, Index, Cert.Basic_Constraints, Cert);
            Cert.Path_Len_Constraint_Present := False;
            Cert.Path_Len_Constraint := 0;
        else
            Log (DEBUG, "Basic Constraint w/ Path Len Constraint");
            Parse_Boolean (Cert_Slice, Index, Cert.Basic_Constraints, Cert);
            Parse_Integer (Cert_Slice, Index, Cert.Path_Len_Constraint, Cert);
            Cert.Path_Len_Constraint_Present := True;
        end if;

    end Parse_Basic_Constraints; 

    ---------------------------------------------------------------------------
    --  Parse_Subject_Key_Identifier
    --  RFC 5280, Section 4.2.1.2
    ---------------------------------------------------------------------------
    procedure Parse_Subject_Key_Identifier (Cert_Slice : String;
                                            Index      : in out Natural;
                                            Cert       : in out Certificate)
        with Pre => Index in Cert_Slice'Range;

    procedure Parse_Subject_Key_Identifier (Cert_Slice : String;
                                            Index      : in out Natural;
                                            Cert       : in out Certificate)
    is
    begin

        if not Cert.Valid then
            return;
        end if;

        Log (TRACE, "Parse_Subject_Key_Identifier");

        -- Subject Key Identifier is an OCTET STRING of the following form:
        --     SubjectKeyIdentifier ::= KeyIdentifier
        --     KeyIdentifier ::= OCTET STRING

        Parse_Octet_String (Cert_Slice, Index, Cert.Subject_Key_Id_Len, Cert.Subject_Key_Id, Cert);

        if not Cert.Valid then
            return;
        end if;

        if X509.Logs.Log_Level >= X509.Logs.DEBUG then
            Log (DEBUG, "Subject Key Identifier:");
            Put_Key_Bytes (Cert.Subject_Key_Id, Cert.Subject_Key_Id_Len);
        end if;

    end Parse_Subject_Key_Identifier;

    ---------------------------------------------------------------------------
    -- Parse_Key_Usage
    ---------------------------------------------------------------------------
    procedure Parse_Key_Usage (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
    is
        Bit_String_Size        : Natural;
        Bit_String_Unused_Bits : Unsigned_8;
        Num_Bitflags           : Natural;
        Key_Usage_Bytes        : Key_Bytes;
    begin

        Log (TRACE, "Parse_Key_Usage");

        if not Cert.Valid then
            return;
        end if;

        Parse_Bit_String (Cert_Slice, Index, Bit_String_Size, Bit_String_Unused_Bits, Key_Usage_Bytes, Cert);

        if not Cert.Valid then
            Log (FATAL, "Unable to parse Key Usage, expected Bit String");
            return;
        end if;

        Num_Bitflags := Bit_String_Size * 8 - Natural(Bit_String_Unused_Bits);

        -- Per RFC 5280, Key Usage extension has up to 9 bitflags.
        -- DER encoding may truncate trailing zero bits, so any
        -- count from 1 to 9 is valid.
        if Num_Bitflags < 1 or Num_Bitflags > 9 then
            Log (FATAL, "Expected 1-9 bitflags for Key Usage extension, got" & Num_Bitflags'Image);
            Cert.Valid := False;
            return;
        end if;

        Cert.Digital_Signature := (if (Key_Usage_Bytes(0) and 2#1000_0000#) /= 0 then True else False);
        Cert.Non_Repudiation   := (if (Key_Usage_Bytes(0) and 2#0100_0000#) /= 0 then True else False);
        Cert.Key_Encipherment  := (if (Key_Usage_Bytes(0) and 2#0010_0000#) /= 0 then True else False);
        Cert.Data_Encipherment := (if (Key_Usage_Bytes(0) and 2#0001_0000#) /= 0 then True else False);
        Cert.Key_Agreement     := (if (Key_Usage_Bytes(0) and 2#0000_1000#) /= 0 then True else False);
        Cert.Key_Cert_Sign     := (if (Key_Usage_Bytes(0) and 2#0000_0100#) /= 0 then True else False);
        Cert.CRL_Sign          := (if (Key_Usage_Bytes(0) and 2#0000_0010#) /= 0 then True else False);

        if Num_Bitflags = 9 then
            Cert.Encipher_Only := (if (Key_Usage_Bytes(0) and 2#0000_0001#) /= 0 then True else False);
            Cert.Decipher_Only := (if (Key_Usage_Bytes(1) and 2#1000_0000#) /= 0 then True else False);
        end if;

        Log (DEBUG, " Key Usage:");
        Log (DEBUG, "  Digital Signature: " & Cert.Digital_Signature'Image);
        Log (DEBUG, "  Non-Repudiation:   " & Cert.Non_Repudiation'Image);
        Log (DEBUG, "  Key Encipherment:  " & Cert.Key_Encipherment'Image);
        Log (DEBUG, "  Data Encipherment: " & Cert.Data_Encipherment'Image);
        Log (DEBUG, "  Key Agreement:     " & Cert.Key_Agreement'Image);
        Log (DEBUG, "  Key Cert Sign:     " & Cert.Key_Cert_Sign'Image);
        Log (DEBUG, "  CRL Sign:          " & Cert.CRL_Sign'Image);
        Log (DEBUG, "  Encipher Only:     " & Cert.Encipher_Only'Image);
        Log (DEBUG, "  Decipher Only:     " & Cert.Decipher_Only'Image);
    end Parse_Key_Usage;

    ---------------------------------------------------------------------------
    --  Parse_Authority_Info_Access
    ---------------------------------------------------------------------------
    procedure Parse_Authority_Info_Access (Cert_Slice : String;
                                           Index      : in out Natural;
                                           Cert       : in out Certificate)
    is
      Authority_Info_Size   : Unsigned_32;
      Authority_Info_End    : Natural;

      Access_Desc_Size      : Unsigned_32;
      Access_Method         : Object_ID;
      Access_Location       : UTF8_String;  -- @TODO this can be other string types
      Sequence_Size         : Unsigned_32;
   begin
      --  Authority Info is a sequence of Obj_ID / Name pairs (sequences)
      --
      --  AuthorityInfoAccessSyntax  ::=
      --  SEQUENCE SIZE (1..MAX) OF AccessDescription
      --
      --  AccessDescription  ::=  SEQUENCE {
      --          accessMethod          OBJECT IDENTIFIER,
      --          accessLocation        GeneralName  }
      --
      --  id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
      --
      --  id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
      --
      --  id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
      Log (TRACE, "Parse_Authority_Info_Access");

      if not Cert.Valid then
         return;
      end if;

      --  Expect a sequence to start.
      Parse_Sequence_Data (Cert_Slice, Index, Authority_Info_Size, Cert);
      Log (DEBUG, " Authority Info Access Size: " & Authority_Info_Size'Image);

      if not Cert.Valid then
         return;
      end if;

      Authority_Info_End := Index + Natural (Authority_Info_Size);

      --  Parse each access description until we reach the end of the sequence
      while Index < Authority_Info_End and Cert.Valid loop
        Parse_Sequence_Data (Cert_Slice, Index, Access_Desc_Size, Cert);

        if not Cert.Valid then
          Log (FATAL, " Invalid Authority Info Access.");
          return;
        end if;

        Log (DEBUG, " Authority Info Access Description Size: " & Access_Desc_Size'Image);

        --  Expect Object ID and then the name
        Parse_Object_Identifier (Cert_Slice, Index, Access_Method, Cert);

        if not Cert.Valid then
          Log (FATAL, " Invalid Authority Info Access Description Object ID");
          return;
        end if;

        --  Get name
        --  @TODO: what if more than one OCSP or CA Issuer is indicated?
        case Access_Method is
            when PKIX_OCSP =>
                Parse_UTF8_String (Cert_Slice, Index, Cert.OCSP, Cert);

                if Cert.Valid then
                    Log (DEBUG, " Authority OCSP Access: " & UB_UTF8String.To_String(Cert.OCSP));
                end if;
            when PKIX_CA_ISSUERS =>
                Parse_UTF8_String (Cert_Slice, Index, Cert.CA_Issuers, Cert);

                if Cert.Valid then
                    Log (DEBUG, " Authority CA Issuer: " & UB_UTF8String.To_String(Cert.CA_Issuers));
                end if;
            when Others =>
                Log (FATAL, " Unsupported Authority Info Access Method");
                Cert.Valid := False;
                return;
        end case;

        if not Cert.Valid then
            Log (FATAL, " Error parsing Authority Info Access Extension");
            return;
        end if;
      end loop;
    end Parse_Authority_Info_Access;                         

    ---------------------------------------------------------------------------
    --  Parse_Authority_Key_Identifier
    ---------------------------------------------------------------------------
    procedure Parse_Authority_Key_Identifier (Cert_Slice : String;
                                              Index      : in out Natural;
                                              Cert       : in out Certificate)
    is
        Seq_Start : Natural := Index;
        Seq_Size : Unsigned_32;
        Ignore : Natural;
    begin
        --  AuthorityKeyIdentifier ::= SEQUENCE {
        --  keyIdentifier             [0] KeyIdentifier           OPTIONAL,
        --  authorityCertIssuer       [1] GeneralNames            OPTIONAL,
        --  authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
        --
        --  KeyIdentifier ::= OCTET STRING
        --
        --  authorityCertIssuer and authorityCertSerialNumber MUST both
        --  be present or both be absent

        Log (TRACE, "Parse_Authority_Key_Identifier");
        
        if not Cert.Valid then
            return;
        end if;

        Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);

        Log (TRACE, "Authority Key Identifier Sequence Size:" & Seq_Size'Image);

        --  TODO: do we always expect this to be 128?
        if Byte_At (Cert_Slice, Index) = 128 then
            Log (TRACE, "Parsing Authority Key Identifier as Octet String");
            Parse_Context_Specific_Octet_String (Cert_Slice, Index, Cert.Key_Identifier_Len, Cert.Key_Identifier, Cert);

            if not Cert.Valid then
                Log (FATAL, "Expected Octet String for Authority Key Identifier extension");
                return;
            else
                Log (TRACE, "Authority Key Identifier Len: " & Cert.Key_Identifier_Len'Image);

                if Log_Level >= DEBUG then
                    Log (DEBUG, " Authority Key Identifier:");
                    Put_Key_Bytes (Cert.Key_Identifier, Cert.Key_Identifier_Len);
                end if;
            end if;
        end if;

        if not Cert.Valid then
            return;
        end if;

        if Index < Seq_Start + Natural(Seq_Size) then

            --  Optional authority data present  - otherwise we're done.
            if Is_String (Cert_Slice (Index)) then
                Put_Line ("b");
                -- need both authorityCertIssuer and authorityCertSerialNumber
                -- Get authorityCertIssuer
                Parse_UTF8_String (Cert_Slice, Index, Cert.Authority_Cert_Issuer, Cert);

                if not Cert.Valid then
                    Log (TRACE, "Unable to parse UTF8 String for Authority Key Issuer");
                    return;
                end if;

                Log (TRACE, "Authority Cert Issuer: " & Cert.Authority_Cert_Issuer'Image);

                -- Expect authorityCertSerialNumber
                if Byte_At (Cert_Slice, Index) /= TYPE_INTEGER then
                    Cert.Valid := False;
                    Log (FATAL, "Expected Authority Key Identifier Cert Serial Number");

                    return;
                end if;

                Parse_Integer (Cert_Slice, Index, Cert.Authority_Cert_Serial_Len, Cert.Authority_Cert_Serial_Number, Cert);

                if not Cert.Valid then
                    Log (FATAL, "Failed to parse Authority Key Identifier Cert Serial Number");
                end if;
            end if;
        end if;

    end Parse_Authority_Key_Identifier;                                              

    ---------------------------------------------------------------------------
    --  Parse_Subject_Alt_Names
    --  RFC 5280, Section 4.2.1.6
    ---------------------------------------------------------------------------
    procedure Parse_Subject_Alt_Names (Cert_Slice : String;
                                       Index      : in out Natural;
                                       Ext_Len    : Natural;
                                       Cert       : in out Certificate)
        with Pre => Index in Cert_Slice'Range;

    procedure Parse_Subject_Alt_Names (Cert_Slice : String;
                                       Index      : in out Natural;
                                       Ext_Len    : Natural;
                                       Cert       : in out Certificate)
    is
        End_Index : Natural;
        Seq_Size  : Unsigned_32;
        Tag       : Unsigned_8;
        Len       : Unsigned_32;
    begin
        if not Cert.Valid then
            return;
        end if;

        Log (TRACE, "Parse_Subject_Alt_Names");

        --  Overflow-safe end index calculation
        if Ext_Len > Cert_Slice'Last - Index then
            Log (FATAL, "SAN extension exceeds certificate bounds");
            Cert.Valid := False;
            return;
        end if;
        End_Index := Index + Ext_Len;

        --  SubjectAltName ::= GeneralNames
        --  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        --  GeneralName ::= CHOICE {
        --       dNSName                  [2] IA5String,
        --       iPAddress                [7] OCTET STRING,
        --       ... }
        Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);

        if not Cert.Valid then
            return;
        end if;

        Cert.SAN_DNS_Name_Count := 0;

        while Index < End_Index and Cert.Valid loop
            Tag := Byte_At (Cert_Slice, Index);
            Index := Index + 1;

            if not (Index in Cert_Slice'Range) then
                Cert.Valid := False;
                Log (FATAL, "SAN: unexpected end of data");
                return;
            end if;

            --  Parse length (short form only for SAN entries)
            Len := Unsigned_32 (Byte_At (Cert_Slice, Index));
            Index := Index + 1;

            --  Ensure entry doesn't extend past SAN extension boundary
            if Index + Natural (Len) > End_Index then
                Log (FATAL, "SAN entry exceeds extension boundary");
                Cert.Valid := False;
                return;
            end if;

            case Tag is
                when 16#82# =>
                    --  dNSName [2] IA5String (context-specific, primitive)
                    if Cert.SAN_DNS_Name_Count < Max_SAN_DNS_Names and
                       Index + Natural (Len) - 1 in Cert_Slice'Range and
                       Natural (Len) <= 64
                    then
                        Cert.SAN_DNS_Name_Count := Cert.SAN_DNS_Name_Count + 1;
                        declare
                            Name : String (1 .. Natural (Len));
                        begin
                            for I in 0 .. Natural (Len) - 1 loop
                                Name (I + 1) := Cert_Slice (Index + I);
                            end loop;
                            Cert.SAN_DNS_Names (SAN_Index (Cert.SAN_DNS_Name_Count)) :=
                                UB_Common_Name.To_Bounded_String (Name);
                        end;
                        Log (DEBUG, " SAN dNSName: " &
                            UB_Common_Name.To_String (
                                Cert.SAN_DNS_Names (SAN_Index (Cert.SAN_DNS_Name_Count))));
                    else
                        Log (WARN, "SAN: dNSName too long or too many SANs, skipping");
                    end if;
                    Index := Index + Natural (Len);
                when others =>
                    --  Skip other GeneralName types (iPAddress, rfc822Name, etc.)
                    Log (DEBUG, " SAN: skipping GeneralName tag" & Tag'Image);
                    Index := Index + Natural (Len);
            end case;
        end loop;

        Log (DEBUG, " SAN DNS Name Count:" & Cert.SAN_DNS_Name_Count'Image);
    end Parse_Subject_Alt_Names;

    ---------------------------------------------------------------------------
    --  Parse_Extension
    ---------------------------------------------------------------------------
    procedure Parse_Extension (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
    is
        Start_Idx : Natural := Index;  -- Need to do some bookkeeping for skipped extensions
        Seq_Size  : Unsigned_32;
        Ext_End   : Natural;  --  End position of this extension
        Object_ID : OID.Object_ID;
        Critical  : Boolean := False;  --  note default value of false, if missing.
        Ext_Len   : Natural;
    begin
        -- Each extension is a SEQUENCE of the following form:
        --     Extension ::= SEQUENCE {
        --         extnID      OBJECT IDENTIFIER,
        --         critical    BOOLEAN DEFAULT FALSE, <optional>
        --         extnValue   OCTET STRING
        --     }
        -- The extnID is an OID that identifies the extension. The critical
        -- field is a BOOLEAN that indicates whether or not the extension is
        -- critical. The extnValue is an OCTET STRING that contains the
        -- extension value. The extension value is defined as an uninterpreted
        -- sequence of bytes. The extension value format and content are
        -- defined by the extension specification.

        if not Cert.Valid then
            return;
        end if;

        Log (TRACE, "Parse_Extension");

        Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);
        --  Record extension end so we can skip past it if parsing fails
        Ext_End := Index + Natural (Seq_Size);
        Parse_Object_Identifier (Cert_Slice, Index, Object_ID, Cert);

        --  For unknown OIDs, Parse_Object_Identifier sets Valid=False.
        --  For non-critical unknown extensions, recover and skip.
        if Object_ID = OID.UNKNOWN then
            Cert.Valid := True;  --  recover from unknown OID
            Log (WARN, "Skipping unknown extension");
            Index := Ext_End;
            return;
        end if;

        if not Cert.Valid then
            return;
        end if;

        -- Critical field?
        if Byte_At (Cert_Slice, Index) = TYPE_BOOLEAN then
            Parse_Boolean (Cert_Slice, Index, Critical, Cert);
        end if;

        Parse_Octet_String_Header (Cert_Slice, Index, Ext_Len, Cert);

        Log (DEBUG, " Extension Seq_Size: " & Seq_Size'Image);
        Log (DEBUG, " Extension Critical? " & Critical'Image);
        Log (DEBUG, " Extension Length: " & Ext_Len'Image);

        if not Cert.Valid then
            return;
        end if;

        case Object_Id is
            when BASIC_CONSTRAINTS =>
                Parse_Basic_Constraints (Cert_Slice, Index, Cert);
            when SUBJECT_KEY_IDENTIFIER =>
                Parse_Subject_Key_Identifier (Cert_Slice, Index, Cert);
            when KEY_USAGE =>
                Parse_Key_Usage (Cert_Slice, Index, Cert);
            when PKIX_AUTHORITY_INFO_ACCESS =>
                Parse_Authority_Info_Access (Cert_Slice, Index, Cert);
            when AUTHORITY_KEY_IDENTIFIER =>
                Parse_Authority_Key_Identifier (Cert_Slice, Index, Cert);
            when SUBJECT_ALT_NAME =>
                Parse_Subject_Alt_Names (Cert_Slice, Index, Ext_Len, Cert);
            --  when CERTIFICATE_POLICIES =>
            --      Parse_Certificate_Policies (Cert_Slice, Index, Cert);
            --  when CRL_DISTRIBUTION_POINTS =>
            --      Parse_CRL_Distribution_Points (Cert_Slice, Index, Cert);
            when others =>
                --  Per RFC 5280, "If an extension containing unexpected values is marked as critical,
                --  the implementation MUST reject the certificate or CRL containing the
                --  unrecognized extension."
                if Critical then
                  Log (FATAL, "Unsupported Critical Extension " & Object_ID'Image);
                  Cert.Valid := False;
                  return;
                else
                  Log (WARN, "Unsupported Extension " & Object_ID'Image);
                  --  Skip over extension content (Ext_Len bytes from
                  --  current Index, which is right after the OCTET STRING
                  --  header).
                  Index := Index + Ext_Len;
                end if;
        end case;

        --  Ensure we advance past the full extension regardless of
        --  whether individual field parsing consumed all bytes.
        if Index < Ext_End then
            Index := Ext_End;
        end if;

    end Parse_Extension;
end X509.Extensions;
