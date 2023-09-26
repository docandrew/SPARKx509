with Ada.Text_IO; use Ada.Text_IO;

with OID; use OID;
with X509.Basic; use X509.Basic;

with SPARKX509.Debug; use SPARKX509.Debug;
with X509.Logs; use X509.Logs;

package body X509.Extensions with
    SPARK_Mode
is

    ---------------------------------------------------------------------------
    --  Parse_Basic_Constraints
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
        Critical : Boolean;
        Sequence_Size : Unsigned_32;
        Sub_Sequence_Size : Unsigned_32;
        Octet_String_Size : Natural;
        
        CA_Flag : Boolean;  -- cA field is a BOOLEAN that indicates whether or
                            -- not the subject of the certificate is a CA.
    begin
        if not Cert.Valid then
            return;
        end if;

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
        Parse_Sequence_Data (Cert_Slice, Index, Sequence_Size, Cert);
        Parse_Boolean (Cert_Slice, Index, Critical, Cert);
        Parse_Octet_String_Header (Cert_Slice, Index, Octet_String_Size, Cert);
        Parse_Sequence_Data (Cert_Slice, Index, Sub_Sequence_Size, Cert);

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
        Outer_Length : Natural;
    begin

        if not Cert.Valid then
            return;
        end if;

        Log (TRACE, "Parse_Subject_Key_Identifier");

        -- Subject Key Identifier is an OCTET STRING of the following form:
        --     SubjectKeyIdentifier ::= KeyIdentifier
        --     KeyIdentifier ::= OCTET STRING

        Parse_Octet_String_Header (Cert_Slice, Index, Outer_Length, Cert);
        
        if not Cert.Valid then
            return;
        end if;
        
        Parse_Octet_String (Cert_Slice, Index, Cert.Subject_Key_Id_Len, Cert.Subject_Key_Id, Cert);

        if not Cert.Valid then
            return;
        end if;

        if Cert.Subject_Key_Id_Len + 2 /= Outer_Length then
            Log (FATAL, "Subject Key Identifier Length Mismatch");
            Cert.Subject_Key_Id_Len := 0;
            Cert.Valid := False;
            return;
        end if;

        if X509.Logs.Log_Level >= X509.Logs.DEBUG then
            Log (DEBUG, "Subject Key Identifier:");
            Put_Key_Bytes (Cert.Subject_Key_Id, Cert.Subject_Key_Id_Len);
        end if;

    end Parse_Subject_Key_Identifier;

    ---------------------------------------------------------------------------
    --  Parse_Extension
    ---------------------------------------------------------------------------
    procedure Parse_Extension (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
    is
        Seq_Size  : Unsigned_32;
        Object_ID : OID.Object_ID;
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
        Parse_Object_Identifier (Cert_Slice, Index, Object_ID, Cert);

        if not Cert.Valid then
            return;
        end if;

        case Object_Id is
            when BASIC_CONSTRAINTS =>
                Parse_Basic_Constraints (Cert_Slice, Index, Cert);
            when SUBJECT_KEY_IDENTIFIER =>
                Parse_Subject_Key_Identifier (Cert_Slice, Index, Cert);
                -- Parse_Authority_Key_Identifier (Cert_Slice, Index, Cert);
            --  when KEY_USAGE =>
            --      Parse_Key_Usage (Cert_Slice, Index, Cert);
            --  when SUBJECT_ALT_NAME =>
            --      Parse_Subject_Alt_Name (Cert_Slice, Index, Cert);
            when others =>
                Put_Line ("FATAL: Unsupported Extension");
                Cert.Valid := False;
                return;
        end case;

        -- Parse_Boolean (Cert_Slice, Index);
    end Parse_Extension;
end X509.Extensions;
