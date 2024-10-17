-------------------------------------------------------------------------------
--  X509.Basic
--  Parsing of basic ASN.1 types
-------------------------------------------------------------------------------
package X509.Basic with
   SPARK_Mode
is
   TYPE_BOOLEAN     : constant := 16#01#;
   TYPE_INTEGER     : constant := 16#02#;
   TYPE_BITSTRING   : constant := 16#03#;
   TYPE_OCTETSTRING : constant := 16#04#;
   TYPE_NULL        : constant := 16#05#;
   TYPE_OBJECTID    : constant := 16#06#;
   TYPE_REAL        : constant := 16#09#;
   TYPE_UTF8STRING  : constant := 16#0C#;
   TYPE_NUMSTRING   : constant := 16#12#;
   TYPE_PRINTSTRING : constant := 16#13#;
   TYPE_UTCTIME     : constant := 16#17#;
   TYPE_GENTIME     : constant := 16#18#;
   TYPE_SEQUENCE    : constant := 16#30#;
   TYPE_SET         : constant := 16#31#;

   --  Constructed Types
   TYPE_VERSION     : constant := 16#A0#;
   TYPE_EXTENSIONS  : constant := 16#A3#;
   TYPE_IA5STRING   : constant := 16#86#;

   ----------------------------------------------------------------------------
   --  Is_String
   ----------------------------------------------------------------------------
   function Is_String (Tag : Character) return Boolean;

   ----------------------------------------------------------------------------
   --  Check_Bounds
   ----------------------------------------------------------------------------
   function Check_Bounds (Cert_Slice : String;
                          Index      : Natural;
                          Obj_Len    : Unsigned_32) return Boolean;

   ----------------------------------------------------------------------------
   --  Parse_Boolean
   ----------------------------------------------------------------------------
   procedure Parse_Boolean (Cert_Slice : String;
                            Index      : in out Natural;
                            Value      : out Boolean;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Size
   ----------------------------------------------------------------------------
   procedure Parse_Size (Cert_Slice : String;
                        Index      : in out Natural;
                        Size       : out Unsigned_32;
                        Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;    

   ----------------------------------------------------------------------------
   --  Parse_Null
   ----------------------------------------------------------------------------
   procedure Parse_Null (Cert_Slice : String;
                         Index      : in out Natural;
                         Cert       : in out Certificate);

   ----------------------------------------------------------------------------
   --  Parse_Sequence_Data
   ----------------------------------------------------------------------------
   procedure Parse_Sequence_Data (Cert_Slice : String;
                                  Index      : in out Natural;
                                  Size       : out Unsigned_32;
                                  Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Set
   ----------------------------------------------------------------------------
   procedure Parse_Set (Cert_Slice : String;
                        Index      : in out Natural;
                        Size       : out Unsigned_32;
                        Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Fwd declare and contracts
   --  Parse_Bit_String_Header parses the header of a bit string, but does not
   --  read in the bytes. This is useful for bit strings which are actually
   --  sequences of other objects, like the public key.
   --  @param Size is the size of the bit string in bytes, not including the
   --     unused bits byte.
   ----------------------------------------------------------------------------
   procedure Parse_Bit_String_Header (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Size       : out Unsigned_32;
                                      Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Object_Identifier
   ----------------------------------------------------------------------------
   procedure Parse_Object_Identifier (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Object_ID  : out OID.Object_ID;
                                      Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Integer
   --  Parse an ASN.1 signed integer
   ----------------------------------------------------------------------------
   procedure Parse_Integer (Cert_Slice : String;
                            Index      : in out Natural;
                            Value      : out Integer;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Integer
   --  For large integers like a RSA key modulus
   ----------------------------------------------------------------------------
   procedure Parse_Integer (Cert_Slice : String;
                            Index      : in out Natural;
                            Length     : out Natural;
                            Bytes      : out Key_Bytes;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Bit_String
   ----------------------------------------------------------------------------
   procedure Parse_Bit_String (Cert_Slice  : String;
                               Index       : in out Natural;
                               Length      : out Natural;
                               Unused_Bits : out Unsigned_8;
                               Bytes       : out Key_Bytes;
                               Cert        : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Time
   ----------------------------------------------------------------------------
   procedure Parse_Time (Cert_Slice : String;
                         Index      : in out Natural;
                         Period     : in out Time;
                         Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Octet_String_Header
   --  Parse the header of an octet string, but do not read in the bytes.
   ----------------------------------------------------------------------------
   procedure Parse_Octet_String_Header (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Length     : out Natural;
                                        Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Parse_Octet_String
   ----------------------------------------------------------------------------
   procedure Parse_Octet_String (Cert_Slice : String;
                                 Index      : in out Natural;
                                 Length     : out Natural;
                                 Bytes      : out Key_Bytes;
                                 Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   ----------------------------------------------------------------------------
   --  Generic_Parse_String
   ----------------------------------------------------------------------------
   generic
      with Package P is new Generic_Bounded_Length (<>);
   procedure Generic_Parse_String (Cert_Slice : String;
                                   Index      : in out Natural;
                                   S          : in out P.Bounded_String;
                                   Cert       : in out Certificate);

   ----------------------------------------------------------------------------
   --  Byte_At
   --  Given the string and position, what ASN.1 type is indicated by the tag
   --  at this position?
   ----------------------------------------------------------------------------
   function Byte_At (Cert_Slice : String; Index : in Natural) return Unsigned_8
     with Pre => Index in Cert_Slice'Range;

end X509.Basic;
