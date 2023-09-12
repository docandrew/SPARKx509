with Ada.Calendar; use Ada.Calendar;
with Ada.Strings.Bounded; use Ada.Strings.Bounded;
with Interfaces; use Interfaces;

with OID; use OID;

package ASN1 with
   SPARK_Mode
is
   --  X.509 strings are defined with upper-bounds, per RFC 5280
   --  package UB_Name        is new Generic_Bounded_Length (Max => 32768);
   package UB_Common_Name     is new Generic_Bounded_Length (Max => 64);
   package UB_Locality        is new Generic_Bounded_Length (Max => 128);
   package UB_State           is new Generic_Bounded_Length (Max => 128);
   package UB_Org             is new Generic_Bounded_Length (Max => 64);
   package UB_Org_Unit        is new Generic_Bounded_Length (Max => 64);
   package UB_Title           is new Generic_Bounded_Length (Max => 64);
   package UB_Given_Name      is new Generic_Bounded_Length (Max => 16);
   package UB_Surname         is new Generic_Bounded_Length (Max => 40);
   package UB_Initials        is new Generic_Bounded_Length (Max => 5);
   package UB_Pseudonym       is new Generic_Bounded_Length (Max => 128);
   package UB_Generation      is new Generic_Bounded_Length (Max => 3);
   package UB_Serial_Number   is new Generic_Bounded_Length (Max => 64);
   package UB_Match           is new Generic_Bounded_Length (Max => 128);
   package UB_Email           is new Generic_Bounded_Length (Max => 255);
   package UB_Country_Name    is new Generic_Bounded_Length (Max => 2);
   package UB_Country_Numeric is new Generic_Bounded_Length (Max => 3);
   package UB_Postal_Code     is new Generic_Bounded_Length (Max => 16);

   subtype Algorithm_Identifier is OID.Object_ID range UNKNOWN_ALGORITHM .. ID_EDDSA448_PH;

   --  Maximum length of serial number is 20 per RFC 5280
   type Serial_Number_Length is new Natural range 1 .. 20;
   type Serial_Number_Type is array (Serial_Number_Length) of Unsigned_8;

   --  Identification of a subject or issuer
   type Identification_Type is record
      Country             : UB_Country_Name.Bounded_String;
      State               : UB_State.Bounded_String;
      Locality            : UB_Locality.Bounded_String;
      Common_Name         : UB_Common_Name.Bounded_String;
      Org                 : UB_Org.Bounded_String;
      Org_Unit            : UB_Org_Unit.Bounded_String;
      Title               : UB_Title.Bounded_String;
      Given_Name          : UB_Given_Name.Bounded_String;
      Surname             : UB_Surname.Bounded_String;
      Initials            : UB_Initials.Bounded_String;
      Pseudonym           : UB_Pseudonym.Bounded_String;
      Generation          : UB_Generation.Bounded_String;
   end record;

   type Key_Bytes is array (Natural range 0 .. 65535) of Unsigned_8;

   -- @field Valid is False if an error was found during parsing, True otherwise.
   -- @field Version is the version of this x.509 certificate
   -- @field Serial is the serial number of this x.509 certificate
   -- @field Serial_Length is the length of the serial number, in bytes
   -- @field Signature_Algorithm, see Signature_Algorithm_Type
   -- @field Issuer is issuer details, see Identification_Type
   -- @field Subject is subject details, see Identification_Type
   -- @field Valid_From is the start of the certificate validity period
   -- @field Valid_To is the end of the certificate validity period
   -- @field Public_Key_Algorithm is the algorithm for the public key
   -- @field Public_Key_Len is the length of the public key, in bytes
   -- @field Public_Key are the actual bytes of the public key
   type Certificate is record
      Valid                : Boolean;
      Version              : Integer;
      Serial_Length        : Serial_Number_Length;
      Serial               : Serial_Number_Type := (others => 0);
      Signature_Algorithm  : Algorithm_Identifier;
      Issuer               : Identification_Type;
      Subject              : Identification_Type;
      Valid_From           : Time;
      Valid_To             : Time;
      Public_Key_Algorithm : Algorithm_Identifier;
      Public_Key_Len       : Natural := 0;
      Public_Key           : Key_Bytes;
   end record;

   ---------------------------------------------------------------------------
   -- Parse_Certificate
   ---------------------------------------------------------------------------
   procedure Parse_Certificate (Cert_Bytes : String; Cert : out Certificate);

end ASN1;