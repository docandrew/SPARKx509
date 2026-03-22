with Ada.Calendar; use Ada.Calendar;

package X509.Validation with
   SPARK_Mode
is
   type Validation_Result is record
      Valid          : Boolean := False;
      Time_Valid     : Boolean := False;
      Hostname_Valid : Boolean := False;
      Key_Usage_OK   : Boolean := False;
      Self_Signed    : Boolean := False;
   end record;

   --  Check if the certificate is within its validity period.
   function Is_Time_Valid (Cert : Certificate;
                           Now  : Time) return Boolean;

   --  Check if the hostname matches SAN dNSName entries (with wildcard
   --  support) or falls back to the Subject Common Name.
   function Is_Hostname_Valid (Cert     : Certificate;
                               Hostname : String) return Boolean;

   --  Check if the certificate's Key Usage extension permits TLS
   --  server authentication (Digital_Signature must be set).
   function Is_Key_Usage_Valid_For_TLS (Cert : Certificate) return Boolean;

   --  Check if the certificate appears to be self-signed (Issuer = Subject).
   function Is_Self_Signed (Cert : Certificate) return Boolean;

   --  Combined validation. Returns a result record with individual checks.
   function Validate (Cert     : Certificate;
                      Hostname : String;
                      Now      : Time) return Validation_Result;

end X509.Validation;
