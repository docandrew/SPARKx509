
with Ada.Calendar; use Ada.Calendar;
with Interfaces; use Interfaces;

with OID; use OID;

with X509.Basic; use X509.Basic;
with X509.Extensions; use X509.Extensions;

package X509.Certificates
   with SPARK_Mode
is
   ---------------------------------------------------------------------------
   -- Parse_Certificate
   ---------------------------------------------------------------------------
   procedure Parse_Certificate (Cert_Bytes : String; Cert : out Certificate);

end X509.Certificates;
