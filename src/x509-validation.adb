with Ada.Characters.Handling; use Ada.Characters.Handling;
with Ada.Strings.Bounded; use Ada.Strings.Bounded;

package body X509.Validation with
   SPARK_Mode => Off
is

   ---------------------------------------------------------------------------
   --  Case-insensitive string comparison
   ---------------------------------------------------------------------------
   function Equal_Case_Insensitive (A, B : String) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in A'Range loop
         if To_Lower (A (I)) /= To_Lower (B (A'First + (I - A'First))) then
            return False;
         end if;
      end loop;
      return True;
   end Equal_Case_Insensitive;

   ---------------------------------------------------------------------------
   --  Match a hostname against a pattern that may contain a wildcard in
   --  the leftmost label (e.g. "*.example.com" matches "foo.example.com").
   ---------------------------------------------------------------------------
   function Matches_Pattern (Pattern  : String;
                              Hostname : String) return Boolean
   is
   begin
      --  Wildcard match: pattern starts with "*."
      if Pattern'Length >= 3 and then
         Pattern (Pattern'First) = '*' and then
         Pattern (Pattern'First + 1) = '.'
      then
         --  The rest of the pattern must match a suffix of hostname after
         --  the first dot.
         declare
            Suffix : constant String :=
               Pattern (Pattern'First + 1 .. Pattern'Last);
         begin
            --  Find the first dot in the hostname
            for I in Hostname'Range loop
               if Hostname (I) = '.' then
                  declare
                     Host_Suffix : constant String :=
                        Hostname (I .. Hostname'Last);
                  begin
                     return Equal_Case_Insensitive (Suffix, Host_Suffix);
                  end;
               end if;
            end loop;
            --  No dot in hostname - wildcard can't match
            return False;
         end;
      else
         return Equal_Case_Insensitive (Pattern, Hostname);
      end if;
   end Matches_Pattern;

   ---------------------------------------------------------------------------
   --  Is_Time_Valid
   ---------------------------------------------------------------------------
   function Is_Time_Valid (Cert : Certificate;
                           Now  : Time) return Boolean
   is
   begin
      return Now >= Cert.Valid_From and Now <= Cert.Valid_To;
   end Is_Time_Valid;

   ---------------------------------------------------------------------------
   --  Is_Hostname_Valid
   ---------------------------------------------------------------------------
   function Is_Hostname_Valid (Cert     : Certificate;
                               Hostname : String) return Boolean
   is
   begin
      --  Check SAN dNSName entries first (RFC 6125: if SANs present,
      --  CN must NOT be used)
      if Cert.SAN_DNS_Name_Count > 0 then
         for I in 1 .. Cert.SAN_DNS_Name_Count loop
            declare
               Name : constant String :=
                  UB_Common_Name.To_String (
                     Cert.SAN_DNS_Names (SAN_Index (I)));
            begin
               if Matches_Pattern (Name, Hostname) then
                  return True;
               end if;
            end;
         end loop;
         return False;
      end if;

      --  Fallback to Common Name (deprecated but still common)
      declare
         CN : constant String :=
            UB_Common_Name.To_String (Cert.Subject.Common_Name);
      begin
         return Matches_Pattern (CN, Hostname);
      end;
   end Is_Hostname_Valid;

   ---------------------------------------------------------------------------
   --  Is_Key_Usage_Valid_For_TLS
   ---------------------------------------------------------------------------
   function Is_Key_Usage_Valid_For_TLS (Cert : Certificate) return Boolean is
   begin
      return Cert.Digital_Signature;
   end Is_Key_Usage_Valid_For_TLS;

   ---------------------------------------------------------------------------
   --  Is_Self_Signed
   ---------------------------------------------------------------------------
   function Is_Self_Signed (Cert : Certificate) return Boolean is
      use UB_Common_Name;
      use UB_Country_Name;
      use UB_Org;
      use UB_State;
   begin
      return Cert.Issuer.Common_Name = Cert.Subject.Common_Name and
             Cert.Issuer.Country     = Cert.Subject.Country and
             Cert.Issuer.Org         = Cert.Subject.Org and
             Cert.Issuer.State       = Cert.Subject.State;
   end Is_Self_Signed;

   ---------------------------------------------------------------------------
   --  Validate
   ---------------------------------------------------------------------------
   function Validate (Cert     : Certificate;
                      Hostname : String;
                      Now      : Time) return Validation_Result
   is
      Result : Validation_Result;
   begin
      Result.Time_Valid     := Is_Time_Valid (Cert, Now);
      Result.Hostname_Valid := Is_Hostname_Valid (Cert, Hostname);
      Result.Key_Usage_OK   := Is_Key_Usage_Valid_For_TLS (Cert);
      Result.Self_Signed    := Is_Self_Signed (Cert);

      Result.Valid := Result.Time_Valid and
                      Result.Hostname_Valid and
                      Result.Key_Usage_OK and
                      Cert.Valid;

      return Result;
   end Validate;

end X509.Validation;
