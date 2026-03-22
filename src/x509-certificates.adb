with Ada.Calendar.Formatting; use Ada.Calendar.Formatting;
with Ada.Text_IO; use Ada.Text_IO;

with OID;
with SPARKx509.Debug; use SPARKx509.Debug;
with x509.Logs; use x509.Logs;

package body X509.Certificates is

   ----------------------------------------------------------------------------
   --  Generic instantiations for the various bounded string types
   ----------------------------------------------------------------------------
   procedure Parse_Country
      is new Generic_Parse_String (UB_Country_Name);
   procedure Parse_State
      is new Generic_Parse_String (UB_State);
   procedure Parse_Locality
      is new Generic_Parse_String (UB_Locality);
   procedure Parse_Common_Name
      is new Generic_Parse_String (UB_Common_Name);
   procedure Parse_Org
      is new Generic_Parse_String (UB_Org);
   procedure Parse_Org_Unit
      is new Generic_Parse_String (UB_Org_Unit);
   procedure Parse_Title
      is new Generic_Parse_String (UB_Title);
   procedure Parse_Given_Name
      is new Generic_Parse_String (UB_Given_Name);
   procedure Parse_Surname
      is new Generic_Parse_String (UB_Surname);
   procedure Parse_Initials
      is new Generic_Parse_String (UB_Initials);
   procedure Parse_Pseudonym
      is new Generic_Parse_String (UB_Pseudonym);
   procedure Parse_Generation
      is new Generic_Parse_String (UB_Generation);

   --  Fwd declare and contracts
   procedure Parse_Version (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Version (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate) is
      Version : Natural;
   begin
      if not Cert.Valid then
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_VERSION then
         --  no version supplied, assume v1, Index remains unchanged
         Put_Line ("No X.509 version supplied, assuming default v1");
         Cert.Version := 1;
      else
         Index := Index + 1;
         --  How long? Should be 3 bytes representing a universal type integer
         if Byte_At (Cert_Slice, Index) /= 3 then
            Log (FATAL, "Expected X.509 version to be 3 bytes (it wasn't).");
            Cert.Valid := False;
            return;
         end if;

         --  Version should be a universal type integer
         Index := Index + 1;
         if Byte_At (Cert_Slice, Index) /= TYPE_INTEGER then
            Log (FATAL, "Expected X.509 version to be an integer");
            Cert.Valid := False;
            return;
         end if;

         --  Integer should be 1 byte long
         Index := Index + 1;
         if Byte_At (Cert_Slice, Index) /= 1 then
            Log (FATAL, "Expected X.509 version integer to be 1 byte");
            Cert.Valid := False;
            return;
         end if;

         Index := Index + 1;
         Version := Natural (Byte_At (Cert_Slice, Index));

         if not (Version in 0 | 1 | 2) then
            Log (FATAL, "Expected X.509 version 0 (v1), 1 (v2) or 2 (v3), got" &
                      Version'Image);
            Cert.Valid := False;
            return;
         else
            Index := Index + 1;
            --  DER encodes version as 0=v1, 1=v2, 2=v3
            Cert.Version := Version + 1;
         end if;
      end if;
   end Parse_Version;

   --  Fwd declare and contracts
   procedure Parse_Serial (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Serial (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate) is
      Serial_Size : Unsigned_32;
   begin
      if not Cert.Valid then
         return;
      end if;

      --  Serial number should be a universal integer
      if Byte_At (Cert_Slice, Index) /= TYPE_INTEGER then
         Log (FATAL, "Expected X.509 serial number (ASN.1 Integer)");
         Cert.Valid := False;
         return;
      end if;

      Index := Index + 1;
      Parse_Size (Cert_Slice, Index, Serial_Size, Cert);

      --  RFC 5280 mandates serials no larger than 20 bytes.
      if Serial_Size > 20 then
         Log (FATAL, "X.509 Serial Number too large");
         Cert.Valid := False;
         return;
      end if;

      if Serial_Size = 0 then
         Log (FATAL, "X.509 Serial Number length cannot be zero");
         Cert.Valid := False;
         return;
      end if;

      if Index + Natural (Serial_Size) > Cert_Slice'Last then
         Log (FATAL, "X.509 serial length exceeds certificate size");
         Cert.Valid := False;
         return;
      end if;

      Cert.Serial_Length := Serial_Number_Length(Serial_Size);

      --  Read in the serial bytes.
      for I in 1 .. Cert.Serial_Length loop
         Cert.Serial (I) := Unsigned_8 (Byte_At (Cert_Slice, Index));
         Index := Index + 1;
      end loop;
   end Parse_Serial;

   --  Fwd declare and contracts
   procedure Parse_Algorithm (Cert_Slice : String;
                              Index      : in out Natural;
                              Algorithm  : in out Algorithm_Identifier;
                              Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Algorithm (Cert_Slice : String;
                              Index      : in out Natural;
                              Algorithm  : in out Algorithm_Identifier;
                              Cert       : in out Certificate)
   is
      Seq_Size   : Unsigned_32;
      Object_ID  : OID.Object_ID;
   begin
      --  Expect a sequence containing an object identifier and then an optional parameter
      Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);

      if not Cert.Valid then
         return;
      end if;

      Parse_Object_Identifier (Cert_Slice, Index, Object_ID, Cert);

      if not Cert.Valid then
         return;
      end if;

      if Object_ID not in Algorithm_Identifier then
         Log (FATAL, "Unknown Signature Algorithm");
         Algorithm := UNKNOWN_ALGORITHM;
         Cert.Valid := False;
         return;
      else
         Algorithm := Algorithm_Identifier (Object_ID);
         --  Cert.Signature_Algorithm := Algorithm;
      end if;

      -- Depends on signature algorithm
      case Algorithm is
         when RSA_ENCRYPTION | SHA256_WITH_RSA | SHA384_WITH_RSA | SHA512_WITH_RSA | SHA224_WITH_RSA =>
            -- Expect a single parameter, a null
            Parse_Null (Cert_Slice, Index, Cert);
         when ID_EDDSA25519 =>
            -- Expect no parameters
            null;
         when EC_PUBLIC_KEY =>
            --  id-ecPublicKey has a named curve OID parameter
            declare
               Curve_OID : OID.Object_ID;
            begin
               Parse_Object_Identifier (Cert_Slice, Index, Curve_OID, Cert);
               if Cert.Valid and then Curve_OID /= OID.SECP256R1 then
                  Log (FATAL, "Unsupported EC curve (only P-256 supported)");
                  Cert.Valid := False;
               end if;
            end;
         when ECDSA_WITH_SHA256 | ECDSA_WITH_SHA384 =>
            --  ECDSA signature algorithms have no parameters
            null;
         when others =>
            Log (FATAL, "Unsupported Algorithm " & Algorithm'Image);
      end case;
   end Parse_Algorithm;

   --  Fwd declare and contracts
   procedure Parse_Signature_Algorithm (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Algorithm  : in out Algorithm_Identifier;
                                        Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Signature_Algorithm (Cert_Slice : String;
                                        Index      : in out Natural;
                                        Algorithm  : in out Algorithm_Identifier;
                                        Cert       : in out Certificate)
   is
   begin
      Parse_Algorithm (Cert_Slice, Index, Algorithm, Cert);
   end Parse_Signature_Algorithm;

   --  Fwd declare and contracts
   procedure Parse_Public_Key_Algorithm (Cert_Slice : String;
                                         Index      : in out Natural;
                                         Cert       : in out Certificate;
                                         Algorithm  : in out Algorithm_Identifier)
      with Pre => Index in Cert_Slice'Range;                                         
   
   procedure Parse_Public_Key_Algorithm (Cert_Slice : String;
                                         Index      : in out Natural;
                                         Cert       : in out Certificate;
                                         Algorithm  : in out Algorithm_Identifier)
   is
   begin
      Parse_Algorithm (Cert_Slice, Index, Algorithm, Cert);
   end Parse_Public_Key_Algorithm;

   --  Fwd declare and contracts
   procedure Parse_Identification (Cert_Slice : String;
                                   Index      : in out Natural;
                                   ID         : in out Identification_Type;
                                   Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Identification (Cert_Slice : String;
                                   Index      : in out Natural;
                                   ID         : in out Identification_Type;
                                   Cert       : in out Certificate)
   is
      Size          : Unsigned_32;
      Seq_End       : Natural;
      ID_Component  : OID.Object_ID;
   begin
      --  Expect a sequence of sets of sequences
      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);
      
      if Cert.Valid and Size /= 0 then
         --  Check for overflow before computing Seq_End
         if Natural (Size) > Cert_Slice'Last - Index then
            Log (FATAL, "Identification sequence exceeds certificate bounds");
            Cert.Valid := False;
            return;
         end if;
         Seq_End := Index + Natural (Size);
      else
         Cert.Valid := False;
         return;
      end if;
      
      while Index < Seq_End loop
         Parse_Set (Cert_Slice, Index, Size, Cert);
         Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);

         --  Expect Object Identifier and then a string of some sort. The type
         --  of string we'll parse depends on the object ID. This is because
         --  different string types have different sizes/character sets here.
         Parse_Object_Identifier (Cert_Slice, Index, ID_Component, Cert);

         if not Cert.Valid then
            return;
         end if;

         case ID_Component is
            when OID.COUNTRY =>
               Put ("Country: ");
               Parse_Country (Cert_Slice, Index, ID.Country, Cert);
               Put_Line (UB_Country_Name.To_String (ID.Country));
            when OID.STATE_OR_PROVINCE =>
               Put ("State: ");
               Parse_State (Cert_Slice, Index, ID.State, Cert);
               Put_Line (UB_State.To_String (ID.State));
            when OID.LOCALITY =>
               Put ("Locality: ");
               Parse_Locality (Cert_Slice, Index, ID.Locality, Cert);
               Put_Line (UB_Locality.To_String (ID.Locality));
            when OID.ORG =>
               Put ("Organization: ");
               Parse_Org (Cert_Slice, Index, ID.Org, Cert);
               Put_Line (UB_Org.To_String (ID.Org));
            when OID.ORG_UNIT =>
               Put ("Organizational Unit: ");
               Parse_Org_Unit (Cert_Slice, Index, ID.Org_Unit, Cert);
               Put_Line (UB_Org_Unit.To_String (ID.Org_Unit));
            when OID.COMMON_NAME =>
               Put ("Common Name: ");
               Parse_Common_Name (Cert_Slice, Index, ID.Common_Name, Cert);
               Put_Line (UB_Common_Name.To_String (ID.Common_Name));
            when OID.GIVEN_NAME =>
               Put ("Given Name: ");
               Parse_Given_Name (Cert_Slice, Index, ID.Given_Name, Cert);
               Put_Line (UB_Given_Name.To_String (ID.Given_Name));
            when OID.SURNAME =>
               Put ("Surname: ");
               Parse_Surname (Cert_Slice, Index, ID.Surname, Cert);
               Put_Line (UB_Surname.To_String (ID.Surname));
            when OID.INITIALS =>
               Put ("Initials: ");
               Parse_Initials (Cert_Slice, Index, ID.Initials, Cert);
               Put_Line (UB_Initials.To_String (ID.Initials));
            when OID.GENERATION_QUALIFIER =>
               Put ("Generation: ");
               Parse_Generation (Cert_Slice, Index, ID.Generation, Cert);
               Put_Line (UB_Generation.To_String (ID.Generation));
            when OID.PSEUDONYM =>
               Put ("Pseudonym: ");
               Parse_Pseudonym (Cert_Slice, Index, ID.Pseudonym, Cert);
               Put_Line (UB_Pseudonym.To_String (ID.Pseudonym));
            when others =>
               Log (FATAL, "Inappropriate Identification Field");
               Cert.Valid := False;
               return;
         end case;
      end loop;
   end Parse_Identification;

   --  Fwd declare and contracts
   procedure Parse_Issuer (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Issuer (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate)
   is
   begin
      Parse_Identification (Cert_Slice, Index, Cert.Issuer, Cert);
   end Parse_Issuer;

   --  Fwd declare and contracts
   procedure Parse_Subject (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Subject (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate)
   is
   begin
      Parse_Identification (Cert_Slice, Index, Cert.Subject, Cert);
   end Parse_Subject;

   --  Fwd declare and contracts
   procedure Parse_Validity_Period (Cert_Slice : String;
                                    Index      : in out Natural;
                                    Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Validity_Period (Cert_Slice : String;
                                    Index      : in out Natural;
                                    Cert       : in out Certificate)
   is
      Seq_Size : Unsigned_32;
   begin
      if not Cert.Valid then
         return;
      end if;

      --  Expect a sequence of 2 UTCTime objects or 2 GeneralizedTime
      --  objects.
      Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);
      Parse_Time (Cert_Slice, Index, Cert.Valid_From, Cert);
      Parse_Time (Cert_Slice, Index, Cert.Valid_To, Cert);
   end Parse_Validity_Period;

   --  Fwd declare and contracts
   procedure Parse_RSA_Key (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate;
                            PKey       : in out Public_Key_Type)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_RSA_Key (Cert_Slice : String;
                            Index      : in out Natural;
                            Cert       : in out Certificate;
                            PKey       : in out Public_Key_Type)
   is
      Bit_String_Size : Unsigned_32;
      Seq_Size        : Unsigned_32;

      Modulus_Size    : Natural;
      Modulus         : Key_Bytes;
      Exponent        : Integer;
   begin
      --  RSA public key is a Bit String containing a sequence of two
      --  integers, modulus and exponent
      Parse_Bit_String_Header (Cert_Slice, Index, Bit_String_Size, Cert);

      if not Cert.Valid or Bit_String_Size = 0 then
         Log (FATAL, "Invalid RSA public key bit string");
         return;
      end if;

      Parse_Sequence_Data (Cert_Slice, Index, Seq_Size, Cert);

      if not Cert.Valid OR Seq_Size = 0 then
         Log (FATAL, "Invalid RSA public key sequence");
         return;
      end if;

      --  Modulus
      Parse_Integer (Cert_Slice, Index, Modulus_Size, Modulus, Cert);

      Put_Line (" Cert still valid? " & Boolean'Image (Cert.Valid));
      Put_Line (" Modulus Bytes:");
      Put_Key_Bytes (Modulus, Natural(Modulus_Size));
      --  Exponent
      Parse_Integer (Cert_Slice, Index, Exponent, Cert);

      if Exponent < 0 then
         Log (FATAL, "RSA public key exponent cannot be negative");
         Cert.Valid := False;
         return;
      end if;

      if Cert.Valid then
         PKey.Modulus_Length := Natural (Modulus_Size);
         PKey.Modulus := Modulus;
         PKey.Exponent := Unsigned_32(Exponent);
      end if;
   end Parse_RSA_Key;

   --  Fwd declare and contracts
   --  Parse_ED25519_Key
   --  Parse an ED25519 public key. This is a bit string with the key
   procedure Parse_ED25519_Key (Cert_Slice : String;
                                Index      : in out Natural;
                                Cert       : in out Certificate;
                                PKey       : in out Public_Key_Type)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_ED25519_Key (Cert_Slice : String;
                                Index      : in out Natural;
                                Cert       : in out Certificate;
                                PKey       : in out Public_Key_Type)
   is
      Length : Integer;
      Key    : Key_Bytes;

      Ignored_Unused_Bits : Unsigned_8;
   begin

      if not Cert.Valid then
         return;
      end if;

      Parse_Bit_String (Cert_Slice, Index, Length, Ignored_Unused_Bits, Key, Cert);

      if not Cert.Valid or Length /= ED25519_PUBLIC_KEY_SIZE then
         Log (FATAL, "Invalid ED25519 public key bit string");
         return;
      end if;

      Put_Line (" Key Bytes:");
      Put_Key_Bytes (Key, Natural (Length));

      PKey.Key := Key;
      PKey.Key_Size := Natural (Length);
   end Parse_ED25519_Key;

   --  Parse an EC (P-256) public key from a BIT STRING
   procedure Parse_EC_Key (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate;
                           PKey       : in out Public_Key_Type)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_EC_Key (Cert_Slice : String;
                           Index      : in out Natural;
                           Cert       : in out Certificate;
                           PKey       : in out Public_Key_Type)
   is
      Length : Integer;
      Key    : Key_Bytes;
      Ignored_Unused_Bits : Unsigned_8;
   begin
      if not Cert.Valid then
         return;
      end if;

      Parse_Bit_String (Cert_Slice, Index, Length, Ignored_Unused_Bits, Key, Cert);

      if not Cert.Valid or Length /= EC_P256_PUBLIC_KEY_SIZE then
         Log (FATAL, "Invalid EC P-256 public key bit string");
         Cert.Valid := False;
         return;
      end if;

      --  Check for uncompressed point format (0x04)
      if Key (0) /= 16#04# then
         Log (FATAL, "Only uncompressed EC points supported");
         Cert.Valid := False;
         return;
      end if;

      Put_Line (" EC Key Bytes:");
      Put_Key_Bytes (Key, Natural (Length));

      PKey.EC_Key := Key;
      PKey.EC_Key_Size := Natural (Length);
   end Parse_EC_Key;

   --  Fwd declare and contracts
   procedure Parse_Subject_Public_Key (Cert_Slice : String;
                                       Index      : in out Natural;
                                       Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Subject_Public_Key (Cert_Slice : String;
                                       Index      : in out Natural;
                                       Cert       : in out Certificate)
   is
   begin
      --  Format of the public key depends on the algorithm
      case Cert.Subject_Public_Key_Algorithm is
         when RSA_ENCRYPTION =>
            Cert.Subject_Public_Key := (Key_Type => RSA_ENCRYPTION, others => <>);
            Parse_RSA_Key (Cert_Slice, Index, Cert, Cert.Subject_Public_Key);
         when ID_EDDSA25519 =>
            Cert.Subject_Public_Key := (Key_Type => ID_EDDSA25519, others => <>);
            Parse_ED25519_Key (Cert_Slice, Index, Cert, Cert.Subject_Public_Key);
         when EC_PUBLIC_KEY =>
            Cert.Subject_Public_Key := (Key_Type => EC_PUBLIC_KEY, others => <>);
            Parse_EC_Key (Cert_Slice, Index, Cert, Cert.Subject_Public_Key);
         when others =>
            Log (FATAL, "Unsupported public key algorithm.");
            Cert.Valid := False;
            return;
      end case;
   end Parse_Subject_Public_Key;

   --  Fwd declare and contracts
   procedure Parse_Subject_Public_Key_Info (Cert_Slice : String;
                                            Index      : in out Natural;
                                            Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Subject_Public_Key_Info (Cert_Slice : String;
                                            Index      : in out Natural;
                                            Cert       : in out Certificate)
   is
      Size : Unsigned_32;
   begin
      if not Cert.Valid then
         return;
      end if;

      -- Expect a sequence of key algo and the key itself.
      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);

      if not Cert.Valid then
         return;
      end if;

      Parse_Public_Key_Algorithm (Cert_Slice, Index, Cert, Cert.Subject_Public_Key_Algorithm);

      if not Cert.Valid then
         return;
      end if;

      Parse_Subject_Public_Key (Cert_Slice, Index, Cert);
   end Parse_Subject_Public_Key_Info;

   --  Fwd declare and contracts
   procedure Parse_Extensions_Header (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Size       : out Unsigned_32;
                                      Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Extensions_Header (Cert_Slice : String;
                                      Index      : in out Natural;
                                      Size       : out Unsigned_32;
                                      Cert       : in out Certificate)
   is
   begin
      if not Cert.Valid then
         Size := 0;
         return;
      end if;

      if Byte_At (Cert_Slice, Index) /= TYPE_EXTENSIONS then
         Log (FATAL, "Expected X.509 Extensions at" &
                   Index'Image &
                   " found byte" &
                   Byte_At (Cert_Slice, Index)'Image &
                   " instead.");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

      Index := Index + 1;

      Parse_Size (Cert_Slice, Index, Size, Cert);
      Put_Line (" Extensions Size: " & Size'Image);

      if not Check_Bounds (Cert_Slice, Index, Size) then
         Log (FATAL, "Extensions length greater than certificate size");
         Cert.Valid := False;
         Size := 0;
         return;
      end if;

   end Parse_Extensions_Header;

   -- Fwd declare and contracts
   procedure Parse_Extensions (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;
   
   procedure Parse_Extensions (Cert_Slice : String;
                               Index      : in out Natural;
                               Cert       : in out Certificate)
   is
      Extensions_Size   : Unsigned_32;
      Sequence_Size     : Unsigned_32;
      Extensions_End    : Natural;
   begin
      --  Expect a header and then a sequence.
      Parse_Extensions_Header (Cert_Slice, Index, Extensions_Size, Cert);

      Log (DEBUG, " Extensions Size: " & Extensions_Size'Image);

      if not Cert.Valid then
         return;
      end if;

      --  Compute end bound safely (Check_Bounds already validated in header)
      Extensions_End := Index + Natural (Extensions_Size);

      Parse_Sequence_Data (Cert_Slice, Index, Sequence_Size, Cert);

      if not Cert.Valid then
         return;
      end if;

      Log (DEBUG, " Sequence Size: " & Sequence_Size'Image);

      --  Parse each extension until we reach the end of the sequence
      while Index < Extensions_End and Cert.Valid loop
         X509.Extensions.Parse_Extension (Cert_Slice, Index, Cert);
      end loop;
   end Parse_Extensions;

   --  Fwd declare and contracts
   procedure Parse_TBS_Certificate (Cert_Slice : String;
                                    Index      : in out Natural;
                                    Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_TBS_Certificate (Cert_Slice : String;
                                    Index      : in out Natural;
                                    Cert       : in out Certificate)
   is
   begin
      --  Expect a constructed universal type sequence with
      --  Version, Serial Number, Signature Algorithm, Issuer, 
      --   Validity, Subject, Subject Key Info, Extensions
      Parse_Version (Cert_Slice, Index, Cert);
      Parse_Serial (Cert_Slice, Index, Cert);
      Parse_Signature_Algorithm (Cert_Slice, Index, Cert.Signature_Algorithm, Cert);
      Parse_Issuer (Cert_Slice, Index, Cert);
      Parse_Validity_Period (Cert_Slice, Index, Cert);
      Parse_Subject (Cert_Slice, Index, Cert);
      Parse_Subject_Public_Key_Info (Cert_Slice, Index, Cert);
      -- Issuer and subject unique ID are deprecated.
      -- Extensions are optional but require v3 certificate
      if Byte_At (Cert_Slice, Index) = TYPE_EXTENSIONS then
         if Cert.Version /= 3 then
            Log (FATAL, "Extensions present in v" & Cert.Version'Image &
                 " certificate (only v3 may have extensions)");
            Cert.Valid := False;
            return;
         end if;
         Parse_Extensions (Cert_Slice, Index, Cert);
      end if;
   end Parse_TBS_Certificate;

   --  Fwd declare and contracts
   procedure Parse_Cert_Info (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
      with Pre => Index in Cert_Slice'Range;

   procedure Parse_Cert_Info (Cert_Slice : String;
                              Index      : in out Natural;
                              Cert       : in out Certificate)
   is
      Size      : Unsigned_32;
      TBS_Start : Natural;
   begin
      --  Save position before TBS SEQUENCE tag for signature verification
      TBS_Start := Index;

      Parse_Sequence_Data (Cert_Slice, Index, Size, Cert);

      --  Record the TBS byte range (includes SEQUENCE tag + length + content)
      Cert.TBS_First := TBS_Start;
      Cert.TBS_Last  := Index + Natural (Size) - 1;

      --  TBS (To-be-signed) Certificate
      Parse_TBS_Certificate (Cert_Slice, Index, Cert);

      -- Signature Algorithm and Signature Value
      Parse_Signature_Algorithm (Cert_Slice, Index, Cert.Signature_Algorithm2, Cert);

      --  Parse the actual signature bit string
      if Cert.Valid then
         declare
            Unused_Bits : Unsigned_8;
         begin
            Parse_Bit_String (Cert_Slice, Index,
                              Cert.Signature_Value_Len, Unused_Bits,
                              Cert.Signature_Value, Cert);
         end;
      end if;

      if not Cert.Valid then
         Put_Line ("Parse Error.");
         return;
      end if;

      --  RFC 5280 Section 4.1.1.2: The signature algorithm in the TBS
      --  certificate MUST match the outer signature algorithm. Mismatch
      --  is a frankencert attack vector.
      if Cert.Signature_Algorithm /= Cert.Signature_Algorithm2 then
         Log (FATAL, "Signature algorithm mismatch: TBS=" &
              Cert.Signature_Algorithm'Image & " outer=" &
              Cert.Signature_Algorithm2'Image);
         Cert.Valid := False;
         return;
      end if;

      Put_Line ("Valid From: " & Image (Cert.Valid_From));
      Put_Line ("Valid To:   " & Image (Cert.Valid_To));

      Put_Line ("Certificate Version: " & Cert.Version'Image);
      Put ("Certificate Serial:  ");

      Put_Serial (Cert.Serial, Cert.Serial_Length);
      New_Line;

      Put_Line ("Signature Algorithm: " & Cert.Signature_Algorithm'Image);
      Put_Line ("Certificate Algorithm: " & Cert.Subject_Public_Key_Algorithm'Image);
   end Parse_Cert_Info;

   procedure Parse_Certificate (Cert_Bytes : String; Cert : out Certificate)
   is
      Index    : Natural := Cert_Bytes'First;
      Size     : Unsigned_32;
      Msg_Size : Natural;
   begin
      --  Cert is valid until proven otherwise.
      Cert.Valid := True;

      --  Expect sequence with Cert Info, Signature Algorithm, Signature
      Parse_Sequence_Data (Cert_Bytes, Index, Size, Cert);
      Msg_Size := Cert_Bytes'Last - Index + 1;

      --  Sanity check that size of sequence = size of rest of message
      if Size /= Unsigned_32 (Msg_Size) then
         Log (FATAL, "X.509 Sequence Size doesn't match message size");
         Put_Line (" Expected:" & Size'Image & " Actual:" & Msg_Size'Image);
         Cert.Valid := False;
         return;
      end if;

      Parse_Cert_Info (Cert_Bytes, Index, Cert);

      --  Reject trailing data after the certificate
      if Cert.Valid and Index /= Cert_Bytes'Last + 1 then
         Log (WARN, "Trailing data after certificate (" &
              Natural'Image (Cert_Bytes'Last + 1 - Index) & " bytes)");
      end if;
   end Parse_Certificate;

end X509.Certificates;
