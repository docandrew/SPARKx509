with Ada.Text_IO; use Ada.Text_IO;
with Test_Cases; use Test_Cases;
with Base64; use Base64;

procedure Base64_Tests is

begin

   --  RFC 4648 Test Vectors
   Test_Case (Decode (Construct ("")),         "");
   Test_Case (Decode (Construct ("Zg==")),     "f");
   Test_Case (Decode (Construct ("Zm8=")),     "fo");
   Test_Case (Decode (Construct ("Zm9v")),     "foo");
   Test_Case (Decode (Construct ("Zm9vYg==")), "foob");
   Test_Case (Decode (Construct ("Zm9vYmE=")), "fooba");
   Test_Case (Decode (Construct ("Zm9vYmFy")), "foobar");

   Test_Case (To_String (Encode ("")),       "");
   Test_Case (To_String (Encode ("f")),      "Zg==");
   Test_Case (To_String (Encode ("fo")),     "Zm8=");
   Test_Case (To_String (Encode ("foo")),    "Zm9v");
   Test_Case (To_String (Encode ("foob")),   "Zm9vYg==");
   Test_Case (To_String (Encode ("fooba")),  "Zm9vYmE=");
   Test_Case (To_String (Encode ("foobar")), "Zm9vYmFy");

   Test_Assert (Validate (""),         "Empty strings are valid Base64");
   Test_Assert (not Validate ("ABC"),  "Base64 Strings must be mod 4 length");
   Test_Assert (not Validate ("A^C="), "Only [A-Za-z0-9/+=] allowed");
   Test_Assert (not Validate ("A=C="), "Equals only allowed at end for padding");
   Test_Assert (Validate ("ABC="),     "Padding chars are valid at end");
   Test_Assert (Validate ("AB=="),     "Padding chars are valid at end");
   Test_Assert (not Validate ("A==="), "Max 2 padding chars");

   Summary;
end Base64_Tests;
