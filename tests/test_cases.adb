with Ada.Assertions; use Ada.Assertions;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Traceback;
with GNAT.Traceback.Symbolic;

package body Test_Cases is

   Test_Count : Natural := 0;
   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   procedure Test_Case (Actual      : String;
                        Expected    : String;
                        Description : String := "") is
   begin
      Test_Count := Test_Count + 1;

      Put ("Test Case" & Test_Count'Image);

      if Description /= "" then
         Put (": " & Description);
      end if;

      New_Line;
      Put_Line ("Expected: " & Expected);
      Put_Line ("Actual:   " & Actual);

      Assert (Actual = Expected);

      Put_Line ("PASS");
      New_Line;
      Pass_Count := Pass_Count + 1;
   exception
      when E : Ada.Assertions.Assertion_Error =>
         Put_Line ("FAIL");
         Put_Line ("Test case failure:");
         Put_Line (GNAT.Traceback.Symbolic.Symbolic_Traceback (E));
         New_Line;
         Fail_Count := Fail_Count + 1;
   end Test_Case;

   procedure Test_Assert (Test_Bool   : Boolean;
                          Description : String := "") is
   begin
         Test_Count := Test_Count + 1;

      Put ("Test Case" & Test_Count'Image);

      if Description /= "" then
         Put (": " & Description);
      end if;

      New_Line;
      Assert (Test_Bool);

      Put_Line ("PASS");
      New_Line;
      Pass_Count := Pass_Count + 1;
   exception
      when E : Ada.Assertions.Assertion_Error =>
         Put_Line ("FAIL");
         Put_Line ("Test case failure:");
         Put_Line (GNAT.Traceback.Symbolic.Symbolic_Traceback (E));
         New_Line;
         Fail_Count := Fail_Count + 1;
   end Test_Assert;

   procedure Summary is
   begin
      Put_Line ("Total number of tests evaluated: " & Test_Count'Image);
      Put_Line (" Passed: " & Pass_Count'Image);
      Put_Line (" Failed: " & Fail_Count'Image);
   end Summary;
end Test_Cases;
