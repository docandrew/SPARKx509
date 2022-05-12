package Test_Cases is

   ---------------------------------------------------------------------------
   -- Compare two strings. The test case passes if they match, fails if they
   --  don't.
   -- @param Actual The actual string produced by the code being tested
   -- @param Expected What the code is expected to output
   -- @param Description A human-readable description of the test (optional)
   ---------------------------------------------------------------------------
   procedure Test_Case (Actual      : String;
                        Expected    : String;
                        Description : String := "");

   ---------------------------------------------------------------------------
   -- Assert that the result of a boolean function is True
   -- @param Test_Bool If True, this test passes, if False, this test fails
   -- @param Description A human-readable description of the test (optional)
   ---------------------------------------------------------------------------
   procedure Test_Assert (Test_Bool   : Boolean;
                          Description : String := "");
   
   procedure Summary;

end Test_Cases;