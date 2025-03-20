pragma Style_Checks (Off);
with Ada.Text_IO;
with adaasn1rtl;
pragma Warnings (Off, "use clause for type");
use type adaasn1rtl.Asn1UInt;
use type adaasn1rtl.Asn1Int;
use type adaasn1rtl.BIT;
pragma Warnings (On, "use clause for type");

function MainProgram return Integer
is
    use Ada.Text_IO;
	pragma Warnings (Off, """totalErrors"" is not modified, could be declared constant");
    totalErrors  : INTEGER:=0;
	pragma Warnings (On, """totalErrors"" is not modified, could be declared constant");
    
begin


    --  used to increase statement coverage

    pragma Warnings (Off, "condition can only be True if invalid values present");
    pragma Warnings (Off, "condition is always False");
    if totalErrors > 0 then
        Put_Line (Integer'Image(totalErrors) & " out of 0 failed."); 
        return 1;
    else
        Put_Line ("All test cases (0) run successfully."); 
        return 0;
    end if;
    pragma Warnings (On, "condition can only be True if invalid values present");
    pragma Warnings (On, "condition is always False");
end MainProgram;