with Ada.Text_IO; use Ada.Text_IO;

package body X509.Logs is

   procedure Log (L : in Log_Level_Type; S : in String)
   is
   begin
      if L <= Log_Level then
         Put_Line (L'Image & ": " & S);
      end if;
   end Log;

end X509.Logs;
