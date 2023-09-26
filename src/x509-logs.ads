package X509.Logs is

   type Log_Level_Type is (Silent, Fatal, Warn, Info, Debug, Trace);

   Log_Level : Log_Level_Type := Trace;

   procedure Log (L : in Log_Level_Type; S : in String);

end X509.Logs;
