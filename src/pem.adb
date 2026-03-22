with Base64;

package body PEM
   with SPARK_Mode
is
   Begin_Marker : constant String := "-----BEGIN ";
   End_Marker   : constant String := "-----END ";
   Dashes       : constant String := "-----";

   procedure Decode (Input : String; Result : out Decode_Result) is
      --  We need to:
      --  1. Find "-----BEGIN <label>-----"
      --  2. Extract the label
      --  3. Collect all Base64 characters between header and footer
      --  4. Base64-decode them

      --  Maximum Base64 content we can handle (generous)
      Max_B64 : constant := (Max_DER_Length * 4) / 3 + 4;

      B64_Buf : String (1 .. Max_B64) := (others => 'A');
      B64_Len : Natural := 0;

      Pos       : Positive;
      Label_Start : Positive;
      Label_End   : Natural;
      Body_Start  : Positive;
   begin
      Result := (OK        => False,
                 Label     => (others => ' '),
                 Label_Len => 0,
                 DER       => (others => Character'Val (0)),
                 DER_Len   => 0);

      if Input'Length < Begin_Marker'Length + Dashes'Length then
         return;
      end if;

      --  Find BEGIN marker
      Pos := Input'First;

      --  Scan for "-----BEGIN "
      Find_Begin : loop
         exit Find_Begin when Pos + Begin_Marker'Length - 1 > Input'Last;

         if Input (Pos .. Pos + Begin_Marker'Length - 1) = Begin_Marker then
            --  Found it. Extract label (everything until "-----")
            Label_Start := Pos + Begin_Marker'Length;
            Label_End := Label_Start;

            --  Find closing dashes of the header line
            Find_Label_End : loop
               exit Find_Label_End when Label_End + Dashes'Length - 1 > Input'Last;

               if Input (Label_End .. Label_End + Dashes'Length - 1) = Dashes then
                  --  Label is Input(Label_Start .. Label_End - 1)
                  declare
                     Len : constant Natural := Label_End - Label_Start;
                  begin
                     if Len > 0 and Len <= Max_Label_Length then
                        Result.Label (1 .. Len) := Input (Label_Start .. Label_End - 1);
                        Result.Label_Len := Len;
                     end if;
                  end;

                  --  Body starts after the closing dashes + newline
                  Body_Start := Label_End + Dashes'Length;

                  --  Skip to next line
                  while Body_Start <= Input'Last and then
                        (Input (Body_Start) = ASCII.LF or
                         Input (Body_Start) = ASCII.CR)
                  loop
                     Body_Start := Body_Start + 1;
                  end loop;

                  --  Collect Base64 characters until "-----END"
                  Pos := Body_Start;
                  Collect : loop
                     exit Collect when Pos > Input'Last;

                     --  Check for END marker
                     if Pos + End_Marker'Length - 1 <= Input'Last and then
                        Input (Pos .. Pos + End_Marker'Length - 1) = End_Marker
                     then
                        exit Collect;
                     end if;

                     --  Skip whitespace (CR, LF, space, tab)
                     if Input (Pos) = ASCII.LF or
                        Input (Pos) = ASCII.CR or
                        Input (Pos) = ' ' or
                        Input (Pos) = ASCII.HT
                     then
                        Pos := Pos + 1;
                     else
                        --  Base64 character
                        if B64_Len < Max_B64 then
                           B64_Len := B64_Len + 1;
                           B64_Buf (B64_Len) := Input (Pos);
                        end if;
                        Pos := Pos + 1;
                     end if;
                  end loop Collect;

                  --  Now decode the Base64
                  if B64_Len > 0 and then
                     B64_Len mod 4 = 0 and then
                     Base64.Validate (B64_Buf (1 .. B64_Len))
                  then
                     declare
                        B64 : constant Base64.Base64_String :=
                           Base64.Construct (B64_Buf (1 .. B64_Len));
                        DER_Str : constant String := Base64.Decode (B64);
                     begin
                        if DER_Str'Length <= Max_DER_Length then
                           Result.DER (1 .. DER_Str'Length) := DER_Str;
                           Result.DER_Len := DER_Str'Length;
                           Result.OK := True;
                        end if;
                     end;
                  end if;

                  return;

               end if;

               Label_End := Label_End + 1;
            end loop Find_Label_End;
         end if;

         Pos := Pos + 1;
      end loop Find_Begin;
   end Decode;

end PEM;
