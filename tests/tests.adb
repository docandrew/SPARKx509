with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;

with X509_Tests;
with Base64_Tests;

procedure Tests is
   
   -- type Byte_Seq is array (Unsigned_32 range <>) of Unsigned_8;

   -- type BToCT is array (Unsigned_8 range 0 .. 15) of Character;

   -- BToC : constant BToCT := (
   --    '0',
   --    '1',
   --    '2',
   --    '3',
   --    '4',
   --    '5',
   --    '6',
   --    '7',
   --    '8',
   --    '9',
   --    'A',
   --    'B',
   --    'C',
   --    'D',
   --    'E',
   --    'F'
   -- );

   -- procedure PB (X : in Unsigned_8)
   -- is
   -- begin
   --    Put ("16#");
   --    Put (BToC (X / 16));
   --    Put (BToC (X mod 16));
   --    Put ("# ");
   -- end PB;

   -- procedure DH (S : in String; D : in Byte_Seq)
   -- is
   -- begin
   --    Put_Line (S);
   --    for I in D'Range loop
   --       PB (D (I));
   --       if I mod 8 = 7 then
   --          New_Line;
   --       end if;
   --    end loop;
   --    New_Line;
   -- end DH;

   -- function To_Byte_Seq (S : String) return Byte_Seq
   -- is
   --    Ret : Byte_Seq (0 .. S'Length - 1);
   -- begin
   --    for I in Ret'Range loop
   --       Ret (I) := Character'Pos (S (S'First + Natural (I)));
   --    end loop;

   --    return Ret;
   -- end To_Byte_Seq;

begin

   Base64_Tests;
   X509_Tests;

end Tests;
