# [Exploiting Return2Libc - pwn09](https://tryhackme.com/room/pwn101)

## Challenge Overview   
  - The challenge involves exploiting a buffer overflow vulnerability, use ROP techinique
  - Goal: Excuting `call_system` with parameter `\bin\sh`

## Initial Analysis 
  - Use checksec tool to know type of this binary<br>
  > <img width="378" height="192" alt="image" src="https://github.com/user-attachments/assets/8ff611e2-4bb9-446a-9f2f-a70d7ae649a3" />
  -> we saw this binary have fixed base address (NO PIE) and 64-bit structure<br>
  - If I put a long input to this binary, it will be crashed<br>
    <img width="697" height="193" alt="image" src="https://github.com/user-attachments/assets/3fd57585-48f8-4c58-b767-b5ee895d0417" /> <br>
    -> it means that there has a vulnerability 
  - We need know how GOT (Global Offset Table) and PLT (Procedure Linkage Table) work together 
    1. GOT
      - it holds actual memory address (pointers). It means that when a function from external library loaded into the memory, its address is written here
      - because of ASLR (Address Space Layout Randomization), external library locations change everytime each execution
    2. PLT
      - it contains small stubs of code for each external function that the binary calls
      - the code stub inside the PLT consists a jump instruction pointing to the corresponding slot in the GOT
   
## Planning To Access Shell  
  - One of ways to know address `system` or address of string `\bin\sh`, we know what library is used
  - Because in a same library, address of any function is related to each others
  - So if we know of what library is used and address of anyone function, we can know other functions' address (`system`) or some string address (like `\bin\sh`) 

## Strategy To Execute Expected Function 
  - 
