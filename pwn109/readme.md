# [Exploiting Return2Libc - pwn09](https://tryhackme.com/room/pwn101)

## Challenge Overview   
  - The challenge involves exploiting a buffer overflow vulnerability, use ROP techinique
  - Goal: Excuting `call_system` with parameter `\bin\sh`

## Initial Analysis 
  - Use checksec tool to know type of this binary<br>
  > <img width="378" height="192" alt="image" src="https://github.com/user-attachments/assets/8ff611e2-4bb9-446a-9f2f-a70d7ae649a3" />
  -> we saw this binary have fixed base address (NO PIE) and 64-bit structure<br>
  - If I put a long input to this binary, it will be crashed<br>
    <img width="697" height="193" alt="image" src="https://github.com/user-attachments/assets/3fd57585-48f8-4c58-b767-b5ee895d0417" />
  - We need know how GOT (Global Offset Table) and PLT (Procedure Linkage Table) work together 
    1. GOT
      - it holds actual memory address (pointers). It means that when a function from external library loaded into the memory, its address is written here
      - because of ASLR (Address Space Layout Randomization), external library locations change everytime each execution
    2. PLT
      - it contains small stubs of code 



  
