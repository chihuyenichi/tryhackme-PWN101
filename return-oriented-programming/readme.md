
# [**Ret2win Challenge** (ROP Emporium)](https://ropemporium.com/challenge/split.html)

## Challenge Overview

Description: That useful string "/bin/cat flag.txt" is still present in this binary, as is a call to system(). So we need to overwrite the stack with some ret address to make this call 


## Exploition 

- first we need to unzip this .zip file and this is it will be <img width="863" height="101" alt="image" src="https://github.com/user-attachments/assets/7f4df580-9046-4991-be7f-5b4ce78179fd" />
- detarmining the type of `split` :
> split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=98755e64e1d0c1bff48fccae1dca9ee9e3c609e2, not stripped
> 
> <img width="506" height="137" alt="image" src="https://github.com/user-attachments/assets/61cc2918-dd7b-4092-aab6-62d2cf167ccd" />

  - we saw `NO PIE`, so all the addresses in this binary are particular

- execute this binary and press something like `AAAAAA` to it <img width="609" height="197" alt="image" src="https://github.com/user-attachments/assets/a42cd791-846a-40b2-8d24-9ea7e508f549" />
- if I pass a longer input, it will be that

  <img width="1732" height="188" alt="image" src="https://github.com/user-attachments/assets/56236a69-4c2d-4cee-bbef-8bfbe72de792" />

  -> this is vulnerability and we can use buffer over flow (BOF) to expoit it

- using IDA to see this disassembly of the binary <img width="1645" height="982" alt="image" src="https://github.com/user-attachments/assets/c5f1c16e-a5c0-474f-9d6c-414c02a1cb35" />

  this is the `main` function and the `pwnme` function is called in it

- `pwnme` included a `read` function with the size_max of input is 0x60 bytes, while `s` (the buffer of our input) is only 0x20 bytes
  
  -> it's the vulnerability that we can overwrite the data on the stack
  
  <img width="1313" height="941" alt="image" src="https://github.com/user-attachments/assets/ccf3e0a5-deed-413b-a39e-08774958b8b4" />

- moreover, there is a function that have command `call _system`

  <img width="984" height="256" alt="image" src="https://github.com/user-attachments/assets/17252dff-2d65-496f-a883-263068b9c10e" />

  it's a useful command that helps us to do something related to its system, so we should save the address of this command 

- goto strings which are listed in IDA

  <img width="784" height="543" alt="image" src="https://github.com/user-attachments/assets/dbe22f0c-9fc1-44ac-83ae-2bc4baf05c44" /><br>
  > .data:0000000000601060	00000012	C	/bin/cat flag.txt

  if it's the parameter of `call _system`, this challenge will be done

  
## ROP (return-oriented programming) Processing 

- our purpose is executing `call _system` with parameter `/bin/sh cat flag.txt`
- to do this, first, we need to make `rdi/edi`'s value to `/bin/sh cat flag.txt` (because in linux, the first parameter which is pass into function is `rdi`)
- from here, we suppose we are in `pwnme` function, value of `rsp` and `rbp` are used at this time
- we will find a ROP gadget that can affect to `rdi`, it is sth like `pop rdi; ret`<br>
  to do it we will use a tool called `ROPgadget Tool`<br>
  > (pwn_env) (base) root@chihuyenich:/mnt/c/daohuyenchi_server/CTF_downloads/tryhackme/PWN101/return-oriented-programming/split_unzip_folder# ROPgadget --binary ./split > gadgets.txt 

  and we see it (note this bolded address)

  <img width="879" height="231" alt="image" src="https://github.com/user-attachments/assets/9876b553-bba7-4628-a695-bb4df07560d4" />

- we have some definitions :<br>
  `pop_rdi_address` is address of start of `pop rdi; ret` that we found above<br>
  `cat_flag_address` is address of the string `/bin/cat flag.txt` in the binary<br>
  `sys_call_address` is address of `call _system`<br>

- the progess will take place as follows:
  1. fill the buffer (with length 0x20) of our input with the current `rbp`
  2. we will overwrite the stack like that<br>
     <img width="400" height="300" alt="image" src="https://github.com/user-attachments/assets/c46194a1-a4a0-4c9d-8ff4-ea2f8de8546f" />

### Explanation 
- the value above `rbp` is a return address of a function, when this function finished, `rip` will jump to the return address and now is `pop_rdi_address` and `rsp` will be added by 0x8 (it points to `cat_flag_address` now) 
- rip start from command `pop rdi`; when it is executed, it will pop the value of top of stack which is `cat_flag_address` now -> so `rdi` will have value of `cat_flag_address`
  now `rsp` will be continue added by 8 and point to `call_sys_address`
- the next instruction is `ret`, so rip will jump to address at top of stack which is `call_sys_address`
  the command `call _system` is executed, with `rdi` is its parameter
  it means we are doing `/bin/cat flag.txt`



## [Code that illustrating above instructions ](./exploit.py)

