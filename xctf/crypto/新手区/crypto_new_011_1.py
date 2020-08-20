# -- coding: utf-8 --
'''
    rsa的第二种类型，给公钥证书和密文，要求解密
    1.先到在线网站解析公钥证书，也可以安装openssl来解析，得到n, e
    2.用在线工具或者yafu来分解大整数n，得到p, q
    3.运行此脚本
'''

import libnum
import rsa

n = 87924348264132406875276140514499937145050893665602592992418171647042491658461
e = 65537
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239
l = (p - 1) * (q - 1)
d = libnum.invmod(e, l)

key = rsa.PrivateKey(n, e, d, p, q)
print(key)

with open("flag.enc","rb") as f:
	print(rsa.decrypt(f.read(),key).decode())

