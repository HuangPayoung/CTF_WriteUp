64位堆题，保护机制全开，增查改三项功能，堆块控制结构溢出导致任意地址写。

# 攻击思路
1. 利用后门泄露libc基址，利用堆块控制结构溢出写了heap基址。
2. 利用任意地址写修改_IO_2_1_stderr_结构，进行FSOP攻击。