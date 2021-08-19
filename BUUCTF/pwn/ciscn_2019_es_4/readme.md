64位堆题，除了PIE其他保护机制全开。增删查改四项功能，漏洞点在于修改时有一个off-by-null漏洞。

# 攻击思路
利用off-by-null清空size.prec_inuse，进行unlink攻击。
