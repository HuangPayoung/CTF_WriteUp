64位elf文件，开了NX和PIE保护，格式化字符串漏洞。

# 攻击思路
1. 利用格式化字符串先泄露elf基址。
2. 修改printf函数got表为system函数plt表。
