# reverse


## 新手练习区

### 001 insanity

用vscode的插件以十六进制打开文件即可，然后就可以看到flag，注意开头是9447

![](reverse_new_001_1.png)


### 002 game

一个编译好的exe文件，游戏的内容就不说了，将exe拖入IDA中进行分析，注意要用32位，64位好像不能编译，然后按 shift + F12 ，再按 Alt + T 查找关于flag的字符串

![](reverse_new_002_1.png)

当查找到相应位置的字符串后，双击在 IDA View-A 查看，还需要按 Ctrl + X 引用到当前位置，再按 F5 进行反编译，查看C源码

![](reverse_new_002_2.png)

可以发现给出了两组数字，分别取两组中的各个数字异或运算，然后再和0x13异或，作为一个字符，最后拼到一起，我写了个脚本来实现

![](reverse_new_002_3.png)

