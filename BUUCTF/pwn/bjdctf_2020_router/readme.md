看程序提供了四个功能，其中只有两个有用，3可以用来泄露canary，1可以用来栈溢出。

后面发现system函数的执行的字符串没有什么检查，直接命令注入就好了，也不用什么溢出后ROP。