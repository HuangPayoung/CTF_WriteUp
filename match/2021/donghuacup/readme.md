终于有点成就感了，和队友AK了PWN题~~不过题目都比较水~~。

自己做了3道简单的，队友做了一道稍微难的，跟着调一下就知道怎么做了。

## cpp1

堆溢出

## gcc2

UAF

## bg3

堆溢出

## boom_script

类似实现一个脚本解释器的东西，逐个单词识别然后执行，逆向非常烦，我逆向了一整天只弄懂了大致的思路。

想想其实不用逆向这么清（虽然我比较喜欢这样），队友一边调一边做，有个越界写的洞，信息泄露也很容易，他打__malloc_hook，我调了一遍自己写一个打__free_hook。
