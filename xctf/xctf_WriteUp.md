# 记录攻防世界WriteUp

## misc



******

## pwn



******

## web

### 新手练习区

#### 001 view_source
按F12打开查看器即可看到网页源码

#### 002 get_post
url处传get参数
![get传参数](web_new_002_1.png)
用hackbar传post参数
![post传参数](web_new_002_2.png)

#### 003 robots
(百度)robots协议也叫robots.txt（统一小写）是一种存放于网站根目录下的ASCII编码的文本文件，它通常告诉网络搜索引擎的漫游器（又称网络蜘蛛），此网站中的哪些内容是不应被搜索引擎的漫游器获取的，哪些是可以被漫游器获取的。因为一些系统中的URL是大小写敏感的，所以robots.txt的文件名应统一为小写。robots.txt应放置于网站的根目录下。
![](web_new_003_1.png)
![](web_new_003_2.png)

#### 004 backup
php的备份有两种：*.php~和*.php.bak

#### 005 cookie
在控制台查看cookie
![](web_new_005_1.png)

用Burp截包查看响应报文

![](web_new_005_2.png)

#### 006 disabled_button
把disabled属性删除，按钮就可以按下了
![](web_new_006_1.png)

#### 007 weak_auth
根据提示用户名root，弱密码（123456）可以去爆破

#### 008 command_execution
先尝试能否注入命令

![](web_new_008_1.png)

发现可以轻松注入后，查找flag文件

![](web_new_008_2.png)

查看flag

![](web_new_008_3.png)

#### 009 

### 高手进阶区



******

## reverse



******

## crypto



******

## mobile



******
