---
title: WEB安全漏洞入门
tags: 红蓝对抗
categories: Web安全打点
top: 10
---
# WEB安全漏洞入门

## SQL注入

### 漏洞成因

- 由于开发者在程序编写过程中，对传入用户数据的过滤不严格，将可能存在的攻击载荷拼接到SQL查询语句中，再将其传递给后端数据库执行造成的数据泄露。

### SQL注入基础

- 数字型和UNION注入

	- 数字型

		- 表现为输入点"$_GET['id']"，会对数值计算进行运算

	- UNION型

		- 通常配合id=-1或很大的值，让前面的语句查询失败，然后嵌入union语句将后半句SQL查询语句显示的结果查询出来

- 字符型注入和布尔盲注

	- 字符型

		- 在MYSQL中，等号两边如果类型不一致，则会发生强制转换。当数字与字符串数据比较时，字符串将被转换为数字，再进行比较。

	- 布尔盲注

		- 虽然我们看不到直接的数据，但是可以通过注入推断出数据，通常配合sunstring()、mid()、substr()这三个函数使用，比较费时。

- 报错注入

	- 有时为了方便开发者调试，有的网站会开启错误调试信息，只要触发SQL语句的错误，即可在页面上看到错误信息。updatexml在执行时，第二个参数应该为合法的XPATH路径，否则会引发报错的同时将传入的参数进行输出。

### 注入点 

- SELECT注入

	- select_expr
	- table_reference
	- WHERE或HAVING后
	- GROUP BY或ORDER BY后
	- LIMIT后

- INSERT注入

	- tbl_name
	- VALUES

- UPDATE注入
- DELETE注入

### 注入与防御

- 字符替换

	- 只过滤了空格

		- 空白符有%0a，%0b，%0c，%0d，%09，%a0，%a0在特定字符集才使用和/**/、括号等

	- 将SELECT替换成空

		- 即在WAF中过滤了SELECT这个关键字

	- 大小写匹配

		- 即使用大小写混合如sEleCT绕过WAF

	- 正则匹配

		- 用关键字"\bselect\b"或内联注入干扰"/*5000select*/"

	- 替换了单引号或双引号

		- 忘记了反斜杠，其实就是最后一个单引号逃逸，使用转义字符先将前面一个单引号转义

- 逃逸引号

	- 编码解码

		- 其实就是逃逸addslashes这个函数，这个函数会对单引号进行转义，我们若先将数据加密，然后传到后端解密并执行就可造成SQL注入

	- 粗心大意的输入点

		- 如httpheader、$_SERVER['PHP_SELF']这些变量通常会被开发者遗忘

	- 二次注入

		- 二次注入的根源在于，开发者信任数据库中取出的数据是无害的，注入是发生在数据被取出数据库并进行查询时发生

### 注入功效

- 在有写文件权限时，直接用INTO OUTFILE或者DUMPFILE向Web目录写文件，或者写文件后结合文件包含漏洞达到代码执行的效果
- 在有读文件权限时，用load_file()函数读取网站源码和配置信息，获取敏感数据
- 提升权限，获得更高的用户权限或者管理员权限，绕过登录，添加用户，调整用户权限等
- 通过注入控制数据库查询出来的数据，控制如模板、缓存等文件的内容来获取权限，或者删除、读取某些关键文件
- 在执行多语句情况下，控制整个数据库，包括控制任意数据、任意字段长度
- 直接执行系统命令

## 任意文件读取漏洞

### 漏洞成因

- 攻击者通过一些手段可以读取服务器上开发者不允许读到的文件。通常作为资产信息收集的一种强力的补充手段，服务器的各种配置文件、文件形式存储的密钥、服务器信息、历史命令、网络信息、应用源码及二进制程序都在这个漏洞触发点被触发。

### 常见触发点

- WEB语言

	- PHP

		- file_get_contents()、file()、fopen()，文件指针操作函数：fread()、fgets()，文件包含函数：include()、require()、include_once()、require_once()，读文件执行系统命令：system()、exec()
		- PHP的Filter机制也是常考点，构造形如"php://filter/convert.base64-encode/resource=xxx.php"的攻击数据读取文件的内容

	- Python

		- 更多倾向于通过其自身的模块启动服务，同时搭配中间件、代理服务将整个Web应用呈现给用户

	- Java

		- Spring Cloud Config Server漏洞(CVE-2019-3799)、Jenkins任意文件读取漏洞(CVE-2018-1999002)

	- Ruby

		- Ruby On Rails远程代码执行漏洞(CVE-2016-0752)、Ruby On Rails路径穿越漏洞(CVE-2018-3760)、Ruby On Rails路径穿越漏洞(CVE-2019-5418)

	- Node

		- Node.js的express模块曾存在任意文件读取漏洞(CVE-2017-14849)

- 中间件/服务器

	- Nginx错误配置

		- 漏洞成因是location最后没有“/”限制，Nginx匹配到路径static后，将其后面的内容拼接到alias，如果传入的是/static../，nginx不认为是跨目录，而是把它当成整个目录名

	- 数据库

		- load_file()函数读取文件首先需要数据库配置FILE权限，其次需要执行其函数的用户/用户组对于目标文件具有可读权限

	- 软链接

		- 生成一个软链接，并将其上传到服务器上

	- Docker-API

		- 通常配合SSRF漏洞利用，通过SSRF漏洞进行UNIX Socket通信时，通过操纵Docker-API把本地文件载入docker容器进行读取

- 客户端相关

	- 浏览器/Flash XSS
	- MarkDown语法解析器XSS

### 常见读取路径

- Linux

	- flag名称(相对路径)，fuzz一下可知路径
	- 服务器信息(绝对路径)

		- /etc
		- /etc/passwd
		- /etc/shadow
		- /etc/apache2/*
		- /etc/nginx/*
		- /etc/apparmor/*
		- /etc/cron.d/*|crontab
		- /etc/environment
		- /etc/hostname
		- /etc/hostname
		- /etc/hosts
		- /etc/issue
		- /etc/mysql/*
		- /etc/php/*
		- /proc
		- proc通常存储着进程动态运行的各种信息，可以使用/proc/self代替/proc/[pid]，对应目录下的cmdline可读出比较敏感的信息，通过cwd可以直接跳转到当前目录

- Windows

	- 和PHP搭配使用时，可以用"<"等符号作为通配符，从而在不知道文件名的情况下进行文件读取

## 敏感信息泄露

### 信息收集的分类

- 敏感目录泄露

	- 漏洞成因

		- 开发人员在开发过程中经常会遗忘 .git文件夹，导致攻击者可以通过.git文件夹中的信息获取开发人员提交过的所有源码，进而可能导致服务器被攻陷。

	- 常规git泄露

		- 使用scrabble工具

	- git回滚

		- 使用git reset命令恢复到以前的版本

	- git分支

		- 使用GitHacker工具

	- 其他

		- SVN泄露

			- SVN是源码版本管理软件，造成泄露的主要原因是管理员操作不规范将SVN隐藏文件夹暴露于外网环境

		- HG泄露

			- 在初始化项目时，HG会在当前文件夹下创建一个.hg隐藏文件夹，包含代码和分支修改记录等信息

- 敏感备份文件

	- gedit备份文件

		- 用gedit编辑器保存后，当前目录下会生成一个后缀为"~"的文件

	- vim备份文件

		- vim因意外退出时，会在当前目录下生成一个备份文件，格式为 *.swp

	- robots.txt文件

		- 记录一些目录和CMS版本信息

- Banner识别

	- 自行搜集指纹库

		- CMS指纹库

	- 使用已有工具

		- Wappalyzer工具

	- 收集网站使用的是哪个Web框架，从而查找其漏洞信息

*XMind - Trial Version*