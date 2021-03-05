---
title: 基因突变的模糊测试(GET参数)
tags: 模糊测试
categories: C#灰帽子
top: true
---

## 基础要求
首先我们得具备最基础的SQL注入和XSS漏洞的基本知识，不懂的读者可以自行百度先学习，然后我们再学习下面的内容。下面我们将使用C#这门编程语言编写模糊测试工具测试是否存在漏洞。

## 代码展示

> **一个小的分解给定URL中的查询字符串参数Main()方法**

```csharp
using System;
using System.IO;
using System.Net;

namespace 突变模糊测试
{
    class Program
    {
        static void Main(string[] args)
        {
            string url = args[0];
            //确定第一个问号的位置，标志URL已经结束，后面是我们要查询的参数
            int index = url.IndexOf("?");
            // 返回一个仅包含URL参数的字符串
            string[] parms = url.Remove(0, index + 1).Split('&');
            foreach (string parm in parms)
            {
                Console.WriteLine(parm);
            }
        }
    }
}
```
<!--more-->
> **污染参数和测试漏洞**

如果服务器不容易受到XSS或SQL注入的攻击，那么服务器会恰当地检查这些数据。向污染数据添加`<xss>`，并且测试SQL注入的数据将具有单引号。

```csharp
foreach (string parm in parms)
{
	string xssUrl = url.Replace(parm, parm + "fd<xss>sa");
	string sqlUrl = url.Replace(parm, parm + "fd'sa");
	Console.WriteLine(xssUrl);
	Console.WriteLine(sqlUrl);
}
```
> **构造HTTP请求**

接下来，使用HttpWebRequest类编程构建HTTP请求，然后我们使用带有污染HTTP参数发起HTTP请求，看看是否有任何错误返回。

```csharp
foreach (string parm in parms)
            {
                //使用污染的数据替换掉旧的参数
                string xssUrl = url.Replace(parm, parm + "fd<xss>sa");
                string sqlUrl = url.Replace(parm, parm + "fd'sa");
                //静态Create()方法基于传递的URL使用工厂模式来创建新的对象
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(sqlUrl);
                request.Method = "GET";

                string sqlresp = string.Empty;
                using (StreamReader rdr = new
                    StreamReader(request.GetResponse().GetResponseStream()))
                sqlresp = rdr.ReadToEnd();
                request = (HttpWebRequest)WebRequest.Create(xssUrl);
                request.Method = "GET";
                string xssresp = string.Empty;

                using (StreamReader rdr = new
                    StreamReader(request.GetResponse().GetResponseStream()))
                    xssresp = rdr.ReadToEnd();

                if (xssresp.Contains("<xss>"))
                    Console.WriteLine("Possible XSS point found in parameter: " + parm);

                if (sqlresp.Contains("error in your SQL syntax"))
                    Console.WriteLine("SQL injection point found in parameter: " + parm);
            }
```

> **测试模糊测试的代码**

tips：这里先要安装badstore环境才能进行测试，这是一个具有漏洞的靶机环境。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210304114933562.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
演示效果如下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210304114955435.png)


