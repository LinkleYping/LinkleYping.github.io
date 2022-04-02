# Android脱壳

## ApkShelling  
https://github.com/OakChen/ApkShelling  
- 修改XposedEntry.java中的targetPackages  
```c  
private static final String[] targetPackages =  
        new String[]{"com.sfysoft.shellingtest", "com.sfysoft.shellingtest2", "com.example.how_debug"};  
```  
- 重启手机运行加壳程序  
```shell  
$ adb logcat -s Xposed  
06-15 14:58:01.091  6048  6048 I Xposed  : Found com.SecShell.SecShell.ApplicationWrapper  
06-15 14:58:01.119  6048  6064 I Xposed  : Thread: 246, File: /data/data/com.example.how_debug/00246-01.dex  
06-15 14:58:01.228  6048  6064 I Xposed  : Thread: 246, File: /data/data/com.example.how_debug/00246-02.dex  
```  
- pull 生成的dex  
如果出现Not found object的问题，可以先把文件移动到`/sdcard/`  
```shell  
root@angler:/data/data/com.example.how_debug # cp 00246-01.dex /sdcard/01.dex  
root@angler:/data/data/com.example.how_debug # cp 00246-02.dex /sdcard/02.dex  
```  
## Frida框架使用  
- 安装：  
https://github.com/frida/frida  
```shell  
push frida-server-arm64 /data/local/tmp  
chmod 777 frida-server-arm64  
./frida-server-arm64  
# 端口转发  
adb forward tcp:27043 tcp:27043  
adb forward tcp:27042 tcp:27042  
# 检查是否成功  
frida-ps -U  
```  
frida自带的Messages机制与进程交互  
```python  
import frida, sys  
   
# hook代码，采用javascript编写  
jscode = """  
javascript代码，重点  
"""  
   
# 自定义回调函数  
def on_message(message, data):  
    if message['type'] == 'send':  
        print("[*] {0}".format(message['payload']))  
    else:  
        print(message)  
   
# 重点的4行代码  
# 获取手机设备并附加到进程  
process = frida.get_usb_device().attach('应用完整包名')  
script = process.create_script(jscode)  
# 回调  
script.on('message', on_message)  
# 在服务端就启动javascript脚本了  
script.load()  
sys.stdin.read()  
```  
这里用到的语言分别是python和javascript，他们之间的关系是python作为载体，javascript作为在android中真正执行代码。  
运行给的两个实例  
1. 直接hook MainActivity中的OnCreate()方法，获取calc函数的返回值  
js代码解释  
```js  
//Java.Perform 开始执行JavaScript脚本。  
Java.perform(function () {  
//定义变量MainActivity，Java.use指定要使用的类  
var MainActivity = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');  
//hook该类下的onCreate方法，重新实现它  
MainActivity.onCreate.implementation = function () {  
    send("Hook Start...");  
    //调用calc()方法，获取返回值  
    var returnValue = this.calc();  
    send("Return:"+returnValue);  
    var result = (1000+returnValue)*107;  
    //解出答案  
    send("Flag:"+"SECCON{"+result.toString()+"}");  
}  
});  
```  
完整实现  
```python  
import frida, sys  
   
def on_message(message, data):  
    if message['type'] == 'send':  
        print("[*] {0}".format(message['payload']))  
    else:  
        print(message)  
   
jscode = """  
Java.perform(function () {  
var MainActivity = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');  
MainActivity.onCreate.implementation = function () {  
    send("Hook Start...");  
    var returnValue = this.calc();  
    send("Return:"+returnValue);  
    var result = (1000+returnValue)*107;  
    send("Flag:"+"SECCON{"+result.toString()+"}");  
}  
});  
"""  
  
process = frida.get_usb_device().attach('com.example.seccon2015.rock_paper_scissors')  
script = process.create_script(jscode)  
script.on('message', on_message)  
script.load()  
sys.stdin.read()  
```  
2. 修改MainActivity中的变量  
js代码  
```js  
Java.perform(function () {  
var MainActivity = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');  
//hook onClick方法，此处要注意的是onClick方法是传递了一个View参数v  
MainActivity.onClick.implementation = function (v) {  
    send("Hook Start...");  
    //调用onClick,模拟点击事件  
    this.onClick(v);  
    //修改参数  
    this.n.value = 0;  
    this.m.value = 2;  
    this.cnt.value = 999;  
    send("Success!")  
}  
});  
```  
完整代码实现  
```python  
import frida, sys  
   
def on_message(message, data):  
    if message['type'] == 'send':  
        print("[*] {0}".format(message['payload']))  
    else:  
        print(message)  
   
jscode = """  
Java.perform(function () {  
var MainActivity = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');  
MainActivity.onClick.implementation = function (v) {  
    send("Hook Start...");  
    this.onClick(v);  
    this.n.value = 0;  
    this.m.value = 2;  
    this.cnt.value = 999;  
    send("Success!")  
}  
});  
"""  
   
process = frida.get_usb_device().attach('com.example.seccon2015.rock_paper_scissors')  
script = process.create_script(jscode)  
script.on('message', on_message)  
script.load()  
sys.stdin.read()  
```  
由于关键的实现部分其实在于js代码，下面是frida js中的一些关键函数  
https://www.frida.re/docs/javascript-api/  
## 参考链接  
[ApkShelling脱壳和FART脱壳](https://www.jianshu.com/p/ed64212ccd38)    
[Frida从入门到入门—安卓逆向菜鸟的frida食用说明](https://bbs.pediy.com/thread-226846.htm)    
[初识Frida--Android逆向之Java层hook](https://bbs.pediy.com/thread-226846.htm)  
