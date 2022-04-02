# Android调试

## IDA调试so  
往年的腾讯的Android题都是native编程比较多，关键代码都在so文件里，先学习一下ida调试动态库。  
  
### android常用命令行  
[Android中使用的shell命令](https://blog.csdn.net/willba/article/details/80215447)  
adb shell dumpsys * 常用的如下：  
>activity 显示所有的Activity信息  
查看Activity: `adb shell dumpsys activity | findstr "mFocusedActivity"`  
查看顶部Activity:  `adb shell dumpsys activity top`  
meminfo 内存信息  
battery 电池信息  
package 包信息  
wifi 信息wifi信息  
alarm 显示alarm信息  
procstats 显示内存信息  
`adb shell dumpsys> info info.txt` 将命令行信息输出到txt中  
  
文件操作  
>安装应用包apk文件 用法：`adb install [apk文件]`    
覆盖或升级相同应用包apk文件 用法：`adb install -r [apk文件]`    
卸载应用 用法：`adb uninstall [packagename]`    
将设备中的文件放到本地 用法：adb pull 示例：`adb pull /sdcard/Pictures/11.jpg D:\gif` 将手机中11.jpg的图片放置到电脑d盘中gif文件下    
将本地文件放置到设备中 用法：adb push    
  
查看当前运行应用程序日志  
>查看所有打印出来的日志信息 用法：adb logcat    
查看某个标签名的日志信息 用法：adb logcat -s tag 示例如下：`adb shell -s tag` 查看标签为tag的日志    
查看包含某个关键字或者进程名或者包名下的日志 用法：adb logcat |findstr pname/pid/keyword 示例如下：`adb logcat |findstr com.android.coolweather`    
将日志输出到文件 用法：adb logcat -f 文件名    
输出某一级别的日志 用法：adb logcat *:级别（注意：星号后面有个冒号）  
  
### 调试  
**这个需要手机有root权限**  
1. 安装应用: `adb install -r xxx.apk`  
2. 上传android_server文件:`adb push android_server /data/local/tmp/`  
3. 可执行权限: `adb shell chmod 777 /data/local/tmp/android_server`  
4. 开启android_server与IDA通信:`adb shell /data/local/tmp/android_server`  
5. 本地端口转发:`adb forward tcp:23946 tcp:23946`  
6. 以调试模式启动程序:`adb shell am start -D -n com.qq.gslab.regme/.MainActivity`  
7. 启动IDA pro，点击Debugger->attach->Remote ARMLinux/Android debugger，输入localhost和相应端口号。  
8. 选择Debugger option，勾选  
>suspend on process entry point    
suspend on thread start/exit    
suspend on library load/unload    
  
9. 打开ddms查看相应apk进程的端口号，使用jdb恢复程序执行`jdb -connect com.sun.jdi.SocketAttach:port=8700,hostname=localhost`  
10. 点击`f9`, 在ida弹出的”Add map”窗口中，一律点击”Cancle”按钮。  
11. 点击ida中的`Debugger -> Debugger windows -> Module list `。在`Modules`窗口中找到要调试的so文件。  
12. 点击ida中的暂停调试按钮，暂停当前的调试  
右击相应so文件，双击找到要调试的函数，再双击即可跳转到函数所在的起始地址，然后在地址处下断点  
13. 再按F9重新开始调试，即可看到程序成功地停在了断点处，到此处就可以正常地调试so文件了。  
  
## JEB调试  
### 设置android:debuggable="true"  
1. 使用apktool反编译apk，打开AndroidManifest文件，如果设置了android:debuggable="true"可以直接使用，如果没有，首先在application中添加android:debuggable="true"  
2. 使用apktool重打包apk，`apktool b dirpath xxx.apk`  
3. 使用keytool生成keystore文件`keytool -genkey -alias demo.keystore -keyalg RSA -validity 40000 -keystore demo.keystore`，各个参数：  
>-genkey 产生证书文件    
-alias 产生别名    
-keystore 指定密钥库的.keystore文件中   
-keyalg 指定密钥的算法,这里指定为RSA(非对称密钥算法)   
-validity 为证书有效天数，这里我们写的是40000天    
  
4. 签名apk  
`jarsigner -verbose -keystore demo.keystore xxx.apk demo.keystore`  
>-verbose 指定生成详细输出   
-keystore 指定数字证书存储路径  
  
5.jeb附加程序  
https://www.jianshu.com/p/8e8ed503d69b  
到这里为止可以调试smali代码了
