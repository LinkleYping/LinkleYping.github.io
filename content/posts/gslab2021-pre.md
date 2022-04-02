---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "2021腾讯游戏安全大赛安卓方向初赛题解"  
date: 2021-09-02T15:22:45+08:00  
categories : [                                  
"writeup",    
]   
draft: false  
---
  
## App分析  
  
### 引擎  
  
`lib`文件夹下有`libmono.so`和`libunity.so`，`assets\bin\Data\Managed`下存在`Assembly-CSharp.dll`说明是mono引擎的unity3d游戏。  
  
`Assembly-CSharp.dll`经过加密处理，加密方式是异或0xaf，异或还原补上PE头之后可以拖进dnspy中分析，但是发现这个`Assembly-CSharp.dll`中并没有包含实际的游戏逻辑，应该是隐藏进了其他地方。  
  
### 检测绕过  
  
frida spawn模式启动app，ida附加调试，在调试`JNI_OnLoad`函数的过程中发现`sub_1F120`用于获取apk的关键字符串信息，还原这个函数并将实际字符串写入调用的注释中。  
  
```python  
import idc  
origin_str = [...] # byte_372A8  
  
key = [0xD1, 0x19, 0x0F, 0xD3, 0x57, 0x49, 0xF7, 0x75, 0xED, 0xC5, 0x17, 0xE9, 0x25, 0xB9, 0xC1, 0x1D, 0x5]  
  
out = {}  
idx = 0  
def fetch():  
    global idx  
    ret = origin_str[idx]  
    idx += 1  
    return ret  
while idx < len(origin_str):  
    start = idx  
    curr_key = fetch()  
    str_len = fetch() ^ curr_key  
    s = ""  
    for i in range(str_len):  
        s += chr(fetch()^curr_key^key[i%0x11])  
    out[start] = s  
    fetch()  
    fetch()  
  
def getStr(index):  
    return out[index]  
  
ea = 0  
end = 0x30474  
ea = idc.next_head(ea)  
while ea < end:  
    ins = idc.generate_disasm_line(ea, 0)  
    if ins == "BL              getStr":  
        addr = idc.prev_head(ea)  
        while True:  
            insPre = idc.generate_disasm_line(addr, 0)  
            if insPre.find("MOV") == 0 and insPre.find("R0") > 0:  
                argc = idc.print_operand(addr, 1)  
                print(addr, argc)  
                argc = argc.lstrip('#')  
                argcI = int(argc, 16)  
                comment = getStr(argcI)  
                print(ea, comment)  
                idc.set_cmt(ea, comment, 0)  
                break  
            else:  
                addr = idc.prev_head(addr)  
    ea = idc.next_head(ea)  
  
```  
  
还原出来的字符串如下：  
  
```shell  
28      Author: saitexie walterjxli  
59      Do you know how unity mono works?  
96      res/drawable-xhdpi-v4/ -> assets/bin/Data/Managed/  
150     initialize  
164     ()I  
171     com/tencent/games/sec2021/Sec2021Application  
219     com/tencent/games/sec2021/Sec2021IPC  
259     hack detected, risk score:%d  
291     getApplicationInfo  
313     ()Landroid/content/pm/ApplicationInfo;  
355     getFilesDir  
370     ()Ljava/io/File;  
390     sourceDir  
403     packageName  
418     nativeLibraryDir  
438     getAbsolutePath  
457     /proc/self/status  
478     TracerPid:  
492     diediedie  
505     /proc/self/maps  
524     rb  
530     delete  
540     %zx-%zx %c%c%c%c %x %x:%x %u %s  
575     android/os/Debug  
595     isDebuggerConnected  
618     sec2021  
629     getClass  
641     getName  
652     getSuperclass  
669     android/app/Application  
696     java/lang/Class  
715     ()Ljava/lang/Class;  
738     ()Landroid/content/pm/ApplicationInfo;  
780     ()Ljava/io/File;  
800     ()Ljava/lang/String;  
824     Assembly-CSharp.dll  
847     Mono.Security.dll  
868     mscorlib.dll  
884     System.Core.dll  
903     System.dll  
917     UnityEngine.dll  
936     UnityEngine.Networking.dll  
966     UnityEngine.PlaymodeTestsRunner.dll  
1005    UnityEngine.UI.dll  
1027    base.apk  
1039    android/content/Context  
1066    ()Ljava/lang/ClassLoader;  
1095    ()Ljava/lang/String;  
1119    zip file  
1131    libsec2021.so  
1148    %s/%s  
1157    dalvik.system.PathClassLoader  
1190    toString  
1202    getClassLoader  
1220    Ljava/lang/String;  
1242    %s%s  
1250    /app/data/libbugly/crash.info  
1283    can you crack me?  
1304    __optional__  
1320    cc/binmt/signature/PmsHookApplication  
1361    com/cloudinject/feature/App  
1392    np/manager/FuckSign  
1415    java/lang/ClassLoader  
1440    findClass  
1453    (Ljava/lang/String;)Ljava/lang/Class;  
1494    getPackageManager  
1515    ()Landroid/content/pm/PackageManager;  
1556    getPackageName  
1574    getPackageInfo  
1592    (Ljava/lang/String;I)Landroid/content/pm/PackageInfo;  
1649    signatures  
1663    [Landroid/content/pm/Signature;  
1698    toByteArray  
1713    ()[B  
1721    java/io/ByteArrayInputStream  
1753    <init>  
1763    ([B)V  
1772    java/security/cert/CertificateFactory  
1813    getInstance  
1828    (Ljava/lang/String;)Ljava/security/cert/CertificateFactory;  
1891    X.509  
1900    generateCertificate  
1923    (Ljava/io/InputStream;)Ljava/security/cert/Certificate;  
1982    getEncoded  
1996    java/security/MessageDigest  
2027    (Ljava/lang/String;)Ljava/security/MessageDigest;  
2080    SHA1  
2088    digest  
2098    ([B)[B  
2108    %s/libsec2021.so  
2128    .text  
2137    res/drawable-xhdpi-v4/sec2021.png  
2174    assets/filelist  
2193    endoffile  
2206    State  
2215    stop  
2223    substrate  
2236    /proc/%u/status  
2255    %s/libmono.so  
2272    rtld_db_dlactivity  
2294    /system/bin/linker  
2316    libjdwp.so  
2330    assets/sig.dat  
2348    opcode crack  
2364    debugger  
2376    bad apk  
2387    bad files  
2400    bad cert  
2412    ida  
2419    frida  
2428    shellcode  
2441    bad dll  
2452    hack detected, type:%s  
2478    0x%08x  
2488    libmono.so  
2502    libunity.so  
2517    libmain.so  
2531    META-INF/TEST.SF  
2551    META-INF/TEST.RSA  
2572    META-INF/MANIFEST.MF  
2596    .so  
2603    simulator  
2616    /system/  
2628    no heart beat.  
2646    (ILjava/lang/String;)V  
2672    onNativeEngineResponse  
2698    /proc/net/tcp  
```  
  
游戏在检测出来`frida`,`ida`等工具时会显示"hack detected, type xxx"。查看字符串的生成位置：  
  
```shell  
/armeabi-v7a$ aarch64-none-linux-gnu-objdump -d libsec2021.so | grep '\#2452'  
   1f988:       e3000994        movw    r0, #2452       ; 0x994  
```  
  
调用位置在`sub_1F788`，其中还调用了`kill`,`sleep`等函数并生成`diediedie`字符串，猜测是进行弹框并退出的函数。  
  
```c  
kill(v11, 9);  
sleep(5u);  
v12 = getStr(492);  
sub_13EC4(0, v12); // diediedie  
```  
  
`sub_13EC4`用于将生成的diediedie字符串写入地址0导致程序崩溃。  
  
在xhyeax大佬的博客里看见替换native函数的代码，记录一下  
  
```js  
function hook_sec2021() {  
    var libbase = Module.findBaseAddress("libsec2021.so");  
    var addr = libbase.add(0x13EC4);  
    var memcpy_ori = new NativeFunction(addr, 'pointer', ['int', 'pointer']);  
    Interceptor.replace(addr, new NativeCallback(function (dst, src) {  
        if (dst == 0) {  
            var zero_replace_ptr = Memory.alloc(10);  
            dst = zero_replace_ptr;  
            console.log(Memory.readByteArray(src, 0x10));  
            return dst;  
        }  
        return memcpy_ori(dst, src);  
    }, 'pointer', ['int', 'pointer']));  
}  
```  
  
该函数被`sub_1F6F0`函数调用，`sub_1F6F0`又被`sub_1FAA8`函数调用。调试发现此处确实为退出函数。查看函数的调用情况:  
  
![](/images/gslab2021-pre/2.png)  
  
把调用退出函数之前的`beq`改成`b`  
  
![](/images/gslab2021-pre/3.png)  
  
patch完之后重打包(apktool不行，直接压缩以后签名就行)就可以调试和Hook了。  
  
### 关键逻辑获取  
  
mono中dll是从`mono_image_open_from_data_with_name`函数处加载，打开libmono.so发现`mono_image_open_from_data_with_name`被加密了。使用GG修改器从内存中dump出来mono.so,发现`mono_image_open_from_data_with_name`函数被Hook转入调用`libsec2021.so`导出表中的函数  
  
![](/images/gslab2021-pre/4.png)  
  
![](/images/gslab2021-pre/5.png)  
  
最终调用可以追溯到`libsec2021.so`中的`sub_1CEDC`函数  
  
![](/images/gslab2021-pre/6.png)  
  
在这里解密`sec2021.png`的后半段获取真正的`Assembly-CSharp.dll`。(其实从解密获取的字符串，参数等于96的地方有提示`res/drawable-xhdpi-v4/ -> assets/bin/Data/Managed/`)  
  
可以hook`mono_image_open_from_data_with_name`的下一条指令，当读取到真正的`Assembly-CSharp.dll`时（通过大小判断），将其dump出来。  
  
```js  
function dump_memory(base,size) {  
    Java.perform(function () {  
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();  
        var dir = currentApplication.getApplicationContext().getFilesDir().getPath();  
        var file_path = dir + "/dumpmemory.bin";  
        var file_handle = new File(file_path, "wb");  
        if (file_handle && file_handle != null) {  
            Memory.protect(ptr(base),size, 'rwx');  
            var libso_buffer = ptr(base).readByteArray(size);  
            file_handle.write(libso_buffer);  
            file_handle.flush();  
            file_handle.close();  
            console.log("[dump]:", file_path);  
        }  
    });  
}  
function hook_mono() {  
    var libbase = Module.findBaseAddress("libmono.so");  
    console.log("libbase", libbase);  
    var addr = Module.findExportByName("libmono.so", "mono_image_open_from_data_with_name");  
    console.log("mono_image_open_from_data_with_name", addr);  
  
    Interceptor.attach(Module.findExportByName("libmono.so", "mono_image_open_from_data_with_name").add(4), {  
        onEnter: function (args) {  
            var data = args[0];  
            var data_len = args[1];  
            if (data_len == 0x2800) {  
               dump_memory(data, data_len);  
            }  
            console.log("mono_image_open_from_data_with_name_ori() called!", data, data_len);  
        },  
        onLeave: function (retval) {  
        }  
    });  
}  
```  
  
也可以直接从sec2021.png中解密，解密函数在`sub_1D2A0`。  
  
![](/images/gslab2021-pre/10.png)  
  
其中key从`sub_6320`处使用`sem_init`,`sem_wait`相关的函数收到的，与`PostMessage/PeekMessage`相似，需要找到信号发送函数，即`sem_post`函数。  
  
```c  
int __fastcall sub_16108(int *a1)  
{  
  *a1 = sub_16128();  
  return sem_post(a1 + 3);  
}  
```  
  
如图，初始密钥是从`classes.dex`文件的crc和`sec2021`,`com/tencent/games/sec2021/Sec2021Application`两个字符串的crc异或得到的。  
  
![](/images/gslab2021-pre/11.png)  
  
直接还原函数得到异或的密钥后解密。png中的偏移是16651开始。  
  
![](/images/gslab2021-pre/7.png)  
  
解密完成以后可以得到真正的`Assembly-CSharp.dll`文件。  
  
### 修改  
  
放到dnspy中查看，看到`MouseController`碰撞检测函数`OnTriggerEnter2D`中对碰撞物体进行了判断，如果不是金币则调用`HitByLaser`函数。  
  
![](/images/gslab2021-pre/8.png)  
  
做出如下修改即可达到撞杆不死的效果  
  
![](/images/gslab2021-pre/9.png)  
  
修改完成之后替换原本的`Assembly-CSharp.dll`文件，修改`libsec2021.so`使其不从`sec2021.png`中解密获取`Assembly-CSharp.dll`  
  
![](/images/gslab2021-pre/12.png)  
  
因为替换后的文件确实以`MZ`开头，所以不进行解密替换，修改完成后重打包就可以达到撞杆不死的效果了。  
  
![](/images/gslab2021-pre/13.jpg)  
  
## 其他思路  
  
看到师傅们的题解大概还有一些可行性思路，总结一下  
  
1. 模拟`libsec2021.so`因为mono.so和unity.so经过加密，且需要调用`g_sec2021_p_array`中的函数进行解密，`libsec2021.so`中又存在诸多完整性校验，所以可以自己写一个libsec模拟这些函数直接去掉原始的壳文件。  
  
2. frida-gadget  
  
   我的理解是这个方法类似把frida脚本直接写进了apk里面，之前没用过，具体细节可以看`xhyeax`师傅的博客。  
  
3. 将UnityEngine.dll和Assembly-CSharp.dll作为引用，编写一个注入dll，从而拦截HitByLaser方法([GitHub - Misaka-Mikoto-Tech/MonoHook: hook C# method at runtime without modify dll file (such as UnityEditor.dll)](https://github.com/Misaka-Mikoto-Tech/MonoHook))。  
  
   在native层hook dlopen函数，过掉libsec2021.so的检测，并获取libmono句柄，然后导出mono的api，在Assembly-CShar p.dll加载后，调用api加载注入dll（使用Cydia Substrate框架）  
  
4. 后面patch dll之后不修改so而是将修改后的dll加密以后再写回sec2021.png，由于会校验CRC所以可以爆破最后四个字节使CRC不变。`assets/filelist`存放了apk所有文件列表及其CRC值，因此还要在这里修改libsec2021.so的CRC(但是好像过了检测绕过以后就不用修改这个了)。  

## 参考链接  
  
https://blog.xhyeax.com/2021/04/04/gslab2021-pre-android/  
  
https://www.52pojie.cn/thread-1420775-1-1.html  
  
https://bbs.pediy.com/thread-226135.htm  
  
https://bbs.pediy.com/thread-226208.htm  
  
https://bbs.pediy.com/thread-226261.htm  