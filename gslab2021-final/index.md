# 2021腾讯游戏安全大赛安卓方向决赛题解

 
## App分析  
  
### 引擎  
  
`lib`文件夹下有`libil2cpp.so`，`assets\bin\Data\Managed\Metadata`下有`global-metadata.dat`，说明是unity3D引擎的il2cpp编译方式。`global-metadata.dat`和`libil2cpp.so`均被加密。  
  
ida 打开 libsec2021.so 不识别，用readelf查看发现`e_phentsize`字段有问题，大小为23，将23改为 32 后可以正常识别。  
  
### 检测绕过  
  
`libsec2021.so`还是壳的so，同样字符串被整体加密处理了，但是解密算法直接inline，而且看起来密文并不完全在一个数组中。  
  
![](/images/gslab2021-final/1.png)  
  
同样frida spawn模式启动app然后ida attach上去调试，发现调试退出的地方都长这样  
  
![](/images/gslab2021-final/2.png)  
  
使用ida脚本对这些地方批量下断点  
  
```python  
import idc  
base = 0xD1E05000  # base of libsec2021  
ea = base + 0x58A0  
end = base + 0x416d4  
idc.create_insn(ea)  
while ea < end:  
    ins = idc.generate_disasm_line(ea, 0)  
    if ins == "EOR             R1, R1, R2":  
        ea_1 = idc.next_head(ea)  
        ins = idc.generate_disasm_line(ea_1, 0)  
        if ins == "BLX             R1":  
            ida_dbg.add_bpt(ea_1)  
            ea = ea_1  
    ea = ea + 4  
    idc.create_insn(ea)  
print("Finished")  
```  
  
![](/images/gslab2021-final/3.png)  
  
经过调试发现 check 的位 置应该在 sub_2E3C8 中，这个函数经过了混淆，直接调用改间接调用，尝试用 keystone 去一下混淆: (这里利用了 ida 会解释这个间接调用的位置，写在调用指令后的注释 中，所以可以直接从注释中取调用的函数地址，不用自己计算)：  
  
```python  
import keystone as ks  
import idautils  
import ida_bytes  
md32 = ks.Ks(ks.KS_ARCH_ARM, ks.KS_MODE_ARM)  
sub_str = "; sub_"  
  
def getASM(str, ea):  
    try:  
        ans = md32.asm(str, ea)[0]  
    except Exception:  
        ans = []  
    return ans  
def main():  
    cur_addr = 0x58A0  
    idc.create_insn(cur_addr)  
    while cur_addr < 0x416D4:  
        idc.create_insn(cur_addr)  
        ins = idc.generate_disasm_line(cur_addr, 0)  
        if ins == "":  
            print(hex(cur_addr), "null")  
        if ins[0] == 'B' and ins.find(" R") > 0:  
            if ins.find(sub_str) >= 0:  
                idx = ins.find(sub_str) + len(sub_str)  
                addr = ins[idx:]  
                b_ins = ins[:ins.find(' ')]  
                print(hex(cur_addr), ins)  
                new_ins = b_ins + ' ' + "0x" + addr  
                new_asmins = getASM(new_ins, cur_addr)  
                print(addr, new_ins, new_asmins)  
                for i in range(len(new_asmins)):  
                    ida_bytes.patch_byte(cur_addr + i, new_asmins[i])                 
        cur_addr = cur_addr + 4  
        idc.create_insn(cur_addr)  
main()  
```  
  
Patch 前后：(有一些 keystone 会解析失败，然后一些系统调用函数没有加进来，比 如说 new [])  
  
![Patch前](/images/gslab2021-final/11.png)  
  
![Patch后](/images/gslab2021-final/12.png)  
  
手动f9将断下来的地方patch。这时程序会断在`libunity`中，应该是利用程序校验和解密unity，patch导致密钥计算不正确解密失败所以出错退出了。  
  
从libunity中的initproc函数调试，发现libunity使用了libsec2021导出表`g_sec2021_p_array`中的第一个函数`sub_39140`去解密。  
  
调试这个函数，`sub_33B08`返回一个bss段的地址，这个地址处存储的是一个指向堆的指针。  
  
![](/images/gslab2021-final/4.png)  
  
`sub_340D8`将`sem_wait`接收到的值写入上述地址中，结合初赛的题目可以猜测这个地方就是key存储的位置。因为程序被patch导致此处key值发生了改变所以`libunity`解密不正确。直接用GG挂上去看内存，得到此处存储的值为`de 42 78 27 03 20 00 00`，将程序patch修改此处的值为固定值即可。  
  
![](/images/gslab2021-final/15.png)  
  
![](/images/gslab2021-final/16.png)  
  
![](/images/gslab2021-final/17.png)  
  
使用`findcrypt`可以检测出AES加密常数，解密算法为AES CBC算法，经过调试和hook发现key是classes.dex，AndroidManifest.xml，代码段，以及 com/tencent/games/sec2021/Sec2021Application这个字符串的crc32值，即为`277842de277842de`，iv为算法中写死的值`[ 0, 4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C]`。  
  
patch完成之后已经可以调试了。  
  
### 程序逻辑修改  
  
准备解密 metadata，直接用GG从内存dump出来 il2cpp.so，替换原始so的.text和.rodata，搜字符串找到 initialize函数。  
  
![](/images/gslab2021-final/5.png)  
  
动态调试截获sub_5B9238的返回值就是解密后的metadata文件。但是直接扔到il2cppdumper中会报错。  
  
参考[FlappyBirdStyleGame](https://github.com/dgkanatsios/FlappyBirdStyleGame)代码，直接编译后发现libil2cpp.so是一样的，这样就能用il2cppdumper恢复符号。找到了OnTriggerEnter2D的位置，修改触碰`Obstacle`后的行为，具体只要把`00540E60`的BNE语句改成B语句。  
  
关键就是过掉这个检测，patch本身很容易，但是由于程序有解密操作，所以直接在解密函数中判断并 patch。 用 bss 段后一小段未使用空间用来计数，当前是第几次解密。如果是第三次解密就进行 patch，把 0x1A 替换为 0xEA。  
  
![](/images/gslab2021-final/6.png)  
  
函数放在解密过后的校验过程里。重打包以后即可达到撞杆不死的效果。  
  
（同样，因为是AES CBC模式的加密，可以将需要修改代码段所在的整个block进行加密。）  
  
## 其他解法  
  
### hot patch  
  
来自[shyoshyo](https://www.52pojie.cn/home.php?mod=space&uid=1396597)师傅的题解。  
  
在过反调试的时候可以从崩溃日志中查看得到出错退出的位置  
  
![](/images/gslab2021-final/7.png)  
  
因为直接patch会导致后续解密失败，可以选择hot patch的方式，修改/proc/pid/mem文件动态修改App内存。  
  
```c  
void ipatch(int mem_fd, unsigned long long addr, unsigned char old, unsigned char new, int dir)  
{  
    unsigned char buf1[] = {0, 0};  
    unsigned char buf2[] = {0, 0};  
    unsigned char buf3[] = {dir ? old : new, 0};  
   
    lseek64(mem_fd, addr, SEEK_SET);  
    read(mem_fd, buf1, 1);  
   
    lseek64(mem_fd, addr, SEEK_SET);  
    write(mem_fd, buf3, 1);  
   
    lseek64(mem_fd, addr, SEEK_SET);  
    read(mem_fd, buf2, 1);  
   
    printf("%s  %08llx: %02x -> %02x\n", dir ? "old" : "new", addr, buf1[0], buf2[0]);  
}  
   
int main(int argc, char *argv[])  
{  
    //…  
    sprintf(mem_file_name, "/proc/%s/mem", argv[1]);  
    mem_fd = open(mem_file_name, O_RDWR);  
    long long addr = findaddr(argv[1], "sec2021", "00000000");  
   
    if (addr != -1)  
    {  
   
        printf("start patch ...\n");  
   
        ipatch(mem_fd, addr + 0x01B541 - 1, 0x2A, 0x00, 0);  
        ipatch(mem_fd, addr + 0x01B543 - 1, 0x00, 0xA0, 0);  
        // 省略若干，都可以根据崩溃日志分析得到  
        ipatch(mem_fd, addr + 0x00024602, 0x2F, 0xA0, 0);  
        ipatch(mem_fd, addr + 0x00024606, 0xE0, 0x00, 0);  
   
   
        ipatch(mem_fd, addr + 0x0004B230, 0x9f, 0x12, 0);  
        ipatch(mem_fd, addr + 0x0004B231, 0x13, 0x34, 0);  
        ipatch(mem_fd, addr + 0x0004B232, 0x79, 0x56, 0);  
        ipatch(mem_fd, addr + 0x0004B233, 0x66, 0x78, 0);  
   
        printf("patch done %d ...\n", 0);  
    }  
    return 0;  
}  
```  
  
然后通过静态注入的方式注入一个共享库，然后在共享库里放 hot-patch 的代码（以及绕过包重签名的）。注入利用 libmain，方式如下：将原来的 libmian.so 重命名为 libmain2.so，注入用的新代码写在 libmain.so 里，并 libmian.so 拉 libmain2.so，而且libmain.so 要将 libmain2.so 导出的 JNI_OnLoad 向调用者传过去。libmian.so 的入口是 my_init()。  
  
### 修复global-metadata  
  
对照 il2cpp 和 il2cppdumper 源码分析，发现偏移值对不上，把开头三个 string 相关区块挪到中间去 了，恢复脚本关键代码如下  
  
![](/images/gslab2021-final/8.png)  
  
![](/images/gslab2021-final/9.png)  
  
分析过程中发现对字符串区段有加密，异或加密  
  
![](/images/gslab2021-final/10.png)  
  
恢复之后丢到 il2cppdumper，还是有问题。 把版本号改成 0x18，成功恢复出 dll。 运行 ida 脚本后找到关键函数`PlayerController$$OnTriggerEnter2D`

## 参考链接  
  
https://blog.xhyeax.com/2021/04/10/gslab2021-final-android/  
  
https://www.52pojie.cn/thread-1420796-1-1.html  
