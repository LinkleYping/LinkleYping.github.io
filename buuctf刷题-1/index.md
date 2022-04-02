# BUUCTF刷题

    
## crackRTF    
是一个资源题，以前没见过，记录一下。    
反编译一下:    
```c    
int __cdecl main_0(int argc, const char **argv, const char **envp)    
{    
DWORD v3; // eax    
DWORD v4; // eax    
CHAR String; // [esp+4Ch] [ebp-310h]    
int v7; // [esp+150h] [ebp-20Ch]    
CHAR String1; // [esp+154h] [ebp-208h]    
BYTE pbData; // [esp+258h] [ebp-104h]    
    
memset(&pbData, 0, 0x104u);    
memset(&String1, 0, 0x104u);    
v7 = 0;    
printf("pls input the first passwd(1): ");    
scanf("%s", &pbData);    
if ( strlen((const char *)&pbData) != 6 )    
{    
printf("Must be 6 characters!\n");    
ExitProcess(0);    
}    
v7 = atoi((const char *)&pbData);    
if ( v7 < 100000 ) //输入的password可以转化为小于100000的数字    
ExitProcess(0);    
strcat((char *)&pbData, "@DBApp");    
v3 = strlen((const char *)&pbData);    
sub_40100A(&pbData, v3, &String1);  //求哈希值    
if ( !_strcmpi(&String1, "6E32D0943418C2C33385BC35A1470250DD8923A9") )    
{    
printf("continue...\n\n");    
printf("pls input the first passwd(2): ");    
memset(&String, 0, 0x104u);    
scanf("%s", &String);    
if ( strlen(&String) != 6 )    
{    
  printf("Must be 6 characters!\n");    
  ExitProcess(0);    
}    
strcat(&String, (const char *)&pbData);    
memset(&String1, 0, 0x104u);    
v4 = strlen(&String);    
sub_401019((BYTE *)&String, v4, &String1);    
if ( !_strcmpi("27019e688a4e62a649fd99cadaafdb4e", &String1) )    
{    
  if ( !sub_40100F(&String) )    
  {    
    printf("Error!!\n");    
    ExitProcess(0);    
  }    
  printf("bye ~~\n");    
}    
}    
return 0;    
}    
```    
第一个密码是一个小于100000的数字，数字后面加上@DBApp后求哈希值，求哈希值的函数如下:    
```cpp    
int __cdecl sub_401230(BYTE *pbData, DWORD dwDataLen, LPSTR lpString1)    
{    
int result; // eax    
DWORD i; // [esp+4Ch] [ebp-28h]    
CHAR String2; // [esp+50h] [ebp-24h]    
char v6[20]; // [esp+54h] [ebp-20h]    
DWORD pdwDataLen; // [esp+68h] [ebp-Ch]    
HCRYPTHASH phHash; // [esp+6Ch] [ebp-8h]    
HCRYPTPROV phProv; // [esp+70h] [ebp-4h]    
    
if ( !CryptAcquireContextA(&phProv, 0, 0, 1u, 0xF0000000) )    
return 0;    
if ( CryptCreateHash(phProv, 0x8004u, 0, 0, &phHash) )    
{    
if ( CryptHashData(phHash, pbData, dwDataLen, 0) )    
{    
  CryptGetHashParam(phHash, 2u, (BYTE *)v6, &pdwDataLen, 0);    
  *lpString1 = 0;    
  for ( i = 0; i < pdwDataLen; ++i )    
  {    
    wsprintfA(&String2, "%02X", (unsigned __int8)v6[i]);    
    lstrcatA(lpString1, &String2);    
  }    
  CryptDestroyHash(phHash);    
  CryptReleaseContext(phProv, 0);    
  result = 1;    
}    
else    
{    
  CryptDestroyHash(phHash);    
  CryptReleaseContext(phProv, 0);    
  result = 0;    
}    
}    
else    
{    
CryptReleaseContext(phProv, 0);    
result = 0;    
}    
return result;    
}    
```    
CryptCreateHash函数的第二个参数用来确定哈希函数的类型    
0x8004 -> SHA1, 0x800c -> SHA256, 0x8003 -> MD5    
所以第一个密码是爆破SHA1，爆破范围是0-100000，爆破结果是123321    
第二个输入是6字节的字符串，然后求MD5，我一开始的想法是爆破后来才知道超过4字节爆破是在想peach    
继续往下走，在sub_40100F函数中调用了sub_4014D0    
```cpp    
char __cdecl sub_4014D0(LPCSTR lpString)    
{    
LPCVOID lpBuffer; // [esp+50h] [ebp-1Ch]    
DWORD NumberOfBytesWritten; // [esp+58h] [ebp-14h]    
DWORD nNumberOfBytesToWrite; // [esp+5Ch] [ebp-10h]    
HGLOBAL hResData; // [esp+60h] [ebp-Ch]    
HRSRC hResInfo; // [esp+64h] [ebp-8h]    
HANDLE hFile; // [esp+68h] [ebp-4h]    
    
hFile = 0;    
hResData = 0;    
nNumberOfBytesToWrite = 0;    
NumberOfBytesWritten = 0;    
hResInfo = FindResourceA(0, (LPCSTR)0x65, "AAA");    
if ( !hResInfo )    
return 0;    
nNumberOfBytesToWrite = SizeofResource(0, hResInfo);    
hResData = LoadResource(0, hResInfo);    
if ( !hResData )    
return 0;    
lpBuffer = LockResource(hResData);    
sub_401005(lpString, (int)lpBuffer, nNumberOfBytesToWrite);    
hFile = CreateFileA("dbapp.rtf", 0x10000000u, 0, 0, 2u, 0x80u, 0);    
if ( hFile == (HANDLE)-1 )    
return 0;    
if ( !WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0) )    
return 0;    
CloseHandle(hFile);    
return 1;    
}    
```    
FindResourceA(0, (LPCSTR)0x65, "AAA")函数用于寻找名称为AAA的资源文件，下面是关于windows中资源文件的的一些资料.      
[VC使用自定义资源,FindResource,LoadResource,UnLockResource](https://blog.csdn.net/jiangqin115/article/details/42081965)      
[Windows MFC工程起步](https://www.jianshu.com/p/1ebf089ff727)      
使用ResourceHacker可以查找文件中的resource:    
![](/images/82d6098067f597367ce05825034d9c9f/11884068-43ea71cd307120be.png)    
    
看到资源AAA中是一系列的字符串    
sub_401005中将AAA中的字节与输入的6字节字符串进行异或，最终将结果写入dbapp.rtf中，用写字板随便写一个文件然后查看RTF文件格式    
![](/images/82d6098067f597367ce05825034d9c9f/11884068-4b2a815c081534ea.png)    
    
取前6个与AAA中的字符串异或就能得到passwd2    
## babyre    
是SCTF2019的一道RE题，当时没做出来看了师傅的WP后明白了，后来看到Ex大佬的WP感觉大佬的做法好特别，记录一下。    
首先是调试:因为前面有花指令无法F5只有看汇编+调试.文件是动态加载的, 无法确定断点位置, 我之前没调过这种, 查资料发现了attach的方法. 先运行可执行文件, 然后使用`ps -aux | grep filename`的方法查看进程号, 使用`sudo gdb filename`的方法运行gdb, 然后使用`attach PID`附加进程. 如果程序停留在库函数中可以使用`finish`命令快速跳过.    
还有一些实用的指令:    
```shell    
1. 反向调试: 要求平台支持记录回放    
reverse-step <--- 反向运行程序到上一次被执行的源代码行。    
reverse-stepi <--- 反向运行程序到上一条机器指令    
watch a <--- 给变量a设置检查点,每次执行一条机器指令会打印出a在指令执行前后的值    
record <--- 启动进程回放    
reverse-next <--- 让程序倒退回到上一步的状态    
    
2. 在启动gdb的时候附加的选项    
-symbols <file> -s <file> 从指定文件中读取符号表。    
-se file 从指定文件中读取符号表信息，并把他用在可执行文件中。    
core <file> -c <file> 调试时core dump的core文件。    
    
3.打印    
x 按十六进制格式显示变量。    
d 按十进制格式显示变量。    
u 按十六进制格式显示无符号整型。    
o 按八进制格式显示变量。    
t 按二进制格式显示变量。    
a 按十六进制格式显示变量。    
c 按字符格式显示变量。    
f 按浮点数格式显示变量。    
(gdb) p i    
$21 = 101    
(gdb) p/a i    
$22 = 0x65    
(gdb) p/c i    
$23 = 101 'e'    
    
查看文件中某变量的值：    
file::variable    
function::variable    
可以通过这种形式指定你所想查看的变量，是哪个文件中的或是哪个函数中的。例如，查看文件f2.c中的全局变量x的值：    
(gdb) p 'f2.c'::x    
查看数组的值, 比如数组的一段，或是动态分配的数据的大小。可以使用GDB的“@”操作符，“@”的左边是第一个内存的地址的值，“@”的右边是想查看内存的长度。    
例如，程序中有这样的语句：    
int *array = (int *) malloc (len * sizeof (int));    
于是，在GDB调试过程中，可以以如下命令显示出这个动态数组的取值：    
p *array@len    
二维数组打印 ----> p **array@len    
如果是静态数组的话，可以直接用print数组名，就可以显示数组中所有数据的内容了。    
http://www.cppblog.com/chaosuper85/archive/2009/08/04/92123.html    
    
4.断点     
gdb断点分类：    
以设置断点的命令分类：    
break 可以根据行号、函数、条件生成断点。    
watch 监测变量或者表达式的值发生变化时产生断点。    
catch 监测信号的产生。例如c++的throw，或者加载库的时候。    
可以借助catch命令来反反调试：    
`catch syscall ptrace`会在发生ptrace调用的时候停下，因此在第二次停住的时候`set $rax=0`，从而绕过程序中`ptrace(PTRACE_TRACEME, 0, 0, 0) ==-1`的判断    
    
gdb中的变量从1开始标号，不同的断点采用变量标号同一管理，可以 用enable、disable等命令管理，同时支持断点范围的操作，比如有些命令接受断点范围作为参数。    
例如：disable 5-8    
    
break，tbreak ----> 可以根据行号、函数、条件生成断点。tbreak设置方法与break相同，只不过tbreak只在断点停一次，过后会自动将断点删除，break需要手动控制断点的删除和使能。    
    
多文件设置断点:    
在进入指定函数时停住:    
C++中可以使用class::function或function(type,type)格式来指定函数名。如果有名称空间，可以使用namespace::class::function或者function(type,type)格式来指定函数名。    
break filename:linenum ---> 在源文件filename的linenum行处停住     
break filename:function ---> 在源文件filename的function函数的入口处停住    
break class::function或function(type,type)  （个人感觉这个比较方便，b 类名::函数名,执行后会提示如：    
>>b GamePerson::update    
Breakpoint 1 at 0x46b89e: file GamePerson.cpp, line 14.    
在类class的function函数的入口处停住    
break namespace::class::function ---> 在名称空间为namespace的类class的function函数的入口处停住    
    
until    
until line-number  继续运行直到到达指定行号，或者函数，地址等。    
until line-number if condition    
     
info break <--- 查看断点信息    
(gdb) bt <--- 查看函数堆栈。backtrace 打印当前的函数调用栈的所有信息。    
#0  func (n=250) at tst.c:5    
#1  0x080484e4 in main () at tst.c:24    
#2  0x400409ed in __libc_start_main () from /lib/libc.so.6    
```    
一共有三关, 第一关是一个三维迷宫    
第二关输入经过特定表表转换之后，不断左移累加，最终的转换结果需要与字符串“sctf_9102”相等      
调试发现是一个4字节到3字节的转换关系, 进行爆破.    
一般的爆破流程:    
```python    
data = [0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000003E, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000003F, 0x00000034, 0x00000035, 0x00000036, 0x00000037, 0x00000038, 0x00000039, 0x0000003A, 0x0000003B, 0x0000003C, 0x0000003D, 0x0000007F, 0x0000007F, 0x0000007F, 0x00000040, 0x0000007F, 0x0000007F, 0x0000007F, 0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006, 0x00000007, 0x00000008, 0x00000009, 0x0000000A, 0x0000000B, 0x0000000C, 0x0000000D, 0x0000000E, 0x0000000F, 0x00000010, 0x00000011, 0x00000012, 0x00000013, 0x00000014, 0x00000015, 0x00000016, 0x00000017, 0x00000018, 0x00000019, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000001A, 0x0000001B, 0x0000001C, 0x0000001D, 0x0000001E, 0x0000001F, 0x00000020, 0x00000021, 0x00000022, 0x00000023, 0x00000024, 0x00000025, 0x00000026, 0x00000027, 0x00000028, 0x00000029, 0x0000002A, 0x0000002B, 0x0000002C, 0x0000002D, 0x0000002E, 0x0000002F, 0x00000030, 0x00000031, 0x00000032, 0x00000033, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F, 0x0000007F]    
# Python>'sctf_9102'.encode('hex')    
# 736374665f39313032    
pass2 = ''    
dest = [0x736374,0x665f39,0x313032]    
for d in range(3):  #三个输入,每个输入有四字节    
for i in range(0x20,0x80):    
    for j in range(0x20,0x80):    
        for k in range(0x20,0x80):    
             for l in range(0x20,0x80):    
                h = (((((data[i]<<6)|data[j])<<6)|data[k])<<6)|data[l]    
                if h == dest[d]:    
                    print chr(i) + chr(j) + chr(k) + chr(l)    
                    pass2 += chr(i) + chr(j) + chr(k) + chr(l)    
print pass2    
```    
Ex大佬直接利用源程序里的流程进行爆破, 我觉得这样可以并不清楚具体实现细节,出错的概率也更小.具体的映射细节在loc_C22中:    
```cpp    
// gcc -fPIC -O3 -shared hook.c -c -o hook.o    
// ld -shared -ldl hook.o -o hook.so    
#include <stdio.h>    
#include <dlfcn.h>    
    
typedef void (*FUNC)(char *, char *);    
    
void _init()    
{    
FUNC func;    
char *printable = "_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";    
#define LENGTH 63    
char in[8], out[8];    
char *image_base = *(void **)dlopen(NULL, 1);    
printf("Image base: %p\n", image_base);    
func = image_base + 0xC22;    
*(size_t *)in = 0;    
for (int i = 0; i < LENGTH; i++)    
{    
    in[0] = printable[i];    
    for (int ii = 0; ii < LENGTH; ii++)    
    {    
        in[1] = printable[ii];    
        for (int iii = 0; iii < LENGTH; iii++)    
        {    
            in[2] = printable[iii];    
            for (int iiii = 0; iiii < LENGTH; iiii++)    
            {    
                in[3] = printable[iiii];    
                *(size_t *)out = 0;    
                func(in, out);    
                switch(*(size_t *)out)    
                {    
                case 0x746373:    
                    fprintf(stderr, "%s -> %s\n",in, out);    
                    break;    
                case 0x395F66:    
                    fprintf(stderr, "%s -> %s\n",in, out);    
                    break;    
                case 0x323031:    
                    fprintf(stderr, "%s -> %s\n",in, out);    
                    break;    
                }    
            }    
        }    
    }    
}    
printf("over\n");    
exit(0);    
}    
```    
运行:    
```c    
$ LD_PRELOAD=./hook.so ./babygame    
Image base: 0x559ccb697000    
c2N0 -> sct    
MTAy -> 102    
Zl85 -> f_9    
over    
```    
主要关键在于LD_PRELOAD, 找到一篇介绍文章如下:      
https://www.cnblogs.com/net66/p/5609026.html      
说明在babygame最开始调用_init函数的时候其实会调用hook.c中的_init函数, _init是一个爆破的函数,调用func时会调用loc_C22      
还有关于dlopen()函数的问题    
https://www.cnblogs.com/youxin/p/5109520.html     
    
第三问是一个可逆函数。    
```c    
array[30]    
array[x+4] = array[x+0] ^ f(array[x+1] ^ array[x+2] ^ array[x+3])    
```    
输入分别分位4个32bit的整数,赋值给array[0]-array[3],然后根据异或变换和f(x)转换得到array[30],最后四个字节分别为0xD8BF92EF,0x9FCC401F,0xC5AF7647,0xBE040680      
f(x)函数依赖于x。所以直接将公式倒置即可。    
```cpp    
// gcc -fPIC -O3 -shared hook2.c -c -o hook2.o    
// ld -shared -ldl hook2.o -o hook2.so    
#include <stdio.h>    
#include <dlfcn.h>    
    
typedef int (*FUNC)(int);    
    
void _init()    
{    
FUNC func;    
int array[0x100] = {0};    
array[0] = 0xD8BF92EF;    
array[1] = 0x9FCC401F;    
array[2] = 0xC5AF7647;    
array[3] = 0xBE040680;    
    
char *image_base = *(void **)dlopen(NULL, 1);    
printf("Image base: %p\n", image_base);    
func = image_base + 0x1464;    
for (int i = 0; i < 26; i++)    
{    
    array[i + 4] = array[i] ^ func(array[i+1] ^ array[i+2] ^ array[i+3]);    
}    
    
for(int i=3;i>=0;i--)    
{    
    printf("%08X\n", array[26 + i]);    
    printf("%c%c%c%c\n", ((char *)&array[26 + i])[0], ((char *)&array[26 + i])[1], ((char *)&array[26 + i])[2], ((char *)&array[26 + i])[3]);    
}    
printf("over\n");    
exit(0);    
}    
```    
运行实例：    
```c    
$ LD_PRELOAD=./hook2.so ./babygame    
Image base: 0x562b0a9e9000    
67346C66    
fl4g    
5F73695F    
_is_    
755F3073    
s0_u    
21793167    
g1y!    
over    
```    
## creakme    
在main函数中，首先进行了一些预处理。sub_402320添加了SEH      
[添加SEH的基本步骤](https://bbs.pediy.com/thread-226688.htm)      
![](/images/82d6098067f597367ce05825034d9c9f/11884068-d4747c8ddb6eacee.png)    
    
在上图中1步骤之前和步骤2之后的SEH链分别如下:      
![](/images/82d6098067f597367ce05825034d9c9f/11884068-a344770e190423f1.png)    
    
安装完SEH后通过`call    ds:DebugBreak`调用DebugBreak函数进入SEH, 在调试过程中发生中断会优先交给调试器处理,需要在SEH函数开始下断点后用`Shift + F9`运行才可以在SEH函数处暂停.    
SEH函数如下:      
![](/images/82d6098067f597367ce05825034d9c9f/11884068-ea5c47300be8bdd0.png)    
    
最终会调用0x4023EF函数,这个函数首先使用`call    ds:CheckRemoteDebuggerPresent`和`call    ds:IsDebuggerPresent`来检查程序是否被调试, 如果没有调试则进入sub_402450函数,这个函数会将0x404000后的0x200个字节与sycloversyclover进行异或    
```python    
import idc    
addr = 0x404000    
sy = "sycloversyclover"    
length = len(sy)    
for i in range(0x200):    
b = int(idc.Byte(addr + i))    
idc.PatchByte(addr+i, ~(b ^ ord(sy[i % length])))    
```    
sub_4024A0首先使用__readfsdword(0x30u)检查程序是否被调试,然后调用404000函数,SMC后404000成了一个函数,用于修改最后的对比字符串。      
最后在sub_4020D0中，对输入进行AES_CBC_128加密。密钥为’sycloversyclover’，IV为’sctfsctfsctfsctf’。这里的AES流程并不是正常的算法流程,这里使用了查表法,对比查表参数可以看出来是AES.      
关于AES查表法的识别有下面的文章可以参考     
[逆向分析及识别恶意代码中的AES算法](http://m.icpojie.com/icpojie/wap_doc/15836426.html)    
## BJDCTF_easy    
下面代码中v2中用来存储v14转化为二进制的数值，v2[0]存储v14的最高位    
```c    
while ( SHIDWORD(v14) > 0 || v14 >= 0 && v14 )    
{    
  v2[v16++] = ((SHIDWORD(v14) >> 31) ^ (((SHIDWORD(v14) >> 31) ^ v14) - (SHIDWORD(v14) >> 31)) & 1)    
            - (SHIDWORD(v14) >> 31);    
  v14 /= 2LL;    
}    
```    
`#define SHIDWORD(x)  (*((int32*)&(x)+1))  `    
取变量X地址的下一个字节的地址并且解引用，最后得到的是地址中的值，通俗点讲就是X所在内存中的邻居    

