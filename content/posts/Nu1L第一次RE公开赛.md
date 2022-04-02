---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "Nu1L第一次RE公开赛WP"  
date: 2020-04-05T15:22:45+08:00  
categories : [                                
"writeup",  
]  
draft: false  
---
  
因为第二天有xctf所以这道题从晚上九点出来到12点我没有做出来就睡了,看了官方的wp记录一下。  
## 引用  
[Nu1L官方wp](https://mp.weixin.qq.com/s?__biz=MzU4MTg1NzAzMA==&mid=2247483865&idx=1&sn=718b2929fc7aac8ac550a4c6160e5bb4&chksm=fd407bb0ca37f2a649951d2643dce6bbbcb376ef3fed2153b4b0f953c7dcafd150d32d69c296&mpshare=1&scene=23&srcid=&sharer_sharetime=1583753556598&sharer_shareid=f0e8c979e190e71002368e0459a8dd84#rd)    
[某大佬的博客](https://www.cnblogs.com/y-m-y/p/12535795.html)    
## 花指令  
关于花指令    
https://blog.csdn.net/whklhhhh/article/details/88677670    
https://blog.csdn.net/whklhhhh/article/details/88730934    
在没有去除花指令之前，打开ida的关键代码如下所示：  
```cpp  
void sub_123413B0()  
{  
unsigned int v0; // ST40_4  
unsigned int v1; // ST44_4  
int v2; // ST78_4  
  
nullsub_11();  
sub_12341340(0);  
v0 = strlen("npointer{");  
v1 = strlen("}");  
v2 = sub_123416AD(v0 + v1 + 33);  
nullsub_12();  
sub_12341020("Input the correct keys: ");  
nullsub_24();  
sub_12341050("%s", v2, v0 + v1 + 33);  
JUMPOUT((char *)&loc_1234148F + 1);  
}  
```  
JUMPOUT后面的代码没有反编译出来，查看汇编代码  
```shell  
.text:12341487 E8 04 00 00 00                    call    near ptr loc_1234148F+1  
.text:1234148C 77 EB                             ja      short loc_12341479  
.text:1234148E 07                                pop     es  
.text:1234148F  
.text:1234148F                         loc_1234148F:                     ; CODE XREF: sub_123413B0+D7↑p  
.text:1234148F 88 36                             mov     [esi], dh  
.text:12341491 83 04 24 01                       add     [esp], 1  
.text:12341495 C3                                retn  
```  
call指令等于这样两条指令，一是把自身所在位置的下一条指令的地址压入堆栈，二是jmp到call的地址处，而ret指令可以理解为jmp到call指令压入堆栈的地址，因此，可以用call指令这样来写花指令：    
1.call一个地址，在call下面随便写一点花指令，但是要注意一点与jmp版花指令不同的，我们要记得自己写的花指令占了多少个字节，比如，占了2字节    
2.在call里面，也就是函数里面，首先pop出压入的地址，然后把这个地址减去花指令占用的字节数，这里是2字节，再重新push进堆栈，然后就ret，这样，call结束以后执行的下一条指令就是我们想要去的位置了，也就是花指令下面的正常的指令了    
对于这样一个花指令，call一个函数内的地址然后再retn返回，IDA会认为被call的地址是一个新的函数，当前函数就被截断了，影响到了IDA的分析。    
图中call指令之后在call函数里将栈顶的值加了1，所以call指令后面的77可以忽略直接到`EB 07`这条指令，这个是`jmp 7`的意思，可以直接跳到retn指令后面。    
官方wp中说主程序中穿插的花指令形式如下:  
```shell  
#define JUNK2(idx) __asm{          \  
__asm  call next1_junk2_##idx          \  
__asm  __emit 0x77          \  
__asm  jmp next_junk2_##idx        \  
__asm  __emit 0x88          \  
__asm  next1_junk2_##idx:            \  
__asm  add dword ptr ss:[esp], 1  \  
__asm  ret              \  
__asm  next_junk2_##idx:              \  
}  
  
  
#define JUNK1(idx) __asm{\  
__asm jmp jlabel##idx \  
__asm __emit 0x88 \  
__asm jlabel_##idx : \  
__asm ret \  
__asm __emit 0xba \  
__asm jlabel##idx : \  
__asm call jlabel_##idx  \  
}  
```  
这两个花指令的二进制形式如下:  
```python  
'''  
EB0388C3BAE8F9FFFFFF  
E80400000077EB07883683042401C3  
'''  
stripd = ""  
with open('gatesXgame_un.exe', "rb") as f:  
  raw = f.read()  
  i = 0  
  while i < len(raw):  
      if raw[i:i+10] == "\xEB\x03\x88\xC3\xBA\xE8\xF9\xFF\xFF\xFF":  
          stripd += "\x90"*10  
          i = i + 10  
      elif raw[i:i+15] == "\xE8\x04\x00\x00\x00\x77\xEB\x07\x88\x36\x83\x04\x24\x01\xC3":  
          stripd += "\x90"*15  
          i = i + 15  
      else:  
          stripd += raw[i]  
          i += 1  
with open('gate_str.exe', 'wb') as f:  
  f.write(stripd)  
```  
去除花指令后的代码  
```cpp  
int sub_123413B0()  
{  
unsigned int v0; // ST40_4  
unsigned int v1; // ST44_4  
char *Buf1; // [esp+6Ch] [ebp-Ch]  
  
sub_12341340(0);  
v0 = strlen("npointer{");  
v1 = strlen("}");  
Buf1 = (char *)sub_123416AD(v0 + v1 + 33);  
print("Input the correct keys: ");  
sub_12341050("%s", Buf1, v0 + v1 + 33);  
if ( !memcmp(Buf1, "npointer{", strlen("npointer{"))  
  && Buf1[strlen(Buf1) - 1] == asc_12343738[0]  
  && (Buf1[strlen(Buf1) - 1] = 0, sub_12341090(sub_12343798, 0x30D3u, (int)&Buf1[strlen("npointer{")])) )  
{  
  sub_12341340(1);  
  print("Congrats!\n");  
}  
else  
{  
  print("Sorry, the gate remains closed.\n");  
}  
return system("pause");  
}  
  
int __cdecl sub_12341090(void *Src, SIZE_T dwSize, int a3)  
{  
HANDLE v4; // eax  
int v5; // ST38_4  
LPVOID Dst; // [esp+1Ch] [ebp-14h]  
  
Dst = VirtualAlloc(0, dwSize, 0x3000u, 0x40u);  
if ( !Dst )  
  return 0;  
memcpy(Dst, Src, dwSize);  
v4 = GetCurrentProcess();  
FlushInstructionCache(v4, Dst, dwSize);  
sub_12341240();  
v5 = ((int (__fastcall *)(_DWORD, int, unsigned int))Dst)(0, a3, strlen((const char *)a3));  
VirtualFree(Dst, 0, 0x8000u);  
return v5;  
}  
```  
所以主要的验证部分在sub_12343798处,在进入检测代码之前设置了一些参数信息:  
```shell  
//edx --> char* flag  
//ecx --> int idx  
//edi --> payload_base  
//ebx --> MAX_STEP (len(flag))  
```  
## 天堂之门  
在Windows64操作系统下，所有的32位程序会被装载到WoW64子系统中运行。而某些windows kernel调用，WoW64会将其钩取为64位调用。在这个过程中，运行的程序会从兼容模式暂时地切换成64位模式运行。利用这个特性，我们可以在程序运行过程中主动切换为64位模式来执行64位代码，以达到某种保护程序(如使静态分析失败、动态跟踪混乱)的目的。  
这种保护方法被称为Heaven's Gate，直译就是天堂之门。架构的切换对于运行在 Wow64 环境下的程序是必不可少的，运行在 64 位 Windows 系统下的 32 位程序在进入系统调用前需要完成下述操作：  
```shell  
32-bit ntdll.dll -> wow64cpu.dll’s Heaven’s Gate -> 64-bit ntdll.dll -> syscall into the kernel  
```  
WoW64根据段寄存器cs的值来确定程序的运行模式，如果cs的值为0x33，则当前是64位模式；如果cs的值为0x23，则当前为兼容模式。  
这道题采用了这样的方式来切换运行模式：  
```shell  
// open_gate_template_x86  
push 0x33 // cs:0x33  
sub esp, 4  
mov dword ptr ss:[esp], grid_dst_ip // next grid  
add qword ptr ss:[esp], edi // payload_base  
inc ecx // step++  
retf  
  
// open_gate_template_x64  
push 0x23 // cs:0x23  
sub rsp, 8  
mov qword ptr ss:[rsp], grid_dst_ip  
add qword ptr ss:[rsp], rdi  
inc rcx // step++  
retfq  
```  
因为架构的切换过程加上验证部分中间依旧穿插了部分花指令，x86到x64的切换大致过程如下  
```python  
b = random.randint(0, 0x7f)  
a = 0x33 ^ b  
open_gate_template_x86_mutated = f"""  
      open_gate_label:  
          push {hex(a)}  
          xor dword ptr ss:[esp], {hex(b)}  
          call next_label // sub esp, 4  
          .byte {random.randint(0,255)}  
          next_label:  
          mov dword ptr ss:[esp], grid_dst_ip  
          add dword ptr ss:[esp], edi  
          inc ecx  
          retf"""  
```  
再弄明白这个架构的切换之后，可以看出来验证部分主要是一个迷宫(图搜索),不过需要确定最最开始的两条路径(即最前面两个字母需要时f4)然后后面的路径过程基本一致，可以写出遍历程序求解。    
补一些关于天堂之门的学习链接    
http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/    
https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73    
https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html    
这部分代码调试需要使用WinDbg(x64),这个调试器可以自动完成32到64位的切换，我试了一下使用这个调试器，在执行retf后，寄存器从eax变成了rax，在执行retfq后，寄存器从rax变成了eax.    
## solve  
膜Thiner  
```python  
#!/usr/bin/python  
  
  
"""  
Solution Author: Thiner @ NeSE  
  
  
The challenge is solved with some luck.  
"""  
  
  
"""  
note here  
rbx=total  
rcx=0  
rdx=buffer without npointer{}  
rdi=&code  
init is 32bit  
return value is check result  
  
  
offset  : 0x2198  
virtaddr: 0x12343798  
code len: 0x30d3  
"""  
  
  
# gatesXgame_un.exe is the upx unpacked binary  
  
  
import capstone as cs  
with open('gatesXgame_un.exe') as f:  
    raw = f.read()  
  
  
  
  
code = raw[0x2198:0x2198+0x30d3]  
  
  
# """  
for i in range(len(code)-5):  
    if code[i:i+5] == '\xe8\x01\x00\x00\x00':  
        code = code[:i+5]+'\xf1'+code[i+6:]  
    if code[i:i+5] == '\xe8\x02\x00\x00\x00':  
        code = code[:i+5]+'\xcd\x81'+code[i+7:]  
    if code[i:i+5] == '\xe8\x03\x00\x00\x00':  
        code = code[:i+5]+'\xcd\x82\xf1'+code[i+8:]  
  
  
# code=code.replace('e803000000e4de78'.replace())  
  
  
md32 = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)  
md64 = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)  
  
  
  
  
def dis32(addr):  
    print ' code 32 {:#x} '.format(addr).center(80, '-')  
    for h, i in enumerate(md32.disasm(code[addr:addr+0x100], addr)):  
        print '{:3d}{:>#8x} {:>7s} {}'.format(h, i.address, i.mnemonic, i.op_str)  
  
  
  
  
def dis64(addr):  
    print ' code 64 {:#x} '.format(addr).center(80, '-')  
    for h, i in enumerate(md64.disasm(code[addr:addr+0x100], addr)):  
        print '{:3d}{:>#8x} {:>7s} {}'.format(h, i.address, i.mnemonic, i.op_str)  
  
  
  
  
def ext32(addr):  
    #dis32(addr)  
    head = list(md32.disasm(code[addr:addr+0x80], addr))  
    # 3+2k  
    l = []  
    for i in range(10):  
        if head[3+2*i].mnemonic != 'cmp':  
            break  
        ch = int(head[3+2*i].op_str.split(',')[-1], 0)  
        tar = int(head[4+2*i].op_str, 0)  
        inst = list(md32.disasm(code[tar:tar+0x30], tar))[4]  
        addr = int(inst.op_str.split(',')[-1], 0)  
        l.append((ch, addr))  
    return l  
  
  
  
  
def ext64(addr):  
    #dis64(addr)  
    head = list(md64.disasm(code[addr:addr+0x80], addr))  
    # 3+5k  
    l = []  
    for i in range(10):  
        if head[3+5*i].mnemonic != 'cmp':  
            break  
        ch = int(head[3+5*i].op_str.split(',')[-1], 0)  
        tar = int(head[4+5*i].op_str, 0)  
        inst = list(md64.disasm(code[tar:tar+0x30], tar))[5]  
        addr = int(inst.op_str.split(',')[-1], 0)  
        l.append((ch, addr))  
    return l  
  
  
  
  
flag = 'f4'  
addr = 0x558  
aset = set([0, 0x49e, 0x558])  
switch = 0  
  
  
  
  
def dfs(flag, addr, aset, switch):  
    if switch == 0:  
        # 32bit  
        extract = ext32  
    else:  
        extract = ext64  
    try:  
        ca = extract(addr)  
    except IndexError:  
        print "flag may be"  
        print 'npointer{'+flag+'}'  
        return  
    for c, a in ca:  
        if a not in aset:  
            dfs(flag+chr(c), a, aset | set([a]), switch ^ 1)  
    else:  
        #print('dead at',repr(flag))  
        pass  
  
  
  
  
dfs(flag, addr, aset, switch)  
```  
代码最前面的修改部分是用来修改花指令的，但是使用int指令代替nop主要是因为int指令可以不改变一条指令的长度  
## 感想  
我好菜我好菜我好菜，出题人原话"本题作为逆向公开赛的第一题，其难度较低"，哎继续努力吧.    
  
## 补一个控制转移指令的总结  
### Call指令  
一条call指令的字节数可以是（2,5,6）byte，对应不同的操作数，下面分情况讨论。  
1. 假设我们在函数src中调用函数dst，对应的call指令是的机器码长度是5 byte，其中第一个字节是e8代表指令，后面四个字节是一个相对偏移offset，dst=src_next+offset，其中src_next是下一条指令的地址，也可以看出是当前指令的地址加上该指令的长度。可以称这种情况为直接转移。    
2. 假设有一个全局函数指针变量g_pDst指向dst函数，我们在函数src中call这个变量，则对应的机器码长度是6 byte，前两个字节是ff 15代表指令，后面四个字节是一个绝对地址即变量g_pDst的地址。可以称这种情况为内存间接寻址。    
3. 假设函数src中有一个函数指针变量pDst指向dst函数，在函数src中call该变量，因为这个指针式保存在栈中的，编译时无法知道它的全局位置，只知道它相对于栈底的位置，所以根据pDst距离栈底ebp的距离。当距离小于0xff时，机器码长度为3，前两个字节是ff 55代表指令，后面一个字节代表相对ebp的偏移（注意偏移都是负数，比如f8，则ebp-8即为实际内存地址）。当距离大于0xff时，机器码长度为6，前两个字节为ff 95表指令，后四个字节是相对ebp的偏移，计算方法与上面相同。可以称这种情况为栈间接寻址。    
4. call寄存器，比如call eax、call ebx；还有call eax + 4。可以称这种情况为寄存器直接寻址。    
5. call寄存器间接转移，比如call [eax]，call [ebx]；以及call [eax] + 4。可以称这种情况为寄存器间接寻址。    
注：对于第一种情况，还有短转移，也就是偏移为一个字节，但是有些编译器（如MSVC）不会编译这种短的call，总之现在比较少见。为什么没有call functionA + 10 这类代码呢，这是因为编译器在编译的时候会自动计算相加后的地址。  
  
### Ret指令  
ret指令比较简单，只有两种情况，ret和ret n。  
  
### Jmp指令  
直接的jmp分3种   
Short Jump（短跳转）机器码 EB rel8   
只能跳转到256字节的范围内   
Near Jump（近跳转）机器码 E9 rel16/32   
可跳至同一个段的范围内的地址   
Far Jump（远跳转）机器码EA ptr 16:16/32   
可跳至任意地址，使用48位/32位全指针   
要注意的是，短跳转和近跳转指令中包含的操作数都是相对于(E)IP的偏移，而远跳转指令中包含的是目标的绝对地址，所以短/近跳转会出现跳至同一目标的指令机器码不同，不仅会不同，而且应该不同。而远跳转中包含的是绝对地址，因此转移到同一地址的指令机器码相同   
  
### 条件转移指令  
条件转移类指令与jmp指令的分类大体类似，但是有一个重要的区别就是，条件转移类指令只有直接转移，没有后面四种，所以条件转移类指令全部是相对偏移的，每种指令可分为长跳转和短跳转。    
![](/images/ed495c9624349256ef02ab1960a9201b/11884068-c22281944fda6692.jpg)  
