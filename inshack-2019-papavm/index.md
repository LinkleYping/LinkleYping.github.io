# InsHack-2019-papavm

   
## 脱壳    
是一个UPX的壳，程序中把UPX换成了ZOB，所以直接用`upx -d`无法脱壳，将ZOB替换成UPX后就可以直接使用`upx -d`脱壳。    
## first step    
脱壳后的程序仍然是一个静态链接去符号表的程序，关键代码部分如下:    
```c    
unsigned __int64 __usercall sub_401C4C@<rax>(__int64 a1@<rbx>, __int64 a2@<r12>, double a3@<xmm0>, double a4@<xmm1>, double a5@<xmm2>, double a6@<xmm3>, double a7@<xmm6>, double a8@<xmm7>)    
{    
double v8; // xmm4_8    
double v9; // xmm5_8    
unsigned __int64 result; // rax    
signed int v11; // [rsp+0h] [rbp-40280h]    
signed int v12; // [rsp+4h] [rbp-4027Ch]    
signed int v13; // [rsp+8h] [rbp-40278h]    
int v14; // [rsp+Ch] [rbp-40274h]    
char v15[262760]; // [rsp+10h] [rbp-40270h]    
unsigned __int64 v16; // [rsp+40278h] [rbp-8h]    
__int64 savedregs; // [rsp+40280h] [rbp+0h]    
    
v16 = __readfsqword(0x28u);    
v11 = 0;    
v12 = 0;    
v13 = 0;    
v14 = 0;    
while ( v11 != 1 || v12 != 1 )    
{    
  if ( v13 > 131376 )    
    v11 = 1;    
  else    
    v15[v14++] = byte_4A80C0[v13];    
  if ( v13 > 131376 )    
    v12 = 1;    
  else    
    v15[v14++] = byte_4C8200[v13];    
  ++v13;    
}    
sub_401B55(v15, 97, a1, a2, a3, a4, a5, a6, a7, a8);    
result = __readfsqword(0x28u) ^ v16;    
if ( result )    
  sub_4405C0(a1, (__int64)&savedregs, a2, a3, a4, a5, a6, v8, v9, a7, a8);    
return result;    
}    
__int64 __usercall sub_401B55@<rax>(const char *a1@<rdi>, char a2@<sil>, __int64 a3@<rbx>, __int64 a4@<r12>, double a5@<xmm0>, double a6@<xmm1>, double a7@<xmm2>, double a8@<xmm3>, double a9@<xmm6>, double a10@<xmm7>)    
{    
unsigned int fd; // ST18_4    
unsigned int v11; // ST1C_4    
size_t count; // ST00_8    
double v13; // xmm4_8    
double v14; // xmm5_8    
__int64 result; // rax    
double v16; // xmm4_8    
double v17; // xmm5_8    
char *v18; // [rsp+20h] [rbp-30h]    
__int64 v19; // [rsp+28h] [rbp-28h]    
char filename[8]; // [rsp+39h] [rbp-17h]    
unsigned __int64 v21; // [rsp+48h] [rbp-8h]    
__int64 savedregs; // [rsp+50h] [rbp+0h]    
    
v21 = __readfsqword(0x28u);    
strcpy(filename, "/tmp/fooXXXXXX");    
fd = mkostemp((__int64 *)filename, 1, (const char *)a4, a5, a6, a7, a8, a9, a10);    
chmod(filename, 320LL);    
v11 = open(filename, 0, a2);    
unlink(filename);    
write(fd, a1, count);    
close(fd);    
v18 = filename;    
v19 = 0LL;    
fexecve(v11, (const char *)&v18, qword_4EB7C0, a3, (const char *)&savedregs, a5, a6, a7, a8, v13, v14, a9, a10);    
result = sub_4093A0("ERROR");    
if ( __readfsqword(0x28u) != v21 )    
  sub_4405C0(a3, (__int64)&savedregs, a4, a5, a6, a7, a8, v16, v17, a9, a10);    
return result;    
}    
```  
在`sub_401C4C`中得到`v15`数组，在`sub_401B55`中将数组写入`/tmp/fooXXXXXX`后执行，将这个数组的值dump出来可以得到另一个可执行文件    
## second step    
第二层可执行文件的主要代码    
```c    
unsigned __int64 sub_1499()    
{    
size_t v0; // rax    
void *v1; // rsp    
size_t v2; // rax    
size_t v3; // rbx    
size_t v5; // [rsp+0h] [rbp-70h]    
__int64 v6; // [rsp+8h] [rbp-68h]    
int i; // [rsp+14h] [rbp-5Ch]    
int v8; // [rsp+18h] [rbp-58h]    
int v9; // [rsp+1Ch] [rbp-54h]    
time_t timer; // [rsp+20h] [rbp-50h]    
struct tm *v11; // [rsp+28h] [rbp-48h]    
char *s; // [rsp+30h] [rbp-40h]    
size_t v13; // [rsp+38h] [rbp-38h]    
const char *v14; // [rsp+40h] [rbp-30h]    
unsigned __int64 v15; // [rsp+48h] [rbp-28h]    
    
v15 = __readfsqword(0x28u);    
time(&timer);    
v11 = localtime(&timer);    
v8 = v11->tm_sec;    
v9 = 7;    
s = "SBVZYBVFMVYLAZHTLOATHP";    
v0 = strlen("SBVZYBVFMVYLAZHTLOATHP");    
v13 = v0 - 1;    
v5 = v0;    
v6 = 0LL;    
v1 = alloca(16 * ((v0 + 15) / 0x10));    
v14 = (const char *)&v5;    
for ( i = 0; ; ++i )    
{    
  v3 = i;    
  if ( v3 >= strlen(s) )    
    break;    
  v2 = strlen(s);    
  v14[i] = s[v2 - i - 1];                     // 逆序    
}    
sub_11F9((__int64)v14, v9);    
sub_13B1(v14);    
return __readfsqword(0x28u) ^ v15;    
}    
__int64 __fastcall sub_11F9(__int64 a1, char a2)    
{    
__int64 result; // rax    
char v3; // [rsp+17h] [rbp-5h]    
char v4; // [rsp+17h] [rbp-5h]    
char v5; // [rsp+17h] [rbp-5h]    
int i; // [rsp+18h] [rbp-4h]    
    
for ( i = 0; ; ++i )    
{    
  result = *(unsigned __int8 *)(i + a1);    
  if ( !(_BYTE)result )    
    break;    
  v3 = *(_BYTE *)(i + a1);    
  if ( v3 <= 0x60 || v3 > 0x7A )              // not a-z    
  {    
    if ( v3 > 0x40 && v3 <= 0x5A )            // A-Z    
    {    
      v5 = v3 - a2;                           // -9    
      if ( v5 <= 0x40 )    
        v5 += 26;                             // 凯撒密码，左移7    
      *(_BYTE *)(a1 + i) = v5;    
    }    
  }    
  else    
  {    
    v4 = v3 - a2;    
    if ( v4 <= 96 )    
      v4 += 26;    
    *(_BYTE *)(a1 + i) = v4;    
  }    
}    
return result;    
}    
unsigned __int64 __fastcall sub_13B1(const char *a1)    
{    
int v2; // [rsp+18h] [rbp-3CA08h]    
signed int i; // [rsp+1Ch] [rbp-3CA04h]    
char v4[248296]; // [rsp+20h] [rbp-3CA00h]    
unsigned __int64 v5; // [rsp+3CA08h] [rbp-18h]    
    
v5 = __readfsqword(0x28u);    
v2 = 0;    
for ( i = 0; i <= (signed int)&unk_3C9E0; ++i )    
{    
  v4[i] = a1[v2++] ^ byte_40A0[i];    
  if ( v2 == strlen(a1) )    
    v2 = 0;    
}    
sub_12BA(v4, (size_t)&unk_3C9E1);    
return __readfsqword(0x28u) ^ v5;    
}    
```  
相似的套路，密钥是`SBVZYBVFMVYLAZHTLOATHP`逆序后左移7然后与`byte_40A0`异或，dump出以后是真正的vm    
## vm    
```c    
// 指令结构    
struct insn_t {    
  signed op: 8;   /* opcode */    
  signed op1: 8;   /* destination register */    
  signed op2: 8;   /* source register */    
  signed dd: 8;   /* unused */    
};    
```  
vm解析(之前一直用input代入的方式太傻了...)    
```python    
#coding = utf-8    
def print_ins(offset, op, arg1="", arg2=""):    
  # print(op)    
  print("{:0>3x}  {:^5s} {:^8s} {:^8s}".format(offset, op, arg1, arg2))    
    
def deal_data(d):    
  a = hex(d).strip('0x')    
  b = a.zfill(7)    
  c = b[::-1]    
  return int(c, 16)    
    
if __name__ == "__main__":    
  data = [513, 769, 263937, 67585, 393986, 2307, 1028, 66820, 328712, 262661, 458757, 524549, 525061, 63238, 519]    
  pc = 0    
  print_ins(0, "load", "R0", "arg[]")    
  print_ins(0, "mov", "R1", "input")    
  print_ins(0, "mov", "R6", "length")    
  while pc < len(data):    
      d = data[pc]    
      ins = deal_data(d)    
      opn = ins >> 24    
      op1 = (ins >> 16) & 0xff    
      op2 = (ins >> 8) & 0xff    
      if opn == 1:    
          op = "mov"    
          arg1 = "R%d"%op1    
          arg2 = str(op2)    
          print_ins(pc, op, arg1, arg2)    
      elif opn == 2:    
          op = "cmp"    
          arg1 = "R%d"%op1    
          arg2 = "R%d"%op2    
          print_ins(pc, op, arg1, arg2)    
          op = "setz"    
          print_ins(pc, op, "R10")    
      elif opn == 3:    
          op = "cmp"    
          arg1 = "R10"    
          print_ins(pc, op, arg1, "1")    
          op = "jz"    
          arg1 = hex(pc + op1)    
          print_ins(pc, op, arg1)    
      elif opn == 4:    
          op = "load"    
          arg1 = "R%d"%op1    
          arg2 = "R%d"%op2    
          print_ins(pc, op, arg1, arg2)    
      elif opn == 5:    
          op = "add"    
          arg1 = "R%d"%op1    
          arg2 = "R%d"%op2    
          print_ins(pc, op, arg1, arg2)    
      elif opn == 6:    
          op = "jmp"    
          arg1 = hex((pc + op1) % (len(data)+1))    
          print_ins(pc, op, arg1)    
      elif opn == 7:    
          op = "ret"    
          arg1 = "R%d"%op1    
          print_ins(pc, op, arg1)    
      elif opn == 8:    
          op = "mul"    
          arg1 = "R%d"%op1    
          arg2 = "R%d"%op2    
          print_ins(pc, op, arg1, arg2)    
      pc = pc + 1    
```  
解析后的指令    
```shell    
000  load     R0     arg[]    
000   mov     R1     input    
000   mov     R6     length    
000   mov     R2       0    
001   mov     R3       0    
002   mov     R7       4    
003   mov     R8       1    
004   cmp     R3       R6    
004  setz    R10    
005   cmp    R10       1    
005   jz     0xe    
006  load     R4       R0    
007  load     R5       R1    
008   mul     R4       R5    
009   add     R2       R4    
00a   add     R0       R7    
00b   add     R1       R8    
00c   add     R3       R8    
00d   jmp    0x4    
00e   ret     R2    
```  
arg[]数组是`[31, 31x31, 31x31x31, ...]`    
## solve    
z3求解(是参考链接中wp里面的，懒得再写一个了，记录一下)    
```python    
#!/usr/bin/python    
from z3 import *    
    
def work(size):    
  b = [BitVec('%d' % i, 8) for i in xrange(size)]    
  s = Solver()    
  t = BitVecVal(0, 64)    
  p = BitVecVal(1, 32)    
  s.add(b[-1] == 10)  #换行符，因为用的fgets读取    
  for i in xrange(size):    
      p *= 31    
      t += SignExt(32, p)*SignExt(56, b[i])    
  s.add(t == 0xffffffc8b0eb3225)    
  if s.check() == sat:    
      flag = ""    
      ans = s.model()    
      for i in b:    
          flag += chr(ans[i].as_long())    
      print "[*] Found:", flag.encode("base64")    
    
i = 1    
while i < 45:    
  work(i)    
  i += 1    
```  
但是这个题不需要用z3求出真正的flag，上面程序的任意一个输出都可以输入返回正确，然后需要连接服务器获取flag    
```python    
#!/usr/bin/python    
from pwn import *    
p = process('./papavm')    
sd=lambda x:p.send(x)    
sl=lambda x:sd(x+'\n')    
sda=lambda x,y:p.sendafter(x,y)    
sla=lambda x,y:sda(x,y+'\n')    
ru=lambda x:p.recvuntil(x)    
rv=lambda x:p.recv(x)    
io=lambda :p.interactive()    
ps=lambda :pause()    
rv(1024)    
sl("")    
rv(1024)    
sl("launch")    
s = "lxFXLH7HnQo="    
sl(s.decode("base64"))    
print rv(1024)    
p.close()    
```  
也可以直接用`echo "lxFXLH7HnQo=" | base64 -d | ssh -p 2231 user@papavm.ctf.insecurity-insa.fr`    
  
## 参考链接    
https://x0r19x91.github.io/2019/2019-05-06-inshack-papavm/    
https://github.com/InsecurityAsso/inshack-2019/blob/ab25eaa9ee/papavm/writeup.md 
