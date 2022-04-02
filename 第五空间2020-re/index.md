# 第五空间2020-re

    
## nop    
去掉花指令后的main函数如下:    
```c    
int __cdecl main(int a1, char **a2)    
{    
  _BYTE *v2; // eax    
      
  sub_804865B(*a2);    
  puts("input your flag");    
  __isoc99_scanf("%d", &dword_804A038);    
  ++dword_804A038;    
  sub_804857B();    
  ++dword_804A038;    
  sub_80485C4();    
  dword_804A038 -= 0x33333334;    
  sub_80485C4();    
  ++dword_804A038;    
  sub_80485C4();    
  v2 = sub_8048691((_BYTE *)dword_804A038);    
  sub_8048691(v2 + 1);    
  puts("Wrong!");    
  return 0;    
}    
```    
输入是一个数字，`sub_804857B`和`sub_80485C4`都是反调试，sub_8048691会把参数处地址的值改为0x90，就是nop，调用了两次可以nop两个字节，所以可以把下面:    
```c    
.text:08048763 EB 00                                   jmp     short $+2    
.text:08048765                         ; ---------------------------------------------------------------------------
.text:08048765    
.text:08048765                         loc_8048765:                            ; CODE XREF: main+C7↑j    
.text:08048765 EB 12                                   jmp     short loc_8048779    
.text:08048767                         ; ---------------------------------------------------------------------------
.text:08048767 83 EC 0C                                sub     esp, 0Ch    
.text:0804876A 68 35 88 04 08                          push    offset format   ; "Right"    
.text:0804876F E8 8C FC FF FF                          call    _printf    
.text:08048774 83 C4 10                                add     esp, 10h    
.text:08048777 EB 10                                   jmp     short loc_8048789    
```    
`8048765`处的两字节nop掉，可以输出Right    
## ManageCode    
应该用了c#和cpp联合编译，用dnspy在c#中只能找到flag的格式是111111-111111-111111-11111111111111，但是没看到检测流程    
用ida打开可以看到检测的流程，首先将输入转16进制，然后对这个16进制数下访问断点可以到检测的函数，直接解方程。    
```python    
from z3 import *    
    
solver = Solver()    
    
a1 = [Int('s%i' % i) for i in range(16)]    
v1 = 1    
v2 = a1[0]    
v3 = a1[2]    
v32 = a1[0]    
v29 = a1[2]    
v31 = a1[1]    
solver.add( -401736 * v2 == -4419096 )    
v1 = 0    
solver.add( 191967 * a1[1] + 473999 * v2 == 23642821 )    
v1 = 0    
v4 = 57125 * v2    
v5 = a1[3]    
v6 = a1[4]    
v30 = a1[3]    
v28 = a1[4]    
solver.add( v4 + 465507 * v31 - 207145 * v3 == 42831307 )    
v1 = 0    
solver.add( 149773 * v5 + -488633 * v32 - 5245 * v31 - 280749 * v3 == -560637 )    
v1 = 0    
solver.add( 381790 * v3 + 59135 * v6 + 130415 * v31 + 174205 * v5 - 83562 * v32 == 27764403 )    
v1 = 0    
v7 = a1[5]    
v27 = a1[5]    
v8 = 500139 * v6    
v9 = v1    
solver.add( 386908 * v32 + 465831 * v30 + v8 + 500998 * v7 + 474240 * v3 - 4838 * v31 == 119143813 )    
v9 = 0    
v10 = a1[6]    
v26 = v10    
solver.add( 182991 * v30 + -200009 * v31 - 497601 * v32 - 153099 * v10 + 269682 * v28 + -269523 * v7 - 441164 * v29 == -52489521 )    
v9 = 0    
v11 = a1[7]    
v23 = a1[7]    
solver.add( -14894 * v11- 162386 * v32+ 522547 * v30+ 260922 * v27+ 428523 * v29+ 508037 * v28- 144626 * v31- 99507 * v10 == 67497415 )    
v9 = 0    
v12 = a1[8]    
v25 = a1[8]    
solver.add( 51126 * v29+ 145838 * v11+ 362957 * v28+ 43500 * v31+ 308294 * v32+ -375461 * v30- 174341 * v12- 394061 * v10- 65395 * v27 == -43306962 )    
v9 = 0    
v13 = a1[9]    
v24 = v13    
solver.add( 350654 * v32+ 495127 * v28+ 434878 * v11- 75418 * v26- 43467 * v31+ -521005 * v27- 226910 * v12- 215985 * v13- 121973 * v30- 446107 * v29 == -137046349 )    
v9 = 0    
v14 = a1[10]    
v22 = v14    
solver.add( -318934 * v31- 25936 * v32- 341583 * v25+ 320416 * v29+ 339525 * v23- 81574 * v28- 502348 * v26- 294177 * v14- 363326 * v30- 391486 * v27- 248464 * v13 == -244744603 )    
v9 = 0    
v15 = a1[11]    
v21 = a1[11]    
solver.add( 81654 * v23+ 432919 * v26+ 110106 * v25- 507164 * v29- 467060 * v27+ -384845 * v15- 197253 * v24- 354555 * v31- 16893 * v14- 254110 * v32- 479559 * v30- 50999 * v28 == -214023755 )    
v9 = 0    
v16 = a1[12]    
v20 = v16    
solver.add( -117388 * v24- 227694 * v32+ 457647 * v28+ 293306 * v23+ 101385 * v30+ 293124 * v22+ 92941 * v16+ 496679 * v25+ 79854 * v29+ -81913 * v31- 507308 * v27- 3285 * v15- 71736 * v26 == 50059304 )    
v9 = 0    
v17 = a1[13]    
solver.add( 281406 * v29+ 314118 * v28+ -480916 * v23- 124091 * v17- 442447 * v22- 25649 * v32+ 389372 * v16+ 15089 * v30+ 210603 * v26+ 5 * (v25 + 17363 * v27 - 91574 * v21)- 469378 * v24- 117744 * v31 == -176657564 )    
v9 = 0    
v18 = a1[14]    
solver.add( 180059 * v26+ 350603 * v32+ -439557 * v21- 485708 * v29+ 52520 * v24+ 303697 * v28+ 395976 * v22+ 406658 * v27+ -354103 * v17- 61339 * v20- 495692 * v31- 198340 * v30- 28153 * v25- 113385 * v23- 492085 * v18 == -48802225 )    
v9 = 0    
result = v9    
solver.add( 473763 * v25+ 249640 * v26+ 450341 * v30+ 273347 * v17+ 386739 * v31+ 24246 * v27+ 20430 * v21+ 69055 * v28+ 391476 * v22+ 100872 * v23+ 458039 * v20+ 71004 * v24+ -277369 * v29- 482854 * a1[15]- 468152 * v32- 409044 * v18 == 224749784 )    
print solver.check()    
print solver.model()    
# 111111-111111-111111-11111111111111    
```    
## rev    
rop控制指令的跳转，调试可以看大具体处理流程，用z3解一下    
```python    
#coding=utf-8    
from z3 import *    
    
solver = Solver()    
    
a1 = [BitVec('s%i' % i, 8) for i in range(16)]    
res = [0x64, 0x25, 0x0F, 0x6C, 0x20, 0x23, 0x8A, 0xDE, 0x10, 0x0E, 0xA5, 0xE1, 0x43, 0x37, 0x11, 0x53]    
# s = [ord('1'), ord('5'), ord('9'), ord('d')]    
rt = []    
for t in range(4):    
  s = []    
  for u in range(4):    
      s.append([a1[t + 4*u]])    
  for edx in range(1, 5):    
      eax = s[-1 + edx]    
      esi = eax * 2    
      ecx = esi    
      ecx = ecx ^ 0x1b    
      eax = edx    
      eax = eax & 3    
      ecx = s[eax]    
      eax = ecx + ecx    
      ebx = ecx    
      ebx = ebx ^ 0x1b    
      ebx = ebx ^ eax    
      eax = eax ^ ecx    
      ecx = edx + 1    
      ebx = edx + 2    
      ecx = ecx & 3    
      ebx = ebx & 3    
      ecx = s[ecx]    
      ecx = ecx ^ s[ebx]    
      ecx = ecx ^ esi    
      eax = eax ^ ecx    
      rt.append(eax ^ (4*t + edx - 1))    
for i in range(len(rt)):    
  solver.add(rt[i] == res[i])    
print solver.check()    
print solver.model()    
```    
Nu1L的wp中用到了angr直接解题，当时我想着用但是不知道怎么输入参数(还是tcl)记录一下    
```python    
import angr,claripy    
project = angr.Project("rev_v2")    
argv1 = claripy.BVS("argv1",100*8)    
initial_state = project.factory.entry_state(args=["./rev_v2",argv1])    
simulation = project.factory.simgr(initial_state)    
simulation.explore(find=0x400481)    
found = simulation.found[0]    
solution = found.solver.eval(argv1, cast_to=bytes)    
print(repr(solution))    
solution = solution[:solution.find(b"\x00")]    
print(solution)    
```    

