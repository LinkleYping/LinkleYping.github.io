---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "De1CTF2019-signal-vm"  
date: 2020-05-01T15:22:45+08:00  
categories : [                                
"writeup",  
]  
draft: false  
---
De1CTF2019这两道vm的题都是与signal通信相关，记录一下。  
## signal vm  
### 恢复符号表  
静态链接去符号表文件，需要恢复符号表  
```shell  
$  strings signal_vm | grep GCC  
GCC: (Ubuntu 7.4.0-1ubuntu1~18.04) 7.4.0  
```
查找sig的链接https://github.com/push0ebp/sig-database  
### 程序分析  
```cpp  
signed __int64 sub_40172D()  
{  
signed int v1; // [rsp+Ch] [rbp-4h]  
  
sub_4102B0((unsigned __int64)"Check up: ");  
sub_410430((unsigned __int64)"%s");  
v1 = _libc_fork("%s", &unk_6D5132);  
if ( v1 < 0 )  
  return 0xFFFFFFFFLL;  
if ( !v1 )  
{  
  ((void (*)(void))loc_4014CA)();  
  exit(0LL);  
}  
sub_400B6D(v1);  
if ( dword_6D74E0[0] )  
  IO_puts("Ture.");  
else  
  IO_puts("False.");  
return 0LL;  
}  
```
输入之后子进程执行`loc_4014ca`父进程进入`sub_400B6D`，子进程的程序如下：  
![](/images/1da3f493949c4cf5d87c8a8516d33711/11884068-aaffa4064329c20d.png)  
程序执行ptrace后有一系列的非法指令  
父进程的程序如下  
```cpp  
__int64 __fastcall sub_400B6D(unsigned int a1)  
{  
__int64 v1; // r8  
__int64 v2; // r9  
__int64 v3; // r8  
__int64 v4; // r9  
char v5; // ST00_1  
__int64 v6; // r8  
__int64 v7; // r9  
__int64 v8; // r8  
__int64 v9; // r9  
char v10; // ST00_1  
char v12; // [rsp+0h] [rbp-160h]  
char v13; // [rsp+0h] [rbp-160h]  
int v14; // [rsp+1Ch] [rbp-144h]  
char v15; // [rsp+30h] [rbp-130h]  
unsigned __int64 v16; // [rsp+B0h] [rbp-B0h]  
int stat_addr[2]; // [rsp+110h] [rbp-50h]  
__int64 v18; // [rsp+118h] [rbp-48h]  
__int64 v19; // [rsp+120h] [rbp-40h]  
__int64 v20; // [rsp+128h] [rbp-38h]  
__int64 v21; // [rsp+130h] [rbp-30h]  
__int64 v22; // [rsp+138h] [rbp-28h]  
unsigned __int64 v23; // [rsp+148h] [rbp-18h]  
  
v23 = __readfsqword(0x28u);  
*(_QWORD *)stat_addr = 0LL;  
v18 = 0LL;  
v19 = 0LL;  
v20 = 0LL;  
v21 = 0LL;  
v22 = 0LL;  
v14 = 0;  
memset(&v15, 0, 0xD8uLL);  
_libc_wait(stat_addr);                        // 等待子进程发来信号或者子进程退出  
while ( LOBYTE(stat_addr[0]) == 127 )  
{  
  ptrace(12LL, a1, 0LL, (__int64)&v15, v1, v2, v12);  //PTRACE_GETREGS 获取寄存器的状态  
  v19 = ptrace(1LL, a1, v16, 0LL, v3, v4, v5);  //PTRACE_PEEKTEXT从进程中读取v16处的值  
  switch ( BYTE1(stat_addr[0]) )  
  {  
    case 4:  
      if ( BYTE1(v19) == 1 )  
      {  
        v14 = *(_DWORD *)((char *)&v19 + 3);  
        v16 += 7LL;  
      }  
      else  
      {  
        v14 = BYTE3(v19);  
        v16 += 4LL;  
      }  
      if ( BYTE1(v19) == 1 )  
      {  
        dword_6D74E0[BYTE2(v19)] = v14;  
      }  
      else if ( (signed int)BYTE1(v19) > 1 )  
      {  
        if ( BYTE1(v19) == 2 )  
        {  
          dword_6D74E0[BYTE2(v19)] = (unsigned __int8)aAlmostHeavenWe[dword_6D74E0[v14]];  
        }  
        else if ( BYTE1(v19) == 32 )  
        {  
          aAlmostHeavenWe[dword_6D74E0[BYTE2(v19)]] = dword_6D74E0[v14];  
        }  
      }  
      else if ( !BYTE1(v19) )  
      {  
        dword_6D74E0[BYTE2(v19)] = dword_6D74E0[v14];  
      }  
      break;  
    case 5:  
      if ( BYTE1(v19) == 1 )  
      {  
        v16 += 7LL;  
        v14 = *(_DWORD *)((char *)&v19 + 3);  
      }  
      else if ( !BYTE1(v19) )  
      {  
        v16 += 4LL;  
        v14 = dword_6D74E0[BYTE3(v19)];  
      }  
      switch ( (unsigned __int8)v19 )  
      {  
        case 0u:  
          dword_6D74E0[BYTE2(v19)] += v14;  
          break;  
        case 1u:  
          dword_6D74E0[BYTE2(v19)] -= v14;  
          break;  
        case 2u:  
          dword_6D74E0[BYTE2(v19)] *= v14;  
          break;  
        case 3u:  
          dword_6D74E0[BYTE2(v19)] /= v14;  
          break;  
        case 4u:  
          dword_6D74E0[BYTE2(v19)] %= v14;  
          break;  
        case 5u:  
          dword_6D74E0[BYTE2(v19)] |= v14;  
          break;  
        case 6u:  
          dword_6D74E0[BYTE2(v19)] &= v14;  
          break;  
        case 7u:  
          dword_6D74E0[BYTE2(v19)] ^= v14;  
          break;  
        case 8u:  
          dword_6D74E0[BYTE2(v19)] <<= v14;  
          break;  
        case 9u:  
          dword_6D74E0[BYTE2(v19)] >>= v14;  
          break;  
        default:  
          goto LABEL_59;  
      }  
      break;  
    case 8:  
      if ( BYTE2(v19) == 1 )  
      {  
        v14 = HIDWORD(v19);  
        dword_6D74FC = dword_6D74E0[BYTE3(v19)] - HIDWORD(v19);  
        v16 += 8LL;  
      }  
      else if ( !BYTE2(v19) )  
      {  
        v14 = BYTE4(v19);  
        dword_6D74FC = dword_6D74E0[BYTE3(v19)] - dword_6D74E0[BYTE4(v19)];  
        v16 += 5LL;  
      }  
      break;  
    case 0xB:  
      switch ( BYTE2(v19) )  
      {  
        case 0u:  
          v16 += *(signed int *)((char *)&v19 + 3);  
          break;  
        case 1u:  
          if ( dword_6D74FC )  
            v16 += 7LL;  
          else  
            v16 += *(signed int *)((char *)&v19 + 3);  
          break;  
        case 2u:  
          if ( dword_6D74FC )  
            v16 += *(signed int *)((char *)&v19 + 3);  
          else  
            v16 += 7LL;  
          break;  
        case 3u:  
          if ( dword_6D74FC <= 0 )  
            v16 += 7LL;  
          else  
            v16 += *(signed int *)((char *)&v19 + 3);  
          break;  
        case 4u:  
          if ( dword_6D74FC < 0 )  
            v16 += 7LL;  
          else  
            v16 += *(signed int *)((char *)&v19 + 3);  
          break;  
        case 5u:  
          if ( dword_6D74FC >= 0 )  
            v16 += 7LL;  
          else  
            v16 += *(signed int *)((char *)&v19 + 3);  
          break;  
        case 6u:  
          if ( dword_6D74FC > 0 )  
            v16 += 7LL;  
          else  
            v16 += *(signed int *)((char *)&v19 + 3);  
          break;  
        default:  
          goto LABEL_59;  
      }  
      break;  
  }  
LABEL_59:  
  ptrace(13LL, a1, 0LL, (__int64)&v15, v6, v7, v13);// PTRACE_SETREGS 设置寄存器的值  
  ptrace(7LL, a1, 0LL, 0LL, v8, v9, v10);     // PTRACE_CONT 相当于gdb中的continue  
  _libc_wait(stat_addr);  
}  
ptrace(8LL, a1, 0LL, 0LL, v1, v2, v12);  //PTRACE_KILL  
return 0LL;  
}  
```
父进程的执行控制主要依靠`stat_addr[1]`和`v19`，`wait()`函数的参数是子进程的返回状态,第一个字节如果是0x7f则表示子进程异常返回，第二个字节是返回值，`eg: exit(2)`则第二个字节为02，子进程出现异常的时候第二个字节是linux的异常信号码  
```shell  
SIGHUP       1          /* Hangup (POSIX).  */                          终止进程     终端线路挂断  
SIGINT       2          /* Interrupt (ANSI).  */                        终止进程     中断进程 Ctrl+C  
SIGQUIT      3          /* Quit (POSIX).  */                            建立CORE文件终止进程，并且生成core文件 Ctrl+\  
SIGILL       4          /* Illegal instruction (ANSI).  */              建立CORE文件,非法指令  
SIGTRAP      5          /* Trace trap (POSIX).  */                      建立CORE文件,跟踪自陷  
SIGABRT      6          /* Abort (ANSI).  */  
SIGIOT       6          /* IOT trap (4.2 BSD).  */                      建立CORE文件,执行I/O自陷  
SIGBUS       7          /* BUS error (4.2 BSD).  */                     建立CORE文件,总线错误  
SIGFPE       8          /* Floating-point exception (ANSI).  */         建立CORE文件,浮点异常  
SIGKILL      9          /* Kill, unblockable (POSIX).  */               终止进程     杀死进程  
SIGUSR1      10         /* User-defined signal 1 (POSIX).  */           终止进程     用户定义信号1  
SIGSEGV      11         /* Segmentation violation (ANSI).  */           建立CORE文件,段非法错误  
SIGUSR2      12         /* User-defined signal 2 (POSIX).  */           终止进程     用户定义信号2  
SIGPIPE      13         /* Broken pipe (POSIX).  */                     终止进程     向一个没有读进程的管道写数据  
SIGALARM     14         /* Alarm clock (POSIX).  */                     终止进程     计时器到时  
SIGTERM      15         /* Termination (ANSI).  */                      终止进程     软件终止信号  
SIGSTKFLT    16         /* Stack fault.  */  
SIGCLD       SIGCHLD    /* Same as SIGCHLD (System V).  */  
SIGCHLD      17         /* Child status has changed (POSIX).  */        忽略信号     当子进程停止或退出时通知父进程  
SIGCONT      18         /* Continue (POSIX).  */                        忽略信号     继续执行一个停止的进程  
SIGSTOP      19         /* Stop, unblockable (POSIX).  */               停止进程     非终端来的停止信号  
SIGTSTP      20         /* Keyboard stop (POSIX).  */                   停止进程     终端来的停止信号 Ctrl+Z  
SIGTTIN      21         /* Background read from tty (POSIX).  */        停止进程     后台进程读终端  
SIGTTOU      22         /* Background write to tty (POSIX).  */         停止进程     后台进程写终端  
SIGURG       23         /* Urgent condition on socket (4.2 BSD).  */    忽略信号     I/O紧急信号  
SIGXCPU      24         /* CPU limit exceeded (4.2 BSD).  */            终止进程     CPU时限超时  
SIGXFSZ      25         /* File size limit exceeded (4.2 BSD).  */      终止进程     文件长度过长  
SIGVTALRM    26         /* Virtual alarm clock (4.2 BSD).  */           终止进程     虚拟计时器到时  
SIGPROF      27         /* Profiling alarm clock (4.2 BSD).  */         终止进程     统计分布图用计时器到时  
SIGWINCH     28         /* Window size change (4.3 BSD, Sun).  */       忽略信号     窗口大小发生变化  
SIGPOLL      SIGIO      /* Pollable event occurred (System V).  */  
SIGIO        29         /* I/O now possible (4.2 BSD).  */              忽略信号     描述符上可以进行I/O  
SIGPWR       30         /* Power failure restart (System V).  */  
SIGSYS       31         /* Bad system call.  */  
SIGUNUSED    31  
```
故`stat_addr[1]`就是子进程的异常信号码，`v19`是`v16`处的值  
### 恢复系统函数的常数参数  
因为是去符号表的程序，所以ptrace函数的参数都用数字的方式显示，一个一个对照着去找有点麻烦，可以用`strace`直接找出系统调用  
```shell  
strace ./signal_vm >& a.out  
execve("./signal_vm", ["./signal_vm"], 0x7ffc6205b0f0 /* 55 vars */) = 0  
brk(NULL)                               = 0xa4e000  
brk(0xa4f1c0)                           = 0xa4f1c0  
arch_prctl(ARCH_SET_FS, 0xa4e880)       = 0  
uname({sysname="Linux", nodename="ubuntu", ...}) = 0  
readlink("/proc/self/exe", "/home/ep/Desktop/signal_vm", 4096) = 26  
brk(0xa701c0)                           = 0xa701c0  
brk(0xa71000)                           = 0xa71000  
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)  
fstat(1, {st_mode=S_IFREG|0644, st_size=774, ...}) = 0  
fstat(0, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0  
read(0, hh  
"hh\n", 1024)                   = 3  
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xa4eb50) = 20978  
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 20978  
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=20978, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
ptrace(PTRACE_GETREGS, 20978, NULL, 0x7ffda8ef6780) = 0  
ptrace(PTRACE_PEEKTEXT, 20978, 0x4014ec, [0x600000000060106]) = 0  
ptrace(PTRACE_SETREGS, 20978, NULL, 0x7ffda8ef6780) = 0  
ptrace(PTRACE_CONT, 20978, NULL, SIG_0) = 0  
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 20978  
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=20978, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
ptrace(PTRACE_GETREGS, 20978, NULL, 0x7ffda8ef6780) = 0  
ptrace(PTRACE_PEEKTEXT, 20978, 0x4014f3, [0x30106]) = 0  
ptrace(PTRACE_SETREGS, 20978, NULL, 0x7ffda8ef6780) = 0  
ptrace(PTRACE_CONT, 20978, NULL, SIG_0) = 0  
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGSEGV}], 0, NULL) = 20978  
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=20978, si_uid=1000, si_status=SIGSEGV, si_utime=0, si_stime=0} ---
```
如上所示，ptrace函数的参数都可以显示出来不用自己一个一个去找。同时因为父进程是根据子进程的异常signal进行处理，一共有`4: "SIGILL", 5 : "SIGTRAP", 8: "SIGFPE", 0xb: "SIGSEGV"`四种异常，只依靠子进程执行的非法指令很难知道每一步触发了什么异常，但是从上面的strace结果中的`wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGSEGV}], 0, NULL) = 20978`可以看到具体的信号，也不用自己一个一个记录了。  
### solve  
到这一步基本上只要根据signal去翻译子进程的那一串非法指令即可。但是我找wp的时候看到了一个直接使用gdb python编程解决的，我感觉会方便很多，记录一下。  
```shell  
signal    | machine code | handler  
-------------------------------------------
SIGILL    | 06           | mov, lea ...  
SIGTRAP   | CC           | add, sub, mul div ...  
SIGSEGV   | 00 00        | jcc  
SIGFPE    | 30 C0 F6 F8  | cmp  
```
ps:gdb python必须要在gdb中执行。使用`source your-python-file`这个命令来执行  
```python  
import gdb  
import struct  
  
class Opcode:  #opcode结构  
  opcode = ""  
  val1 = 0  
  const = 0  
  src = 0  
  dest = 0  
  final = 0  
  final2 = 0  
  
  def __init__(self, opcode):  
      self.opcode = opcode  
      test = struct.unpack("<Q", int(opcode, 16).to_bytes(8, byteorder='big'))[0]  
      self.val1 = test >> 56  
      self.const = (test >> 48) & 0xff  
      self.src = (test >> 40) & 0xff  
      self.dest = (test >> 32) & 0xff  
      self.final = struct.unpack("<I", ((test & 0xffffffff00) >> 8).to_bytes(4, byteorder='big'))[0]        
      self.final2 = struct.unpack("<I", (test & 0xffffffff).to_bytes(4, byteorder='big'))[0]  
  
  def __repr__(self):  
      str_out = "-------------------\n"  
      str_out += "OPCODE : %s  |  %d\n" % (self.opcode, int(self.opcode, 16) )   
      str_out += "val1 = %d | const = %d | src = %d | dest = %d\n" % (self.val1, self.const, self.src, self.dest)  
      str_out += "val1 = %s | const = %s | src = %s | dest = %s\n" % (hex(self.val1), hex(self.const), hex(self.src), hex(self.dest))  
      str_out += "final = %d    |   final2 =  %d \n" % (self.final, self.final2)  
      str_out += "-------------------\n"  
      return str_out  
  
  
sign = {4: "SIGILL", 5 : "SIGTRAP", 8: "SIGFPE", 0xb: "SIGSEGV" }  
mov_ins = {0: "%d: mov r%d r%d\n",1: "%d: mov r%d 0x%x\n" ,2: "%d: mov r%d [r%d]\n", 32: "%d: mov [r%d] r%d\n"}  
ops = ["add" , "sub" ,  "mul" , "div" , "mod" , "or" , "and" , "xor" , "lsh" , "rsh"]  
op_sym = ["+", "-", "*", "/", "%", "|", "&", "^", "<<", ">>"]  
str_ops = ["%d: %s r%d r%d\n", "%d: %s r%d 0x%x\n"]  
jmp = ["", "eq", "neq", "le", "lt", "ge", "gt"]  
  
f = open('ins.out', 'w')  
  
gdb.execute("file signal_vm")  # 加载被调试的可执行程序文件  
gdb.execute("set pagination off") #gdb会全部输出，中间不暂停  
gdb.execute("set follow-fork-mode parent") #fork之后继续调试父进程  
gdb.execute("b * 0x400C5B")  # 获取子进程内存值的ptrace处  
gdb.execute("b * 0x400C67")  # signal控制跳转处  
gdb.execute("b * 0x401448")  # 设置寄存器值的ptrace处  
  
gdb.execute("r < input")  
  
i = 0  
while True:  
  try:  
      i = int(gdb.execute("p/x $rdx", to_string=True).split("=")[1].strip(),16)  
      if a == 0:  
          a = i  
      i = i % a  
      gdb.execute("ni") # 执行call ptrace后获取rax中的返回值  
  except gdb.error:  
      break  
  opcode = gdb.execute("p/x $rax", to_string=True).split("=")[1].strip()  
  gdb.execute("c")  
  
  # 将BYTE1(stat_addr[0])保存在al中来控制跳转的，直接获取al的值  
  sig = gdb.execute("p/x $al", to_string=True).split("=")[1].strip()  
  gdb.execute("c")  
  
  print(sign[int(sig, 16)])  
  op = Opcode(opcode)      
  print(op)  
  
  # 根据sig和opcode进行翻译  
  if int(sig, 16) == 4:  
      if op.const == 1:  
          f.write(mov_ins[op.const] % (i, op.src, op.final))  
      else:  
          f.write(mov_ins[op.const] % (i, op.src, op.dest))  
  
  elif int(sig, 16) == 5:  
  
      if op.const == 1:  
          f.write(str_ops[1] % (i, ops[op.val1], op.src, op.final))        
      else:  
          f.write(str_ops[0] % (i, ops[op.val1], op.src, op.dest))        
  
  elif int(sig, 16) == 8:   
      if op.src == 1:  
          f.write("%d: cmp r%d 0x%x\n" % (i, op.dest, op.final2))  
      else:  
          f.write("%d: cmp r%d r%d\n" % (i, op.dest, op.final2 & 0xff))  
  
  elif int(sig, 16) == 0xb:  
      f.write("%d: jmp %s 0x%x\n" % (i, jmp[op.src], op.dest))  
  
  else:  
      print("Error")  
  
  gdb.execute("c")  
  i = i + 1  
f.close()  
```
在2.5.60版Linux内核及以后，GDB对使用fork/vfork创建子进程的程序提供了follow-fork-mode选项来支持多进程调试。  
follow-fork-mode的用法为：`set follow-fork-mode [parent|child]`  
parent: fork之后继续调试父进程，子进程不受影响。  
child: fork之后调试子进程，父进程不受影响。  
因此如果需要调试子进程，在启动gdb后：  
```shell  
(gdb) set follow-fork-mode child  
```
## signal vm delta  
delta版本除了加入写子进程的内存之外，算法也更加复杂。  
```cpp  
#include <sys/ptrace.h>  
long int ptrace(enum __ptrace_request request, pid_t pid, void * addr, void * data)  
PTRACE_PEEKTEXT 1  
PTRACE_POKETEXT 4  
PTRACE_SETREGS 13  
PTRACE_CONT 7  
PTRACE_KILL 8  
PTRACE_GETREGS 12  
PTRACE_TRACEME 0  
```
每个request的详细信息文档: http://godorz.info/2011/02/process-tracing-using-ptrace/  
## 参考链接  
https://blog.bi0s.in/2019/08/08/RE/Linux/de1ctf19-signal-vm/  
https://blog.bi0s.in/2019/08/09/RE/Linux/de1ctf19-signal-vm-de1ta/  