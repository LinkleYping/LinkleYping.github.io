---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "Unicorn"  
date: 2020-06-16T15:22:45+08:00  
categories : [                                
"notes",  
]  
draft: false  
---
## 介绍  
*   Unocorn引擎是什么?  
  
简单的来讲，一款模拟器。尽管不太常见，你不能用来模拟整个程序或者系统，同时它也不支持syscall。你只能通过手动的方式来映射内存以及数据写入，然后就可以从某个指定的地址开始执行模拟了。  
  
*   模拟器在什么时候是有用的？  
  
*   你可以执行一些恶意软件中你感兴趣的函数而不必创建整个进程  
*   CTF比赛中也很常用  
*   [Fuzzing](https://hackernoon.com/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf)  
*   GDB插件扩充，例如支持长跳转  
*   模拟混淆后的代码  
## 备忘  
`from unicorn import *` - 加载Unicorn库。包含一些函数和基本的常量。  
`from unicorn.x86_const import*` - 加载 X86 和X64架构相关的常量  
  
所有unicorn模块中的常量  
```shell  
UC_API_MAJOR                UC_ERR_VERSION              UC_MEM_READ                 UC_PROT_ALL  
UC_API_MINOR                UC_ERR_WRITE_PROT           UC_MEM_READ_AFTER           UC_PROT_EXEC  
UC_ARCH_ARM                 UC_ERR_WRITE_UNALIGNED      UC_MEM_READ_PROT            UC_PROT_NONE  
UC_ARCH_ARM64               UC_ERR_WRITE_UNMAPPED       UC_MEM_READ_UNMAPPED        UC_PROT_READ  
UC_ARCH_M68K                UC_HOOK_BLOCK               UC_MEM_WRITE                UC_PROT_WRITE  
UC_ARCH_MAX                 UC_HOOK_CODE                UC_MEM_WRITE_PROT           UC_QUERY_MODE  
UC_ARCH_MIPS                UC_HOOK_INSN                UC_MEM_WRITE_UNMAPPED       UC_QUERY_PAGE_SIZE  
UC_ARCH_PPC                 UC_HOOK_INTR                UC_MILISECOND_SCALE         UC_SECOND_SCALE  
UC_ARCH_SPARC               UC_HOOK_MEM_FETCH           UC_MODE_16                  UC_VERSION_EXTRA  
UC_ARCH_X86                 UC_HOOK_MEM_FETCH_INVALID   UC_MODE_32                  UC_VERSION_MAJOR  
UC_ERR_ARCH                 UC_HOOK_MEM_FETCH_PROT      UC_MODE_64                  UC_VERSION_MINOR  
UC_ERR_ARG                  UC_HOOK_MEM_FETCH_UNMAPPED  UC_MODE_ARM                 Uc  
UC_ERR_EXCEPTION            UC_HOOK_MEM_INVALID         UC_MODE_BIG_ENDIAN          UcError  
UC_ERR_FETCH_PROT           UC_HOOK_MEM_PROT            UC_MODE_LITTLE_ENDIAN       arm64_const  
UC_ERR_FETCH_UNALIGNED      UC_HOOK_MEM_READ            UC_MODE_MCLASS              arm_const  
UC_ERR_FETCH_UNMAPPED       UC_HOOK_MEM_READ_AFTER      UC_MODE_MICRO               debug  
UC_ERR_HANDLE               UC_HOOK_MEM_READ_INVALID    UC_MODE_MIPS3               m68k_const  
UC_ERR_HOOK                 UC_HOOK_MEM_READ_PROT       UC_MODE_MIPS32              mips_const  
UC_ERR_HOOK_EXIST           UC_HOOK_MEM_READ_UNMAPPED   UC_MODE_MIPS32R6            sparc_const  
UC_ERR_INSN_INVALID         UC_HOOK_MEM_UNMAPPED        UC_MODE_MIPS64              uc_arch_supported  
UC_ERR_MAP                  UC_HOOK_MEM_VALID           UC_MODE_PPC32               uc_version  
UC_ERR_MODE                 UC_HOOK_MEM_WRITE           UC_MODE_PPC64               unicorn  
UC_ERR_NOMEM                UC_HOOK_MEM_WRITE_INVALID   UC_MODE_QPX                 unicorn_const  
UC_ERR_OK                   UC_HOOK_MEM_WRITE_PROT      UC_MODE_SPARC32             version_bind  
UC_ERR_READ_PROT            UC_HOOK_MEM_WRITE_UNMAPPED  UC_MODE_SPARC64             x86_const  
UC_ERR_READ_UNALIGNED       UC_MEM_FETCH                UC_MODE_THUMB                
UC_ERR_READ_UNMAPPED        UC_MEM_FETCH_PROT           UC_MODE_V8                   
UC_ERR_RESOURCE             UC_MEM_FETCH_UNMAPPED       UC_MODE_V9  
```  
`mu = Uc(arch,mode)` - 获取Uc实例。在这里指定目标架构，例如：  
- `mu = Uc(UC_ARCH_X86,UC_MODE_64)` - 获取X86-64架构的实例。  
- `mu = Uc(UC_ARCH_X86,UC_MODE_32)` - 获取X86-32架构的实例。  
  
`mu.mem_map(ADDRESS,4096)` - 映射一片内存区域    
`mu.mem_write(ADDRESS,DATA)` - 向内存中写入数据    
`tmp = mu.mem_read(ADDRESS,SIZE)` - 从内存中读取数据    
`mu.reg_write(UC_X86_REG_ECX,0X0)` - 设置ECX值。    
`r_esp = mu.reg_read(UC_X86_REG_ESP)` - 读取ESP的值。    
`mu.emu_start(ADDRESS_START,ADDRESS_END)` - 开始执行模拟。    
命令追踪:  
```python  
def hook_code(mu, address, size, user_data):   
print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))   
   
mu.hook_add(UC_HOOK_CODE, hook_code)  
```  
这段代码添加了一个HOOK（向Unicorn引擎中），我们定义的函数会在执行每一条命令之前被执行。参数含义如下：  
- Uc实例  
- 指令的地址  
- 指令的长度  
- 用户定义数据（通过hook_add()函数传递）  
## 第一个例子: fibonacci  
```python  
#coding=utf-8  
from unicorn import *  
from unicorn.x86_const import *  
  
import struct  
  
def read(name):  
    with open(name, 'rb') as f:  
        return f.read()  
    
def u32(data):  
    return struct.unpack("I", data)[0]  
  
def p32(num):  
    return struct.pack("I", num)  
  
# 为x86-64架构初始化一下Unicorn引擎。  
mu = Uc (UC_ARCH_X86, UC_MODE_64)  
# Uc函数需要一下参数：  
# 第一个参数：架构类型。这些常量以UC_ATCH_为前缀  
# 第二个参数：架构细节说明。这些常量以UC_MODE_为前缀  
  
BASE = 0x400000  
STACK_ADDR = 0x0  
STACK_SIZE = 1024*1024  
# mem_map: 映射内存  
mu.mem_map(BASE, 1024*1024) # 初始化存储空间  
mu.mem_map(STACK_ADDR, STACK_SIZE) # 初始化栈空间  
  
  
mu.mem_write(BASE, read("./fibonacci")) # 加载程序  
# rsp指向栈顶  
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)  
# 因为库函数没有加载，所以调用库函数的地方需要跳过  
instructions_skip_list = [0x00000000004004EF, 0x00000000004004F6, 0x0000000000400502, 0x000000000040054F]  
  
def hook_code(mu, address, size, user_data):    
#print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))  
  
if address in instructions_skip_list:  
    mu.reg_write(UC_X86_REG_RIP, address+size)  
  
elif address == 0x400560: #that instruction writes a byte of the flag  
    c = mu.reg_read(UC_X86_REG_RDI)  
    print(chr(c))  
    mu.reg_write(UC_X86_REG_RIP, address+size)  
  
mu.hook_add(UC_HOOK_CODE, hook_code)  
  
mu.emu_start(0x00000000004004E0, 0x0000000000400575)  
```  
## 第二个例子: 分析shellcode  
```python  
from unicorn import *  
from unicorn.x86_const import *  
   
shellcode = "\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"  
   
   
BASE = 0x400000  
STACK_ADDR = 0x0  
STACK_SIZE = 1024*1024  
   
mu = Uc (UC_ARCH_X86, UC_MODE_32)  
   
mu.mem_map(BASE, 1024*1024)  
mu.mem_map(STACK_ADDR, STACK_SIZE)  
   
   
mu.mem_write(BASE, shellcode)  
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE/2)  
   
def syscall_num_to_name(num):  
    syscalls = {1: "sys_exit", 15: "sys_chmod"}  
    return syscalls[num]  
   
def hook_code(mu, address, size, user_data):  
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))   
   
machine_code = mu.mem_read(address, size)  
if machine_code == "\xcd\x80": # int 80   
    r_eax = mu.reg_read(UC_X86_REG_EAX)  
    r_ebx = mu.reg_read(UC_X86_REG_EBX)  
    r_ecx = mu.reg_read(UC_X86_REG_ECX)  
    r_edx = mu.reg_read(UC_X86_REG_EDX)  
    syscall_name = syscall_num_to_name(r_eax)  
   
    print "--------------"  
    print "We intercepted system call: "+syscall_name  
   
    if syscall_name == "sys_chmod":  
        s = mu.mem_read(r_ebx, 20).split("\x00")[0]  
        print "arg0 = 0x%x -> %s" % (r_ebx, s)  
        print "arg1 = " + oct(r_ecx)  
    elif syscall_name == "sys_exit":  
        print "arg0 = " + hex(r_ebx)  
        exit()  
   
    mu.reg_write(UC_X86_REG_EIP, address + size)  
   
mu.hook_add(UC_HOOK_CODE, hook_code)  
   
mu.emu_start(BASE, BASE-1) # 根据exit命令退出，直接加载整个shellcode  
```  
所以不仅可以直接可执行文件中的一段代码，还可以直接执行shellcode  
## 第三个例子  
```python  
from unicorn import *  
from unicorn.x86_const import *  
import struct  
   
   
def read(name):  
    with open(name) as f:  
        return f.read()  
   
def u32(data):  
    return struct.unpack("I", data)[0]  
   
def p32(num):  
    return struct.pack("I", num)  
   
mu = Uc (UC_ARCH_X86, UC_MODE_32)  
   
BASE = 0x08048000  
STACK_ADDR = 0x0  
STACK_SIZE = 1024*1024  
   
mu.mem_map(BASE, 1024*1024)  
mu.mem_map(STACK_ADDR, STACK_SIZE)  
   
   
mu.mem_write(BASE, read("./function"))  
r_esp = STACK_ADDR + (STACK_SIZE/2)     #ESP points to this address at function call  
   
STRING_ADDR = 0x0  
mu.mem_write(STRING_ADDR, "batman\x00") #write "batman" somewhere. We have choosen an address 0x0 which belongs to the stack.  
   
mu.reg_write(UC_X86_REG_ESP, r_esp)     #set ESP  
mu.mem_write(r_esp+4, p32(5))           #set the first argument. It is integer 5  
mu.mem_write(r_esp+8, p32(STRING_ADDR)) #set the second argument. This is a pointer to the string "batman"  
   
   
mu.emu_start(0x8048464, 0x804849A)      #start emulation from the beginning of super_function, end at RET instruction  
return_value = mu.reg_read(UC_X86_REG_EAX)  
print "The returned value is: %d" % return_value  
```  
可以通过修改内存来控制函数的调用参数  
## 第四个例子  
```python  
from unicorn import *  
from unicorn.arm_const import *  
   
   
import struct  
   
def read(name):  
    with open(name) as f:  
        return f.read()  
   
def u32(data):  
    return struct.unpack("I", data)[0]  
   
def p32(num):  
    return struct.pack("I", num)  
   
   
mu = Uc (UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)  
   
   
BASE = 0x10000  
STACK_ADDR = 0x300000  
STACK_SIZE = 1024*1024  
   
mu.mem_map(BASE, 1024*1024)  
mu.mem_map(STACK_ADDR, STACK_SIZE)  
   
   
mu.mem_write(BASE, read("./task4"))  
mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE/2)  
   
instructions_skip_list = []  
   
CCC_ENTRY = 0x000104D0  
CCC_END = 0x00010580  
   
stack = []                                          # Stack for storing the arguments  
d = {}                                              # Dictionary that holds return values for given function arguments  
   
def hook_code(mu, address, size, user_data):   
#print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))  
   
if address == CCC_ENTRY:                        # Are we at the beginning of ccc function?  
    arg0 = mu.reg_read(UC_ARM_REG_R0)           # Read the first argument. it is passed by R0  
   
    if arg0 in d:                               # Check whether return value for this function is already saved.  
        ret = d[arg0]  
        mu.reg_write(UC_ARM_REG_R0, ret)        # Set return value in R0  
        mu.reg_write(UC_ARM_REG_PC, 0x105BC)    # Set PC to point at "BX LR" instruction. We want to return from fibonacci function  
   
    else:  
        stack.append(arg0)                      # If return value is not saved for this argument, add it to stack.  
   
elif address == CCC_END:  
    arg0 = stack.pop()                          # We know arguments when exiting the function  
   
    ret = mu.reg_read(UC_ARM_REG_R0)            # Read the return value (R0)  
    d[arg0] = ret                               # Remember the return value for this argument  
   
mu.hook_add(UC_HOOK_CODE, hook_code)  
   
mu.emu_start(0x00010584, 0x000105A8)  
   
return_value = mu.reg_read(UC_ARM_REG_R1)           # We end the emulation at printf("%d\n", ccc(x)).  
print "The return value is %d" % return_value  
```  
arm版本  
## 参考链接  
https://bbs.pediy.com/thread-224330.htm    
http://eternal.red/2018/unicorn-engine-tutorial/#cheatsheet    
https://ctf-wiki.github.io/ctf-wiki/reverse/unicorn/introduction-zh/    
这里有很多代码示例：  
https://github.com/unicorn-engine/unicorn/tree/master/bindings/python  