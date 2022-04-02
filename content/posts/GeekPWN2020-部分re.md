---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "GeekPWN2020-部分re"  
date: 2020-08-30T15:22:45+08:00  
categories : [                                
"writeup",  
]  
draft: false  
---
  
## 12. androidcmd  
程序被平坦化了，尝试去掉混淆没成功，只能直接看了。  
首先在`sub_10BC`中进行了md5值的验证，可以直接把f5后的代码写进.c文件，加上一个验证的main函数，用angr求解(后来发现其实字符串是直接用字符相等验证的)  
```cpp  
......  
int main()  
{  
    char s[40];  
    scanf("%s", s);  
    if(sub_848(s) == 0)  
        printf("Right\n");  
    else  
        printf("Wrong\n");  
}  
```  
求解脚本：  
```python  
import angr, sys  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno()) # (1)  
    if b'Right' in stdout_output: # (2)  
        return True # (3)  
    else:  
        return False  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno())     
    if b'Wrong' in  stdout_output:  
        return True  
    else:  
        return False  
  
def main():  
    filename = "test"  
    proj = angr.Project(filename)  
    initial_state = proj.factory.entry_state()  
    simgr = proj.factory.simgr(initial_state)  
    simgr.explore(find=is_successful, avoid=should_abort)  
    if simgr.found:  
        solution = simgr.found[0]  
        print(solution.posix.dumps(sys.stdin.fileno()))  
  
if __name__ == "__main__":  
    main()  
```  
求解出来md5的一部分是:"94bda84799d"  
后面的验证部分跟求md5的一样，字符格式是`82600087-****-4524-9eaa-69646e04bf68`中间差了4字节需要用md5来爆破一下。注意求md5的字符串后面需要加上换行符...不然出不来结果  
## 13. babyre  
加密过程如下：  
```python  
consts = xxx  
j = 0  
for i in range(0, 32, 8):  
    a=consts^(flag[i] | (flag[i+2]<<8))  
    buf[j]=(a&0xffff)^nums[j]  
    j = j + 1  
    b=consts^(flag[i+1] | (flag[i+3]<<8))  
    buf[j]=(b&0xffff)^nums[j]  
    j = j + 1  
    c=consts^(flag[i+7] | (flag[i+4]<<8))  
    buf[j]=(c&0xffff)^nums[j]  
    j = j + 1  
    d=consts^(flag[i+6] | flag[i+5] << 8)  
    buf[j]=(d&0xffff)^nums[j]  
    j = j + 1  
    consts=consts ^ buf[j-1] ^ buf[j-2] ^ buf[j-3] ^ buf[j-4]  
  
a=consts^(flag[32] | flag[35]<< 8)^0xFFFFBF9E  
buf[j]=(a&0xffff)  
j = j + 1  
a = (flag[33] << 8 | flag[34]) ^ consts ^ 0xFA2C  
buf[j]=(a&0xffff)  
```  
首先要求出加密用的常数，这个常数是根据main函数的部分异或算出来的，所以不能通过调试的方式得到，可以使用unicorn求得常数的值:  
```python  
#coding=utf-8  
from unicorn import *  
from unicorn.x86_const import *  
  
mu = Uc (UC_ARCH_X86, UC_MODE_64)  
  
BASE = 0x400000  
STACK_ADDR = 0x0  
STACK_SIZE = 1024*1024  
mu.mem_map(BASE, 1024*1024) # 初始化存储空间  
mu.mem_map(STACK_ADDR, STACK_SIZE) # 初始化栈空间  
  
mu.mem_write(BASE, read("./babyre")) # 加载程序  
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)  
  
def hook_code(mu, address, size, user_data):  
    if address == 0x4054A9:  
        c = mu.reg_read(UC_X86_REG_RBX)  
        print(hex(c))  
  
mu.hook_add(UC_HOOK_CODE, hook_code)  
  
mu.emu_start(0x40546B, 0x4054B0)  
```  
这里得到的是v5,进行下面的操作后是const:  
```python  
def HIDWORD(a):  
    b = a & 0xffffffff00000000  
    b = b >> 32  
    return b  
consts = (v5&0xffffffff) ^ ((v5&0xffffffff) >> 16) ^ HIDWORD(v5) ^ (v5 >> 48)  
```  
得到常数后直接解密就行：  
```python  
nums = [7107, 2676, 52815, 3666, 54091, 28777, 35367, 10586, 25358, 65063, 6311, 24454, 42823, 33695, 16895, 7107, 49054, 64044]  
  
enc = [55568, 49906, 1737, 38871, 50041, 14151, 40283, 30065, 9059, 61980, 19841, 3054, 26730, 6325, 56961, 34785, 23561, 8122]  
  
def dec(consts):  
    const_list = []  
    for i in range(0,16,4):  
        const_list.append(consts)  
        consts=consts^enc[i]^enc[i+1]^enc[i+2]^enc[i+3]  
    const_list.append(consts)  
    j = 0  
    for i in range(4):  
        consts=const_list[i]  
        for j in range(4*i, 4*i+4):  
            enc[j]=enc[j]^nums[j]  
            enc[j]=enc[j]^consts  
            enc[j]=enc[j]&0xffff  
    enc[16] = enc[16] ^ 0xFFFFBF9E  
    enc[16] = enc[16] ^ const_list[-1]  
    enc[16] = enc[16] & 0xffff  
    enc[17] = enc[17] ^ 0xFA2C  
    enc[17] = enc[17] ^ const_list[-1]  
    enc[17] = enc[17] & 0xffff  
  
if __name__ == "__main__":  
    dec(0x64e2fbe3)  
    s = "".join(hex(i)[2:].zfill(2) for i in enc)  
    print(bytes.fromhex(s).decode('utf-8'))  
```  
解密以后需要根据加密调整一下字符的顺序  
