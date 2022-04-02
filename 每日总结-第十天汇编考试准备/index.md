# 汇编基础

## 使用gcc生成AT&T汇编风格的代码  
```c  
gcc -S -o test.s test.c  
```  
## 与Intel相比  
- 寄存器前冠以“％”，而立即数前冠以“$”  
- 目标操作数在源操作数的右边`mov $1, a ==> a=1`, `sub 1,a ==> a=a-1`  
- 操作数的字长由操作符的最后一个字母决定  
- 内存寻址`movw array(%base, %index, scale), %cx ==> cx=base+index*scale(scale等于1, 4 or 8`  
- intel中基地址使用“[” 、“]” ，而在 AT&T 中使用“(”、“)” ；另外处理复杂操作数的语法 也 不同 ， intel为 `Segreg:[base+index*scale+disp]`， 而在 AT&T 中为`%segreg:disp(base,index,sale)`，其中segreg，index，scale，disp都是可选的，在指定index而没有显式指定Scale的情况下使用默认值 1。Scale和 disp不需要加前缀“&”   
内存操作数的语法及举例  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-e7aad3cc7a8e22be.png)  
  
## cmp指令  
cmp是比较指令,cmp的功能相当于减法指令(sub)。它不保存结果，只是影响相应的标志位。其他的指令通过识别这些被影响的标志位来得知比较结果。  
cmp指令格式:   `cmp   操作对象1, 操作对象2`  
注意是计算 `操作对象2 - 操作对象1`，和sub的一样， 但不保存结果，只是根据结果修改相应的标志位。  
flag寄存器  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-dd083056fa40291c.png)  
  
## 移位指令  
;SHL(Shift Left):             逻辑左移  
;SHR(Shift Right):            逻辑右移  
;SAL(Shift Arithmetic Left):  算术左移  
;SAR(Shift Arithmetic Right): 算术右移  
  
;其中的 SHL 和 SAL 相同, 但 SHR 和 SAR 不同.  
  
;SHL、SAL: 每位左移, 低位补 0,  高位进 CF  
;SHR     : 每位右移, 低位进 CF, 高位补 0  
;SAR     : 每位右移, 低位进 CF, 高位不变  
  
;它们的结果影响 OF、SF、ZF、PF、CF  
;它们的指令格式相同:  
```c  
movl$0, %eax # result= 0  
.L2: # loop:  
movq%rdi, %rdx  
andl$1, %edx # t = x& 0x1  
addq%rdx, %rax # result+= t  
shrq%rdi # x>>= 1  
jne.L2 # if(x) gotoloop //注意这里  
rep; ret # synonym of “ret”  
```  
## JL/JG 和 JB/JA  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-d2544a055d68512f.png)  
  
```shell  
JL: jump less 有符号小于跳转  
JG: jump great 有符号大于  
JB: jump below 无符号小于  
JA: jump above 无符号大于  
JLE/JNE...  
```  
## switch指令汇编形式  
1. 条件判断  
```c  
#include <algorithm>  
  
int test_switch(){  
int i ;  
int a = std::rand();  
switch(a){  
    case 0: i = 0;break;  
    case 1: i = 1;break;  
    case 2: i = 2;break;  
    default: i = 3;break;  
}  
return i;  
}  
```  
汇编  
```c  
	movl	-4(%rbp), %eax  
	cmpl	$1, %eax  
	je	.L3  
	cmpl	$2, %eax  
	je	.L4  
	testl	%eax, %eax  
	jne	.L8  
	movl	$0, -8(%rbp)  
	jmp	.L6  
.L3:  
	movl	$1, -8(%rbp)  
	jmp	.L6  
.L4:  
	movl	$2, -8(%rbp)  
	jmp	.L6  
.L8:  
	movl	$3, -8(%rbp)  
	nop  
```  
2. 逐条件判断法  
```c  
#include <algorithm>  
  
int test_switch(){  
int i ;  
int a = std::rand();  
switch(a){  
    case 0: i = 0;break;  
    case 1: i = 1;break;  
    case 2: i = 2;break;  
    case 3: i = 3;break;  
    case 4: i = 4;break;  
    case 5: i = 5;break;  
    case 6: i = 6;break;  
    case 7: i = 7;break;  
    case 8: i = 8;break;  
    case 9: i = 9;break;  
    default: i = 10;break;  
}  
return i;  
}  
```  
汇编  
```c  
	movl	-4(%rbp), %eax  
	movq	.L4(,%rax,8), %rax  
	jmp	*%rax  
.L4:  
	.quad	.L3  
	.quad	.L5  
	.quad	.L6  
	.quad	.L7  
	.quad	.L8  
	.quad	.L9  
	.quad	.L10  
	.quad	.L11  
	.quad	.L12  
	.quad	.L13  
	.text  
.L3:  
	movl	$0, -8(%rbp)  
	jmp	.L14  
.L5:  
	movl	$1, -8(%rbp)  
	jmp	.L14  
...  
```  
3. 二分查找  
```c  
#include <algorithm>  
  
int test_switch(){  
int i ;  
int a = std::rand();  
switch(a){  
    case 4: i = 4;break;  
    case 10: i = 10;break;  
    case 50: i = 50;break;  
    case 100: i = 100;break;  
    case 200: i = 200;break;  
    case 500: i = 500;break;  
    default: i = 0;break;  
}  
return i;  
}  
```  
汇编  
```c  
    movl	-4(%rbp), %eax  
	cmpl	$50, %eax  
	je	.L3  
	cmpl	$50, %eax  
	jg	.L4  
	cmpl	$4, %eax  
	je	.L5  
	cmpl	$10, %eax  
	je	.L6  
	jmp	.L2  
.L4:  
	cmpl	$200, %eax  
	je	.L7  
	cmpl	$500, %eax  
	je	.L8  
	cmpl	$100, %eax  
	je	.L9  
	jmp	.L2  
```  
## 栈结构  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-b3a32f91efac31eb.png)  
函数调用时的栈结构  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-9d554d83635d7d9a.png)  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-7debf96a4e375451.png)  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-b235c1a6a13a8258.png)  
  
## gdb指令  
```shell  
gdb$ p *(int *)($rbp-0x14) //打印$rbp-0x14处地址中存储的值  
gdb$ x /x $rbp-0x14 //same  
```  
## mov指令与lea指令  
lea指令不解引用  
```shell  
mov 8(%rbp), rdi   --> rdi = *($rbp+8)  
lea 8(%rbp), rdi    --> rdi = ($rbp + 8)  
```  
## test指令  
test属于逻辑运算指令  
功能: 执行BIT与BIT之间的逻辑运算   
测试(两操作数作与运算,仅修改标志位,不回送结果).   
Test对两个参数(目标，源)执行AND逻辑操作,并根据结果设置标志寄存器,结果本身不会保存。EST AX,BX 与 AND AX,BX 命令有相同效果  
语法: TEST r/m,r/m/data   
影响标志: C,O,P,Z,S(其中C与O两个标志会被设为0)  
  
运用举例:   
1.Test用来测试一个位,例如  
```shell  
test eax, 100b; b表示二进制  
jnz **; 如果eax右数第三个位为1,jnz将会跳转  
```  
2.Test的一个非常普遍的用法是用来测试一方寄存器是否为空:  
```shell  
test ecx, ecx   
jz somewhere  
```  
如果ecx为零,设置ZF零标志为1,Jz跳转  
## 寄存器  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-dcbad6def99efbfc.png)  
## 直接跳转&间接跳转  
直接跳转：跳转目标是作为指令封一部分编码。  
间接跳转：目标是从寄存器或存储器位置读出来的。  
## typdef  
```c  
#define ZLEN 5  
typedef int zip_dig[ZLEN];  
zip_dig cmu= { 1, 5, 2, 1, 3 }; //zip_dig cmu相当于int cmu[5]  
```  
## 二维数组的存储  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-0959697b6bff7b3a.png)  
A[i][j]的地址`A+(i*C*4)+(j*4)`  
指针数组版本  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-20633bb734106a22.png)  
### 结构体和偏移  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-86e07e753aea91db.png)  
如果结构体中最大的对齐要求是k那么总结构体的大小一定是k的倍数  
eg  
```c  
struct S1{  
double v;  
int a[2];  
char c;  
};  
//结构体大小为24(double的倍数)而不是17/18  
struct S1{  
double v;  
char c[4];  
};  
//结构体大小是16(double的倍数)而不是12  
```  
## Union  
只分配最大的变量的存储空间，一次只允许使用一个值。  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-527ac0f9a021bb16.png)  
## ISA  
一个处理器支持的指令和指令的字节级编码称为它的指令集体系结构（Instruction-Set Architecture,ISA）  
![](/images/048a2bfa594b80479584648bbb1a51f8/11884068-baeebb52bbbe601a.png)  
### Y86-64指令集  
https://www.cnblogs.com/ysocean/p/7686213.html  
http://hczhcz.github.io/2014/06/13/y86-instruction-set.html  
## HCL  
https://www.cnblogs.com/ysocean/p/7686219.html  
- 门电路  
- MUX & ALU  
- 寄存器与存储器  
> 大多数时候，寄存器都保持在稳定状态（用x表示），产生的输出等于它的当前状态，信号沿着寄存器前面的组合逻辑传播，这时产生了一个新的寄存器输入（用y表示），但是只要时钟信号是低电位的，寄存器的输出就保持不变。当时钟变为高电位时，输入信号就加载到寄存器中，称为下一个状态y，直到下一个时钟上升沿，这个状态就一直是寄存器的新输出。  
## SEQ CPU  
https://blog.csdn.net/dennis_fan/article/details/8284248  

