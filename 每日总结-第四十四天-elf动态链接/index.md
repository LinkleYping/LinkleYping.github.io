# ELF动态链接

   
## 什么是PLT和GOT    
 GOT全称Global Offset Table，即全局偏移量表。它在可执行文件中是一个单独的section，位于.data section的前面。每个被目标模块引用的全局符号（函数或者变量）都对应于GOT中一个8字节的条目。编译器还为GOT中每个条目生成一个重定位记录。在加载时，动态链接器会重定位GOT中的每个条目，使得它包含正确的目标地址。    
 PLT全称Procedure Linkage Table，即过程链接表。它在可执行文件中也是一个单独的section，位于.textsection的前面。每个被可执行程序调用的库函数都有它自己的PLT条目。每个条目实际上都是一小段可执行的代码。    
### .got    
这是我们常说的GOT, 即Global Offset Table, 全局偏移表. 这是链接器在执行链接时    
实际上要填充的部分, 保存了所有外部符号的地址信息.    
不过值得注意的是, 在i386架构下, 除了每个函数占用一个GOT表项外，GOT表项还保留了    
3个公共表项, 每项32位(4字节), 保存在前三个位置, 分别是:    
    
*   got[0]: 本ELF动态段(.dynamic段)的装载地址    
*   got[[1]](http://www.cs.stevens.edu/~jschauma/810/elf.html): 本ELF的`link_map`数据结构描述符地址    
*   got[[2]](http://www.cs.dartmouth.edu/~sergey/cs108/dyn-linking-with-gdb.txt): `_dl_runtime_resolve`函数的地址    
    
其中, `link_map`数据结构的定义如下:    
    
```c    
struct link_map    
{    
 /* Shared library's load address. */    
 ElfW(Addr) l_addr;                     
 /* Pointer to library's name in the string table. */                                     
 char *l_name;        
 /*     
    Dynamic section of the shared object.    
    Includes dynamic linking info etc.    
    Not interesting to us.      
 */                       
 ElfW(Dyn) *l_ld;       
 /* Pointer to previous and next link_map node. */                     
 struct link_map *l_next, *l_prev;       
};    
    
```    
    
### .plt    
    
这也是我们常说的PLT, 即Procedure Linkage Table, 进程链接表. 这个表里包含了一些代码,    
用来(1)调用链接器来解析某个外部函数的地址, 并填充到.got.plt中, 然后跳转到该函数; 或者    
(2)直接在.got.plt中查找并跳转到对应外部函数(如果已经填充过).    
    
### .got.plt    
    
.got.plt相当于.plt的GOT全局偏移表, 其内容有两种情况：    
1)如果在之前查找过该符号,  内容为外部函数的具体地址.    
2)如果没查找过, 则内容为跳转回.plt的代码, 并执行查找.    
    
ld-linux-x86-64.so.2 是一个动态链接库，负责查找程序所使用的函数绝对地址，并将其写入到GOT表中，以供后续调用。其中GOT[0]为空，GOT[1]和GOT[2]用于保存查找的绝对函数地址，GOT[1]保存的是一个地址，指向已经加载的共享库的链表地址；GOT[2]保存的是一个函数的地址，定义如下：GOT[2] = &_dl_runtime_resolve，这个函数的主要作用就是找到某个符号的地址，并把它写到与此符号相关的GOT项中，然后将控制转移到目标函数，而后面的GOT[3]，GOT[4]…都是通过_dl_fixup 添加的。    
    
### 函数第一次被调用的过程    
![](/images/ELF-link/5970003-bcf9343191848103.webp)    
第一步由函数调用跳入到PLT表中，然后第二步PLT表跳到GOT表中，可以看到第三步由GOT表回跳到PLT表中，这时候进行压栈，把代表函数的ID压栈，接着第四步跳转到公共的PLT表项中，第5步进入到GOT表中，然后_dl_runtime_resolve对动态函数进行地址解析和重定位，第七步把动态函数真实的地址写入到GOT表项中，然后执行函数并返回。    
    
解释下dynamic段，link_map和_dl_runtime_resolve    
dynamic段：提供动态链接的信息，例如动态链接中各个表的位置    
link_map：已加载库的链表，由动态库函数的地址构成的链表    
_dl_runtime_resolve：在第一次运行时进行地址解析和重定位工作    
    
### 函数后来被调用的过程    
![](/images/ELF-link/5970003-9baedd55881a39dd.webp)    
可以看到，第一步还是由函数调用跳入到PLT表，但是第二步跳入到GOT表中时，由于这个时候该表项已经是动态函数的真实地址了，所以可以直接执行然后返回。    
    
对于动态函数的调用，第一次要经过地址解析和回写到GOT表项中，第二次直接调用即可    
## 参考链接    
https://github.com/tinyclub/open-c-book/blob/master/zh/chapters/02-chapter4.markdown    
https://luomuxiaoxiao.com/?p=578      
https://www.cnblogs.com/pannengzhi/p/2018-04-09-about-got-plt.html    
https://www.jianshu.com/p/0ac63c3744dd 
