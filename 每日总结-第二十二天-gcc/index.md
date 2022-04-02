# gcc详解

## 编译流程  
gcc、g++分别是gnu的c、c++编译器，gcc/g++在执行编译工作的时候，总共需要4步:  
- 预处理： 生成预处理文件，后缀名 .i (预处理器cpp)  
- 编译： 预处理后的文件编译生成汇编语言文件，后缀名 .s(编译器egcs)  
- 汇编： 汇编语言文件汇编生成目标代码(机器代码)文件，后缀名.o (汇编器as)  
- 链接： 链接目标代码, 生成可执行文件 (链接器ld)  
  
源码从前端经过词法分析、语法分析/语义分析之后生成AST/GENERIC，再转换成GIMPLE中间表示，GCC还需要对GIMPLE进行低级化、IPA处理等，再转成SSA优化后生成RTL，最终才生成汇编代码，整个过程如下：  
![](/images/ff8279eca9bfd880a8a6d0ac511f44cc/11884068-edf42458aba36443.jpg)  
gcc编译系统主要由三部分组成：与语言相关的前端、与语言无关的后端、与机器相关的机器描述  
GCC的优化流程主要是: 编译器首先从编译命令行中解析出优化参数，经过语法分析器将源程序翻译成等价的AST(抽象语法树)形式； 再由中间代码生成器将AST转换为RTL(Register transfer language)；然后由优化器根据解析出的优化参数实施相应的优化策略；最后由代码生成器读入优化后的RTL并生成可执行机器码予以输出。事实上,GCC的优化绝大部分都是在RTL这个层次上实施的。  
## 参数详解  
- -x: `gcc -x language filename` 设定文件所使用的语言, 使后缀名无效, 对以后的多个有效。language可以是：`c, objective-c, c-header, c++, cpp-output, assembler, assembler-with-cpp`  
eg: `gcc -x c test.png` language为none时表示自动识别语言  
- -c: 只激活预处理,编译,和汇编,也就是他只把程序做成obj文件  
eg: `gcc -c test.c`只生成.obj文件  
- -S 只激活预处理和编译，就是指把文件编译成为汇编代码。  
- -E 只激活预处理,这个不生成文件, 你需要把它重定向到一个输出文件里面  
```shell  
gcc -E test.c > test.txt  
```  
- -ansi 使用-ansi参数可以支持 ISO C89风格。  
比如下面的代码:  
```c  
#include<stdio.h>  
int main(void)  
{  
// Print the string  
 printf("\n The Geek Stuff\n");  
 return 0;  
}  
```  
使用-ansi参数编译上面的代码会出错，因为ISO C89不支持C++风格的注释。  
- -fno-asm 此选项实现ansi选项的功能的一部分，它禁止将asm,inline和typeof用作关键字。  
- -include file 包含某个代码，简单来说，就是当某个文件需要另一个文件的时候，就可以用它设定，功能就相当于在代码中使用#include<filename>  
eg： `gcc hello.c -include /root/pianopan.h`  
- -Idir 在你使用#include "file"的时候，gcc/g++会先在当前目录查找你所指定的头文件，如果没有找到，他会到缺省的头文件目录找，如果使用-I指定了目录，他会先在你所指定的目录查找，然后再按常规的顺序去找。对于#include <file>, gcc/g++会到-I指定的目录查找，查找不到，然后将到系统的缺省的头文件目录查找。  
- -I- 就是取消前一个参数的功能,所以一般在-Idir之后使用  
- -idirafter dir 在-I的目录里面查找失败，将到这个目录里面查找。  
- -iprefix prefix，-iwithprefix dir 一般一起使用，当-I的目录查找失败，会到prefix+dir下查找  
- -nostdinc 使编译器不在系统缺省的头文件目录里面找头文件，一般和-I联合使用，明确限定头文件的位置  
- -nostdinc++ 规定不在g++指定的标准路经中搜索，但仍在其他路径中搜索，此选项在创建libg++库使用  
- -C 在预处理的时候,不删除注释信息，一般和-E一起使用，有时候分析程序，用这个很方便的  
- -M 生成文件关联的信息。包含目标文件所依赖的所有源代码  
```shell  
test.o: test.c /usr/include/stdc-predef.h /usr/include/stdio.h \  
 /usr/include/x86_64-linux-gnu/bits/libc-header-start.h \  
 /usr/include/features.h /usr/include/x86_64-linux-gnu/sys/cdefs.h \  
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \  
 /usr/include/x86_64-linux-gnu/bits/long-double.h \  
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \  
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \  
 /usr/lib/gcc/x86_64-linux-gnu/8/include/stddef.h \  
 /usr/lib/gcc/x86_64-linux-gnu/8/include/stdarg.h \  
 /usr/include/x86_64-linux-gnu/bits/types.h \  
 /usr/include/x86_64-linux-gnu/bits/typesizes.h \  
 /usr/include/x86_64-linux-gnu/bits/types/__fpos_t.h \  
 /usr/include/x86_64-linux-gnu/bits/types/__mbstate_t.h \  
 /usr/include/x86_64-linux-gnu/bits/types/__fpos64_t.h \  
 /usr/include/x86_64-linux-gnu/bits/types/__FILE.h \  
 /usr/include/x86_64-linux-gnu/bits/types/FILE.h \  
 /usr/include/x86_64-linux-gnu/bits/types/struct_FILE.h \  
 /usr/include/x86_64-linux-gnu/bits/stdio_lim.h \  
 /usr/include/x86_64-linux-gnu/bits/sys_errlist.h  
```  
- -MM 和上面的那个一样，但是它将忽略由#include<file>造成的依赖关系。  
- -MD 和-M相同，但是输出将导入到.d的文件里面  
- -MMD和-MM相同，但是输出将导入到.d的文件里面  
- -Wa,option 此选项传递option给汇编程序；如果option中间有逗号，就将option分成多个选项，然后传递给汇编程序  
- -Wl.option 此选项传递option给链接程序；如果option中间有逗号，就将option分成多个选项，然后传递给链接程序.  
- -llibrary 指定编译的时候使用的库 例如： gcc -lcurses hello.c  
- -Ldir 指定编译的时候，搜索库的路径。如果不指定，编译器将只在标准库的目录找。  
- -O0，-O1，-O2，-O3 编译器的优化选项的4个级别，-O0表示没有优化，-O1为缺省值，-O3优化级别最高  
- -g 指示编译器，在编译的时候，产生调试信息。  
- -gstabs 此选项以stabs格式生成调试信息，但是不包括gdb调试信息  
- -gstabs+此选项以stabs格式生成调试信息，并且包含仅供gdb使用的额外调试信息。  
- -ggdb 此选项将尽可能的生成gdb可以使用的调试信息。  
- -static 此选项将禁止使用动态库。  
- -share 此选项将尽量使用动态库。  
- -traditional 试图让编译器支持传统的C语言特性  
- -w 不生成任何警告信息。默认选项  
- -Wall 开启大多数警告  
- 使用-fPIC产生位置无关的代码  
当产生共享库的时候，应该创建位置无关的代码，这会让共享库使用任意的地址而不是固定的地址，要实现这个功能，需要使用-fPIC参数。  
下面的例子产生libCfile.so动态库。  
```shell  
$ gcc -c -Wall -Werror -fPIC Cfile.c  
$ gcc -shared -o libCfile.so Cfile.o  
```  
- -D 可以用作定义编译时的宏。  
```c  
#include<stdio.h>  
int main(void)  
{  
#ifdef MY_MACRO  
printf("\n Macro defined \n");  
#endif  
char c = -10;  
// Print the string  
 printf("\n The Geek Stuff [%d]\n", c);  
 return 0;  
}  
```  
-D可以用作从命令行定义宏MY_MACRO。  
```shell  
$ gcc -Wall -DMY_MACRO main.c -o main  
$ ./main  
 Macro defined   
 The Geek Stuff [-10]  
```  
- 使用@参数从文件中读取参数  
```shell  
$ cat opt_file   
-Wall -omain  
# opt_file包含编译参数  
$ gcc main.c @opt_file  
main.c: In function ‘main’:  
main.c:6:11: warning: ‘i’ is used uninitialized in this function [-Wuninitialized]  
```  
- 指定支持的c++/c的标准 `gcc -std=c++11 hello-world.cpp`  
标准如 c++11, c++14, c90, c89等。  
- 使用-static生成静态链接的文件  
静态编译文件(把动态库的函数和其它依赖都编译进最终文件)  
`gcc main.c -static -o main -lpthread`  
相反的使用-shared使用动态库链接  

