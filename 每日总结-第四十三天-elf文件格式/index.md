# ELF文件组成

## ELF文件组成  
ELF头部(ELF_Header): 每个ELF文件都必须存在一个ELF_Header,这里存放了很多重要的信息用来描述整个文件的组织,如: 版本信息,入口信息,偏移信息等。程序执行也必须依靠其提供的信息。  
  
程序头部表(Program_Header_Table): 可选的一个表，用于告诉系统如何在内存中创建映像,在图中也可以看出来,有程序头部表才有段,有段就必须有程序头部表。其中存放各个段的基本信息(包括地址指针)。  
  
节区头部表(Section_Header_Table): 类似与Program_Header_Table,但与其相对应的是节区(Section)。  
  
节区(Section): 将文件分成一个个节区，每个节区都有其对应的功能，如符号表，哈希表等。  
  
段(Segment): 将文件分成一段一段映射到内存中。段中通常包括一个或多个节区。  
![image](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-662fa3223869aa0b.jpg)  
## ELF头  
```shell  
$ readelf -h main  
ELF Header:  
Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  
Class:                             ELF64  
Data:                              2's complement, little endian  
Version:                           1 (current)  
OS/ABI:                            UNIX - System V  
ABI Version:                       0  
Type:                              DYN (Shared object file)  
Machine:                           Advanced Micro Devices X86-64  
Version:                           0x1  
Entry point address:               0x660  
Start of program headers:          64 (bytes into file)  
Start of section headers:          6616 (bytes into file)  
Flags:                             0x0  
Size of this header:               64 (bytes)  
Size of program headers:           56 (bytes)  
Number of program headers:         9  
Size of section headers:           64 (bytes)  
Number of section headers:         29  
Section header string table index: 28  
```  
```c  
/* ELF Header */  
#define EI_NIDENT 16  
typedef struct elfhdr {  
unsigned char    e_ident[EI_NIDENT]; /* ELF Identification */  
Elf32_Half    e_type;        /* object file type */  
Elf32_Half    e_machine;    /* machine */  
Elf32_Word    e_version;    /* object file version */  
Elf32_Addr    e_entry;      /* virtual entry point */  
Elf32_Off     e_phoff;      /* program header table offset */  
Elf32_Off     e_shoff;      /* section header table offset */  
Elf32_Word    e_flags;      /* processor-specific flags */  
Elf32_Half    e_ehsize;     /* ELF header size */  
Elf32_Half    e_phentsize;    /* program header entry size */  
Elf32_Half    e_phnum;      /* number of program header entries */  
Elf32_Half    e_shentsize;    /* section header entry size */  
Elf32_Half    e_shnum;      /* number of section header entries */  
Elf32_Half    e_shstrndx;    /* section header table's "section   
                   header string table" entry offset */  
} Elf32_Ehdr;  
  
typedef struct {  
unsigned char    e_ident[EI_NIDENT];    /* Id bytes */  
Elf64_Quarter    e_type;            /* file type */  
Elf64_Quarter    e_machine;        /* machine type */  
Elf64_Half       e_version;        /* version number */  
Elf64_Addr       e_entry;         /* entry point */  
Elf64_Off        e_phoff;         /* Program hdr offset */  
Elf64_Off        e_shoff;         /* Section hdr offset */  
Elf64_Half       e_flags;         /* Processor flags */  
Elf64_Quarter    e_ehsize;        /* sizeof ehdr */  
Elf64_Quarter    e_phentsize;     /* Program header entry size */  
Elf64_Quarter    e_phnum;         /* Number of program headers */  
Elf64_Quarter    e_shentsize;     /* Section header entry size */  
Elf64_Quarter    e_shnum;         /* Number of section headers */  
Elf64_Quarter    e_shstrndx;      /* String table index */  
} Elf64_Ehdr;  
```  
e_ident字段含义  
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-dec3fc1f6df50ce3.png)  
ELF Header 中各个字段的说明如表：  
![image](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-6ecbdf2d01aad98c.png)  
## 程序头  
```shell  
ep@EP:/mnt/d/code/linux$ readelf -l main  
  
Elf file type is DYN (Shared object file)  
Entry point 0x660  
There are 9 program headers, starting at offset 64  
  
Program Headers:  
Type           Offset             VirtAddr           PhysAddr  
             FileSiz            MemSiz              Flags  Align  
PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040  
             0x00000000000001f8 0x00000000000001f8  R      0x8  
INTERP         0x0000000000000238 0x0000000000000238 0x0000000000000238  
             0x000000000000001c 0x000000000000001c  R      0x1  
  [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]  
LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000  
             0x00000000000009e8 0x00000000000009e8  R E    0x200000  
LOAD           0x0000000000000d98 0x0000000000200d98 0x0000000000200d98  
             0x0000000000000278 0x0000000000000280  RW     0x200000  
DYNAMIC        0x0000000000000da8 0x0000000000200da8 0x0000000000200da8  
             0x00000000000001f0 0x00000000000001f0  RW     0x8  
NOTE           0x0000000000000254 0x0000000000000254 0x0000000000000254  
             0x0000000000000044 0x0000000000000044  R      0x4  
GNU_EH_FRAME   0x00000000000008a4 0x00000000000008a4 0x00000000000008a4  
             0x000000000000003c 0x000000000000003c  R      0x4  
GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000  
             0x0000000000000000 0x0000000000000000  RW     0x10  
GNU_RELRO      0x0000000000000d98 0x0000000000200d98 0x0000000000200d98  
             0x0000000000000268 0x0000000000000268  R      0x1  
  
 Section to Segment mapping:  
Segment Sections...  
 00  
 01     .interp  
 02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame  
 03     .init_array .fini_array .dynamic .got .data .bss  
 04     .dynamic  
 05     .note.ABI-tag .note.gnu.build-id  
 06     .eh_frame_hdr  
 07  
 08     .init_array .fini_array .dynamic .got  
```  
可执行文件或者共享目标文件的程序头部是一个结构数组，每个结构描述了一个段 或者系统准备程序执行所必需的其它信息。目标文件的“段”包含一个或者多个“节区”， 也就是“段内容(Segment Contents)”。程序头部仅对于可执行文件和共享目标文件 有意义。 可执行目标文件在 ELF 头部的 e_phentsize和e_phnum 成员中给出其自身程序头部 的大小。程序头部的数据结构:  
```c  
/* Program Header */  
typedef struct {  
Elf32_Word    p_type;        /* segment type */  
Elf32_Off    p_offset;    /* segment offset */  
Elf32_Addr    p_vaddr;    /* virtual address of segment */  
Elf32_Addr    p_paddr;    /* physical address - ignored? */  
Elf32_Word    p_filesz;    /* number of bytes in file for seg. */  
Elf32_Word    p_memsz;    /* number of bytes in mem. for seg. */  
Elf32_Word    p_flags;    /* flags */  
Elf32_Word    p_align;    /* memory alignment */  
} Elf32_Phdr;  
  
typedef struct {  
Elf64_Half    p_type;        /* entry type */  
Elf64_Half    p_flags;    /* flags */  
Elf64_Off    p_offset;    /* offset */  
Elf64_Addr    p_vaddr;    /* virtual address */  
Elf64_Addr    p_paddr;    /* physical address */  
Elf64_Xword    p_filesz;    /* file size */  
Elf64_Xword    p_memsz;    /* memory size */  
Elf64_Xword    p_align;    /* memory & file alignment */  
} Elf64_Phdr;  
```  
其中各个字段说明：  
- p_offset 此成员给出从文件头到该段第一个字节的偏移。  
- p_vaddr 此成员给出段的第一个字节将被放到内存中的虚拟地址。  
- p_paddr 此成员仅用于与物理地址相关的系统中。因为 System V 忽略所有应用程序的物理地址信息，此字段对与可执行文件和共享目标文件而言具体内容是指定的。  
- p_filesz 此成员给出段在文件映像中所占的字节数。可以为 0。  
- p_memsz 此成员给出段在内存映像中占用的字节数。可以为 0。  
- p_flags 此成员给出与段相关的标志。  
- p_align 可加载的进程段的 p_vaddr 和 p_offset 取值必须合适，相对于对页面大小的取模而言。此成员给出段在文件中和内存中如何 对齐。数值 0 和 1 表示不需要对齐。否则 p_align 应该是个正整数，并且是 2 的幂次数，p_vaddr 和 p_offset 对 p_align 取模后应该相等。  
- p_type 此数组元素描述的段的类型，或者如何解释此数组元素的信息。具体如下图。  
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-b3945fe549c5c31e.png)  
### PT_LOAD  
一个可执行文件至少有一个PT_LOAD 类型的段。这类程序头描述的是可装载的段，也就是说，这种类型的段将被装载或者映射到内存中。例如，一个需要动态链接的ELF 可执行文件通常包含以下两个可装载的段（类型为PT_LOAD）：  
1. 存放程序代码的text 段；  
2. 存放全局变量和动态链接信息的data 段。  
### PT_DYNAMIC——动态段的Phdr  
动态段是动态链接可执行文件所特有的，包含了动态链接器所必需的一些信息。在动态段中包含了一些标记值和指针，包括但不限于以下内容：  
- 运行时需要链接的共享库列表；  
- 全局偏移表（GOT）的地址  
- 重定位条目的相关信息。  
### PT_INTERP   
PT_INTERP 段只将位置和大小信息存放在一个以null 为终止符的字符串中，是对程序解释器位置的描述。例如，/lib/linux-ld.so.2 一般是指动态链接器的位置，也即程序解释器的位置。  
### PT_PHDR  
PT_PHDR 段保存了程序头表本身的位置和大小。Phdr 表保存了所有的Phdr 对文件（以及内存镜像）中段的描述信息。  
## ELF节头  
```c  
ep@EP:/mnt/d/code/linux$ readelf -S main  
There are 29 section headers, starting at offset 0x19d8:  
  
Section Headers:  
[Nr] Name              Type             Address           Offset  
   Size              EntSize          Flags  Link  Info  Align  
[ 0]                   NULL             0000000000000000  00000000  
   0000000000000000  0000000000000000           0     0     0  
[ 1] .interp           PROGBITS         0000000000000238  00000238  
   000000000000001c  0000000000000000   A       0     0     1  
[ 2] .note.ABI-tag     NOTE             0000000000000254  00000254  
   0000000000000020  0000000000000000   A       0     0     4  
[ 3] .note.gnu.build-i NOTE             0000000000000274  00000274  
   0000000000000024  0000000000000000   A       0     0     4  
......  
Key to Flags:  
W (write), A (alloc), X (execute), M (merge), S (strings), I (info),  
L (link order), O (extra OS processing required), G (group), T (TLS),  
C (compressed), x (unknown), o (OS specific), E (exclude),  
l (large), p (processor specific)  
```  
节头的数据结构：  
```c  
/* Section Header */  
typedef struct {  
Elf32_Word    sh_name;    /* name - index into section header  
                   string table section */  
Elf32_Word    sh_type;    /* type */  
Elf32_Word    sh_flags;    /* flags */  
Elf32_Addr    sh_addr;    /* address */  
Elf32_Off     sh_offset;    /* file offset */  
Elf32_Word    sh_size;    /* section size */  
Elf32_Word    sh_link;    /* section header table index link */  
Elf32_Word    sh_info;    /* extra information */  
Elf32_Word    sh_addralign;    /* address alignment */  
Elf32_Word    sh_entsize;    /* section entry size */  
} Elf32_Shdr;  
  
typedef struct {  
Elf64_Half    sh_name;    /* section name */  
Elf64_Half    sh_type;    /* section type */  
Elf64_Xword   sh_flags;    /* section flags */  
Elf64_Addr    sh_addr;    /* virtual address */  
Elf64_Off     sh_offset;    /* file offset */  
Elf64_Xword   sh_size;    /* section size */  
Elf64_Half    sh_link;    /* link to another */  
Elf64_Half    sh_info;    /* misc info */  
Elf64_Xword   sh_addralign;    /* memory alignment */  
Elf64_Xword   sh_entsize;    /* table entry size */  
} Elf64_Shdr;  
```  
各个字段的解释如下:   
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-2ac7a0afb44b51f9.png)  
sh_type 字段 节区类型定义：  
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-3a53fe7d050d047f.png)  
常用节区:  
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-8e8dfde7128ba932.png)  
### 节与段  
节，不是段。段是程序执行的必要组成部分，在每个段中，会有代码或者数据被划分为不同的节。节头表是对这些节的位置和大小的描述，主要用于链接和调试。节头对于程序的执行来说不是必需的，没有节头表，程序仍可以正常执行，因为节头表没有对程序的内存布局进行描述，对程序内存布局的描述是程序头表的任务。节头是对程序头的补充。readelf –l 命令可以显示一个段对应有哪些节，可以很直观地看到节和段之间的关系。  
如果二进制文件中缺少节头，并不意味着节就不存在。只是没有办法通过  
节头来引用节，对于调试器或者反编译程序来说，只是可以参考的信息变少了而已。  
## 字符串表（String Table）  
字符串表节区包含以 NULL(ASCII 码 0)结尾的字符序列，通常称为字符串。ELF 目标文件通常使用字符串来表示符号和节区名称。对字符串的引用通常以字符串在字符串表中的下标给出。  
比如下面这样：  
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-ce74ae0ccb745cd8.jpg)  
那么偏移与他们对用的字符串如下表:  
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-f4e855e0a0f35dd7.jpg)  
这样在ELF中引用字符串只需要给出一个数组下标即可。字符串表在ELF也以段的形式保存，常见的段名为”.strtab”或”.shstrtab”。这两个字符串表分别为字符串表(String Table)和段表字符串表(Header String Table)，字符串表保存的是普通的字符串，而段表字符串表用来保存段表中用到的字符串，比如段名。  
  
在使用、分析字符串表时，要注意以下几点:  
1. 字符串表索引可以引用节区中任意字节。  
2. 字符串可以出现多次  
3. 可以存在对子字符串的引用  
4. 同一个字符串可以被引用多次。  
5. 字符串表中也可以存在未引用的字符串。  
## 符号表（Symbol Table）  
目标文件的符号表中包含用来定位、重定位程序中符号定义和引用的信息。符号表 索引是对此数组的索引。索引 0 表示表中的第一表项，同时也作为 定义符号的索引。  
```c  
/* Symbol Table Entry */  
typedef struct elf32_sym {  
Elf32_Word    st_name;    /* name - index into string table */  
Elf32_Addr    st_value;    /* symbol value */  
Elf32_Word    st_size;    /* symbol size */  
unsigned char    st_info;    /* type and binding */  
unsigned char    st_other;    /* 0 - no defined meaning */  
Elf32_Half    st_shndx;    /* section header index */  
} Elf32_Sym;  
  
typedef struct {  
Elf64_Half    st_name;    /* Symbol name index in str table */  
Elf_Byte    st_info;    /* type / binding attrs */  
Elf_Byte    st_other;    /* unused */  
Elf64_Quarter    st_shndx;    /* section index of symbol */  
Elf64_Xword    st_value;    /* value of symbol */  
Elf64_Xword    st_size;    /* size of symbol */  
} Elf64_Sym;  
```  
各个字段的含义如下:  
![](/images/f3f85f4d8aafeb0510343c3f46f7676a/11884068-d56d236da5e8104e.png)  
符号是对某些类型的数据或者代码（如全局变量或函数）的符号引用。例如，printf()函数会在动态符号表`.dynsym` 中存有一个指向该函数的符号条目。在大多数共享库和动态链接可执行文件中，存在两个符号表。如前面使用`readelf –S` 命令输出的内容中，可以看到有两个节：`.dynsym`和`.symtab`。  
`.dynsym `保存了引用来自外部文件符号的全局符号，如printf 这样的库函数，`.dynsym` 保存的符号是`.symtab` 所保存符号的子集，`.symtab` 中还保存了可执行文件的本地符号，如全局变量，或者代码中定义的本地函数等。因此，`.symtab` 保存了所有的符号，而`.dynsym` 只保存动态/全局符号。  
因此，就存在这样一个问题：既然`.symtab` 中保存了`.dynsym` 中所有的符号，那么为什么还需要两个符号表呢？使用`readelf –S` 命令查看可执行文件的输出，可以看到一部分节被标记为了A（ALLOC）、WA（WRITE/ALLOC）或者AX（ALLOC/EXEC）。`.dynsym` 是被标记了ALLOC 的，而`.symtab`则没有标记。  
ALLOC 表示有该标记的节会在运行时分配并装载进入内存，而`.symtab`不是在运行时必需的，因此不会被装载到内存中。`.dynsym` 保存的符号只能在运行时被解析，因此是运行时动态链接器所需要的唯一符号。`.dynsym` 符号表对于动态链接可执行文件的执行来说是必需的，而`.symtab` 符号表只是用来进行调试和链接的，有时候为了节省空间，会将`.symtab `符号表从生产二进制文件中删掉。  
```shell  
ep@EP:/mnt/d/code/linux$ readelf -s main  
  
Symbol table '.dynsym' contains 11 entries:  
 Num:    Value          Size Type    Bind   Vis      Ndx Name  
 0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND  
 1: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab  
 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)  
 3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (2)  
 4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.2.5 (2)  
 5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (2)  
 6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__  
 7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.2.5 (2)  
 8: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable  
 9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND sleep@GLIBC_2.2.5 (2)  
10: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (2)  
  
Symbol table '.symtab' contains 67 entries:  
 Num:    Value          Size Type    Bind   Vis      Ndx Name  
 0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND  
 1: 0000000000000238     0 SECTION LOCAL  DEFAULT    1  
 2: 0000000000000254     0 SECTION LOCAL  DEFAULT    2  
 3: 0000000000000274     0 SECTION LOCAL  DEFAULT    3  
 4: 0000000000000298     0 SECTION LOCAL  DEFAULT    4  
 5: 00000000000002b8     0 SECTION LOCAL  DEFAULT    5  
 6: 00000000000003c0     0 SECTION LOCAL  DEFAULT    6  
 7: 000000000000045c     0 SECTION LOCAL  DEFAULT    7  
 8: 0000000000000478     0 SECTION LOCAL  DEFAULT    8  
 9: 0000000000000498     0 SECTION LOCAL  DEFAULT    9  
10: 0000000000000558     0 SECTION LOCAL  DEFAULT   10  
11: 00000000000005d0     0 SECTION LOCAL  DEFAULT   11  
12: 00000000000005f0     0 SECTION LOCAL  DEFAULT   12  
13: 0000000000000650     0 SECTION LOCAL  DEFAULT   13  
14: 0000000000000660     0 SECTION LOCAL  DEFAULT   14  
15: 0000000000000864     0 SECTION LOCAL  DEFAULT   15  
16: 0000000000000870     0 SECTION LOCAL  DEFAULT   16  
17: 00000000000008a4     0 SECTION LOCAL  DEFAULT   17  
18: 00000000000008e0     0 SECTION LOCAL  DEFAULT   18  
19: 0000000000200d98     0 SECTION LOCAL  DEFAULT   19  
20: 0000000000200da0     0 SECTION LOCAL  DEFAULT   20  
21: 0000000000200da8     0 SECTION LOCAL  DEFAULT   21  
22: 0000000000200f98     0 SECTION LOCAL  DEFAULT   22  
23: 0000000000201000     0 SECTION LOCAL  DEFAULT   23  
24: 0000000000201010     0 SECTION LOCAL  DEFAULT   24  
25: 0000000000000000     0 SECTION LOCAL  DEFAULT   25  
26: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c  
27: 0000000000000690     0 FUNC    LOCAL  DEFAULT   14 deregister_tm_clones  
28: 00000000000006d0     0 FUNC    LOCAL  DEFAULT   14 register_tm_clones  
29: 0000000000000720     0 FUNC    LOCAL  DEFAULT   14 __do_global_dtors_aux  
30: 0000000000201010     1 OBJECT  LOCAL  DEFAULT   24 completed.7698  
31: 0000000000200da0     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtors_aux_fin  
32: 0000000000000760     0 FUNC    LOCAL  DEFAULT   14 frame_dummy  
33: 0000000000200d98     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_init_array_  
34: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS main.c  
35: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c  
36: 00000000000009e4     0 OBJECT  LOCAL  DEFAULT   18 __FRAME_END__  
37: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS  
38: 0000000000200da0     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_end  
39: 0000000000200da8     0 OBJECT  LOCAL  DEFAULT   21 _DYNAMIC  
40: 0000000000200d98     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_start  
41: 00000000000008a4     0 NOTYPE  LOCAL  DEFAULT   17 __GNU_EH_FRAME_HDR  
42: 0000000000200f98     0 OBJECT  LOCAL  DEFAULT   22 _GLOBAL_OFFSET_TABLE_  
43: 0000000000000860     2 FUNC    GLOBAL DEFAULT   14 __libc_csu_fini  
44: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab  
45: 0000000000201000     0 NOTYPE  WEAK   DEFAULT   23 data_start  
46: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5  
47: 0000000000201010     0 NOTYPE  GLOBAL DEFAULT   23 _edata  
48: 0000000000000864     0 FUNC    GLOBAL DEFAULT   15 _fini  
49: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@@GLIBC_2.2.5  
50: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND read@@GLIBC_2.2.5  
51: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@@GLIBC_  
52: 0000000000201000     0 NOTYPE  GLOBAL DEFAULT   23 __data_start  
53: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__  
54: 0000000000201008     0 OBJECT  GLOBAL HIDDEN    23 __dso_handle  
55: 0000000000000870     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used  
56: 00000000000007f0   101 FUNC    GLOBAL DEFAULT   14 __libc_csu_init  
57: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@@GLIBC_2.2.5  
58: 0000000000201018     0 NOTYPE  GLOBAL DEFAULT   24 _end  
59: 0000000000000660    43 FUNC    GLOBAL DEFAULT   14 _start  
60: 0000000000201010     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start  
61: 000000000000076a   126 FUNC    GLOBAL DEFAULT   14 main  
62: 0000000000201010     0 OBJECT  GLOBAL HIDDEN    23 __TMC_END__  
63: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable  
64: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND sleep@@GLIBC_2.2.5  
65: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@@GLIBC_2.2  
66: 00000000000005d0     0 FUNC    GLOBAL DEFAULT   11 _init  
```  
## 参考  
https://blog.csdn.net/xuehuafeiwu123/article/details/72963229    
https://felixzhang00.github.io/2016/12/24/2016-12-24-ELF%E6%96%87%E4%BB%B6%E8%A3%85%E8%BD%BD%E9%93%BE%E6%8E%A5%E8%BF%87%E7%A8%8B%E5%8F%8Ahook%E5%8E%9F%E7%90%86/  
