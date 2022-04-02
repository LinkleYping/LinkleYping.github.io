---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "PE文件格式"  
date: 2020-05-15T15:22:45+08:00  
categories : [                                
"notes",  
]  
draft: false  
---
## 参考  
逆向工程核心原理  
## 地址概念  
- 虚拟内存地址（`Virtual Address, VA`）PE文件中的指令被装入内存后的地址。  
- 相对虚拟内存地址（`Reverse Virtual Address, RVA`)相对虚拟地址是内存地址相对于映射基址的偏移量。  
- 文件偏移地址（`File Offset Address, FOA`）数据在PE文件中的地址叫文件偏移地址，这是文件在磁盘上存放时相对于文件开头的偏移。  
- 装载基址（`Image base`）PE装入内存时的基地址。默认情况下，EXE文件在内存中的基地址时0x00400000, DLL文件是0x10000000。这些位置可以通过修改编译选项更改。  
- 虚拟内存地址、映射基址、相对虚拟内存地址的关系：`VA = Image Base + RVA`  
- 文件偏移(`RAW`)是相对于文件开始处0字节的偏移，相对虚拟地址则是相对于装载基址0x00400000处的偏移。（1）PE文件中的数据按照磁盘数据标准存放，以0x200字节为基本单位进行组织，PE数据节的大小永远是0x200的整数倍。（2）当代码装入内存后，将按照内存数据标准存放，并以0x1000字节为基本单位进行组织，内存中的节总是0x1000的整数倍。  
## PE基本结构  
| DOS头:  IMAGE_DOS_HEADER       |  
| :-------------: |  
| DOS存根：大小不固定，即使没有也可以正常运行      |  
| NT头:  IMAGE_NT_HEADERS（签名、文件头、可选头）     |  
| 节区头: IMAGE_SECTION_HEADER(一个节区一个) |  
|  PE体(各个节区) |  
## DOS头  
```c  
  typedef struct _IMAGE_DOS_HEADER {  
    WORD e_magic;  
    WORD e_cblp;  
    WORD e_cp;  
    WORD e_crlc;  
    WORD e_cparhdr;  
    WORD e_minalloc;  
    WORD e_maxalloc;  
    WORD e_ss;  
    WORD e_sp;  
    WORD e_csum;  
    WORD e_ip;  
    WORD e_cs;  
    WORD e_lfarlc;  
    WORD e_ovno;  
    WORD e_res[4];  
    WORD e_oemid;  
    WORD e_oeminfo;  
    WORD e_res2[10];  
    LONG e_lfanew;  
  } IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;  
```  
`e_magic`: DOS签名，4D5A(MZ)  
`e_lfanew`: 指示NT头偏移  
![DOS_HEADER.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-79fae966ecf09982.png)  
  
## DOS存根  
是个可选项，且大小不固定，即使没有DOS stub，文件也能正常运行，DOS stub由代码和数据混合而成，用于在DOS系统中运行，输出"This program cannot be run in DOS mode"  
## NT头  
```c  
  typedef struct _IMAGE_NT_HEADERS {  
    DWORD Signature; // 签名50450000h  
    IMAGE_FILE_HEADER FileHeader; // 文件头  
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;  // 可选头  
  } IMAGE_NT_HEADERS32,*PIMAGE_NT_HEADERS32;  
```  
### NT头: 文件头  
```c  
  typedef struct _IMAGE_FILE_HEADER {  
    WORD Machine;  
    WORD NumberOfSections;  
    DWORD TimeDateStamp;  
    DWORD PointerToSymbolTable;  
    DWORD NumberOfSymbols;  
    WORD SizeOfOptionalHeader;  
    WORD Characteristics;  
  } IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;  
```  
- Machine  
每个CPU具有唯一的Machine码  
```c  
#define IMAGE_FILE_MACHINE_UNKNOWN 0  
#define IMAGE_FILE_MACHINE_I386 0x014c  // Intel 386  
#define IMAGE_FILE_MACHINE_R3000 0x0162 // MIPS little-endian, 0x160 big-endian  
#define IMAGE_FILE_MACHINE_R4000 0x0166 // MIPS little-endian  
#define IMAGE_FILE_MACHINE_R10000 0x0168 // MIPS little-endian  
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169 // MIPS little-endian WCE v2  
#define IMAGE_FILE_MACHINE_ALPHA 0x0184 // Alpha_AXP  
#define IMAGE_FILE_MACHINE_SH3 0x01a2  // SH3 little-endian  
#define IMAGE_FILE_MACHINE_SH3DSP 0x01a3  
#define IMAGE_FILE_MACHINE_SH3E 0x01a4  // SH3E little-endian  
#define IMAGE_FILE_MACHINE_SH4 0x01a6  // SH4 little-endian  
#define IMAGE_FILE_MACHINE_SH5 0x01a8  
#define IMAGE_FILE_MACHINE_ARM 0x01c0  // ARM little-endian  
#define IMAGE_FILE_MACHINE_ARMV7 0x01c4  
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4  
#define IMAGE_FILE_MACHINE_THUMB 0x01c2  
#define IMAGE_FILE_MACHINE_AM33 0x01d3  
#define IMAGE_FILE_MACHINE_POWERPC 0x01F0 // IBM PowerPC Little-Endian  
#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1  
#define IMAGE_FILE_MACHINE_IA64 0x0200  // Intel 64  
#define IMAGE_FILE_MACHINE_MIPS16 0x0266  // MIPS  
#define IMAGE_FILE_MACHINE_ALPHA64 0x0284  // ALPHA64  
#define IMAGE_FILE_MACHINE_MIPSFPU 0x0366  // MIPS  
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x0466  // MIPS  
#define IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64  
#define IMAGE_FILE_MACHINE_TRICORE 0x0520  
#define IMAGE_FILE_MACHINE_CEF 0x0CEF  
#define IMAGE_FILE_MACHINE_EBC 0x0EBC  
#define IMAGE_FILE_MACHINE_AMD64 0x8664  
#define IMAGE_FILE_MACHINE_M32R 0x9041  
#define IMAGE_FILE_MACHINE_CEE 0xc0ee  
```  
- Characteristics  
用于标识文件的属性，文件是否是可运行的形态，是否为DLL文件等信息，以bit OR形式组合起来，比较重要的是0002h和2000h  
```c  
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001  //重定位  
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002  // 可执行文件  
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004  // 行号信息  
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008  // 符号信息  
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010  
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020  
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080  
#define IMAGE_FILE_32BIT_MACHINE 0x0100  // 32位  
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200  // 调试信息  
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400  
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800  
#define IMAGE_FILE_SYSTEM 0x1000  
#define IMAGE_FILE_DLL 0x2000  // DLL文件  
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000  
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000  
```  
![FILE_HEADER.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-6d6cd200f91f2a33.png)  
  
### NT头: 可选头  
```c  
  typedef struct _IMAGE_DATA_DIRECTORY {  
    DWORD VirtualAddress;  
    DWORD Size;  
  } IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;  
  
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16  
  
  typedef struct _IMAGE_OPTIONAL_HEADER {  
  
    WORD Magic;  
    BYTE MajorLinkerVersion;  
    BYTE MinorLinkerVersion;  
    DWORD SizeOfCode;  
    DWORD SizeOfInitializedData;  
    DWORD SizeOfUninitializedData;  
    DWORD AddressOfEntryPoint;  
    DWORD BaseOfCode;  
    DWORD BaseOfData;  
    DWORD ImageBase;  
    DWORD SectionAlignment;  
    DWORD FileAlignment;  
    WORD MajorOperatingSystemVersion;  
    WORD MinorOperatingSystemVersion;  
    WORD MajorImageVersion;  
    WORD MinorImageVersion;  
    WORD MajorSubsystemVersion;  
    WORD MinorSubsystemVersion;  
    DWORD Win32VersionValue;  
    DWORD SizeOfImage;  
    DWORD SizeOfHeaders;  
    DWORD CheckSum;  
    WORD Subsystem;  
    WORD DllCharacteristics;  
    DWORD SizeOfStackReserve;  
    DWORD SizeOfStackCommit;  
    DWORD SizeOfHeapReserve;  
    DWORD SizeOfHeapCommit;  
    DWORD LoaderFlags;  
    DWORD NumberOfRvaAndSizes;  
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];  
  } IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;  
```  
- Magic  
为IMAGE_OPTIONAL_HEADER32结构体时，Magic码为10B，为IMAGE_OPTIONAL_HEADER64结构体时，Magic码为20B  
- AddressOfEntryPoint  
持有EP的RVA值，该值指出程序最先执行的代码起始地址，相当重要  
- ImageBase  
程序优先装入的地址，EXE、DLL文件被装载到用户内存的0~0x7FFFFFFF， SYS文件载入内核内存的0x80000000~FFFFFFFF中。EIP寄存器的值开始为`ImageBase+AddressOfEntryPoint`  
- SectionAlignment, FileAlignment  
FileAlignment指定了节区在磁盘文件中的最小单位，SectionAlignment指定了节区在内存中的最小单位，磁盘文件或内存的节区大小必定为FileAlignment或SectionAlignment的整数倍  
- SizeOfImage  
指定PE Image在虚拟内存中所占空间的的大小  
- SizeOfHeaders  
用来指出整个PE头的大小，该值必须为FileAlignment的整数倍。第一节区所在的位置与SectionOfHeaders距文件开始偏移的量相同  
- SubSystem  
用来区分系统驱动文件与普通的可执行文件，Subsystem成员可以拥有的值如下:  
0x1: Driver文件，系统驱动  
0x2: GUI文件，窗口应用程序  
0x3: CUI文件，控制台应用程序  
- NumberOfRvaAndSizes  
用来指定DataDirectory数组的个数，虽然结构体定义中明确的指出了数组的个数为IMAGE_NUMBEROF_DIRECTORY_ENTRIES(16)，但是PE装载器通过查看NumberOfRvaAndSize值来识别数组大小，换言之，数组的大小也不一定是16  
- DataDirectory  
是由IMAGE_DATA_DIRECTORY结构体组成的数组，数组的每一项都有被定义的值。  
```c  
DataDirectory[0] = EXPORT Directory  
DataDirectory[1] = IMPORT Directory  
DataDirectory[2] = RESOURCE Directory  
DataDirectory[3] = EXCEPTION Directory  
DataDirectory[4] = SECURITY Directory  
DataDirectory[5] = BASERELOC Directory  
DataDirectory[6] = DEBUG Directory  
DataDirectory[7] = COPYROGHT Directory  
DataDirectory[8] = GLOBALPTR Directory  
DataDirectory[9] = TLS Directory  
DataDirectory[a] = LOAD_CONFIG Directory  
DataDirectory[b] = BOUND_IMPORT Directory  
DataDirectory[c] = IAT Directory  
DataDirectory[d] = DELAY_IMPORT Directory  
DataDirectory[e] = COM_DESCRIPTOR Directory  
DataDirectory[f] = Reserved Directory  
```  
![OPTIONAL_HEADER.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-1a4f9c84fdd9282d.png)  
  
## 节区头  
 PE文件中的code, data, resource按照不同属性分类存储在不同的节区  
```c  
#define IMAGE_SIZEOF_SHORT_NAME 8  
  
  typedef struct _IMAGE_SECTION_HEADER {  
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];  
    union {  
	DWORD PhysicalAddress;  
	DWORD VirtualSize;  
    } Misc;  
    DWORD VirtualAddress;  
    DWORD SizeOfRawData;  
    DWORD PointerToRawData;  
    DWORD PointerToRelocations;  
    DWORD PointerToLinenumbers;  
    WORD NumberOfRelocations;  
    WORD NumberOfLinenumbers;  
    DWORD Characteristics;  
  } IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;  
```  
主要成员以及含义如下  
成员 | 含义   
:----:|:------:  
VirtualSize | 内存中节区所占大小  
VirtualAddress | 内存中节区起始地址(RVA)  
SizeOfRawData | 磁盘文件中节区所占大小  
PointerToRawData | 磁盘文件中节区起始地址  
PE文件加载到内存时，每个节区必须准确完成内存地址与文件偏移的映射，即`RVA to RAW`  
```shell  
RAW - PointerToRawData = RVA - VirtualAddress  
RAW = RVA - VirtualAdress + PointerToRawData  
```  
Characteristic | 节区属性(bit OR)  
Characteristic的值由如下值组合而成(bit OR)  
```c  
#define IMAGE_SCN_CNT_CODE 0x00000020  
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040  
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080  
#define IMAGE_SCN_MEM_EXECUTE 0x20000000  
#define IMAGE_SCN_MEM_READ 0x40000000  
#define IMAGE_SCN_MEM_WRITE 0x80000000  
```  
Name成员并不像一般c字符串一样用NULL结尾，而且没有“必须使用"ASIC"值的限制，PE规范并没有规定节区的name，所以名称并不能保证其百分之百被用作某种信息。  
![SECTION_HEADER.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-8e852138d52d9044.png)  
  
## IAT  
IAT: Import Address Table 导入地址表。IAT是用来记录程序正在使用哪些库中的哪些函数。  
DLL特征:  
- 不要把库包含到程序中，单独组成DLL文件，需要时调用即可。  
- 内存映射技术使加载后的DLL代码、资源在多个进程中实现共享。  
- 更新库时只需要替换相关DLL文件即可  
  
加载DLL的方式有两种，一种是显式链接(Explicit Linking)，程序使用DLL时加载使用完毕后释放内存；另一种是隐式链接(Implicit Linking)，程序开始时即一同加载DLL，程序终止时再释放占用的内存。IAT提供的机制与隐式链接有关。  
- IMAGE_IMPORT_DESCRIPTOR  
```c  
  typedef struct _IMAGE_IMPORT_DESCRIPTOR {  
    __C89_NAMELESS union {  
	DWORD Characteristics;  
	DWORD OriginalFirstThunk;  
    } DUMMYUNIONNAME;  
    DWORD TimeDateStamp;  
  
    DWORD ForwarderChain;  
    DWORD Name;  
    DWORD FirstThunk;  
  } IMAGE_IMPORT_DESCRIPTOR;  
  
  typedef struct _IMAGE_IMPORT_BY_NAME {  
    WORD Hint;  // 库中函数的固有编号  
    BYTE Name[1];  
  } IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;  
```  
- OriginalFirstThunk: INT(Import Name Table) address(RVA)INT地址  
- Name: library name string address(RVA)库名称字符串地址  
- FirstThunk: IAT(Import Address Table) address(RVA)IAT地址  
- INT与IAT是长整型数组，以NULL结束(未明确指出大小)  
- INT中个元素的值为IMAGE_IMPORT_BY_NAME结构体指针  
- INT与IAT大小应该相同  
  
执行一个普通的程序时往往需要导入多个库，导入多少库就存在多少个IMAGE_IMPORT_DESCRTPTOR结构体，这些结构体组成了数组，且结构体数组最后以NULL结构体结尾，数组的起始地址在NT可选头中的`DataDirectory[1] = IMPORT Directory`中  
![IMPORT_DESCRIPTOR.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-33c5ae055b2ffc5f.png)  
从图中可以看到KERNEL32.dll的INT数组VA为70d68，看一下70d68的内容:  
![INT.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-c730425beedc424f.png)  
是一个地址数组，查看数组中的第一个地址:  
![INT_NAME.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-060e42e5f34ee53a.png)  
是`IMAGE_IMPORT_BY_NAME`结构体  
KERNEL32.dll的IAT地址为1130，查看1130处的内容:  
![IAT.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-2c43d36afdf7daf3.png)  
IDA中是静态还没载入的时候，看一下OD中的:  
![IAT_OD.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-85bed04d64e9f7b4.png)  
PE装载器把导入函数输入至IAT的过程：  
```shell  
1. 读取IID的Name成员，获取库名称字符串  
2. 装载相应库:  
  -> LoadLibrary("kernel32.dll")  
3. 读物IID的OriginalFirstThunk成员，获取INT地址  
4. 逐一读取INT数组中的值，获取相应IMAGE_IMPORT_BY_NAME地址(RVA)  
5. 使用IMAGE_IMPORT_BY_NAME的Hint(Ordinal)或Name项，获取相应函数的起始地址。  
  -> GetProcAddress("GetCurrentThreadId")  
6. 读取IID的FirstThunk(IAT)成员，获取IAT地址  
7. 将上面获得的函数地址输入相应的IAT数组值  
8. 重复4-7直到INT结束(NULL)  
```  
## EAT  
EAT是一种核心机制，它使不同的应用程序可以调用库文件中提供的函数，也就是说只有通过EAT才能准确求得从相应库中导入函数的起始地址。IMAGE_EXPORT_DIRECTORY结构体中保存着导出信息，且**PE文件中有且仅有一个用来说明库EAT的IMAGE_EXPORT_DIRECTORY结构体**，结构体的地址记录在可选头中的`DataDirectory[0] = EXPORT Directory`，**IAT中的IMAGE_IMPORT_DIRECTORY结构体以数组的形式存在，且拥有多个成员，这样是因为PE文件可以导入多个库**  
```c  
  typedef struct _IMAGE_EXPORT_DIRECTORY {  
    DWORD Characteristics;  
    DWORD TimeDateStamp;  
    WORD MajorVersion;  
    WORD MinorVersion;  
    DWORD Name;  // address of library file name  
    DWORD Base; // ordinal base  
    DWORD NumberOfFunctions;  // 实际Export函数的个数  
    DWORD NumberOfNames; // Export函数中具名函数的个数  
    DWORD AddressOfFunctions; // Export函数地址数组(数组元素个数=NumberOfFunctions)  
    DWORD AddressOfNames; // 函数名称地址数组(数组元素个数=NumberOfNames)  
    DWORD AddressOfNameOrdinals; // Ordinal地址数组(数组元素个数=NumberOfNames)  
  } IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;  
```  
从库中获取函数地址的API为GetProcAddress函数，该API引用EAT来获取指定API的地址，GetProcAddress()API拥有函数名称，下面是获取函数地址的过程:  
```shell  
1. 利用AddressOfNames成员转到`函数名称数组`  
2. `函数名称数组`中存储着字符串地址，通过比较字符串，查找指定函数名称  
3. 利用AddressOfNameOrdinals成员转到ordinal数组  
4. 在ordinal数组中通过name_index查找相应ordinal值  
5. 利用AddressOfFunctions成员转到`函数地址数组(EAT)`  
6. 在EAT中将刚刚得到的ordinal值用作地址索引，获取指定函数的起始地址。  
```  
kernel32.dll的EAT:  
![EAT.png](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-6a3769997757f844.png)  
看一下函数名称数组:  
![函数名称数组](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-e177da8d560e6161.png)  
`AddAtomW`函数的Index是5，转到ordinal数组:  
![ordinal数组](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-39cc06272f6c01a1.png)  
可以看到index等于5的ordinal等于8，查看`函数地址数组`:  
![函数地址数组](/images/c7a66ef3a0c91ae1848c9fc725f93a4a/11884068-2c4fb896b834ffb0.png)  
可以看到EAT中index等于8的就是`AddAtomW`函数地址。  
