# 腾讯游戏安全竞赛2020

## ring3  
### 从dmp文件中恢复出可执行文件  
使用windbg `open crash dump`:  
```shell  
0:004> lmvm winmine  
Browse full module list  
start    end        module name  
01000000 01020000   winmine    (deferred)               
Image path: D:\Temp\bin\winmine.exe  
Image name: winmine.exe  
Browse all global symbols  functions  data  
Timestamp:        Sat Aug 18 04:54:13 2001 (3B7D8475)  
CheckSum:         000273C4  
ImageSize:        00020000  
File version:     5.1.2600.0  
Product version:  5.1.2600.0  
File flags:       0 (Mask 3F)  
File OS:          40004 NT Win32  
File type:        1.0 App  
File date:        00000000.00000000  
Translations:     0804.04b0  
Information from resource tables:  
    CompanyName:      Microsoft Corporation  
    ProductName:      Microsoft(R) Windows(R) Operating System  
    InternalName:     winmine  
    OriginalFilename: WINMINE.EXE  
    ProductVersion:   5.1.2600.0  
    FileVersion:      5.1.2600.0 (xpclient.010817-1148)  
    FileDescription:  Entertainment Pack Minesweeper Game  
    LegalCopyright:   (C) Microsoft Corporation. All rights reserved.  
  
0:004> .writemem D:\winmine1.exe 01000000 L?20000  
```  
## 查找dump出的文件与原始文件指令的不同之处  
```python  
#coding:utf-8  
import capstone as cs  
with open('winmine.exe') as f:  
    raw1 = f.read()  
  
with open('winmine1.exe') as f:  
    raw2 = f.read()  
  
  
code1 = raw1[0x80c:0x80c+0x2a15]  
code2 = raw2[0x140c:0x140c+0x2a15]  
  
md32 = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)  
  
  
def ext32():  
    discode1 = list(md32.disasm(code1, 0x0100140C))  
    discode2 = list(md32.disasm(code2, 0x0100140C))  
    length1 = len(discode1)  
    length2 = len(discode2)  
    j = 0  
    for i in range(length1):  
        op1 = discode1[i].mnemonic  
        ch1 = discode1[i].op_str  
        op2 = discode2[j].mnemonic  
        ch2 = discode2[j].op_str  
        if op1 == op2 and ch1 == ch2:  
            j = j + 1  
        else:  
            address = discode1[i].address  
            offset = address - 0x0100140C + 0x80c  
            print "\noffset: ", hex(offset).strip('L')  
            print "address: ", hex(address).strip('L')  
            print "==========before========="  
            print discode1[i - 1].mnemonic, discode1[i - 1].op_str  
            print op1, ch1  
            print discode1[i + 1].mnemonic, discode1[i + 1].op_str  
            print "==========after========="  
            print discode2[j - 1].mnemonic, discode2[j - 1].op_str  
            print op2, ch2,  
            if op2 == "nop":  
                while op2 == "nop":  
                    j = j + 1  
                    op2 = discode2[j].mnemonic  
                    if op2 == "nop":  
                        print op2,  
                print ""  
                print discode2[j].mnemonic, discode2[j].op_str  
            else:  
                j = j + 1  
                print ""  
                print discode2[j].mnemonic, discode2[j].op_str  
  
if __name__ == "__main__":  
    ext32()  
```  
执行结果如下  
```shell  
$ python cmp.py  
  
offset:  0x23f5  
address:  0x1002ff5  
==========before=========  
jge 0x1003007  
inc dword ptr [0x100579c]  
call 0x10028b5  
==========after=========  
jge 0x1003007  
nop  nop nop nop nop nop   
call 0x10028b5  
  
offset:  0x2991  
address:  0x1003591  
==========before=========  
call 0x1002eab  
push 0  
jmp 0x10035ab  
==========after=========  
call 0x1002eab  
jmp 0x10035b0   
jmp 0x10035ab  
```  
可以看到有两处修改，分别位于0x23f5和0x2991处  
## 指令修改的作用  
分别对这两处进行分析可知0x23f5处执行修改的目的是**停止计时**，0x2991处指令修改的目的是**即使踩雷也不会结束游戏**。  
## ring0  
膜大佬[跪] https://www.jianshu.com/p/daf0a914df3c  

