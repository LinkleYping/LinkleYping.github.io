# De1CTF-2020--re

   
## parser    
这道题挣扎的做出来了，但是我看了别人的wp之后发现我密码学真的很差==    
### flag格式检查    
程序首先把输入进行拆分，分为`De1CTF`, `{`, `strs`, `_`, `+`, ... ,`}`, `\n`这几个部分，所以flag的格式是`De1CTF{str+'_/+'+str+...}`，拆分以后对括号里面的内容进行加密运算，加密的方式有三种，分别是RC4, DES和AES, 其中每一个被`_ or +`分开的字符部分都要做RC4, 然后`_`是DES运算, `+`是AES运算，_的优先级高于+。    
### solve    
#### RC4    
RC4的解密部分很好写，密钥就是`De1CTF`    
```python    
def de_rc4(s,k):    
  ci = ARC4.new(k)    
  return ci.decrypt(s)    
```    
#### DES    
菜的部分来了，首先我看到它padding了一部分，padding的内容是padding的长度，然后异或了一个东西，然后8字节一加密，密钥是`De1CTF\x02\x02`，然后8字节加密完成之后，加密的结果又与下一个8字节以后后在加密，然后我按照这个过程写的script，就这样我都没看出来这是个CBC模式的加密==我真的是服了自己了，菜哭了。就这样我也配说我学过密码学==还是刷刷Crypto吧    
```python    
def padding(s,n):    
  len1 = len(s)    
  n1 = len1 % n    
  s += chr(n-n1)*(n-n1)    
  return s    
    
def de_des_cbc(s,k):    
  if len(s) % 8 != 0:    
    s = padding(s,8)    
  key = padding(k,8)    
  iv = key    
  ci = DES.new(key,AES.MODE_CBC,iv)    
  return ci.decrypt(s)    
#   out = ''    
#   for i in range(len(s)/8):    
#     ci = DES.new(key,DES.MODE_ECB)    
#     m1 = ci.decrypt(s[8*i:8*i+8])        
#     out += xor_str(m1,iv)    
#     iv = s[8*i:8*i+8]    
#   return out      
    
def en_des_cbc(s,k):    
  s = padding(s,8)    
  key = padding(k,8)    
  iv = key    
  ci = DES.new(key, DES.MODE_CBC,iv)    
  return ci.encrypt(s)    
#   out = ''    
#   for i in range(len(s)/8):    
#     ci = DES.new(key,DES.MODE_ECB)    
#     m1 = xor_str(s[8*i:8*i+8],iv)    
#     iv = ci.encrypt(m1)        
#     out += iv    
#   return out    
```    
#### AES    
一样的没看出来CBC==我不配我不配我不配    
```python    
def padding(s,n):    
  len1 = len(s)    
  n1 = len1 % n    
  s += chr(n-n1)*(n-n1)    
  return s    
    
def de_aes_cbc(s,k):    
  if len(s) % 16 != 0:    
    s = padding(s,16)    
  key = padding(k,16)    
  iv = key    
  ci = AES.new(key,AES.MODE_CBC,iv)    
  return ci.decrypt(s)    
    
def en_aes_cbc(s,k):    
  s = padding(s,16)    
  key = padding(k,16)    
  iv = key    
  ci = AES.new(key,AES.MODE_CBC,iv)    
  return ci.encrypt(s)    
```    
## FLw    
这道题我没有仔细做，前面是学弟解析了一下，然后学长就做出来了，虚拟机有点特别，是基于队列的，一个是一个循环队列，跟我平时做的基于栈的还挺不一样的，这个故事告诉我们就也不一定是模仿程序执行的    
```python    
from Queue import Queue    
from string import printable    
    
def vm():    
	pcode = '\x3A\x14\x1C\x34\xFF\x41\x20\x19\x20\x1A\x20\x1B\x20\x1C\x20\x1D\x20\x1E\x20\x1F\x20\x20\x20\x21\x20\x22\x20\x23\x20\x24\x20\x25\x20\x26\x20\x27\x20\x28\x20\x29\x20\x2A\x20\x2B\x20\x2C\x20\x2D\x20\x2E\x20\x2F\x20\x30\x20\x31\x20\x32\x20\x33\x20\x34\x2A\x19\x14\x44\x34\xFF\x14\x00\x20\xFF\x2A\x1A\x14\x65\x34\xFF\x14\x20\x2A\xFF\x2A\xFF\x33\x33\x2B\x30\x14\x21\x2A\xFF\x2A\xFF\x33\x33\x2B\x30\x14\x03\x20\xFE\x2A\xFF\x14\x03\x35\x2A\xFE\x14\x3F\x33\x33\x31\x3A\x2C\x14\x01\x2A\xFE\x34\x20\xFE\x2A\xFE\x40\x17\x2A\xFF\x14\x01\x33\x20\xFF\x2A\xFF\x14\x0A\x34\x40\x3D\x2A\x1D\x14\x54\x34\xFF\x2A\x1E\x14\x46\x34\xFF\x2A\x1F\x14\x7B\x34\xFF\x14\x00\x20\xFF\x36\x15\x2A\xFF\x14\x40\x33\x2B\x32\x30\x2A\xFF\x14\x40\x33\x36\x2C\x2A\xFF\x14\x01\x33\x20\xFF\x2A\xFF\x14\x1E\x34\x40\x1D\x2A\x1C\x14\x43\x34\xFF\x2A\x1B\x14\x31\x34\xFF\x14\x00\x20\xFF\x14\x00\x14\x00\x30\x30\x2A\xFF\x14\x40\x2A\xFF\x14\x41\x33\x33\x2B\x2B\x34\x30\x2A\xFF\x14\x41\x33\x36\x2C\x2A\xFF\x14\x41\x2A\xFF\x14\x42\x33\x33\x2B\x2B\x33\x30\x2A\xFF\x14\x42\x33\x36\x2C\x2A\xFF\x14\x40\x2A\xFF\x14\x42\x33\x33\x2B\x2B\x37\x30\x2A\xFF\x14\x40\x33\x36\x2C\x2A\xFF\x14\x03\x33\x20\xFF\x2A\xFF\x14\x1E\x34\x40\x51\x2A\x34\x14\x7D\x34\xFF\x2A\x40\x14\x7A\x34\xFF\x2A\x41\x14\x19\x34\xFF\x2A\x42\x14\x4F\x34\xFF\x2A\x43\x14\x6E\x34\xFF\x2A\x44\x14\x0E\x34\xFF\x2A\x45\x14\x56\x34\xFF\x2A\x46\x14\xAF\x34\xFF\x2A\x47\x14\x1F\x34\xFF\x2A\x48\x14\x98\x34\xFF\x2A\x49\x14\x58\x34\xFF\x2A\x4A\x14\x0E\x34\xFF\x2A\x4B\x14\x60\x34\xFF\x2A\x4C\x14\xBD\x34\xFF\x2A\x4D\x14\x42\x34\xFF\x2A\x4E\x14\x8A\x34\xFF\x2A\x4F\x14\xA2\x34\xFF\x2A\x50\x14\x20\x34\xFF\x2A\x51\x14\x97\x34\xFF\x2A\x52\x14\xB0\x34\xFF\x2A\x53\x14\x3D\x34\xFF\x2A\x54\x14\x87\x34\xFF\x2A\x55\x14\xA0\x34\xFF\x2A\x56\x14\x22\x34\xFF\x2A\x57\x14\x95\x34\xFF\x2A\x58\x14\x79\x34\xFF\x2A\x59\x14\xF9\x34\xFF\x2A\x5A\x14\x41\x34\xFF\x2A\x5B\x14\x54\x34\xFF\x2A\x5C\x14\x0C\x34\xFF\x2A\x5D\x14\x6D\x34\xFF\xAB'    
    
	data = '0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm+/='    
    
	queue = Queue(maxsize=100)    
	mem = [0]*256    
	inpt = [0]*256    
    
	reg = 0    
	pc = 0    
	while True:    
		code = ord(pcode[pc])-20    
		if code == 0:    
			opnum = ord(pcode[pc+1])    
			queue.put(opnum)    
			print '0x%02x code %03d push imm %d'%(pc,code,opnum)    
			pc += 2    
		elif code == 1:    
			opnum = queue.get()    
			print '0x%02x code %03d simple pop %d'%(pc,code,opnum)    
			pc += 1    
		elif code == 12:    
			opnum1 = ord(pcode[pc+1])    
			opnum2 = queue.get()    
			mem[opnum1] = opnum2    
			print '0x%02x code %03d mem[%d] = %d '%(pc,code,opnum1,opnum2)    
			pc += 2    
		elif code == 22:    
			opnum = ord(pcode[pc+1])    
			queue.put(mem[opnum])    
			print '0x%02x code %03d push mem[imm %d] = %d '%(pc,code, opnum, mem[opnum])    
			pc += 2    
		elif code == 23:    
			opnum = queue.get()    
			queue.put(mem[opnum])    
			print '0x%02x code %03d push mem[queue %d] = %d '%(pc,code,opnum, mem[opnum])    
			pc += 1    
		elif code == 24:    
			opnum1 = queue.get()    
			opnum2 = queue.get()    
			mem[opnum1] = opnum2&0xff    
			print '0x%02x code %03d mem[%d] = %d '%(pc,code,opnum1, opnum2&0xff)    
			pc += 1    
		elif code == 28:    
			reg = (queue.get() + (reg << 8))&0xffff    
			print '0x%02x code %03d fetch %d '%(pc,code,reg)    
			pc += 1    
		elif code == 29:    
			opnum = ord(pcode[pc+1])    
			oreg = reg    
			mod = reg % opnum    
			queue.put(mod)    
			reg /= opnum    
			print '0x%02x code %03d %d/%d=%d...%d '%(pc,code,oreg,opnum,reg,mod)    
			pc += 2    
		elif code == 30:    
			opnum = queue.get()    
			queue.put(ord(data[opnum]))    
			print '0x%02x code %03d push data[%d]=%d '%(pc,code,opnum,ord(data[opnum]))    
			pc += 1    
		elif code == 31:    
			opnum1 = queue.get()    
			opnum2 = queue.get()    
			queue.put(opnum1+opnum2)    
			print '0x%02x code %03d %d+%d=%d '%(pc,code,opnum2,opnum1,opnum2+opnum1)    
			pc += 1    
		elif code == 32:    
			opnum1 = queue.get()    
			opnum2 = queue.get()    
			queue.put(opnum2-opnum1)    
			print '0x%02x code %03d %d-%d=%d '%(pc,code,opnum2,opnum1,opnum2-opnum1)    
			pc += 1    
		elif code == 33:    
			opnum1 = queue.get()    
			opnum2 = queue.get()    
			queue.put(opnum1*opnum2)    
			print '0x%02x code %03d %d*%d=%d '%(pc,code,opnum2,opnum1,opnum2*opnum1)    
			pc += 1    
		elif code == 35:    
			opnum1 = queue.get()    
			opnum2 = queue.get()    
			queue.put(opnum1^opnum2)    
			print '0x%02x code %03d %d^%d=%d '%(pc,code,opnum2,opnum1,opnum2^opnum1)    
			pc += 1    
		elif code == 38:    
			inpt = list('De1CTF{01234567890123456789}')    
			queue.put(28)    
			print '0x%02x code %03d input %s'%(pc,code,'De1CTF{01234567890123456789}')    
			pc += 1    
		elif code == 44:    
			opnum1 = queue.get()    
			opnum2 = ord(pcode[pc+1])    
			print '0x%02x code %03d jnz %d flag %d'%(pc,code,opnum2, opnum1)    
			if opnum1!=0:    
				pc -= opnum2    
			else:    
				pc += 2    
		elif code == 45:    
			for i in range(28):    
				queue.put(ord(inpt[i]))    
			pc += 1    
			print '0x%02x code %03d pushall flag'%(pc,code)    
		elif code == 151:    
			print 'failed'    
			break    
		elif code == 235:    
			opnum = queue.get()    
			print '0x%02x code %03d jnz fail flag %d'%(pc,code,opnum)    
			# if opnum!=0:    
				# print 'failed'    
				# break    
			# else:    
			pc += 1    
		elif code == 34:    
			queue.put(reg)    
			print '0x%02x code %03d push reg=%d'%(pc,code,reg)    
			pc += 1    
		else:    
			print '0x%02x code %03d nop'%(pc,code)    
			pc+=2    
vm()    
```    
## little elves    
### PE头修改    
用ida无法直接打开，用readelf显示PE头跟正常PE差距挺大的，但是只要修改标识大端序小端序的那个位(第5字节)，改成0x01后还是可以用ida打开的，PE文件:    
```c    
; [ Full breakdown ]    
; --- Elf Header     
; Offset  #  Value             Purpose    
; 0-3     A  7f454c46          Magic number - 0x7F, then 'ELF' in ASCII    
; 4       B  ba                1 = 32 bit, 2 = 64 bit    
; 5       C  dc                1 = little endian, 2 = big endian    
; 6       D  fe                ELF Version    
; 7       E  21                OS ABI - usually 0 for System V    
; 8-F     F  43be69191228eb3c  Unused/padding     
; 10-11   G  0200              1 = relocatable, 2 = executable, 3 = shared, 4 = core    
; 12-13   H  3e00              Instruction set    
; 14-17   I  01000000          ELF Version    
; 18-1F   J  0400000001000000  Program entry position    
; 20-27   K  1c00000000000000  Program header table position - This is actually in the middle of J.    
; 28-2f   L  0000000000000000  Section header table position (Don't have one here so whatev)    
; 30-33   M  01000000          Flags - architecture dependent    
; 34-35   N  4000              Header size    
; 36-37   O  3800              Size of an entry in the program header table    
; 38-39   P  0100              Number of entries in the program header table    
; 3A-3B   Q  0200              Size of an entry in the section header table    
; 3C-3D   R  b0a9              Number of entries in the section header table [holds mov al, 0xa9 load syscall]    
; 3E-3F   S  0f05              Index in section header table with the section name [holds syscall opcodes]    
;    
; --- Program Header    
; OFFSET  #   Value            Purpose     
; 1C-1F   PA  01000000         Type of segment    
;                                0 = null - ignore the entry    
;                                1 = load - clear p_memsz bytes at p_vaddr to 0, then copy p_filesz bytes from p_offset to p_vaddr     
;                                2 = dynamic - requires dynamic linking    
;                                3 = interp - contains a file path to an executable to use as an interpreter for the following segment    
;                                4 = note section    
; 20-23   PB  1c000000         Flags     
;                                1 = executable    
;                                2 = writable    
;                                4 = readable    
;                                In this case the flags are 1c which is 00011100    
;                                The ABI only pays attention to the lowest three bits, meaning this is marked "read"    
; 24-2B   PC 0000000000000000   The offset in the file that the data for this segment can be found (p_offset)    
; 2C-33   PD 0000000001000000   Where you should start to put this segment in virtual memory (p_vaddr)    
; 34-3B   PE 4000380001000200   Physical Address     
; 3C-43   PF b0a90f0500000000   Size of the segment in the file (p_filesz) | NOTE: Can store string here and p_memsz as long as they    
; 44-4B   PG b0a90f0500000000   Size of the segment in memory (p_memsz)    | are equal and not over 0xffff - holds mov al, 0xa9 and syscall     
; 4C-43   PH bfaddee1feebe990   The required alignment for this section (must be a power of 2)  Well... supposedly, because you can write code here.    
;     
; Breakdown of the hex dump according to the above data    
;           A---------- B- C- D- E-  F----------------------
; 00000000  7f 45 4c 46 ba dc fe 21  43 be 69 19 12 28 eb 3c  |.ELF...!C.i..(.<|    
;                                                PA---------
;           G---- H---- I----------J----------------------
; 00000010  02 00 3e 00 01 00 00 00  04 00 00 00 01 00 00 00  |..>.............|    
;           PB--------- PC---------------------- PD---------
;           K----------------------L----------------------
; 00000020  1c 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|    
;           PD--------- PE---------------------- PF---------
;           M---------- N---- O----P---- Q---- R---- S----
; 00000030  01 00 00 00 40 00 38 00  01 00 02 00 b0 a9 0f 05  |....@.8.........|    
;           PF--------- PG---------------------- PH---------
; 00000040  00 00 00 00 b0 a9 0f 05  00 00 00 00 bf ad de e1  |................|    
;           PH---------
; 00000050  fe eb e9 90                                       |....|    
```    
### 去除花指令    
花指令大致格式是`jz xxx jmp xxx`这种，需要把中间的jmp patch    
```python    
import struct    
stripd = ""    
jmp = [0xe7,0xe8,0xe9,0xea,0xeb]    
with open('little_elves', "rb") as f:    
    raw = f.read()    
    i = 0    
    while i < len(raw):    
        if raw[i] == "\x74":    
            length = struct.unpack('<B', raw[i+1])[0]    
            next_ins = struct.unpack('<B', raw[i+2])[0]    
            # print next_ins    
            if next_ins in jmp:    
                stripd += raw[i:i+2] + "\x90"*length    
                i = i + length + 2    
            else:    
                stripd += raw[i]    
                i = i + 1    
        else:    
            stripd += raw[i]    
            i += 1    
with open('little_elves_strip', 'wb') as f:    
    f.write(stripd)    
```    
去除花指令后可以看到大致的检测流程    
```python    
  for i in range(44):    
    ch3 = 0      
    for j in range(44):    
      ch1 = input[j]    
      ch2 = t1[i][j]         
      for k in range(8):    
        if ch2 & 1:    
          ch3 ^= ch1    
        flag = ch1 & 0x80    
        ch1 = (ch1 << 1)&0xff    
        if flag:    
          ch1 ^= 0x39    
        ch2 >>= 1    
    assert(ch3 == t2[i])    
```    
### solve    
我做到这一步就不会解了==z3也解不出来，我哭了，还是密码学==    
就是在GF(2^8)下解一个AX=B的线性方程组    
其中，当a2&0x80==1时，`a2 = ((a2 * 2)&0xff) ^ 0x39`相当于`a2 = (a2 * 2) ^ 0x139`    
https://blog.csdn.net/hunyxv/article/details/89033227    
```python    
F.<x> = GF(2^8,modulus=[1,0,0,1,1,1,0,0,1])    
mt =  [[166, 8, 116, 187, 48, 79, 49, 143, 88, 194, 27, 131, 58, 75, 251, 195, 192, 185, 69, 60, 84, 24, 124, 33, 211, 251, 140, 124, 161, 9, 44, 208, 20, 42, 8, 37, 59, 147, 79, 232, 57, 16, 12, 84],    
        [73, 252, 81, 126, 50, 87, 184, 130, 196, 114, 29, 107, 153, 91, 63, 217, 31, 191, 74, 176, 208, 252, 97, 253, 55, 231, 82, 169, 185, 236, 171, 86, 208, 154, 192, 109, 255, 62, 35, 140, 91, 49, 139, 255],    
        [57, 18, 43, 102, 96, 26, 50, 187, 129, 161, 7, 55, 11, 29, 151, 219, 203, 139, 56, 12, 176, 160, 250, 237, 1, 238, 239, 211, 241, 254, 18, 13, 75, 47, 215, 168, 149, 154, 33, 222, 77, 138, 240, 42],    
        [96, 198, 230, 11, 49, 62, 42, 10, 169, 77, 7, 164, 198, 241, 131, 157, 75, 147, 201, 103, 120, 133, 161, 14, 214, 157, 28, 220, 165, 232, 20, 132, 16, 79, 9, 1, 33, 194, 192, 55, 109, 166, 101, 110],    
        [108, 159, 167, 183, 165, 180, 74, 194, 149, 63, 211, 153, 174, 97, 102, 123, 157, 142, 47, 30, 185, 209, 57, 108, 170, 161, 126, 248, 206, 238, 140, 105, 192, 231, 237, 36, 46, 185, 123, 161, 97, 192, 168, 129],    
        [72, 18, 132, 37, 37, 42, 224, 99, 92, 159, 95, 27, 18, 172, 43, 251, 97, 44, 238, 106, 42, 86, 124, 1, 231, 63, 99, 147, 239, 180, 217, 195, 203, 106, 21, 4, 238, 229, 43, 232, 193, 31, 116, 213],    
        [17, 133, 116, 7, 57, 79, 20, 19, 197, 146, 5, 40, 103, 56, 135, 185, 168, 73, 3, 113, 118, 102, 210, 99, 29, 12, 34, 249, 237, 132, 57, 71, 44, 41, 1, 65, 136, 112, 20, 142, 162, 232, 225, 15],    
        [224, 192, 5, 102, 220, 42, 18, 221, 124, 173, 85, 87, 112, 175, 157, 72, 160, 207, 229, 35, 136, 157, 229, 10, 96, 186, 112, 156, 69, 195, 89, 86, 238, 167, 169, 154, 137, 47, 205, 238, 22, 49, 177, 83],    
        [234, 233, 189, 191, 209, 106, 254, 220, 45, 12, 242, 132, 93, 12, 226, 51, 209, 114, 131, 4, 51, 119, 117, 247, 19, 219, 231, 136, 251, 143, 203, 145, 203, 212, 71, 210, 12, 255, 43, 189, 148, 233, 199, 224],    
        [5, 62, 126, 209, 242, 136, 95, 189, 79, 203, 244, 196, 2, 251, 150, 35, 182, 115, 205, 78, 215, 183, 88, 246, 208, 211, 161, 35, 39, 198, 171, 152, 231, 57, 44, 91, 81, 58, 163, 230, 179, 149, 114, 105],    
        [72, 169, 107, 116, 56, 205, 187, 117, 2, 157, 39, 28, 149, 94, 127, 255, 60, 45, 59, 254, 30, 144, 182, 156, 159, 26, 39, 44, 129, 34, 111, 174, 176, 230, 253, 24, 139, 178, 200, 87, 44, 71, 67, 67],    
        [5, 98, 151, 83, 43, 8, 109, 58, 204, 250, 125, 152, 246, 203, 135, 195, 8, 164, 195, 69, 148, 14, 71, 94, 81, 37, 187, 64, 48, 50, 230, 165, 20, 167, 254, 153, 249, 73, 201, 40, 106, 3, 93, 178],    
        [104, 212, 183, 194, 181, 196, 225, 130, 208, 159, 255, 32, 91, 59, 170, 44, 71, 34, 99, 157, 194, 182, 86, 167, 148, 206, 237, 196, 250, 113, 22, 244, 100, 185, 47, 250, 33, 253, 204, 44, 191, 50, 146, 181],    
        [143, 5, 236, 210, 136, 80, 252, 104, 156, 100, 209, 109, 103, 134, 125, 138, 115, 215, 108, 155, 191, 160, 228, 183, 21, 157, 225, 61, 89, 198, 250, 57, 189, 89, 205, 152, 184, 86, 207, 72, 65, 20, 209, 155],    
        [103, 51, 118, 167, 111, 152, 184, 97, 213, 190, 175, 93, 237, 141, 92, 30, 82, 136, 16, 212, 99, 21, 105, 166, 161, 214, 103, 21, 116, 161, 148, 132, 95, 54, 60, 161, 207, 183, 250, 45, 156, 81, 208, 15],    
        [150, 65, 4, 37, 202, 4, 54, 106, 113, 55, 51, 181, 225, 120, 173, 61, 251, 42, 153, 149, 88, 160, 79, 197, 204, 20, 65, 79, 165, 85, 203, 193, 203, 97, 9, 142, 53, 50, 127, 193, 225, 11, 121, 148],    
        [99, 27, 20, 52, 248, 197, 117, 210, 216, 249, 122, 48, 225, 117, 211, 2, 33, 172, 60, 140, 84, 44, 71, 187, 160, 198, 26, 100, 162, 92, 89, 181, 82, 55, 184, 152, 112, 51, 248, 255, 205, 145, 31, 137],    
        [209, 78, 219, 94, 189, 146, 92, 172, 214, 106, 122, 121, 90, 60, 174, 6, 82, 28, 166, 206, 248, 86, 28, 113, 159, 183, 196, 12, 183, 146, 225, 107, 169, 128, 67, 221, 228, 244, 212, 66, 118, 136, 162, 218],    
        [163, 143, 112, 123, 98, 87, 0, 143, 198, 176, 196, 246, 231, 201, 157, 169, 244, 123, 106, 210, 50, 159, 47, 55, 28, 203, 235, 91, 74, 16, 175, 125, 53, 54, 82, 2, 112, 159, 122, 251, 118, 138, 120, 184],    
        [187, 81, 128, 55, 221, 223, 44, 37, 166, 168, 32, 169, 22, 255, 169, 251, 101, 158, 161, 153, 89, 1, 244, 87, 246, 237, 157, 232, 180, 3, 248, 23, 58, 162, 144, 159, 173, 28, 117, 196, 186, 225, 81, 83],    
        [169, 45, 229, 173, 17, 248, 83, 201, 242, 38, 116, 201, 12, 87, 3, 231, 200, 143, 166, 63, 146, 86, 240, 197, 26, 198, 21, 34, 202, 192, 26, 188, 203, 3, 13, 238, 109, 179, 214, 146, 193, 255, 226, 189],    
        [16, 63, 38, 178, 184, 25, 51, 81, 142, 189, 2, 37, 163, 244, 157, 193, 149, 21, 6, 215, 185, 13, 205, 56, 158, 45, 48, 243, 98, 248, 129, 223, 68, 111, 88, 62, 119, 28, 255, 243, 132, 238, 149, 75],    
        [185, 141, 49, 173, 86, 9, 150, 99, 183, 114, 226, 133, 170, 2, 65, 124, 2, 164, 2, 155, 153, 89, 109, 220, 138, 127, 150, 213, 114, 6, 151, 227, 248, 172, 28, 0, 92, 63, 41, 229, 214, 120, 49, 164],    
        [242, 48, 147, 252, 204, 89, 111, 168, 251, 136, 160, 106, 5, 155, 137, 198, 250, 250, 57, 180, 252, 118, 165, 21, 254, 155, 154, 247, 242, 217, 131, 65, 35, 207, 112, 77, 209, 176, 122, 192, 147, 107, 80, 37],    
        [52, 183, 251, 29, 226, 175, 39, 75, 34, 254, 233, 96, 155, 144, 9, 254, 189, 41, 169, 184, 91, 97, 87, 88, 251, 138, 114, 118, 91, 156, 198, 75, 222, 19, 183, 52, 81, 194, 144, 13, 249, 111, 3, 73],    
        [21, 107, 222, 106, 222, 98, 190, 4, 244, 225, 112, 133, 120, 253, 141, 48, 52, 154, 63, 235, 190, 78, 33, 209, 4, 172, 158, 187, 219, 151, 17, 233, 214, 32, 120, 38, 26, 0, 250, 129, 251, 40, 89, 39],    
        [25, 66, 117, 107, 200, 80, 88, 90, 24, 176, 247, 95, 59, 121, 118, 67, 56, 133, 145, 167, 24, 46, 180, 145, 128, 220, 200, 29, 172, 157, 100, 9, 97, 253, 8, 200, 52, 229, 147, 218, 254, 255, 182, 170],    
        [172, 79, 214, 26, 85, 230, 228, 223, 32, 227, 84, 74, 109, 209, 222, 45, 48, 66, 23, 197, 52, 212, 179, 184, 90, 149, 199, 128, 153, 70, 3, 73, 160, 39, 49, 165, 88, 252, 135, 9, 157, 140, 32, 33],    
        [72, 233, 196, 173, 35, 166, 146, 186, 61, 86, 64, 42, 25, 86, 66, 93, 12, 255, 63, 83, 95, 219, 108, 152, 205, 31, 238, 77, 74, 156, 149, 228, 68, 244, 178, 78, 181, 173, 251, 248, 185, 99, 181, 205],    
        [106, 86, 224, 51, 91, 194, 158, 83, 144, 77, 217, 95, 125, 119, 144, 47, 85, 220, 24, 40, 59, 77, 70, 190, 188, 20, 105, 150, 79, 85, 194, 168, 64, 215, 234, 226, 4, 99, 157, 0, 186, 74, 18, 94],    
        [36, 23, 51, 78, 191, 254, 1, 166, 174, 62, 222, 243, 131, 207, 37, 4, 199, 35, 169, 7, 216, 42, 190, 241, 120, 11, 166, 129, 117, 93, 184, 50, 237, 84, 122, 67, 250, 248, 60, 96, 117, 91, 187, 79],    
        [248, 17, 173, 127, 98, 184, 11, 20, 50, 140, 249, 248, 24, 222, 34, 86, 71, 0, 237, 138, 148, 107, 115, 104, 62, 191, 39, 221, 123, 115, 131, 229, 127, 56, 64, 177, 106, 239, 26, 255, 100, 88, 1, 75],    
        [144, 18, 85, 103, 3, 31, 157, 44, 67, 24, 228, 226, 82, 208, 69, 17, 189, 216, 205, 140, 6, 1, 33, 11, 61, 223, 12, 116, 123, 167, 151, 58, 167, 79, 96, 189, 151, 233, 92, 94, 22, 60, 254, 254],    
        [216, 167, 82, 244, 143, 231, 192, 63, 79, 49, 131, 176, 212, 46, 141, 107, 125, 207, 201, 5, 103, 155, 107, 166, 210, 49, 182, 60, 34, 26, 220, 198, 225, 160, 57, 52, 138, 27, 247, 181, 0, 67, 1, 205],    
        [19, 243, 215, 203, 156, 157, 71, 187, 142, 198, 244, 52, 100, 195, 129, 134, 38, 227, 155, 241, 122, 192, 145, 179, 195, 16, 180, 70, 86, 219, 250, 67, 127, 47, 178, 249, 19, 36, 183, 50, 154, 186, 239, 15],    
        [163, 224, 95, 10, 171, 106, 49, 57, 28, 178, 119, 6, 40, 228, 92, 163, 93, 225, 23, 37, 24, 211, 72, 105, 209, 70, 0, 165, 70, 226, 43, 187, 167, 60, 143, 233, 207, 209, 12, 207, 64, 246, 222, 16],    
        [245, 140, 237, 250, 89, 99, 215, 112, 85, 182, 51, 26, 62, 220, 116, 17, 196, 247, 172, 121, 22, 106, 91, 200, 115, 240, 31, 78, 47, 126, 50, 114, 109, 88, 83, 120, 17, 95, 198, 206, 71, 112, 172, 49],    
        [254, 198, 189, 175, 121, 123, 248, 38, 163, 170, 91, 171, 125, 66, 94, 37, 181, 207, 13, 60, 210, 178, 252, 39, 175, 18, 106, 94, 171, 196, 182, 129, 101, 165, 103, 164, 234, 110, 146, 69, 36, 75, 58, 98],    
        [184, 162, 160, 24, 71, 214, 24, 14, 196, 222, 67, 178, 163, 150, 206, 104, 38, 176, 245, 98, 180, 213, 93, 134, 25, 198, 166, 10, 183, 99, 207, 127, 163, 10, 141, 105, 52, 68, 18, 121, 217, 209, 124, 127],    
        [142, 153, 245, 130, 182, 55, 211, 250, 217, 10, 172, 119, 212, 171, 244, 99, 99, 41, 223, 221, 128, 66, 31, 129, 195, 145, 241, 50, 77, 139, 29, 232, 60, 167, 110, 139, 124, 135, 18, 197, 200, 85, 15, 159],    
        [225, 159, 86, 55, 158, 137, 229, 250, 129, 194, 200, 31, 147, 30, 219, 233, 147, 28, 6, 219, 81, 172, 132, 162, 212, 115, 232, 60, 152, 105, 146, 77, 187, 9, 20, 191, 157, 96, 131, 190, 125, 175, 141, 4],    
        [110, 75, 232, 58, 102, 13, 222, 137, 137, 14, 191, 155, 48, 100, 169, 184, 49, 249, 49, 39, 138, 124, 63, 73, 237, 150, 244, 126, 127, 206, 91, 252, 110, 45, 189, 116, 188, 42, 18, 68, 194, 244, 53, 2],    
        [109, 116, 87, 241, 128, 121, 227, 188, 2, 6, 81, 194, 4, 225, 176, 48, 8, 59, 243, 50, 234, 228, 192, 176, 168, 187, 248, 244, 27, 188, 107, 204, 222, 202, 73, 141, 160, 139, 151, 206, 1, 227, 152, 81],    
        [13, 149, 85, 158, 164, 119, 149, 36, 138, 84, 173, 132, 39, 230, 96, 229, 84, 218, 14, 153, 184, 98, 160, 129, 2, 161, 99, 41, 17, 114, 55, 67, 192, 102, 241, 168, 149, 191, 216, 18, 229, 153, 94, 171]]    
t = [200, 201, 204, 116, 124, 94, 129, 127, 211, 85, 61, 154, 50, 51, 27, 28, 19, 134, 121, 70, 100, 219, 1, 132, 93, 252, 152, 87, 32, 171, 228, 156, 43, 98, 203, 2, 24, 63, 215, 186, 201, 128, 103, 52]    
for i in range(44):    
    for j in range(44):    
        mt[i][j] = F(mt[i][j].bits())    
for i in range(44):    
    t[i] = F(t[i].bits())    
MT = matrix(F, mt)    
TT = matrix(F, t).T    
#print(T)    
inp = MT.inverse() * TT    
inp = inp.T[0].list()    
x = [i.integer_representation() for i in inp]    
print (x)    
flag=""    
for i in x:    
    flag+=chr(i)    
print(flag)    
```    
## mc_ticktock    
解出upx之后没看明白是个啥我就点了x。。。whcwhcwhc    
### go程序识别    
https://www.anquanke.com/post/id/170332    
是个striped的程序，go程序的会包含.gopclntab这个段，段中存储了函数的实际名称(windows下编译的除外)    
![](/images/321088362703dcf03b556004eb7fd0d1/11884068-7cd3cd8fc9cf9450.png)    
可以使用https://github.com/sibears/IDAGolangHelper这个插件来恢复符号信息，如果运行了以后出现以下错误:    
![](/images/321088362703dcf03b556004eb7fd0d1/11884068-5a10a294d970276a.png)    
需要将`ida_ida.inf_get_min_ea()`修改为`idc.BeginEA()`    
### 程序分析    
运行webserver发现程序使用了80和8080两个端口    
![](/images/321088362703dcf03b556004eb7fd0d1/11884068-229f5e59a8c3ac4d.png)    
```c    
_QWORD *__fastcall main_muxRegister(__int64 a1, __int64 a2)    
{    
  __int64 v2; // rdx    
  __int64 v3; // r8    
  __int64 v4; // r9    
  _QWORD *v5; // rax    
  __int64 v6; // rdx    
  __int64 v7; // r8    
  __int64 v8; // r9    
  __int64 v9; // rdx    
  _QWORD *v11; // rcx    
  __int64 v12; // [rsp+0h] [rbp-40h]    
  _QWORD *v13; // [rsp+8h] [rbp-38h]    
  _QWORD *v14; // [rsp+18h] [rbp-28h]    
  _QWORD *v15; // [rsp+28h] [rbp-18h]    
  void *retaddr; // [rsp+40h] [rbp+0h]    
    
  if ( &retaddr <= *(__readfsqword(0xFFFFFFF8) + 16) )    
    runtime_morestack_noctxt(a1, a2);    
  runtime_makemap_small(a1);    
  runtime_newobject(a1, a2);    
  v5 = v13;    
  if ( dword_9B4370 )    
  {    
    a1 = (v13 + 7);    
    runtime_gcWriteBarrier(v13 + 7);    
    v5 = v11;    
  }    
  else    
  {    
    v13[7] = v12;    
  }    
  v15 = v5;    
  github_com_gorilla_mux__ptr_Router_HandleFunc(a1, a2, v2, &off_753B08, v3, v4, v5, &unk_73CD7C, 9LL, &off_753B08);    
  github_com_gorilla_mux__ptr_Router_HandleFunc(a1, a2, v6, off_753B20, v7, v8, v15, &unk_73CD73, 9LL, off_753B20);    
  github_com_gorilla_mux__ptr_Router_PathPrefix(a1, a2, v9, "/0456:;<=>?@BCLMNOPSZ[\"\\\n\r\t");    
  if ( !v14[5] )    
  {    
    *v14 = &off_7A4E40;    
    if ( dword_9B4370 )    
      runtime_gcWriteBarrier(v14 + 1);    
    else    
      v14[1] = &off_753B28;    
  }    
  return v15;    
}    
```    
Router_HandleFunc是设置访问路由的，第一个设置的是`webproxy`第二个是`ticktock`，尝试访问`http://192.168.190.128/ticktock`会提示缺少text字段，加上后显示如下:    
![](/images/321088362703dcf03b556004eb7fd0d1/11884068-6df7fc5bec2d1bea.png)    
处理`ticktock`路由的函数如下:    
```c    
__int64 __fastcall main_muxRegister_func2(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 a7, __int64 a8, __int64 *a9)    
{    
  __int64 v9; // rcx    
  __int64 result; // rax    
  __int64 v11; // rdx    
  __int64 v12; // rcx    
  __int64 v13; // r8    
  char v14; // r9    
  __int64 v15; // r8    
  __int64 v16; // r9    
  __int64 v17; // rcx    
  __int128 v18; // ST00_16    
  __int64 v19; // r8    
  __int64 v20; // r9    
  __int64 v21; // r8    
  __int64 v22; // rdx    
  __int64 v23; // r8    
  __int64 v24; // r9    
  __int64 v25; // rdx    
  __int64 v26; // rdx    
  __int64 v27; // r8    
  __int64 v28; // r9    
  __int64 v29; // rdx    
  __int64 v30; // r8    
  char v31; // dl    
  int v32; // ecx    
  char v33; // r8    
  __int64 v34; // [rsp+8h] [rbp-88h]    
  _QWORD *v35; // [rsp+8h] [rbp-88h]    
  char *v36; // [rsp+8h] [rbp-88h]    
  __int64 v37; // [rsp+18h] [rbp-78h]    
  __int64 *v38; // [rsp+20h] [rbp-70h]    
  __int64 v39; // [rsp+20h] [rbp-70h]    
  __int64 v40; // [rsp+28h] [rbp-68h]    
  __int64 v41; // [rsp+30h] [rbp-60h]    
  __int64 v42; // [rsp+38h] [rbp-58h]    
  __int64 v43; // [rsp+58h] [rbp-38h]    
  __int64 v44; // [rsp+80h] [rbp-10h]    
    
  if ( &v44 <= *(__readfsqword(0xFFFFFFF8) + 16) )    
    runtime_morestack_noctxt(a1, a2);    
  v9 = *a9;    
  if ( a9[1] != 3 || *v9 != 17735 || *(v9 + 2) != 84 )    
    return (*(a7 + 40))(a1, a2, a3, a8, a5, a6, a8, 405LL);    
  net_url__ptr_URL_Query(a1, a2, a3, a9[2], a5, a6, a9[2]);    
  runtime_mapaccess2_faststr(a1, a2, v11, v12, v13, v14);    
  v17 = *v38;    
  if ( v40 && v38[1] > 0 && *(v17 + 8) > 0LL )    
  {    
    if ( qword_996E00 < 0x10 )    
      runtime_panicSliceAcap(a1, a2);    
    v43 = *v38;    
    *&v18 = qword_996DF0;    
    *(&v18 + 1) = 16LL;    
    webserver_crypt_NewCipher(a1, a2, qword_996E00, v17, v15, v16, v18, qword_996E00);    
    if ( v40 )    
    {    
      runtime_newobject(a1, a2);    
      *v35 = 'lanretni';    
      *(v35 + 6) = 'rorre la';    
      result = (*(a7 + 32))(a1);    
    }    
    else    
    {    
      if ( qword_996E20 < 0x10 )    
        runtime_panicSliceAcap(a1, a2);    
      crypto_cipher_newCFB(a1, a2, qword_996E20, 4LL, v19, v20, 4LL, v38, qword_996E10, 0x10, qword_996E20, 0);    
      runtime_stringtoslicebyte(a1, a2, v42, *(v43 + 8), v21);    
      runtime_makeslice(a1, a2, v37);    
      (*(v41 + 24))(a1, a2, v39, *(v41 + 24));    
      encoding_base64__ptr_Encoding_EncodeToString(a1, a2, v22, v39, v23, v24);    
      runtime_convTstring(a1, a2, v25);    
      v44 = v39;    
      fmt_Sprintf(a1, a2, v26, &unk_6C5A40, v27, v28, &unk_73DD90);// TickTock %s    
      runtime_stringtoslicebyte(a1, a2, v29, v39, v30);    
      v36 = &unk_1;    
      (*(a7 + 32))(a8);    
      if ( qword_98B3C8 == v39 )    
      {    
        v36 = off_98B3C0;    
        runtime_memequal(a8, 1LL, v37, v39);    
        result = v39;    
      }    
      else    
      {    
        result = 0LL;    
      }    
      if ( result )    
      {    
        runtime_newobject(a8, 1LL);    
        *v36 = 'arceniM\n';    
        *(v36 + 8) = byte_741CD8;               // Minecra is ticking...    
        (*(a7 + 32))(a8);    
        result = runtime_newproc(a8, 1, v31, v32, v33);    
      }    
    }    
  }    
  else    
  {    
    runtime_newobject(a1, a2);    
    *v34 = ' dilavni';                          // invalid param: text    
    *(v34 + 3) = *&byte_7400D5;    
    result = (*(a7 + 32))(a1);    
  }    
  return result;    
}    
```    
处理过程是经过一层CFB模式的加密后再base64，结果需要与` off_98B3C0`比较，比较过程在`runtime_memequal(a8, 1LL, v37, v39)`中，根据恢复出来的函数名称可以看到加密算法为feistel结构的分组对称加密，CFB模式，KEY和IV为常量的sha256的hash值，**crypto_cipher_newCFB参数中有控制加解密模式的参数。将0x693743处的patch将解密模式变成解密模式**    
`mov     byte ptr [rsp+90h+var_68], 1`    
```shell    
http://192.168.190.128/ticktock?text=%A4%A3%04%B9%1E%F1%96%C6%0A%26%4D%E9%AF%FD%B1%FF%06%EE%E5%CF%6B%2E%0C%02%17%6A%97%B7%95%AC%B8%11%1A%8F%13%83%E5%AF%67%C9%6A%26%99%2B%1C%AD%3F%41%DF%AA%36%36%08%A2%04%9D    
TickTock: SGVyZSBpcyBhIEZMQUc6IERlMUNURnt0MUNrLXQwY2tfVGxjay0xb2NLX01DMk8yMF86KVNNNH0=    
base64 decode: Here is a FLAG: De1CTF{t1Ck-t0ck_Tlck-1ocK_MC2O20_:)SM4}    
```    
## 参考链接    
https://mp.weixin.qq.com/s/KKkxUb_rUEi7Pxj0Qj5Odw    
是Chamd5的wp，感觉详细很多   
