# 钓鱼城杯-mobile题解

 
## AES    
前面是AES加密，把AES的四个步骤拼在一起了，然后S盒是动态生成的，可以调试的时候看一下是不是S盒的特征数字(当然也有时候会换掉标准的S盒）    
我稍微记一下这种AES的步骤    
1. 密钥生成    
```c    
long double __fastcall sub_7FA04C1AC4(unsigned int *a1, __int64 a2, __int128 *a3)    
{    
v3 = 0LL;    
v4 = bswap32(*a1);    
*(_DWORD *)a3 = v4;    
*((_DWORD *)a3 + 1) = bswap32(a1[1]);    
*((_DWORD *)a3 + 2) = bswap32(a1[2]);    
v5 = a3 + 1;    
*((_DWORD *)a3 + 3) = bswap32(a1[3]);    
do    
{    
  v6 = *((unsigned int *)v5 - 1);    
  v7 = unk_7FA04C5E20[0].n128_u32[v3];    
  ++v3;    
  v4 ^= v7 ^ (((stru_7FA04C5040[0].n128_u8[(v6 >> 16) & 0xFF] << 24) & 0xFF00FFFF | (stru_7FA04C5040[0].n128_u8[(unsigned __int16)v6 >> 8] << 16)) & 0xFFFF00FF | (stru_7FA04C5040[0].n128_u8[(unsigned __int8)v6] << 8) | stru_7FA04C5040[0].n128_u8[v6 >> 24]);    
  v8 = *((_DWORD *)v5 - 2);    
  v9 = v4 ^ *((_DWORD *)v5 - 3);    
  *(_DWORD *)v5 = v4;    
  *((_DWORD *)v5 + 1) = v9;    
  v10 = v9 ^ v8;    
  *((_DWORD *)v5 + 2) = v10;    
  *((_DWORD *)v5 + 3) = v10 ^ v6;    
  ++v5;    
}    
while ( v3 != 10 );    
v11 = a3[9];    
v13 = a3[7];    
v12 = a3[8];    
a3[11] = a3[10];    
a3[12] = v11;    
v14 = a3[5];    
v15 = a3[6];    
a3[13] = v12;    
a3[14] = v13;    
v17 = a3[3];    
result = *((long double *)a3 + 4);    
a3[15] = v15;    
a3[16] = v14;    
v18 = *a3;    
v20 = a3[1];    
v19 = a3[2];    
*((long double *)a3 + 17) = result;    
a3[18] = v17;    
a3[21] = v18;    
a3[19] = v19;    
a3[20] = v20;    
return result;    
}    
```    
2. 加密    
```c    
if ( v7 )    
{    
  v9 = 0;    
  do    
  {    
    v10 = *v6;    
    BYTE4(v75) = v6[1];    
    v11 = v10 ^ (v79 >> 24);    
    v12 = BYTE4(v75) ^ (v79 >> 16);    
    v13 = 0LL;    
    LOBYTE(v76) = v6[2];    
    v14 = (unsigned __int8)v76 ^ (v79 >> 8);    
    BYTE4(v76) = v6[3];    
    v15 = BYTE4(v76) ^ v79;    
    v16 = v6[4];    
    v17 = v6[5];    
    BYTE1(v76) = v6[6];    
    v18 = v16 ^ (v80 >> 24);    
    v19 = v17 ^ (v80 >> 16);    
    v20 = BYTE1(v76) ^ (v80 >> 8);    
    BYTE5(v76) = v6[7];    
    v21 = BYTE5(v76) ^ v80;    
    v22 = v6[8];    
    v23 = v6[9];    
    v24 = v6[10];    
    BYTE6(v76) = v6[11];    
    v25 = v22 ^ (v81 >> 24);    
    v26 = v23 ^ (v81 >> 16);    
    v27 = v24 ^ (v81 >> 8);    
    v28 = BYTE6(v76) ^ v81;    
    v29 = v6[14];    
    v30 = v6[15];    
    v31 = v6[12] ^ (v82 >> 24);    
    v32 = v6[13] ^ (v82 >> 16);    
    v33 = v29 ^ (v82 >> 8);    
    v34 = v30 ^ v82;    
    LOBYTE(v75) = v11;    
    BYTE1(v75) = v18;    
    BYTE2(v75) = v25;    
    BYTE4(v75) ^= BYTE2(v79);    
    BYTE5(v75) = v19;    
    BYTE6(v75) = v26;    
    LOBYTE(v76) = v76 ^ BYTE1(v79);    
    BYTE1(v76) ^= BYTE1(v80);    
    BYTE2(v76) = v27;    
    BYTE4(v76) ^= v79;    
    BYTE5(v76) ^= v80;    
    BYTE6(v76) ^= v81;    
    BYTE3(v75) = v31;    
    HIBYTE(v75) = v32;    
    BYTE3(v76) = v29 ^ BYTE1(v82);    
    HIBYTE(v76) = v30 ^ v82;    
    do    
    {    
      v35 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v11];    
      v36 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v18];    
      v37 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v25];    
      v38 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v31];    
      v39 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v12];    
      v40 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v26];    
      v41 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v32];    
      v42 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v14];    
      v43 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v20];    
      v44 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v27];    
      v45 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v33];    
      v46 = stru_7FA04C5040[0].n128_u8[v15];    
      v47 = stru_7FA04C5040[0].n128_u8[v21];    
      v48 = stru_7FA04C5040[0].n128_u8[v28];    
      v49 = stru_7FA04C5040[0].n128_u8[v34];    
      BYTE4(v75) = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v19];    
      LOBYTE(v75) = v35;    
      BYTE1(v75) = v36;    
      BYTE2(v75) = v37;    
      BYTE3(v75) = v38;    
      BYTE5(v75) = v40;    
      BYTE6(v75) = v41;    
      HIBYTE(v75) = v39;    
      LOBYTE(v76) = v44;    
      BYTE1(v76) = v45;    
      BYTE2(v76) = v42;    
      BYTE3(v76) = v43;    
      BYTE4(v76) = v49;    
      BYTE5(v76) = v46;    
      BYTE6(v76) = v47;    
      HIBYTE(v76) = v48;    
      sub_7FA04C1EE0((__int128 *)&v75);    
      v50 = *(unsigned int *)((char *)&v79 + v13 + 16);    
      v51 = *(unsigned int *)((char *)&v79 + v13 + 20);    
      v11 = (unsigned __int8)v75 ^ (v50 >> 24);    
      v12 = BYTE4(v75) ^ (v50 >> 16);    
      v14 = (unsigned __int8)v76 ^ (v50 >> 8);    
      v15 = BYTE4(v76) ^ v50;    
      v53 = *(unsigned int *)((char *)&v79 + v13 + 24);    
      v52 = *(unsigned int *)((char *)&v79 + v13 + 28);    
      v18 = BYTE1(v75) ^ (v51 >> 24);    
      v19 = BYTE5(v75) ^ (v51 >> 16);    
      v20 = BYTE1(v76) ^ (v51 >> 8);    
      v21 = BYTE5(v76) ^ v51;    
      v13 += 16LL;    
      v25 = BYTE2(v75) ^ (v53 >> 24);    
      v26 = BYTE6(v75) ^ (v53 >> 16);    
      v27 = BYTE2(v76) ^ (v53 >> 8);    
      v28 = BYTE6(v76) ^ v53;    
      v31 = BYTE3(v75) ^ (v52 >> 24);    
      v32 = HIBYTE(v75) ^ (v52 >> 16);    
      v33 = BYTE3(v76) ^ (v52 >> 8);    
      v34 = HIBYTE(v76) ^ v52;    
      LOBYTE(v75) = v11;    
      BYTE1(v75) = v18;    
      BYTE2(v75) = v25;    
      BYTE3(v75) ^= HIBYTE(v52);    
      BYTE4(v75) = v12;    
      BYTE5(v75) = v19;    
      BYTE6(v75) = v26;    
      HIBYTE(v75) ^= BYTE2(v52);    
      LOBYTE(v76) = v14;    
      BYTE1(v76) = v20;    
      BYTE2(v76) = v27;    
      BYTE3(v76) ^= BYTE1(v52);    
      BYTE4(v76) = v15;    
      BYTE5(v76) = v21;    
      BYTE6(v76) = v28;    
      HIBYTE(v76) ^= v52;    
    }    
    while ( (_DWORD)v13 != 144 );    
    v54 = (char *)&v79 + v13;    
    v55 = *(unsigned int *)((char *)&v79 + v13 + 16);    
    v56 = *(unsigned int *)((char *)&v79 + v13 + 20);    
    v57 = *((_DWORD *)v54 + 6);    
    LODWORD(v54) = *((_DWORD *)v54 + 7);    
    v9 += 16;    
    v58 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v18] ^ (v56 >> 24);    
    v59 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v25] ^ (v57 >> 24);    
    v60 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v31] ^ ((unsigned int)v54 >> 24);    
    v61 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v19] ^ (v55 >> 16);    
    v62 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v26] ^ (v56 >> 16);    
    v63 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v32] ^ (v57 >> 16);    
    v64 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v12] ^ ((unsigned int)v54 >> 16);    
    v65 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v27] ^ (v55 >> 8);    
    v66 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v33] ^ (v56 >> 8);    
    v67 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v14] ^ (v57 >> 8);    
    v68 = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v20] ^ ((unsigned int)v54 >> 8);    
    v69 = stru_7FA04C5040[0].n128_u8[v34] ^ v55;    
    v70 = stru_7FA04C5040[0].n128_u8[v15] ^ v56;    
    v71 = stru_7FA04C5040[0].n128_u8[v21] ^ v57;    
    v72 = stru_7FA04C5040[0].n128_u8[v28] ^ (unsigned __int8)v54;    
    LOBYTE(v75) = stru_7FA04C5040[0].n128_u8[(unsigned __int8)v11] ^ HIBYTE(v55);    
    BYTE1(v75) = v58;    
    BYTE2(v75) = v59;    
    BYTE3(v75) = v60;    
    BYTE4(v75) = v61;    
    BYTE5(v75) = v62;    
    BYTE6(v75) = v63;    
    HIBYTE(v75) = v64;    
    LOBYTE(v76) = v65;    
    BYTE1(v76) = v66;    
    BYTE2(v76) = v67;    
    BYTE3(v76) = v68;    
    BYTE4(v76) = v69;    
    BYTE5(v76) = v70;    
    BYTE6(v76) = v71;    
    HIBYTE(v76) = v72;    
    *v5 = v75;    
    v5[1] = v61;    
    v6 += 16;    
    v5[2] = v76;    
    v73 = BYTE4(v76);    
    v5[4] = v58;    
    v5[3] = v73;    
    v5[5] = BYTE5(v75);    
    v5[6] = BYTE1(v76);    
    v5[7] = BYTE5(v76);    
    v5[8] = BYTE2(v75);    
    v5[9] = BYTE6(v75);    
    v5[10] = BYTE2(v76);    
    v5[11] = BYTE6(v76);    
    v5[12] = BYTE3(v75);    
    v5[13] = HIBYTE(v75);    
    v5[14] = BYTE3(v76);    
    v5[15] = HIBYTE(v76);    
    v5 += 16;    
  }    
  while ( v9 < v7 );    
}    
```    
这里是ECB模式加密，密钥是'\x01'*16    
## RC5    
然后找到RC5的magic number以为自己要出了，结果一直解密到结束都没解密出来，菜狗罢了。    
RC5的magic number:     
```c    
v8 = 0xB7E15163; // 0xB7E15163就是-0x481EAE9D    
v9 = malloc(0x20u);    
v10 = vcvtmd_u64_f64((sqrt(5.0) + -1.0) * 2147483650.0); // 0x9E3779B9    
dword_7FA04C5E60[0] = 0xB7E15163;    
unk_7FA04C5E64 = v10 - 0x481EAE9D;    
unk_7FA04C5E68 = v10 - 0x481EAE9D + v10;    
unk_7FA04C5E6C = v10 - 0x481EAE9D + v10 + v10;    
```    
    
RC5支持可变的[块大小](https://zh.wikipedia.org/wiki/%E5%9D%97%E5%A4%A7%E5%B0%8F "块大小")(32、64或128[比特](https://zh.wikipedia.org/wiki/%E4%BD%8D%E5%85%83 "比特"))，[密钥长度](https://zh.wikipedia.org/wiki/%E5%AF%86%E9%92%A5%E9%95%BF%E5%BA%A6 "密钥长度")（0至2040位）和加密轮数（0～255）。最初建议选择的参数是64位的块大小，128位的密钥和12轮加密。    
    
RC5的一个关键特征是使用基于数据的置换。RC5的其中一个目标是促进对于这类作为原始密码的操作的研究和评估。RC5也包括一些的[取模](https://zh.wikipedia.org/wiki/%E6%A8%A1%E7%AE%97%E6%95%B8 "模算数")加法和[逻辑异或(XOR)](https://zh.wikipedia.org/wiki/%E9%80%BB%E8%BE%91%E5%BC%82%E6%88%96 "逻辑异或")运算。这个加密的一般结构是一种类[费斯妥](https://zh.wikipedia.org/wiki/%E8%B4%B9%E6%96%AF%E5%A6%A5%E5%AF%86%E7%A0%81 "费斯妥密码")网络。加密和解密程序可以用几行代码写完，但密钥的生成算法更复杂。密钥扩展使用了[e](https://zh.wikipedia.org/wiki/E_(%E6%95%B0%E5%AD%A6%E5%B8%B8%E6%95%B0) "E (数学常数)")和[黄金比例](https://zh.wikipedia.org/wiki/%E9%BB%84%E9%87%91%E5%88%86%E5%89%B2%E7%8E%87 "黄金分割率")代入一个[单向函数](https://zh.wikipedia.org/wiki/%E5%96%AE%E5%90%91%E5%87%BD%E6%95%B8 "单向函数")，将所得值作为“[袖子里是空的](https://zh.wikipedia.org/w/index.php?title=%E8%A2%96%E5%AD%90%E9%87%8C%E6%98%AF%E7%A9%BA%E7%9A%84%E6%95%B0%E5%AD%97&action=edit&redlink=1 "袖子里是空的数字（页面不存在）")”数字（即无任何来源依据的魔法数字）。算法的诱人的简洁性和基于数据的置换的特性，让RC5吸引了众多密码研究人员将其作为研究对象。 RC5通常被记为RC5-w/r/b，w=字的大小（以bit为单位），r=加密轮数，b=密钥的字节数。    
    
解RC5最主要的是确定密钥的长度，轮数，块大小以及padding的内容    
这里padding的方式是PKCS#7，基本长度是8。密钥长度是32字节(这里被坑了，以为是16，IDA里OWord表示16字节)，轮数是12，块大小是32    
记一份标准RC5加解密的python算法：    
https://github.com/tbb/pyRC5    
```python    
class RC5:    
    
  def __init__(self, w, R, key, strip_extra_nulls=False):    
      self.w = w  # block size (32, 64 or 128 bits)    
      self.R = R  # number of rounds (0 to 255)    
      self.key = key  # key (0 to 2040 bits)    
      self.strip_extra_nulls = strip_extra_nulls    
      # some useful constants    
      self.T = 2 * (R + 1)    
      self.w4 = w // 4    
      self.w8 = w // 8    
      self.mod = 2 ** self.w    
      self.mask = self.mod - 1    
      self.b = len(key)    
    
      self.__keyAlign()    
      self.__keyExtend()    
      self.__shuffle()    
    
  def __lshift(self, val, n):    
      n %= self.w    
      return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))    
    
  def __rshift(self, val, n):    
      n %= self.w    
      return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)    
    
  def __const(self):  # constants generation    
      if self.w == 16:    
          return 0xB7E1, 0x9E37  # return P, Q values    
      elif self.w == 32:    
          return 0xB7E15163, 0x9E3779B9    
      elif self.w == 64:    
          return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15    
    
  def __keyAlign(self):    
      if self.b == 0:  # key is empty    
          self.c = 1    
      elif self.b % self.w8:    
          self.key += b'\x00' * (self.w8 - self.b % self.w8)  # fill key with \x00 bytes    
          self.b = len(self.key)    
          self.c = self.b // self.w8    
      else:    
          self.c = self.b // self.w8    
      L = [0] * self.c    
      for i in range(self.b - 1, -1, -1):    
          L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]    
      self.L = L    
    
  def __keyExtend(self):    
      P, Q = self.__const()    
      self.S = [(P + i * Q) % self.mod for i in range(self.T)]    
    
  def __shuffle(self):    
      i, j, A, B = 0, 0, 0, 0    
      for k in range(3 * max(self.c, self.T)):    
          A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)    
          B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)    
          i = (i + 1) % self.T    
          j = (j + 1) % self.c    
    
  def encryptBlock(self, data):    
      A = int.from_bytes(data[:self.w8], byteorder='little')    
      B = int.from_bytes(data[self.w8:], byteorder='little')    
      A = (A + self.S[0]) % self.mod    
      B = (B + self.S[1]) % self.mod    
      for i in range(1, self.R + 1):    
          A = (self.__lshift((A ^ B), B) + self.S[2 * i]) % self.mod    
          B = (self.__lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod    
      return (A.to_bytes(self.w8, byteorder='little')    
              + B.to_bytes(self.w8, byteorder='little'))    
    
  def decryptBlock(self, data):    
      A = int.from_bytes(data[:self.w8], byteorder='little')    
      B = int.from_bytes(data[self.w8:], byteorder='little')    
      for i in range(self.R, 0, -1):    
          B = self.__rshift(B - self.S[2 * i + 1], A) ^ A    
          A = self.__rshift(A - self.S[2 * i], B) ^ B    
      B = (B - self.S[1]) % self.mod    
      A = (A - self.S[0]) % self.mod    
      return (A.to_bytes(self.w8, byteorder='little')    
              + B.to_bytes(self.w8, byteorder='little'))    
    
  def encryptFile(self, inpFileName, outFileName):    
      with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:    
          run = True    
          while run:    
              text = inp.read(self.w4)    
              if not text:    
                  break    
              if len(text) != self.w4:    
                  text = text.ljust(self.w4, b'\x00')    
                  run = False    
              text = self.encryptBlock(text)    
              out.write(text)    
    
  def decryptFile(self, inpFileName, outFileName):    
      with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:    
          while True:    
              text = inp.read(self.w4)    
              if not text:    
                  break    
              text = self.decryptBlock(text)    
              if self.strip_extra_nulls:    
                  text = text.rstrip(b'\x00')    
              out.write(text)    
    
  def encryptBytes(self, data):    
      res, run = b'', True    
      while run:    
          temp = data[:self.w4]    
          if len(temp) != self.w4:    
              data = data.ljust(self.w4, b'\x00') # padding    
              run = False    
          res += self.encryptBlock(temp)    
          data = data[self.w4:]    
          if not data:    
              break    
      return res    
    
  def decryptBytes(self, data):    
      res, run = b'', True    
      while run:    
          temp = data[:self.w4]    
          if len(temp) != self.w4:    
              run = False    
          res += self.decryptBlock(temp)    
          data = data[self.w4:]    
          if not data:    
              break    
      return res.rstrip(b'\x00') # padding    
```    
## exp    
```python    
#!/usr/bin/env python    
from Crypto.Cipher import AES    
from Crypto.Util.number import *    
from RC5 import RC5    
import struct    
    
datalist = [202 , 96 , 85 , 48 , 181 , 219 , 212 , 166 , 1 , 21 , 63 , 184 , 188 , 76 , 156 , 136 , 234 , 244 , 118 , 221 , 141 , 123 , 26 , 38 , 218 , 116 , 44 , 29 , 40 , 99 , 75 , 136 , 68 , 34 , 126 , 33 , 14 , 108 , 244 , 174 , 228 , 33 , 199 , 103 , 33 , 64 , 197 , 59 , 178 , 85 , 146 , 33 , 155 , 41 , 250 , 51]    
data = bytes(datalist)    
print(data,len(data))    
    
key = b'\x02'*32    
    
rc5 = RC5(32, 12, key)    
result = rc5.decryptBytes(data)    
print('xxx\n')    
for r in result:    
  print(hex(int(r)), end=",")    
print('end\n')    
key = b'\x01'*16    
cipher = AES.new(key, AES.MODE_ECB)    
msg = cipher.decrypt(result)    
print(msg)    
# flag{AES_and_rc5_modified_in_jni_onloadXDDD}    
```    
[一个RC系列实现的文章](https://qianfei11.github.io/2019/09/03/C%E8%AF%AD%E8%A8%80%E5%AE%9E%E7%8E%B0RC2%E3%80%81RC5%E3%80%81RC6%E5%8A%A0%E5%AF%86%E8%A7%A3%E5%AF%86%E7%AE%97%E6%B3%95/#Intro)    

