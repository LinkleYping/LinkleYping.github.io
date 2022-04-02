---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "TSCTF202-re"    
date: 2020-10-26T15:22:45+08:00    
categories : [                                  
"writeup",    
]    
draft: false    
---
### easyre    
有两层加密，第一层是AES，第二层是RC5    
前面是padding，填充方式是PKCS#7    
#### AES    
在`sub_FBE`这个函数中有明显的AES加密特征:    
![image](/images/950bc4825dc51c8081513efc5b48c978/11884068-bf81b134f049dbde.png)    
有十轮加密，四个步骤，第十轮少了中间的步骤。对应的是AES的:字节代换、行移位、列混淆和轮密钥加，第十轮没有列混淆。    
`sub_DA2`是密钥扩展步骤。代码中AES的Sbox被修改了，在文件中给出了Sbox和InvSbox。    
密钥扩展部分也进行了一点修改，所以生成的子密钥会有不同。    
AES代码:    
```c    
for (i = 1; i <= 10; i++)    
{    
for (j = 0; j < 4; j++)    
{    
    unsigned char t[4];    
    for (r = 0; r < 4; r++)    
    {    
        t[r] = j ? w[i][r][j - 1] : w[i - 1][r][3];    
    }    
    if (j == 0)    
    {    
        unsigned char temp = t[0];    
        for (r = 0; r < 3; r++)    
        {    
            t[r] = Sbox[t[(r + 1) % 4]];    
        }    
        t[3] = Sbox[temp];    
        t[0] ^= rc[i - 1];    
    }    
    for (r = 0; r < 4; r++)    
    {    
        w[i][r][j] = w[i - 1][r][j] ^ t[r];    
    }    
}    
}    
```    
修改后的：    
```c    
if ( !l )    
{    
for ( n = 0; n <= 3; ++n )    
    v12[n] = *(_BYTE *)(a1 + (unsigned __int8)v12[(n + 1) % 4] + 8);    
v12[0] ^= *(&v13 + k - 1);    
}    
```    
等于3的这个部分有一点更改，但是可以不用管这个更改的细节，直接dump出文件中扩展出来的密钥解密即可。    
#### RC5    
根据0xB7E15163, 0x9E3779B9这两个长度可以判断猜测是RC5，密钥长度是16，轮数是12，块大小是32.同样可以找个RC5的代码进行加密验证一下    
#### solve    
```python    
class AES:    
    
MIX_C  = [[0x2, 0x3, 0x1, 0x1], [0x1, 0x2, 0x3, 0x1], [0x1, 0x1, 0x2, 0x3], [0x3, 0x1, 0x1, 0x2]]    
I_MIXC = [[0xe, 0xb, 0xd, 0x9], [0x9, 0xe, 0xb, 0xd], [0xd, 0x9, 0xe, 0xb], [0xb, 0xd, 0x9, 0xe]]    
RCon   = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000]    
    
S_BOX = [[54, 79, 98, 216, 181, 132, 205, 246, 220, 42, 230, 237, 171, 82, 1, 175], [208, 10, 104, 20, 39, 161, 219, 135, 156, 231, 41, 102, 53, 233, 180, 145], [139, 206, 243, 52, 86, 94, 35, 97, 112, 195, 167, 50, 45, 128, 12, 196], [245, 44, 114, 164, 201, 6, 185, 110, 25, 18, 7, 34, 214, 211, 0, 113], [152, 14, 107, 202, 100, 61, 186, 254, 136, 2, 227, 70, 239, 31, 47, 143], [46, 58, 49, 155, 240, 226, 123, 153, 187, 168, 72, 99, 212, 141, 244, 105], [191, 232, 75, 222, 218, 118, 176, 16, 184, 151, 198, 159, 22, 247, 172, 221], [69, 188, 197, 225, 173, 124, 91, 252, 204, 174, 89, 154, 111, 229, 103, 163], [88, 199, 140, 101, 129, 73, 83, 131, 64, 57, 93, 55, 177, 116, 142, 77], [207, 51, 248, 162, 117, 115, 250, 215, 74, 203, 130, 120, 23, 224, 149, 125], [8, 241, 189, 65, 183, 4, 15, 138, 209, 81, 62, 56, 147, 194, 137, 210], [150, 148, 26, 251, 95, 126, 96, 36, 84, 234, 127, 11, 27, 67, 38, 43], [28, 179, 78, 133, 63, 90, 192, 30, 80, 119, 255, 9, 228, 158, 37, 157], [5, 19, 238, 213, 48, 170, 40, 121, 134, 76, 249, 87, 109, 235, 71, 178], [217, 24, 182, 190, 122, 193, 160, 13, 92, 200, 165, 68, 106, 60, 32, 166], [3, 17, 59, 21, 144, 253, 146, 236, 169, 33, 85, 29, 223, 108, 66, 242]]    
    
I_SBOX = [[62, 14, 73, 240, 165, 208, 53, 58, 160, 203, 17, 187, 46, 231, 65, 166], [103, 241, 57, 209, 19, 243, 108, 156, 225, 56, 178, 188, 192, 251, 199, 77], [238, 249, 59, 38, 183, 206, 190, 20, 214, 26, 9, 191, 49, 44, 80, 78], [212, 82, 43, 145, 35, 28, 0, 139, 171, 137, 81, 242, 237, 69, 170, 196], [136, 163, 254, 189, 235, 112, 75, 222, 90, 133, 152, 98, 217, 143, 194, 1], [200, 169, 13, 134, 184, 250, 36, 219, 128, 122, 197, 118, 232, 138, 37, 180], [182, 39, 2, 91, 68, 131, 27, 126, 18, 95, 236, 66, 253, 220, 55, 124], [40, 63, 50, 149, 141, 148, 101, 201, 155, 215, 228, 86, 117, 159, 181, 186], [45, 132, 154, 135, 5, 195, 216, 23, 72, 174, 167, 32, 130, 93, 142, 79], [244, 31, 246, 172, 177, 158, 176, 105, 64, 87, 123, 83, 24, 207, 205, 107], [230, 21, 147, 127, 51, 234, 239, 42, 89, 248, 213, 12, 110, 116, 121, 15], [102, 140, 223, 193, 30, 4, 226, 164, 104, 54, 70, 88, 113, 162, 227, 96], [198, 229, 173, 41, 47, 114, 106, 129, 233, 52, 67, 153, 120, 6, 33, 144], [16, 168, 175, 61, 92, 211, 60, 151, 3, 224, 100, 22, 8, 111, 99, 252], [157, 115, 85, 74, 204, 125, 10, 25, 97, 29, 185, 221, 247, 11, 210, 76], [84, 161, 255, 34, 94, 48, 7, 109, 146, 218, 150, 179, 119, 245, 71, 202]]    
    
def SubBytes(self, State):    
    # 字节替换    
    return [self.S_BOX[i][j] for i, j in     
           [(_ >> 4, _ & 0xF) for _ in State]]    
    
def SubBytes_Inv(self, State):    
    # 字节逆替换    
    return [self.I_SBOX[i][j] for i, j in    
           [(_ >> 4, _ & 0xF) for _ in State]]    
    
def ShiftRows(self, S):    
    # 行移位    
    return [S[ 0], S[ 5], S[10], S[15],     
            S[ 4], S[ 9], S[14], S[ 3],    
            S[ 8], S[13], S[ 2], S[ 7],    
            S[12], S[ 1], S[ 6], S[11]]    
    
def ShiftRows_Inv(self, S):    
    # 逆行移位    
    return [S[ 0], S[13], S[10], S[ 7],    
            S[ 4], S[ 1], S[14], S[11],    
            S[ 8], S[ 5], S[ 2], S[15],    
            S[12], S[ 9], S[ 6], S[ 3]]    
    
def MixColumns(self, State):    
    # 列混合    
    return self.Matrix_Mul(self.MIX_C, State)    
    
def MixColumns_Inv(self, State):    
    # 逆列混合    
    return self.Matrix_Mul(self.I_MIXC, State)    
    
def RotWord(self, _4byte_block):    
    # 用于生成轮密钥的字移位    
    return ((_4byte_block & 0xffffff) << 8) + (_4byte_block >> 24)    
    
def SubWord(self, _4byte_block):    
    # 用于生成密钥的字节替换    
    result = 0    
    for position in range(4):    
        i = _4byte_block >> position * 8 + 4 & 0xf    
        j = _4byte_block >> position * 8 & 0xf    
        result ^= self.S_BOX[i][j] << position * 8    
    return result    
    
def mod(self, poly, mod = 0b100011011):      
    # poly模多项式mod    
    while poly.bit_length() > 8:    
        poly ^= mod << poly.bit_length() - 9    
    return poly    
    
def mul(self, poly1, poly2):    
    # 多项式相乘    
    result = 0    
    for index in range(poly2.bit_length()):    
        if poly2 & 1 << index:    
            result ^= poly1 << index    
    return result    
    
def Matrix_Mul(self, M1, M2):  # M1 = MIX_C  M2 = State    
    # 用于列混合的矩阵相乘    
    M = [0] * 16    
    for row in range(4):    
        for col in range(4):    
            for Round in range(4):    
                M[row + col*4] ^= self.mul(M1[row][Round], M2[Round+col*4])    
            M[row + col*4] = self.mod(M[row + col*4])    
    return M    
    
def round_key_generator(self, _16bytes_key):    
    # 轮密钥产生    
    w = [_16bytes_key >> 96,     
         _16bytes_key >> 64 & 0xFFFFFFFF,     
         _16bytes_key >> 32 & 0xFFFFFFFF,     
         _16bytes_key & 0xFFFFFFFF] + [0]*40    
    for i in range(4, 44):    
        temp = w[i-1]    
        if not i % 4:    
            temp = self.SubWord(self.RotWord(temp)) ^ self.RCon[i//4-1]    
        w[i] = w[i-4] ^ temp    
    return [self.num_2_16bytes(    
                sum([w[4 * i] << 96, w[4*i+1] << 64,     
                     w[4*i+2] << 32, w[4*i+3]])    
                ) for i in range(11)]    
    
def AddRoundKey(self, State, RoundKeys, index):    
    # 异或轮密钥    
    return self._16bytes_xor(State, RoundKeys[index])    
    
def _16bytes_xor(self, _16bytes_1, _16bytes_2):    
    return [_16bytes_1[i] ^ _16bytes_2[i] for i in range(16)]    
    
def _16bytes2num(cls, _16bytes):    
    # 16字节转数字    
    return int.from_bytes(_16bytes, byteorder = 'big')    
    
def num_2_16bytes(cls, num):    
    # 数字转16字节    
    return num.to_bytes(16, byteorder = 'big')    
    
def aes_encrypt(self, plaintext_list, RoundKeys):    
    State = plaintext_list    
    State = self.AddRoundKey(State, RoundKeys, 0)    
    for Round in range(1, 10):    
        State = self.SubBytes(State)    
        State = self.ShiftRows(State)    
        State = self.MixColumns(State)    
        State = self.AddRoundKey(State, RoundKeys, Round)    
    State = self.SubBytes(State)    
    State = self.ShiftRows(State)    
    State = self.AddRoundKey(State, RoundKeys, 10)    
    return State    
    
def aes_decrypt(self, ciphertext_list, RoundKeys):    
    State = ciphertext_list    
    State = self.AddRoundKey(State, RoundKeys, 10)    
    for Round in range(1, 10):    
        State = self.ShiftRows_Inv(State)    
        State = self.SubBytes_Inv(State)    
        State = self.AddRoundKey(State, RoundKeys, 10-Round)    
        State = self.MixColumns_Inv(State)    
    State = self.ShiftRows_Inv(State)    
    State = self.SubBytes_Inv(State)    
    State = self.AddRoundKey(State, RoundKeys, 0)    
    return State    
    
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
            data = data.ljust(self.w4, b'\x00')    
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
    return res.rstrip(b'\x00')    
    
if __name__ == '__main__':    
enc = [0x70, 0x24, 0x76, 0xfd, 0xc7, 0x29, 0xc5, 0x97, 0xef, 0xee, 0xb6, 0x22, 0x5e, 0xb5, 0x46, 0xf2, 0x39, 0x47, 0x8f, 0xc2, 0x9e, 0x9c, 0x88, 0x2b, 0xfa, 0xd8, 0x7f, 0xd3, 0xeb, 0x6c, 0x9c, 0xa6, 0x5e, 0x30, 0x18, 0xd9, 0xdb, 0x96, 0xc2, 0x2b, 0xa5, 0x57, 0x36, 0x47, 0xd5, 0x72, 0xa6, 0xd5]    
    
## 解RC5    
rc5 = RC5(32, 12, b'welcometotsctf\x00\x00')    
data = bytes(enc)    
result = rc5.decryptBytes(data)    
invRC5 = [int(t) for t in result]    
    
# 解AES    
aes = AES()    
    
# 子密钥(从程序中dump)    
w = [0x77,0x6f,0x6f,0x74,0x65,0x6d,0x74,0x66,0x6c,0x65,0x73,0x0,0x63,0x74,0x63,0x0,0xc6,0xa9,0xc6,0xb2,0x53,0x3e,0x4a,0x2c,0x5a,0x3f,0x4c,0x4c,0xf5,0x81,0xe2,0xe2,0xe9,0x40,0x86,0x34,0xbc,0x82,0xc8,0xe4,0xec,0xd3,0x9f,0xd3,0x75,0xf4,0x16,0xf4,0x97,0xd7,0x51,0x65,0x69,0xeb,0x23,0xc7,0x7c,0xaf,0x30,0xe3,0x2c,0xd8,0xce,0x3a,0x81,0x56,0x7,0x62,0xd7,0x3c,0x1f,0xd8,0x7b,0xd4,0xe4,0x7,0x98,0x40,0x8e,0xb4,0x17,0x41,0x46,0x24,0x21,0x1d,0x2,0xda,0x24,0xf0,0x14,0x13,0xcb,0x8b,0x5,0xb1,0xce,0x8f,0xc9,0xed,0x35,0x28,0x2a,0xf0,0xb0,0x40,0x54,0x47,0xea,0x61,0x64,0xd5,0x8d,0x2,0xcb,0x26,0xcb,0xe3,0xc9,0x39,0x1a,0x5a,0xe,0x49,0x32,0x53,0x37,0xe2,0x1f,0x1d,0xd6,0xf0,0xc9,0x2a,0xe3,0xda,0xac,0xf6,0xf8,0xb1,0x5a,0x9,0x3e,0xdc,0xfd,0xe0,0x36,0xc6,0x5d,0x77,0x94,0x4e,0xc1,0x37,0xcf,0x7e,0x7b,0x72,0x4c,0x90,0xe4,0x4,0x32,0xf4,0x3a,0x4d,0xd9,0x97,0xe,0x39,0xf6,0x88,0xbf,0xcd,0x81,0x11]    
    
RoundKeys = []    
for i in range(11):    
    temp = w[16*i:16*(i+1)]    
    r = []    
    for j in range(4):    
        for k in range(4):    
            r.append(temp[4*k+j])    
    RoundKeys.append(bytes(r))    
    
flag = []    
for i in range(0, len(invRC5), 16):    
    ciphertext = bytes(invRC5[i:i+16])    
    plaintext = aes.aes_decrypt(ciphertext, RoundKeys)    
    flag = flag + plaintext    
print("".join(chr(i) for i in flag))    
```    
#### something else    
作为re第一题，是我面向源码做题了...我自己感觉AES改的少应该还可以，但是其实拿到题改动未知的时候会想很多，这个代码又很复杂。我不应该改动它的，或者换一个简单的算法 (跪    
### babywasm    
题目描述中出现了wasi，稍微搜一下应该能搜到这份使用教程: https://docs.wasmer.io/integrations/c/setup 里面包含了很多c程序调用wasm代码的示例。这道题用了wasmer-c-api来构建,主程序为re, program.wasm为子程序。    
对照着示例(eg: https://docs.wasmer.io/integrations/c/examples/host-functions)不难看出，ELF的`main`函数中首先导入`boom`函数到wasm的环境变量中，然后调用了wasm的`start`函数。    
    
对program.wasm逆向分析.基础教程:    
https://xz.aliyun.com/t/5170    
反汇编的话，可以把wasm转成c语言的格式，用wasm2c    
```shell    
$ ./wasm2c wasm.wasm -o wasm.c    
==> 得到wasm.c和wasm.h    
```    
但是因为生成的c语言很长而且基本跟看wat没什么区别，所以需要再编译成二进制文件放到ida里面去看    
将之前反编译出来的wasm.c，wasm.h，以及wabt项目内的wasm-rt.h，wasm-rt-impl.c，wasm-rt-impl.h三个文件放到同一个文件夹。    
直接gcc wasm.c会报错，因为很多wasm的函数没有具体的实现。但是我们可以只编译不链接，我们关心的只是程序本身的逻辑，不需要真正编译出能运行的elf来。    
`$ gcc -c wasm.c -o wasm.o` 得到的还未连接的elf文件wasm.o, 将wasm.o放到ida里面分析会比较清楚一些。    
    
得到二进制文件后首先可以搜索一下字符串，可以发现一个特殊的字符串`There is a fire in each one's heart`，查找引用可以看到在`init_memory`中找到，这部分主要是初始化字符串，这个字符串存储在了`w2c_memory + 2176`的偏移处。    
    
查看`start`函数，这个函数中引用了四个函数，在`w2c_f9`中调用了`Z_envZ_boomZ_ii`，这个函数是在ELF中导入的，所以这里应该是程序的关键点。    
```c    
__int64 __fastcall w2c_f9(__m128i a1)    
{    
int v1; // ST30_4    
int v2; // ST34_4    
unsigned int v3; // ST38_4    
unsigned int v4; // ST3C_4    
unsigned int v5; // ST6C_4    
unsigned int v7; // [rsp+Ch] [rbp-64h]    
    
if ( ++wasm_rt_call_stack_depth > 0x1F4u )    
wasm_rt_trap(7LL);    
w2c_g0 -= 16;    
v7 = w2c_g0;    
i32_store(&w2c_memory, (unsigned int)w2c_g0 + 12LL, 0);    
i32_store(&w2c_memory, v7, 2752);    
w2c_f11(1024u, v7, a1);    
v1 = w2c_f106(2752u);    
i32_store(&w2c_memory, v7 + 8LL, v1);    
v2 = w2c_f63(256LL);    
i32_store(&w2c_memory, v7 + 4LL, v2);    
v3 = i32_load(&w2c_memory, v7 + 4LL);    
w2c_f7(v3, 2176LL, 36LL);    
v4 = i32_load(&w2c_memory, v7 + 4LL);    
v5 = i32_load(&w2c_memory, v7 + 8LL);    
w2c_f8(v4, 2752LL, v5);    
if ( (unsigned int)Z_envZ_boomZ_ii(2752LL) == 0 )    
w2c_f103(1034LL, 0LL);    
else    
w2c_f103(1027LL, 0LL);    
w2c_g0 = v7 + 16;    
--wasm_rt_call_stack_depth;    
return 0LL;    
}    
```    
在这个函数中首先调用了`w2c_f11`函数，参数是1024，猜测是字符串内容，可以找到1024偏移处字符串的值(0x39480 - 2147 + 1024 -> 0x3901d),这个地方的字符串是`%s`所以这个地方应该是`scanf`函数。输入的字符串存储在`2752`处。`w2c_f106`的参数是输入字符串的位置，里面的代码很明显时求输入字符串的长度。长度存储在`v7 + 8LL`处。    
然后将一个与输入无关的函数`w2c_f63`返回值存储在`v7 + 4LL`处，然后`w2c_f7(v3, 2176LL, 36LL);`这个函数第一个参数时`w2c_f63`的返回值，第二个参数是`There is a fire in each one's heart`这个字符串，第三个参数是字符串的长度加1.    
进入`w2c_f7`这个函数内部可以发现，进行了两个循环，每个循环执行256次，第一个循环中对长度取模(第三个参数)，第二个循环中对256取模。这时候应该猜测出来是RC4(当然不猜直接看也还比较容易看懂，就是数据赋值变成了store和load而已，给了流密钥的提示就更容易看了)。    
所以`w2c_f7`这个函数是密钥的初始化，随后调用`w2c_f8(v4, 2752LL, v5)`，第一个参数是初始化变换后的密钥，第二个参数是输入的字符串，第三个参数是字符串的长度（这个函数中的加密也有对256取模 & 数据交换的各种操作）    
在加密完成过后调用`Z_envZ_boomZ_ii`函数，通过打印`Right`。    
#### solve    
```python    
from Crypto.Cipher import ARC4    
def myRC4(data,key):    
rc41 = ARC4.new(key)    
encrypted = rc41.encrypt(data)    
return encrypted.encode('hex').upper()    
enc = [0xbf, 0xcf, 0x61, 0x4c, 0xed, 0x4c, 0x29, 0x24, 0x5, 0x8a, 0x60, 0x87, 0x35, 0x81, 0x73, 0xf, 0xde, 0x96, 0x65, 0xa5, 0x41, 0x18, 0xac, 0xf5, 0x1c, 0x42, 0xda, 0x26, 0x96, 0xad, 0x35, 0xde, 0xf4, 0xc3, 0xcd, 0x1c, 0x96, 0xeb]    
s = "".join(chr(i) for i in enc)    
key = "There is a fire in each one's heart\0"# 因为初始化密钥的长度比这个字符串的长度长1，所以记得补个0，当然如果找的是实现代码可以直接用长度36    
enc = myRC4(s, key)    
print enc.decode('hex')    
```    
    
### babybios    
这道题在uboot arm的bios里添加了一个getflag指令。在指令的回调函数里实现了对flag的校验逻辑。动态调试可以使用gdb-multiarch+qemu去调试，静态直接用IDA分析即可。    
这道题的关键是找到指令的回调函数，而线索就是uboot在添加和搜索指令的机制。https://blog.csdn.net/itxiebo/article/details/50991049    
观察cmd_tbl结构体可以发现，结构体包含了命令名字符串指针`name`，回调函数指针`cmd`，命令帮助字符串指针`help`。    
```c    
struct cmd_tbl {    
	char		*name;		/* Command Name			*/    
	int		maxargs;	/* maximum number of arguments	*/    
					/*    
					 * Same as ->cmd() except the command    
					 * tells us if it can be repeated.    
					 * Replaces the old ->repeatable field    
					 * which was not able to make    
					 * repeatable property different for    
					 * the main command and sub-commands.    
					 */    
	int		(*cmd_rep)(struct cmd_tbl *cmd, int flags, int argc,    
				   char *const argv[], int *repeatable);    
					/* Implementation function	*/    
	int		(*cmd)(struct cmd_tbl *cmd, int flags, int argc,    
			       char *const argv[]);    
	char		*usage;		/* Usage message	(short)	*/    
#ifdef	CONFIG_SYS_LONGHELP    
	char		*help;		/* Help  message	(long)	*/    
#endif    
#ifdef CONFIG_AUTO_COMPLETE    
	/* do auto completion on the arguments */    
	int		(*complete)(int argc, char *const argv[],    
				    char last_char, int maxv, char *cmdv[]);    
#endif    
};    
```    
那么在IDA中搜索命令名字符串指针，也就是`getflag`字符串的指针`0x88EEA`，就找到了下图的位置（IDA按D键可以修改数据的类型）。    
![image](/images/950bc4825dc51c8081513efc5b48c978/11884068-0d1d97cc92ad8e72.png)    
    
对照`cmd_tbl`结构体，能够确定命令回调函数的地址为`0x11A00`。反编译这个函数。    
![image](/images/950bc4825dc51c8081513efc5b48c978/11884068-dc41250bf480433b.png)    
    
逆一下几个函数，基本能够确定流程，sub_116D8函数对输入做base64解码，sub_118A8函数之后的部分首先填充了一个9*9的数独，之后对数独进行校验。    
把数独从ida中抠出来放进在线数独求解器，再做base64编码，就得到了flag。    
    
    
### wbenc    
这道题来自某IoT设备中的白盒加密(white box encrypt)。    
加密分为三个部分，第一和第三部分进行了一些简单的变换，可以直接逆向。    
中间的大段代码需要花功夫逆一下。    
逆向之后，整个中间部分共有10轮，每一轮的操作如下。    
```python    
v13 = int32_split(magic_tbl[buf[5]  | 0x100] ^ magic_tbl[buf[0]]          ^ magic_tbl[buf[10] | 0x200] ^ magic_tbl[buf[15] | 0x300])    
v15 = int32_split(magic_tbl[buf[4]  | 0x400] ^ magic_tbl[buf[9] | 0x500]  ^ magic_tbl[buf[14] | 0x600] ^ magic_tbl[buf[3]  | 0x700])    
v17 = int32_split(magic_tbl[buf[13] | 0x900] ^ magic_tbl[buf[8] | 0x800]  ^ magic_tbl[buf[2]  | 0xA00] ^ magic_tbl[buf[7]  | 0xB00])    
v18 = int32_split(magic_tbl[buf[11] | 0xF00] ^ magic_tbl[buf[1] | 0xD00]  ^ magic_tbl[buf[12] | 0xC00] ^ magic_tbl[buf[6]  | 0xE00])    
```    
分析可知，这四行代码的是独立的，也就是每行的4byte输入转换为4byte输出。那么对这样的4byte变换直接暴破的话，时间复杂度高。2\^32很难在普通计算机下暴破。    
我们可以利用中间相遇攻击的思想对暴力破解进行优化。例如我们对下面的第一行进行逆向（暴破）。    
```c    
v13 = int32_split(magic_tbl[buf[5]  | 0x100] ^ magic_tbl[buf[0]] ^ magic_tbl[buf[10] | 0x200] ^ magic_tbl[buf[15] | 0x300])    
```    
首先枚举所有可能的`magic_tbl[buf[5]  | 0x100] ^ magic_tbl[buf[0]]`这样一个异或和，也就是0xff * 0xff种可能，存储在一张有序表当中。    
再枚举所有的`magic_tbl[buf[10] | 0x200] ^ magic_tbl[buf[15] | 0x300]`，也就是后面两个字节的异或和，把异或的结果和v13去做异或，得到的值在前面存储的表中查询是否存在，有序表的查询操作时间复杂度是O(logn)。    
如果存在，那么说明我们找到了一组`(buf[5],buf[0]],buf[10],buf[15])`，满足`magic_tbl[buf[5]  | 0x100] ^ magic_tbl[buf[0]]          ^ magic_tbl[buf[10] | 0x200] ^ magic_tbl[buf[15] | 0x300]=v13`，也就是从输出的4byte逆向得到了输入的4byte。    
利用这样一个空间换时间的优化，能够在可以接受的时间复杂度下逆向得到输入。    
之后编写解密脚本就能够从输出获得输入。    
解密脚本如下    
```python    
import sys    
    
magic_tbl = []    
    
def loadTable(filename):    
global magic_tbl    
    
fp = open(filename, 'r')    
content = fp.read()    
fp.close()    
    
content = content.split(' ')    
content = [int(content[i], 16) for i in xrange(len(content))]    
tbl = [content[i] | content[i+1]<<8 | content[i+2]<<16 | content[i+3]<<24 for i in xrange(0, len(content), 4)]    
    
print hex(len(tbl))    
magic_tbl = tbl    
    
    
def listDump(l):    
for x in xrange(len(l)):    
    print hex(l[x]),    
print ''    
    
def int32_split(x):    
return [x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff]    
    
def ROTR(ch, n, sz):    
tmp = ((ch >> (n%sz)) | (ch << (sz - (n % sz) ))) & ((1 << sz) - 1)    
return tmp    
    
def ROTL(ch, n, sz):    
tmp = ((ch << (n%sz)) | (ch >> (sz - (n % sz) ))) & ((1 << sz) - 1)    
return tmp    
    
def decode(input):    
buf = [0] * 16    
    
# ROT decode    
v64 = 0    
v66 = 0    
v68 = 0    
v70 = 0    
    
for i in xrange(16):    
    
    tmp = ord(input[i]) ^ v64    
    buf[i] = ROTR(tmp, i*2, 8)    
    v64 += 0xd    
    v66 += 0xca    
    v68 += 0x73    
    v70 += 0x9b    
    
#listDump(buf)    
#print buf    
    
v56 = int32_split(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24))    
v57 = int32_split(buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24))    
v67 = int32_split(buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24))    
v71 = int32_split(buf[12] | (buf[13] << 8) | (buf[14] << 16) | (buf[15] << 24))    
    
# MITM attack    
    
# init    
def get_dict(x, y):    
    dic = {}    
    for i in xrange(256):    
        for j in xrange(256):    
            tmp = magic_tbl[i | x] ^ magic_tbl[j | y]    
            dic[tmp] = [i, j]    
    
    return dic    
    
def mitm(dic, res, u, v):    
    res = res[0] | res[1] << 8 | res[2] << 16 | res[3] << 24    
    
    for i in xrange(256):    
        for j in xrange(256):    
            tmp = magic_tbl[i | u] ^ magic_tbl[j | v]    
            tmp ^= res    
            if dic.has_key(tmp):    
                [k, l] = dic[tmp]    
                #print [i, j, k, l]    
                return [i, j, k, l]    
    
# round 9    
v51 = [0] * 4    
v52 = [0] * 4    
v53 = [0] * 4    
v55 = [0] * 4    
v55[3], v53[2], v52[1], v51[0] = mitm(get_dict(0x9100, 0x9000), v56, 0x9300, 0x9200)    
v52[0], v53[1], v55[2], v51[3] = mitm(get_dict(0x9600, 0x9700), v57, 0x9400, 0x9500)    
v51[2], v55[1], v53[0], v52[3] = mitm(get_dict(0x9800, 0x9B00), v67, 0x9A00, 0x9900)    
v51[1], v55[0], v52[2], v53[3] = mitm(get_dict(0x9E00, 0x9F00), v71, 0x9D00, 0x9C00)    
    
# round 8    
v47 = [0] * 4    
v48 = [0] * 4    
v49 = [0] * 4    
v50 = [0] * 4    
v49[2], v48[1], v47[0], v50[3] = mitm(get_dict(0x8000, 0x8300), v51, 0x8200, 0x8100)    
v48[0], v49[1], v50[2], v47[3] = mitm(get_dict(0x8600, 0x8700), v52, 0x8400, 0x8500)    
v49[0], v50[1], v47[2], v48[3] = mitm(get_dict(0x8A00, 0x8B00), v53, 0x8800, 0x8900)    
v49[3], v50[0], v47[1], v48[2] = mitm(get_dict(0x8D00, 0x8E00), v55, 0x8F00, 0x8C00)    
    
# round 7    
v42 = [0] * 4    
v43 = [0] * 4    
v44 = [0] * 4    
v46 = [0] * 4    
v44[2], v43[1], v42[0], v46[3] = mitm(get_dict(0x7000, 0x7300), v47, 0x7200, 0x7100)    
v43[0], v44[1], v46[2], v42[3] = mitm(get_dict(0x7600, 0x7700), v48, 0x7400, 0x7500)    
v43[3], v44[0], v46[1], v42[2] = mitm(get_dict(0x7900, 0x7A00), v49, 0x7B00, 0x7800)    
v46[0], v42[1], v43[2], v44[3] = mitm(get_dict(0x7E00, 0x7F00), v50, 0x7C00, 0x7D00)    
    
# round 6    
v37 = [0] * 4    
v38 = [0] * 4    
v40 = [0] * 4    
v41 = [0] * 4    
v38[1], v37[0], v40[2], v41[3] = mitm(get_dict(0x6200, 0x6300), v42, 0x6100, 0x6000)    
v38[0], v40[1], v41[2], v37[3] = mitm(get_dict(0x6600, 0x6700), v43, 0x6400, 0x6500)    
v40[0], v41[1], v37[2], v38[3] = mitm(get_dict(0x6A00, 0x6B00), v44, 0x6800, 0x6900)    
v41[0], v37[1], v38[2], v40[3] = mitm(get_dict(0x6E00, 0x6F00), v46, 0x6C00, 0x6D00)    
    
# round 5    
v33 = [0] * 4    
v34 = [0] * 4    
v35 = [0] * 4    
v36 = [0] * 4    
v34[1], v33[0], v35[2], v36[3] = mitm(get_dict(0x5200, 0x5300), v37, 0x5100, 0x5000)    
v34[0], v35[1], v36[2], v33[3] = mitm(get_dict(0x5600, 0x5700), v38, 0x5400, 0x5500)    
v35[0], v36[1], v33[2], v34[3] = mitm(get_dict(0x5A00, 0x5B00), v40, 0x5800, 0x5900)    
v36[0], v33[1], v34[2], v35[3] = mitm(get_dict(0x5E00, 0x5F00), v41, 0x5C00, 0x5D00)    
    
# round 4    
v28 = [0] * 4    
v30 = [0] * 4    
v31 = [0] * 4    
v32 = [0] * 4    
v28[0], v30[1], v31[2], v32[3] = mitm(get_dict(0x4200, 0x4300), v33, 0x4000, 0x4100)    
v31[1], v30[0], v32[2], v28[3] = mitm(get_dict(0x4600, 0x4700), v34, 0x4500, 0x4400)    
v31[0], v32[1], v28[2], v30[3] = mitm(get_dict(0x4A00, 0x4B00), v35, 0x4800, 0x4900)    
v32[0], v28[1], v30[2], v31[3] = mitm(get_dict(0x4E00, 0x4F00), v36, 0x4C00, 0x4D00)    
    
# round 3    
v24 = [0] * 4    
v25 = [0] * 4    
v26 = [0] * 4    
v27 = [0] * 4    
v25[1], v24[0], v26[2], v27[3] = mitm(get_dict(0x3200, 0x3300), v28, 0x3100, 0x3000)    
v25[0], v26[1], v27[2], v24[3] = mitm(get_dict(0x3600, 0x3700), v30, 0x3400, 0x3500)    
v26[0], v27[1], v24[2], v25[3] = mitm(get_dict(0x3A00, 0x3B00), v31, 0x3800, 0x3900)    
v27[0], v24[1], v25[2], v26[3] = mitm(get_dict(0x3E00, 0x3F00), v32, 0x3C00, 0x3D00)    
    
# round 2    
v19 = [0] * 4    
v21 = [0] * 4    
v22 = [0] * 4    
v23 = [0] * 4    
v19[0], v21[1], v22[2], v23[3] = mitm(get_dict(0x2200, 0x2300), v24, 0x2000, 0x2100)    
v22[1], v21[0], v23[2], v19[3] = mitm(get_dict(0x2600, 0x2700), v25, 0x2500, 0x2400)    
v22[0], v23[1], v19[2], v21[3] = mitm(get_dict(0x2A00, 0x2B00), v26, 0x2800, 0x2900)    
v23[0], v19[1], v21[2], v22[3] = mitm(get_dict(0x2E00, 0x2F00), v27, 0x2C00, 0x2D00)    
    
# round 1    
v13 = [0] * 4    
v15 = [0] * 4    
v17 = [0] * 4    
v18 = [0] * 4    
v17[2], v13[0], v15[1], v18[3] = mitm(get_dict(0x1100, 0x1300), v19, 0x1200, 0x1000)    
v15[0], v17[1], v18[2], v13[3] = mitm(get_dict(0x1600, 0x1700), v21, 0x1400, 0x1500)    
v17[0], v18[1], v13[2], v15[3] = mitm(get_dict(0x1A00, 0x1B00), v22, 0x1800, 0x1900)    
v18[0], v13[1], v15[2], v17[3] = mitm(get_dict(0x1E00, 0x1F00), v23, 0x1C00, 0x1D00)    
    
# round 0    
buf = [0] * 16    
buf[5], buf[0], buf[10], buf[15] = mitm(get_dict(0x200, 0x300), v13, 0x100, 0x000)    
buf[4], buf[9], buf[14], buf[3] =  mitm(get_dict(0x600, 0x700), v15, 0x400, 0x500)    
buf[13], buf[8], buf[2], buf[7] =  mitm(get_dict(0xA00, 0xB00), v17, 0x900, 0x800)    
buf[11], buf[1], buf[12], buf[6] = mitm(get_dict(0xC00, 0xE00), v18, 0xF00, 0xD00)    
    
#print buf    
    
#ROT Decode    
v4 = 0    
v5 = 0    
v6 = 0    
v7 = 0    
msg = [0] * 16    
idx = 0    
    
while True:    
    c = 0    
    for i in xrange(256):    
        v9 = ROTL(i, v6, 8)    
        v10 = ROTL(i, v5, 8) ^ v9    
        v11 = ROTL(i, v4, 8)    
    
        v12 = v11 ^ v10 ^ v7    
        v12 &= 0xff    
        #print v12, buf[idx]    
        if v12 == buf[idx]:    
            c = i    
            break    
        
    v4 += 0xF1    
    v5 += 0x54    
    v6 += 0xC3    
    v7 += 0x6C    
        
    msg[idx] = c    
    idx += 1    
    
    if v7 == 0x6C0:    
        break    
    
#msg = [chr(msg[i]) for i in xrange(len(msg))]    
#msg = ''.join(msg)    
return msg    
    
# 从IDA中导出magic_tbl    
loadTable('export_results.txt')    
    
res = decode("4bf7f78ef088f4c94472f9f61f2c3331".decode('hex'))    
print res    
a = ''.join(["%c" % res[x] for x in xrange(len(res))])    
    
res = decode("e68ac8bbcbac1e982cc246cd9dd34308".decode('hex'))    
a += ''.join(["%c" % res[x] for x in xrange(len(res))])    
print "%s" % a    
```    
