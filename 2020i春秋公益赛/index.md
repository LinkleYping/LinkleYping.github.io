# i春秋公益赛_部分re题目

  
## First    
官方wp有点简略...研究了一下补个详细的。我好菜我好菜我好菜。很多代码都是官方wp里面的，拿过来做个笔记.    
## 奇怪的安装包    
这道题其实不是很难,但是我是动态调试做出来的,看到wp上的解法要简单很多。      
这里的安装包使用nsis打包,NSIS的打包教程如下:      
[使用nsis打包程序](https://blog.csdn.net/myiloveuuu/article/details/78400153)      
其中有NSIS脚本可以自定义安装的步骤,所以这个题目中弹出的key和flag的验证窗口就是写在NSIS脚本中的。      
我本来觉得是应该有脚本的,我用了普通解压的方式解开了exe文件,但是并没有发现NSIS脚本。后来知道是NSIS后查了一下,发现只有19.00版本的7z才可以解压得到NSIS脚本。具体可以在这里下载：      
[7-Zip 19.00 增加nsis脚本反编译版](https://www.52pojie.cn/thread-877884-1-1.html)      
flag部分的验证过程如下:      
```shell    
Dialogs::InputBox 1 请输入flag "Input your flag" 确定 取消 4 6    
; Call Initialize_____Plugins    
; AllowSkipFiles off    
; File $PLUGINSDIR\Dialogs.dll    
; SetDetailsPrint lastused    
; Push 6    
; Push 4    
; Push 取消    
; Push 确定    
; Push "Input your flag"    
; Push 请输入flag    
; Push 1    
; CallInstDLL $PLUGINSDIR\Dialogs.dll InputBox    
IntCmp $4 1 0 label_415 label_415    
Push $6    
Call func_429    
Pop $6    
StrCpy $3 gm`fzd787`7bb,g72d,592b,8`g1,cg96813e8d``|    
StrCmp $3 $6 0 label_417    
MessageBox MB_OK flag正确,可以愉快的玩游戏了    
Goto label_419    
    
Function func_429    
Pop $9    
StrCpy $3 ""    
StrCpy $0 $9    
StrCpy $1 0    
label_433:    
StrCpy $2 $0 1 $1    
StrCmp $2 "" label_443    
Push $2    
Call func_445    
Pop $2    
IntOp $2 $2 ^ 1    
IntFmt $2 %c $2    
IntOp $1 $1 + 1    
StrCpy $3 $3$2    
Goto label_433    
label_443:    
Push $3    
FunctionEnd    
    
Function func_445    
Exch $0    
; Push $0    
; Exch    
; Pop $0    
Push $1    
Push $2    
StrCpy $2 1    
label_451:    
IntFmt $1 %c $2    
StrCmpS $1 $0 0 label_455    
StrCpy $0 $2    
Goto label_458    
label_455:    
IntOp $2 $2 + 1    
StrCmp $2 255 0 label_451    
StrCpy $0 0    
label_458:    
Pop $2    
Pop $1    
Exch $0    
; Push $0    
; Exch    
; Pop $0    
FunctionEnd    
```  
过程就是与1异或以后的值与gm\`fzd787\`7bb,g72d,592b,8`g1,cg96813e8d``|相等      
  
## CrackMe    
是一个修改了的AES代码(加密前后各多了一个异或的操作，并且替换了常用的S盒,代码里面还比较贴心的给了对应的逆S盒),官方给了一个比较齐全的AES的c代码(查表法),留作参考,毕竟让我自己看我是看不出来的...对照着看还有可能...    
```cpp    
//    
//  AES.hpp    
//  AES    
//    
//  Created by zoe on 2020/3/3.    
//  Copyright © 2020年 zoe. All rights reserved.    
//    
    
#pragma once    
#ifndef SRC_UTILS_AES_H    
#define SRC_UTILS_AES_H    
    
class AES    
{    
public:    
AES(unsigned char* key);    
virtual ~AES();    
unsigned char* Cipher(unsigned char* input);    // 加密，传入的数组大小必须是16字节    
unsigned char* InvCipher(unsigned char* input);    // 解密，传入的数组也必须是16字节    
void* Cipher(void* input, int length = 0);    // 可以传入数组，大小必须是16的整数倍，如果不是将会越界操作；如果不传length而默认为0，那么将按照字符串处理，遇'\0'结束    
void* InvCipher(void* input, int length);    // 必须传入数组和大小，必须是16的整数倍    
void AddRoundKey(unsigned char state[][4], unsigned char k[][4]);    
private:    
unsigned char Sbox[256];    
unsigned char InvSbox[256];    
unsigned char w[11][4][4];    
    
void KeyExpansion(unsigned char* key, unsigned char w[][4][4]);    
unsigned char FFmul(unsigned char a, unsigned char b);    
    
void SubBytes(unsigned char state[][4]);    
void ShiftRows(unsigned char state[][4]);    
void MixColumns(unsigned char state[][4]);    
    
    
void InvSubBytes(unsigned char state[][4]);    
void InvShiftRows(unsigned char state[][4]);    
void InvMixColumns(unsigned char state[][4]);    
};    
    
#endif    // SRC_UTILS_AES_H    
    
//    
//  AES.cpp    
//  AES    
//    
//  Created by zoe on 2020/3/3.    
//  Copyright © 2020年 zoe. All rights reserved.    
//    
    
#include "AES.hpp"    
#include "string.h"    
using namespace std;    
    
AES::AES(unsigned char* key)    
{    
unsigned char sBox[] =    
{    
    0x36, 0x4F, 0x62, 0xD8, 0xB5, 0x84, 0xCD, 0xF6, 0xDC, 0x2A, 0xE6, 0xED, 0xAB, 0x52, 0x01, 0xAF,    
    0xD0, 0x0A, 0x68, 0x14, 0x27, 0xA1, 0xDB, 0x87, 0x9C, 0xE7, 0x29, 0x66, 0x35, 0xE9, 0xB4, 0x91,    
    0x8B, 0xCE, 0xF3, 0x34, 0x56, 0x5E, 0x23, 0x61, 0x70, 0xC3, 0xA7, 0x32, 0x2D, 0x80, 0x0C, 0xC4,    
    0xF5, 0x2C, 0x72, 0xA4, 0xC9, 0x06, 0xB9, 0x6E, 0x19, 0x12, 0x07, 0x22, 0xD6, 0xD3, 0x00, 0x71,    
    0x98, 0x0E, 0x6B, 0xCA, 0x64, 0x3D, 0xBA, 0xFE, 0x88, 0x02, 0xE3, 0x46, 0xEF, 0x1F, 0x2F, 0x8F,    
    0x2E, 0x3A, 0x31, 0x9B, 0xF0, 0xE2, 0x7B, 0x99, 0xBB, 0xA8, 0x48, 0x63, 0xD4, 0x8D, 0xF4, 0x69,    
    0xBF, 0xE8, 0x4B, 0xDE, 0xDA, 0x76, 0xB0, 0x10, 0xB8, 0x97, 0xC6, 0x9F, 0x16, 0xF7, 0xAC, 0xDD,    
    0x45, 0xBC, 0xC5, 0xE1, 0xAD, 0x7C, 0x5B, 0xFC, 0xCC, 0xAE, 0x59, 0x9A, 0x6F, 0xE5, 0x67, 0xA3,    
    0x58, 0xC7, 0x8C, 0x65, 0x81, 0x49, 0x53, 0x83, 0x40, 0x39, 0x5D, 0x37, 0xB1, 0x74, 0x8E, 0x4D,    
    0xCF, 0x33, 0xF8, 0xA2, 0x75, 0x73, 0xFA, 0xD7, 0x4A, 0xCB, 0x82, 0x78, 0x17, 0xE0, 0x95, 0x7D,    
    0x08, 0xF1, 0xBD, 0x41, 0xB7, 0x04, 0x0F, 0x8A, 0xD1, 0x51, 0x3E, 0x38, 0x93, 0xC2, 0x89, 0xD2,    
    0x96, 0x94, 0x1A, 0xFB, 0x5F, 0x7E, 0x60, 0x24, 0x54, 0xEA, 0x7F, 0x0B, 0x1B, 0x43, 0x26, 0x2B,    
    0x1C, 0xB3, 0x4E, 0x85, 0x3F, 0x5A, 0xC0, 0x1E, 0x50, 0x77, 0xFF, 0x09, 0xE4, 0x9E, 0x25, 0x9D,    
    0x05, 0x13, 0xEE, 0xD5, 0x30, 0xAA, 0x28, 0x79, 0x86, 0x4C, 0xF9, 0x57, 0x6D, 0xEB, 0x47, 0xB2,    
    0xD9, 0x18, 0xB6, 0xBE, 0x7A, 0xC1, 0xA0, 0x0D, 0x5C, 0xC8, 0xA5, 0x44, 0x6A, 0x3C, 0x20, 0xA6,    
    0x03, 0x11, 0x3B, 0x15, 0x90, 0xFD, 0x92, 0xEC, 0xA9, 0x21, 0x55, 0x1D, 0xDF, 0x6C, 0x42, 0xF2    
};    
unsigned char invsBox[256] =    
{    
    0x3e, 0x0e, 0x49, 0xf0, 0xa5, 0xd0, 0x35, 0x3a, 0xa0, 0xcb, 0x11, 0xbb, 0x2e, 0xe7, 0x41, 0xa6,    
    0x67, 0xf1, 0x39, 0xd1, 0x13, 0xf3, 0x6c, 0x9c, 0xe1, 0x38, 0xb2, 0xbc, 0xc0, 0xfb, 0xc7, 0x4d,    
    0xee, 0xf9, 0x3b, 0x26, 0xb7, 0xce, 0xbe, 0x14, 0xd6, 0x1a, 0x09, 0xbf, 0x31, 0x2c, 0x50, 0x4e,    
    0xd4, 0x52, 0x2b, 0x91, 0x23, 0x1c, 0x00, 0x8b, 0xab, 0x89, 0x51, 0xf2, 0xed, 0x45, 0xaa, 0xc4,    
    0x88, 0xa3, 0xfe, 0xbd, 0xeb, 0x70, 0x4b, 0xde, 0x5a, 0x85, 0x98, 0x62, 0xd9, 0x8f, 0xc2, 0x01,    
    0xc8, 0xa9, 0x0d, 0x86, 0xb8, 0xfa, 0x24, 0xdb, 0x80, 0x7a, 0xc5, 0x76, 0xe8, 0x8a, 0x25, 0xb4,    
    0xb6, 0x27, 0x02, 0x5b, 0x44, 0x83, 0x1b, 0x7e, 0x12, 0x5f, 0xec, 0x42, 0xfd, 0xdc, 0x37, 0x7c,    
    0x28, 0x3f, 0x32, 0x95, 0x8d, 0x94, 0x65, 0xc9, 0x9b, 0xd7, 0xe4, 0x56, 0x75, 0x9f, 0xb5, 0xba,    
    0x2d, 0x84, 0x9a, 0x87, 0x05, 0xc3, 0xd8, 0x17, 0x48, 0xae, 0xa7, 0x20, 0x82, 0x5d, 0x8e, 0x4f,    
    0xf4, 0x1f, 0xf6, 0xac, 0xb1, 0x9e, 0xb0, 0x69, 0x40, 0x57, 0x7b, 0x53, 0x18, 0xcf, 0xcd, 0x6b,    
    0xe6, 0x15, 0x93, 0x7f, 0x33, 0xea, 0xef, 0x2a, 0x59, 0xf8, 0xd5, 0x0c, 0x6e, 0x74, 0x79, 0x0f,    
    0x66, 0x8c, 0xdf, 0xc1, 0x1e, 0x04, 0xe2, 0xa4, 0x68, 0x36, 0x46, 0x58, 0x71, 0xa2, 0xe3, 0x60,    
    0xc6, 0xe5, 0xad, 0x29, 0x2f, 0x72, 0x6a, 0x81, 0xe9, 0x34, 0x43, 0x99, 0x78, 0x06, 0x21, 0x90,    
    0x10, 0xa8, 0xaf, 0x3d, 0x5c, 0xd3, 0x3c, 0x97, 0x03, 0xe0, 0x64, 0x16, 0x08, 0x6f, 0x63, 0xfc,    
    0x9d, 0x73, 0x55, 0x4a, 0xcc, 0x7d, 0x0a, 0x19, 0x61, 0x1d, 0xb9, 0xdd, 0xf7, 0x0b, 0xd2, 0x4c,    
    0x54, 0xa1, 0xff, 0x22, 0x5e, 0x30, 0x07, 0x6d, 0x92, 0xda, 0x96, 0xb3, 0x77, 0xf5, 0x47, 0xca    
};    
    
/*    
 unsigned char sBox[] =    
 {    
 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,    
 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,    
 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,    
 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,    
 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,    
 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,    
 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,    
 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,    
 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,    
 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,    
 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,    
 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,    
 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,    
 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,    
 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,    
 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16    
 };    
 unsigned char invsBox[256] =    
 {    
 0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,    
 0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,    
 0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,    
 0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,    
 0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,    
 0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,    
 0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,    
 0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,    
 0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,    
 0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,    
 0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,    
 0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,    
 0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,    
 0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,    
 0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,    
 0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d    
 };*/    
    
memcpy(Sbox, sBox, 256);    
memcpy(InvSbox, invsBox, 256);    
KeyExpansion(key, w);    
}    
    
AES::~AES()    
{    
    
}    
    
unsigned char* AES::Cipher(unsigned char* input)    
{    
unsigned char state[4][4];    
int i, r, c;    
int key1[4][4] = { 0x88, 0x88,0x66,0x77,0x99, 0x99,0x66,0x77,0x99,0x88,0x66,0x77,0x99,0x88,0x66,0x77 };    
for (r = 0; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        state[r][c] = input[c * 4 + r]^key1[r][c];//后来添加的    
    }    
}    
    
AddRoundKey(state, w[0]);    
    
for (i = 1; i <= 10; i++)    
{    
    SubBytes(state);    
    ShiftRows(state);    
    if (i != 10)MixColumns(state);    
    AddRoundKey(state, w[i]);    
}    
int key[4][4] = {0x88,0x99,0x66,0x77,0x99, 0x88,0x66,0x77,0x88,0x66,0x77,0x99, 0x88,0x66,0x77,0x99};    
for (r = 0; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        input[c * 4 + r] = state[r][c]^key[r][c];//后来添加的    
    }    
}    
    
return input;    
}    
    
unsigned char* AES::InvCipher(unsigned char* input)    
{    
unsigned char state[4][4];    
int i, r, c;    
int key[4][4] = { 0x88,0x99,0x66,0x77,0x99, 0x88,0x66,0x77,0x88,0x66,0x77,0x99, 0x88,0x66,0x77,0x99};    
for (r = 0; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        state[r][c] = input[c * 4 + r] ^ key[r][c];  //解密的过程也加上这部分    
    }    
}    
    
AddRoundKey(state, w[10]);    
for (i = 9; i >= 0; i--)    
{    
    InvShiftRows(state);    
    InvSubBytes(state);    
    AddRoundKey(state, w[i]);    
    if (i)    
    {    
        InvMixColumns(state);    
    }    
}    
int key1[4][4] = { 0x88, 0x88,0x66,0x77,0x99, 0x99,0x66,0x77,0x99,0x88,0x66,0x77,0x99,0x88,0x66,0x77 };    
for (r = 0; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        input[c * 4 + r] = state[r][c] ^ key1[r][c];    
    }    
}    
    
return input;    
}    
    
void* AES::Cipher(void* input, int length)    
{    
unsigned char* in = (unsigned char*)input;    
int i;    
if (!length)        // 如果是0则当做字符串处理    
{    
    while (*(in + length++));    
    in = (unsigned char*)input;    
}    
for (i = 0; i < length; i += 16)    
{    
    Cipher(in + i);    
}    
return input;    
}    
    
void* AES::InvCipher(void* input, int length)    
{    
unsigned char* in = (unsigned char*)input;    
int i;    
for (i = 0; i < length; i += 16)    
{    
    InvCipher(in + i);    
}    
return input;    
}    
    
void AES::KeyExpansion(unsigned char* key, unsigned char w[][4][4])    
{    
int i, j, r, c;    
//----------------------------------------------------
unsigned char rc[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };    
for (r = 0; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        w[0][r][c] = key[r + c * 4];    
//            int kk = r + c * 4;    
    }    
}    
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
}    
    
unsigned char AES::FFmul(unsigned char a, unsigned char b)    
{    
unsigned char bw[4];    
unsigned char res = 0;    
int i;    
bw[0] = b;    
for (i = 1; i < 4; i++)    
{    
    bw[i] = bw[i - 1] << 1;    
    if (bw[i - 1] & 0x80)    
    {    
        bw[i] ^= 0x1b;    
    }    
}    
for (i = 0; i < 4; i++)    
{    
    if ((a >> i) & 0x01)    
    {    
        res ^= bw[i];    
    }    
}    
return res;    
}    
    
void AES::SubBytes(unsigned char state[][4])    
{    
int r, c;    
for (r = 0; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        state[r][c] = Sbox[state[r][c]];    
    }    
}    
}    
    
void AES::ShiftRows(unsigned char state[][4])    
{    
unsigned char t[4];    
int r, c;    
for (r = 1; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        t[c] = state[r][(c + r) % 4];    
    }    
    for (c = 0; c < 4; c++)    
    {    
        state[r][c] = t[c];    
    }    
}    
}    
    
void AES::MixColumns(unsigned char state[][4])    
{    
unsigned char t[4];    
int r, c;    
for (c = 0; c < 4; c++)    
{    
    for (r = 0; r < 4; r++)    
    {    
        t[r] = state[r][c];    
    }    
    for (r = 0; r < 4; r++)    
    {    
        state[r][c] = FFmul(0x02, t[r])    
        ^ FFmul(0x03, t[(r + 1) % 4])    
        ^ FFmul(0x01, t[(r + 2) % 4])    
        ^ FFmul(0x01, t[(r + 3) % 4]);    
    }    
}    
}    
    
void AES::AddRoundKey(unsigned char state[4][4], unsigned char k[4][4])    
{    
int r, c;    
for (c = 0; c < 4; c++)    
{    
    for (r = 0; r < 4; r++)    
    {    
        state[r][c] ^= k[r][c];    
    }    
}    
}    
    
void AES::InvSubBytes(unsigned char state[][4])    
{    
int r, c;    
for (r = 0; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        state[r][c] = InvSbox[state[r][c]];    
    }    
}    
}    
    
void AES::InvShiftRows(unsigned char state[][4])    
{    
unsigned char t[4];    
int r, c;    
for (r = 1; r < 4; r++)    
{    
    for (c = 0; c < 4; c++)    
    {    
        t[c] = state[r][(c - r + 4) % 4];    
    }    
    for (c = 0; c < 4; c++)    
    {    
        state[r][c] = t[c];    
    }    
}    
}    
    
void AES::InvMixColumns(unsigned char state[][4])    
{    
unsigned char t[4];    
int r, c;    
for (c = 0; c < 4; c++)    
{    
    for (r = 0; r < 4; r++)    
    {    
        t[r] = state[r][c];    
    }    
    for (r = 0; r < 4; r++)    
    {    
        state[r][c] = FFmul(0x0e, t[r])    
        ^ FFmul(0x0b, t[(r + 1) % 4])    
        ^ FFmul(0x0d, t[(r + 2) % 4])    
        ^ FFmul(0x09, t[(r + 3) % 4]);    
    }    
}    
}    
    
//    
//  main.cpp    
//  AES    
//    
//  Created by zoe on 2020/3/3.    
//  Copyright © 2020年 zoe. All rights reserved.    
//    
    
#include "AES.hpp"    
#include <stdio.h>    
#include <stdlib.h>    
#include <string.h>    
#include <string>    
using namespace std;    
    
int main() {    
//flag{8a6e13fc-4ea0-47fa-9d5c-07a3c2c28ed9}";    
    
unsigned char hexData[48] = {    
    0x20,0xb0,0x0e,0xa2,0x0c,0x3a,0x15,0x55,0x1d,0x0b,0x5b,0x8e,0x1c,0x2a,0xce,0x54,0xb4,0x4a,0xc1,0xbc,0x00,0x3c,0xac,0x40,0x42,0x03,0x71,0xbd,0x25,0x3a,0xb9,0xe9,0xf0,0x89,0x40,0x2d,0x6f,0x94,0x47,0x16,0xea,0xf9,0x0f,0x95,0xab,0xc8,0xcb,0x14    
};    
unsigned char key[] = "696368756e716975";    
AES aes(key);    
aes.InvCipher(hexData, 48);    
for (int i = 0; i < 48; i++) {    
    printf("%c", hexData[i]);    
        
}    
printf("\n");    
return 0;    
    
}    
```  
  
## Factory    
这个题是个VM, 程序利用父进程与子进程之间使用signal通信来执行opcode,且signal的注册在main之前,main之前还利用以下代码进程反调试      
```cpp    
v0 = getppid();    
snprintf(&s, 0x18uLL, "/proc/%d/cmdline", v0);    
stream = fopen(&s, "r");    
fgets(&v5, 256, stream);    
```  
signal注册的代码如下:    
![](/images/b20263284ea0618c2a1d24897c22b593/11884068-988530e8005521b1.png)    
  
子进程使用opcode执行每个handler的过程如下:      
![](/images/b20263284ea0618c2a1d24897c22b593/11884068-3adde0ad980a2deb.png)    
  
看到一个简单的关于vm解题的教程:      
[从做题到出题再到做题三部曲-VM](https://xz.aliyun.com/t/3890)      
提取opcode进行解释:(最主要的是要有寄存器、堆栈、EIP的想法)    
```python    
def func34(arg):    
    global r0,r1,r2,oparg    
    if arg == "r0":    
        f.write("PUSH " + arg + '\n')    
        stack.append(r0)    
    elif arg == "r1":    
        f.write("PUSH " + arg + '\n')    
        stack.append(r1)    
    elif arg == "r2":    
        f.write("PUSH " + arg + '\n')    
        stack.append(r2)    
    elif arg == "arg":    
        f.write("PUSH "+ str(oparg) + '\n')    
        stack.append(oparg)    
    
def func35(arg):    
    global r0,r1,r2    
    f.write("POP " + arg + '\n')    
    if arg == "r0":    
        r0 = stack.pop()    
    elif arg == "r1":    
        r1 = stack.pop()    
    elif arg == "r2":    
        r2 = stack.pop()    
def func36():    
    f.write("ADD r0, r1\n")    
    def func37(arg):    
    global oparg,r0,r1,r2    
    f.write("ADD " + arg + ", " + str(oparg) + '\n')    
    if arg == "r0":    
        r0 = r0 + oparg    
    elif arg == "r1":    
        r1 = r1 + oparg    
    elif arg == "r2":    
        r2 = r2 + oparg    
def func38():    
    f.write("SUB r0, r1\n")    
    def func39(arg):    
    global oparg,r0,r1,r2    
    f.write("SUB " + arg + ", " + str(oparg) + '\n')    
    if arg == "r0":    
        r0 = r0 - oparg    
    elif arg == "r1":    
        r1 = r1 - oparg    
    elif arg == "r2":    
        r2 = r2 - oparg    
def func40():    
    f.write("XOR r0, r1\n")    
    def func41():    
    global flag    
    f.write("CMP r0, r1\n")    
    flag = (r0 == r1)    
def func42():    
    global EIP, oparg    
    f.write("PUSH EIP\n")    
    stack.append(EIP)    
    f.write("MOV EIP, " + str(oparg) + '\n')    
    EIP = oparg    
def func43():    
    global EIP    
    f.write("POP EIP\n")    
    EIP = stack.pop()    
def func44():    
    global EIP, oparg    
    f.write("MOV EIP, " + str(oparg) + '\n')    
    EIP = oparg    
def func45():    
    global EIP, oparg, flag    
    if flag:    
        f.write("EQ MOV EIP, " + str(oparg) + '\n')    
        EIP = oparg    
def func46():    
    global r2    
    f.write("PUSH input["+str(r2)+"]\n")    
    stack.append(input[r2])    
def func47():    
    global r2    
    f.write("POP input["+str(r2)+"]\n")    
    input[r2] = stack.pop()    
    
opcodes = [0x11, 0x34, 0x0, 0x2a, 0x5, 0x10, 0x14, 0x9, 0x17, 0x0, 0x20, 0x5, 0x3, 0x11, 0x1d, 0x6, 0x0, 0x0, 0x5, 0x3, 0x11, 0x40, 0x6, 0x0, 0x40, 0x5, 0x11, 0x1d, 0x17, 0xe, 0x1, 0x15, 0x4, 0xf, 0x1, 0x16, 0x2, 0x0, 0x0, 0x4, 0x3, 0x5, 0x10, 0x14, 0x32, 0x5, 0x9, 0x2, 0x13, 0x1d, 0x5, 0x12, 0x15, 0x4, 0x10, 0x14, 0x3d, 0xa, 0x1, 0x13, 0x34, 0x3, 0x4, 0x12, 0xe, 0x1, 0x15, 0x4, 0x7, 0x1, 0x16, 0x2, 0x0, 0x0, 0x4, 0x3, 0x5, 0x10, 0x14, 0x55, 0x5, 0x9, 0x1, 0x13, 0x40, 0x5, 0x12]    
f = open("instructions.txt", "w+")    
EIP = 0    
r0 = 0    
r1 = 0    
r2 = 0    
esp = 0    
r4 = 0    
flag = 0    
stack = []    
t = [0, 8, 9, 0xa, 0xc, 0xd, 0xe, 0x11, 0x13, 0x14]    
oparg = 0    
input = [104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 0]    
while True:    
    opcode = opcodes[EIP]    
    EIP = EIP + 1    
    if opcode == 0x17:    
        f.write("Retn 0x17\n")    
        break    
    if opcode in t:    
        oparg = opcodes[EIP]    
        EIP += 1    
    if opcode == 0:    
        func34("arg")    
    elif opcode == 1:    
        func34("r0")    
    elif opcode == 2:    
        func34("r1")    
    elif opcode == 3:    
        func34("r2")    
    elif opcode == 4:    
        func35("r0")    
    elif opcode == 5:    
        func35("r1")    
    elif opcode == 6:    
        func35("r2")    
    elif opcode == 7:    
        func36()    
    elif opcode == 8:    
        func37("r0")    
    elif opcode == 9:    
        func37("r1")    
    elif opcode == 0xa:    
        func37("r2")    
    elif opcode == 0xb:    
        func38()    
    elif opcode == 0xc:    
        func39("r0")    
    elif opcode == 0xd:    
        func39("r1")    
    elif opcode == 0xe:    
        func39("r2")    
    elif opcode == 0xf:    
        func40()    
    elif opcode == 0x10:    
        func41()    
    elif opcode == 0x11:    
        func42()    
    elif opcode == 0x12:    
        func43()    
    elif opcode == 0x13:    
        func44()    
    elif opcode == 0x14:    
        func45()    
    elif opcode == 0x15:    
        func46()    
    elif opcode == 0x16:    
        func47()    
    else:    
        f.write("Retn " + str(opcode) + '\n')    
        break    
```  
提取出来伪汇编代码：      
![](/images/b20263284ea0618c2a1d24897c22b593/11884068-86e424bc80ca6aa2.png)    
  
代码的流程就是首先计算字符串长度,长度需要等于42,然后从最后一个元素开始,每一个字符异或(0x20 + 2 * i)然后减去i,最后异或(0x40 + 2 * i)      
## Code2    
没做出来...wtcl      
看到wp上写的是arithmetic coding算法,中间调试的时候发现了有浮点数,所以觉得还挺奇怪的,没见过arithmetic coding算法,记录一下。      
[算术编码Arithmetic Coding](https://www.cnblogs.com/xubenben/p/3426646.html)      
这个算法大致的想法是根据一个字符与浮点数的对应表将一个字符串映射成一个浮点数,然后还可以根据这个表和最后的浮点数还原出字符串。  我感觉这个题用的算法跟给的链接的算术编码算法相比有一点区别,根据反汇编代码对原始算法进行了一些更改。      
```cpp    
#include<iostream>    
#include<map>    
#include<string>    
#include<cassert>    
#include<utility>    
    
using namespace std;    
int main(int argc,char **argv)    
{    
    double High=1.0;    
    double Low=0.0;    
    string original="8ab86b896";    
        
    //create a map to store all chars and it's occurrence frequency    
    map<char,pair<double,double>> char_freq;    
    char_freq['8'] = make_pair(0.0,0.33333334);    
    char_freq['a'] = make_pair(0.33333334,0.11111111);    
    char_freq['b'] = make_pair(0.44444445,0.22222222);    
    char_freq['6'] = make_pair(0.66666669,0.11111111);    
    char_freq['9'] = make_pair(0.777778,0.11111111);    
    char_freq['7'] = make_pair(0.888889,0.11111111);    
        
    for(string::size_type i=0;i<original.size();i++)    
    {    
        char temp=original[i];    
        assert(char_freq.count(temp));    
        
        double Range=High;    
        High=High*char_freq[temp].second;    
        Low=Low+Range*char_freq[temp].first;    
    }    
    double result=Low;    
    cout<<"Compression Result: "<<result<<endl;    
    //the core code to decompress    
    result = 0.1295556;    
    bool goon=true;    
    cout<<"Original Text: ";    
    do{    
        map<char,pair<double,double> >::const_iterator itr=char_freq.begin();    
        while(itr!=char_freq.end())    
        {    
            if((result - itr->second.first) / itr->second.second >= 0.0 && (result - itr->second.first) / itr->second.second <= 0.888889)    
            {    
                cout<<itr->first;    
                result=(result - itr->second.first) / itr->second.second;    
                break;    
            }    
            ++itr;    
        }    
        if(itr==char_freq.end())    
            goon=false;    
    }while(goon);    
    cout<<endl;    
    return 0;    
}    
```  
因为给的浮点数是一个范围,所以还原出来的原始字符串并不完全正确,最后一位有一些区别,但是因为字符只能是给定的6个字符,所以还比较容易试出来结果。      
## Veryeasyre    
一共有两个验证,第一层验证是一个。(总字符串的长度是81,输入的字符串依次填补在总字符串中为0的地方,填补完以后9\*9的数组中,每行每列每个3*3块都是数字1-9),原始字符串如下:        
```c    
0 0 5 0 9 4 0 0 0     
0 0 1 5 0 0 2 0 9     
0 7 0 2 0 0 0 0 1     
0 9 0 0 0 0 0 0 6     
8 0 0 0 0 0 1 0 5     
5 0 0 0 2 0 0 0 8     
0 0 0 3 5 0 0 7 0     
7 4 0 0 0 6 0 1 0     
3 0 0 0 0 7 8 0 0    
```  
输入的字符串依次填补在0处,找到了一个求的代码:      
```python    
import re    
import copy    
    
# 默认模板-->在这里写准备求的    
sudoku_template1 = [[ 0 , 0 , 5 , 0 , 9 , 4 , 0 , 0 , 0 ], [ 0 , 0 , 1 , 5 , 0 , 0 , 2 , 0 , 9 ], [ 0 , 7 , 0 , 2 , 0 , 0 , 0 , 0 , 1 ], [ 0 , 9 , 0 , 0 , 0 , 0 , 0 , 0 , 6 ], [ 8 , 0 , 0 , 0 , 0 , 0 , 1 , 0 , 5 ], [ 5 , 0 , 0 , 0 , 2 , 0 , 0 , 0 , 8 ], [ 0 , 0 , 0 , 3 , 5 , 0 , 0 , 7 , 0 ], [ 7 , 4 , 0 , 0 , 0 , 6 , 0 , 1 , 0 ], [ 3 , 0 , 0 , 0 , 0 , 7 , 8 , 0 , 0 ]]    
    
    
# 芬兰数学家英卡拉（Arto Inkala）设计的号称“最难” - 1000次平均耗时320ms/次    
sudoku_template2 = [[8,0,0,0,0,0,0,0,0],    
                [0,0,3,6,0,0,0,0,0],    
                [0,7,0,0,9,0,2,0,0],    
                [0,5,0,0,0,7,0,0,0],    
                [0,0,0,0,4,5,7,0,0],    
                [0,0,0,1,0,0,0,3,0],    
                [0,0,1,0,0,0,0,6,8],    
                [0,0,8,5,0,0,0,1,0],    
                [0,9,0,0,0,0,4,0,0]]    
    
def crack_it(sudoku=sudoku_template1):    
    '''主函数,输入进行运算,如未输入则调用默认,格式为9x9的二维列表'''    
    init_sudoku = str_to_num(copy.deepcopy(sudoku))   # Python的坑！列表或字典等对象作为函数参数时,函数可能修改其元素的指针,导致外部列表也会改变    
    if is_valid_sudoku(sudoku):   # 判断输入的Sudoku是否合理（是否冲突）    
        candidate_list = filter_candidate_list(init_sudoku, init_candidate_list(init_sudoku), start=0)   # 针对Sudoku中的每一个空格（空格都默认填入数字0）,都算出其可能的备选数,存入data_list中；每当空格被确认唯一值时,剩余data_list都需要再被刷新    
        cracked_sudoku = fill_blank(init_sudoku, candidate_list, start=0)   # 破解    
        print_sudoku(cracked_sudoku)   # 在控制台显示已破解的,默认开启    
        return cracked_sudoku    
    else:    
        return '请检查一下输入是否有误- -0'    
    
def str_to_num(data):    
    '''初步校验+统一格式,空字符转0,无效字符转0'''    
    for i in range(9):    
        for j in range(9):    
            if re.match('[1-9]', str(data[i][j])):   # 1-9字符转int 1-9    
                data[i][j] = int(data[i][j])    
            elif re.match('', str(data[i][j])):   # 空位转int 0    
                data[i][j] = 0    
            else:   # 无效字符转int 0,或者也可以return False,拒绝服务    
                data[i][j] = 0    
    return data    
                
    
def is_valid_sudoku(data):    
    '''判断整个是否有效'''    
    for y in range(9):    
        for x in range(9):    
            if data[y][x] > 9:    
                return False    
        
            if data[y][x] != 0 and data[y].count(data[y][x]) > 1:    
                return False    
        
            for col in range(9):    
                if data[y][x] != 0 and col != y:    
                    if data[col][x] == data[y][x]:    
                        return False    
        
            for i in range(3):    
                for j in range(3):    
                    if data[y][x] != 0 and (i+3*(y//3), j+3*(x//3)) != (y, x):    
                        if data[i+3*(y//3)][j+3*(x//3)] == data[y][x]:    
                            return False    
    return True    
    
def init_candidate_list(data):    
    '''初始化建立一个的备选数列表,一个空格就对应其坐标以及填上1~9的备选数字,格式为81x9的二维列表'''    
    data_list = []    
    for y in range(9):    
        for x in range(9):    
            if data[y][x] == 0:    
                data_list.append([(x, y), [1, 2, 3, 4, 5, 6, 7, 8, 9]])    
    return data_list    
    
def filter_candidate_list(data, data_list, start):    
    '''对的备选数表进行过滤,删除无效的备选数'''    
    for blank_index in range(start, len(data_list)):    
        data_list[blank_index][1] = []    
        for num in range(1,10):    
            if is_valid_num(data, data_list[blank_index][0][0], data_list[blank_index][0][1], num):    
                data_list[blank_index][1].append(num)    
    return data_list    
    
def is_valid_num(data, x, y, num):    
    '''输入、坐标、数字,判断该位置填入该数字是否合理'''    
    if data[y].count(num) > 0:   # 行判断    
        return False    
        
    for col in range(9):   # 列判断    
        if data[col][x] == num:    
            return False    
        
    for a in range(3):   # 九宫格判断    
        for b in range(3):    
            if data[a+3*(y//3)][b+3*(x//3)] == num:    
                return False    
    return True    
    
def fill_blank(data, data_list, start):    
    '''    
    核心函数,递归尝试代入备选数,类似深度优先遍历算法。    
    一旦某位置填入为True（由is_valid_num函数判断）,则开始下一位置的填入；若某位置填入为False,则return回上一级。    
    参数解释：    
    data: 矩阵,二维列表    
    data_list: 备选数表,二维列表    
    start: 递归进行的位置,对应data_list的下标    
    '''    
    all_data = []    
    if start < len(data_list):    
        one = data_list[start]    
        for num in one[1]:    
            if is_valid_num(data, one[0][0], one[0][1], num):    
                data[one[0][1]][one[0][0]] = num   # 赋值,如果能给每一格成功赋值,则意味破解成功；如果出现失败,则需要将错误赋值清零    
                # data_list = filter_candidate_list(data, data_list, start)   # 每一步赋值都会改变备选数表,但刷新备选数表的操作非常耗时,若加上这句,速度会慢100倍    
                tem_data = fill_blank(data, data_list, start+1)   # start+1,使递归进入下一格点    
                if tem_data:   # 注意！如果下一格点return,分两种情况：1.成功破解所有格点；2.发生错误,for loop结束也会return,此时返回值为None    
                    return tem_data    
        data[one[0][1]][one[0][0]] = 0   # 注意！可能向下递归了若干格才发现前面是错误的（即for loop结束,return None）,此时需要将所有错误的赋值清零。    
    else:    
        return data    
    
def print_sudoku(data):    
    '''打印到控制台'''    
    print('>>> 破解结果:')    
    # for i in range(9):    
    #     for j in range(9):    
    #         print('{:^3}'.format(data[i][j]), end='')    
    #     print('')    
    # print('')    
    s = ""    
    for i in range(9):    
        for j in range(9):    
            if sudoku_template1[i][j] == 0:    
                s = s + str(data[i][j])    
    print(s)  #输出原始中是0的部分    
    
if __name__ == '__main__':    
    crack_it()    
```  
在验证通过后做了一个异或运算并且提示"This is part of the key"(ps:真的每一句提示都要仔细琢磨一下...),异或一下:      
```python    
import idc    
s = "28163746738936845178453226739434617961829429853594162"    
key = []    
ex = 0x277190    
for i in range(16):    
    a = idc.Dword(ex + 4 * i)    
    key.append(a ^ ord(s[i * 3]))    
print key    
print "".join(chr(i) for i in key)    
#fa{3cmtL!#U_vr03 <--输出    
```  
后面的代码要求输入长度为32的字符串,使用一个流密码算法加密,加密的密钥是输入字符串的奇数位组成的16位字符串,根据刚才part of the key的提示,以及输出字符串的内容可以联想到,`fa{3cmtL!#U_vr03`就是输入的奇数位字符串,任意补全偶数位,就可以得到经过变换后的key,将这些key与加密后的内容异或就可以得到flag.      
```python    
key = [0x9c, 0x34, 0x11, 0x27, 0x52, 0x2d, 0x05, 0x90, 0x41,0x17,0x86,0xa6, 0xd9,0xd4,0x72, 0xc3, 0x21, 0x6a, 0xa5, 0xb5, 0x13, 0x7d, 0x5e, 0xfe, 0xfc, 0x60, 0xbd, 0xd2, 0xaa, 0x07, 0x31, 0x6f]  #流密码中变换后的key    
enc = [65, 125, 85, 251, 235, 82, 30, 62, 197, 233, 122, 36, 183, 29, 152, 233, 148, 250, 73, 123, 171, 29, 34, 86, 164, 142, 18, 133, 95, 95, 52, 215]    
print enc    
s = ""    
for i in range(32):    
    s = s + chr(enc[i] ^ key[(i // 4)*4 + 3 - i%4])    
print s    
# flag{W3lcometoL0!_#ZUC_Ev3ry0n3}    
```  
看到wp中提到,这个流密码是ZUC,给了一个ZUC的源码,学习一下      
```cpp    
/* ————————————W—————————- */    
typedef unsigned char u8;    
typedef unsigned int u32;    
/* —————————————t————————- */    
/* the state registers of LFSR 16 cells*/    
u32 LFSR_S0;    
u32 LFSR_S1;    
u32 LFSR_S2;    
u32 LFSR_S3;    
u32 LFSR_S4;    
u32 LFSR_S5;    
u32 LFSR_S6;    
u32 LFSR_S7;    
u32 LFSR_S8;    
u32 LFSR_S9;    
u32 LFSR_S10;    
u32 LFSR_S11;    
u32 LFSR_S12;    
u32 LFSR_S13;    
u32 LFSR_S14;    
u32 LFSR_S15;    
/* the registers of f算法中的R1,R2 */    
u32 F_R1;    
u32 F_R2;    
/* the outputs of BitReorganization BR中的X0,X1,X2,X3*/    
u32 BRC_X0;    
u32 BRC_X1;    
u32 BRC_X2;    
u32 BRC_X3;    
/* the s-boxes 两个S盒*/    
u8 S0[256] = {    
0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,    
0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,    
0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,    
0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,    
0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,    
0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,    
0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,    
0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,    
0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,    
0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,    
0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,    
0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,    
0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,    
0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,    
0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,    
0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60    
};    
//s0盒    
u8 S1[256] = {    
0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,    
0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,    
0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,    
0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,    
0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,    
0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,    
0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,    
0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,    
0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,    
0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,    
0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,    
0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,    
0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,    
0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,    
0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,    
0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2    
};    
//s1盒    
/* the constants D */    
u32 EK_d[16] = {    
0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,    
0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC    
};    
/* ——————————————————————- */    
/* c = a + b mod (2^31 – 1)  那个附录里复杂的计算*/    
u32 AddM(u32 a, u32 b) {    
	u32 c = a + b;    
	return (c & 0x7FFFFFFF) + (c >> 31);    
}    
/* LFSR with initialization mode */    
#define MulByPow2(x, k) ((((x) << k) | ((x) >> (31 - k))) & 0x7FFFFFFF)     
void LFSRWithInitialisationMode(u32 u) {    
	u32 f, v; f = LFSR_S0;    
	v = MulByPow2(LFSR_S0, 8);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S4, 20);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S10, 21);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S13, 17);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S15, 15);    
	f = AddM(f, v);    
    
	f = AddM(f, u);    
	/* update the state */    
	LFSR_S0 = LFSR_S1;    
	LFSR_S1 = LFSR_S2;    
	LFSR_S2 = LFSR_S3;    
	LFSR_S3 = LFSR_S4;    
	LFSR_S4 = LFSR_S5;    
	LFSR_S5 = LFSR_S6;    
	LFSR_S6 = LFSR_S7;    
	LFSR_S7 = LFSR_S8;    
	LFSR_S8 = LFSR_S9;    
	LFSR_S9 = LFSR_S10;    
	LFSR_S10 = LFSR_S11;    
	LFSR_S11 = LFSR_S12;    
	LFSR_S12 = LFSR_S13;    
	LFSR_S13 = LFSR_S14;    
	LFSR_S14 = LFSR_S15;    
	LFSR_S15 = f;    
}    
/* LFSR with work mode 工作模式*/    
void LFSRWithWorkMode() {    
	u32 f, v; f = LFSR_S0;    
	v = MulByPow2(LFSR_S0, 8);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S4, 20);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S10, 21);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S13, 17);    
	f = AddM(f, v);    
    
	v = MulByPow2(LFSR_S15, 15);    
	f = AddM(f, v);    
    
	/* update the state */    
	LFSR_S0 = LFSR_S1;    
	LFSR_S1 = LFSR_S2;    
	LFSR_S2 = LFSR_S3;    
	LFSR_S3 = LFSR_S4;    
	LFSR_S4 = LFSR_S5;    
	LFSR_S5 = LFSR_S6;    
	LFSR_S6 = LFSR_S7;    
	LFSR_S7 = LFSR_S8;    
	LFSR_S8 = LFSR_S9;    
	LFSR_S9 = LFSR_S10;    
	LFSR_S10 = LFSR_S11;    
	LFSR_S11 = LFSR_S12;    
	LFSR_S12 = LFSR_S13;    
	LFSR_S13 = LFSR_S14;    
	LFSR_S14 = LFSR_S15;    
	LFSR_S15 = f;    
}    
    
/* BitReorganization */    
void BitReorganization() {    
	BRC_X0 = ((LFSR_S15 & 0x7FFF8000) << 1) | (LFSR_S14 & 0xFFFF);    
	BRC_X1 = ((LFSR_S11 & 0xFFFF) << 16) | (LFSR_S9 >> 15);    
	BRC_X2 = ((LFSR_S7 & 0xFFFF) << 16) | (LFSR_S5 >> 15);    
	BRC_X3 = ((LFSR_S2 & 0xFFFF) << 16) | (LFSR_S0 >> 15);    
}    
#define ROT(a, k) (((a) << k) | ((a) >> (32 - k)))    
/* L1 */    
u32 L1(u32 X) {    
	return (X ^ ROT(X, 2) ^ ROT(X, 10) ^ ROT(X, 18) ^ ROT(X, 24));    
}    
/* L2 */    
u32 L2(u32 X) {    
	return (X ^ ROT(X, 8) ^ ROT(X, 14) ^ ROT(X, 22) ^ ROT(X, 30));    
}    
#define MAKEU32(a, b, c, d) (((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | ((u32)(d)))    
/* F */    
u32 F() {    
	u32 W, W1, W2, u, v;    
	W = (BRC_X0 ^ F_R1) + F_R2;    
	W1 = F_R1 + BRC_X1;    
	W2 = F_R2 ^ BRC_X2;    
	u = L1((W1 << 16) | (W2 >> 16));    
	v = L2((W2 << 16) | (W1 >> 16));    
	F_R1 = MAKEU32(S0[u >> 24], S1[(u >> 16) & 0xFF],    
		S0[(u >> 8) & 0xFF], S1[u & 0xFF]);    
	F_R2 = MAKEU32(S0[v >> 24], S1[(v >> 16) & 0xFF],    
		S0[(v >> 8) & 0xFF], S1[v & 0xFF]);    
	return W;    
}    
#define MAKEU31(a, b, c)(((u32)(a) << 23)|((u32)(b) << 8)|(u32)(c))    
/* initialize */    
//初始化    
void Initialization(u8* k, u8* iv) {    
	u32 w, nCount;    
    
	/* expand key */    
	LFSR_S0 = MAKEU31(k[0], EK_d[0], iv[0]);    
	LFSR_S1 = MAKEU31(k[1], EK_d[1], iv[1]);    
	LFSR_S2 = MAKEU31(k[2], EK_d[2], iv[2]);    
	LFSR_S3 = MAKEU31(k[3], EK_d[3], iv[3]);    
	LFSR_S4 = MAKEU31(k[4], EK_d[4], iv[4]);    
	LFSR_S5 = MAKEU31(k[5], EK_d[5], iv[5]);    
	LFSR_S6 = MAKEU31(k[6], EK_d[6], iv[6]);    
	LFSR_S7 = MAKEU31(k[7], EK_d[7], iv[7]);    
	LFSR_S8 = MAKEU31(k[8], EK_d[8], iv[8]);    
	LFSR_S9 = MAKEU31(k[9], EK_d[9], iv[9]);    
	LFSR_S10 = MAKEU31(k[10], EK_d[10], iv[10]);    
	LFSR_S11 = MAKEU31(k[11], EK_d[11], iv[11]);    
	LFSR_S12 = MAKEU31(k[12], EK_d[12], iv[12]);    
	LFSR_S13 = MAKEU31(k[13], EK_d[13], iv[13]);    
	LFSR_S14 = MAKEU31(k[14], EK_d[14], iv[14]);    
	LFSR_S15 = MAKEU31(k[15], EK_d[15], iv[15]);    
	/* set F_R1 and F_R2 to zero */    
	F_R1 = 0;    
	F_R2 = 0;    
	nCount = 32;    
	while (nCount > 0)    
	{    
		BitReorganization();    
		w = F();    
		LFSRWithInitialisationMode(w >> 1);    
		nCount--;    
	}    
}    
//生成密钥流    
void GenerateKeystream(u32* pKeystream, int KeystreamLen) {    
	int i;    
	{    
		BitReorganization();    
		F();		/* discard the output of F */    
		LFSRWithWorkMode();    
	}    
	for (i = 0; i < KeystreamLen; i++) {    
		BitReorganization();    
		pKeystream[i] = F() ^ BRC_X3;    
		LFSRWithWorkMode();    
	}    
}    
void ZUC(u8* k, u8* iv, u32* ks, int len)    
{      
	/* The initialization of ZUC, see page 17 of ref. [3]*/    
	Initialization(k, iv);    
	/*  The procedure of generating keystream of ZUC, see page 18 of ref. [3]*/    
	GenerateKeystream(ks, len);    
}    
// 在这里加密    
void EEA3(u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* C)    
{    
	u32* z, L, i;    
	u8 IV[16];    
	L = (LENGTH + 31) / 32;    
	z = (u32*)malloc(L * sizeof(u32));    
	IV[0] = (COUNT >> 24) & 0xFF;    
	IV[1] = (COUNT >> 16) & 0xFF;    
	IV[2] = (COUNT >> 8) & 0xFF;    
	IV[3] = COUNT & 0xFF;    
	IV[4] = ((BEARER << 3) | ((DIRECTION & 1) << 2)) & 0xFC;    
	IV[5] = 0;    
	IV[6] = 0;    
	IV[7] = 0;    
	IV[8] = IV[0];    
	IV[9] = IV[1];    
	IV[10] = IV[2];    
	IV[11] = IV[3];    
	IV[12] = IV[4];    
	IV[13] = IV[5];    
	IV[14] = IV[6];    
	IV[15] = IV[7];    
	ZUC(CK, IV, z, L);    
	for (i = 0; i < L; i++)    
	{    
		C[i] = M[i] ^ z[i];    
	}    
	free(z);    
}    
```  

