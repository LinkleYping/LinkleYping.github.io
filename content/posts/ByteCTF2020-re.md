---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "ByteCTF2020-re"    
date: 2020-10-27T15:22:45+08:00    
categories : [                                  
"writeup",    
]    
draft: false    
---
这次比赛让我知道了AES密钥长度除了可以等于16还可以等于32...不要看到`AES256`的时候脑子里只有AES没有256==    
## DaShen Decode AES    
白给题，sqlite直接查询出来`iv`和`key`然后`AES`解密即可    
```python    
#!/usr/bin/env python    
from Crypto.Util.number import *    
from Crypto.Cipher import AES    
import sqlite3    
    
fileName = "db.db"    
conn = sqlite3.connect(fileName)    
c =conn.cursor()    
ret = c.execute("SELECT  * FROM  config1 WHERE a=1")    
for i in ret:    
  print(i)    
    
enc = "db6427960a6622ffac27ef5437acf1459a592d1a96b73e75490c8badb0ed294c1e9232213e63461dd2d9f6d327e51641"    
iv = b"a5efdbd57b84ca88"    
key = b"37eaae0141f1a3adf8a1dee655853766"    
key = long_to_bytes(int(key,16))    
    
cipher = AES.new(key,AES.MODE_CBC,iv)    
enc = long_to_bytes(int(enc,16))    
    
dec = cipher.decrypt(enc)    
print(dec)    
# ByteCTF{fl-ag-IS-to-ng-xu-el-ih-ai}    
```    
## QIAO    
main函数的ollvm去掉以后可以看到大致逻辑    
```c    
_int64 __fastcall main(int a1, char **a2, char **a3, __m128i a4)    
{    
void *v5; // [rsp+60h] [rbp-30h]    
unsigned int v6; // [rsp+78h] [rbp-18h]    
    
if ( a1 == 2 && strlen(a2[1]) == 32 && (v5 = sub_401180(a2[1]), (unsigned int)sub_4018C0((__int64)v5, a4)) )    
{    
  printf("[*]%s.\n", a2[1]);    
  v6 = 0;    
}    
else    
{    
  v6 = -1;    
  printf("[*]ByteCTF{d2h5IG5vdCBnbyBob21l}.\n");    
}    
return v6;    
}    
```    
`sub_401180`将输入转16进制数，`sub_4018C0`调用了`sub_401E90`是个很大的vm，调试了一会儿发现没啥用，最后面动态调用了一个函数`((void (__fastcall *)(_QWORD, _QWORD))v149)(*inputStr, *v136);`,在这个地方下断点然后对输入下读写断点以后，断了几次发现了下面这个：    
![image](/images/bb4bbf109c9ae05d6224b2cf2981c9c9/11884068-b32450d80c805252.png)    
尝试输入了一下发现真的就是flag...    
## CrackMe    
sha256算法经过了更改，在输入长度超过32个字节的时候只有前四个字节参与了运算，直接爆破前四个字节    
sha256我在github上找了一个很相似的项目改了一下：https://github.com/monkeyDemon/Blockchain-programming-exercises/blob/master/1.Blockchain%20basic%20exercises/2.Cryptography%20and%20security%20technology/SHA256/C%20Code/sha256.c    
```cpp    
#include <stdio.h>    
#include <stdint.h>    
#include <string.h>    
#include <stdlib.h>    
#include <memory.h>    
#include <string.h>    
#include "sha256.h"    
    
#define BLOCKSIZE 16    
    
typedef struct{    
  uint32_t eK[44],dK[44];    
  int rounds;    
} AESKEY;    
    
#define ROF32(x,n) ((x << n) | (x >> (32-n)))    
    
#define ROR32(x,n) ((x >> n) | (x << (32-n)))    
    
#define BYTE(x,n) (((x)>>((n)*8)) & 0xff)    
    
#define MIX(x)  (((S[BYTE((x),2)] << 24) & 0xff000000) ^ \    
               ((S[BYTE((x),1)] << 16) & 0xff0000) ^ \    
               ((S[BYTE((x),0)] << 8) & 0xff00) ^ \    
               ((S[BYTE((x),3)]) & 0xff))    
                  
    
#define LOAD32(x,y) do{ (x) = \    
  ((uint32_t)((y)[0]&0xff)<<24) |\    
  ((uint32_t)((y)[1]&0xff)<<16) |\    
  ((uint32_t)((y)[2]&0xff)<<8 ) |\    
  ((uint32_t)((y)[3]&0xff));\    
}while(0)    
    
#define  STORE32(x,y) do{ \    
  (y)[0] = (uint8_t)(((x)>>24) & 0xff) ; \    
  (y)[1] = (uint8_t)(((x)>>16) & 0xff) ; \    
  (y)[2] = (uint8_t)(((x)>>8) & 0xff) ; \    
  (y)[3] = (uint8_t)((x) & 0xff) ; \    
}while(0)    
    
     
unsigned char S[256] = {    
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,    
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,    
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,    
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,    
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,    
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,    
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,    
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,    
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,    
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,    
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,    
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,    
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,    
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,    
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,    
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};    
    
unsigned char inv_S[256] = {    
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,    
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,    
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,    
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,    
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,    
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,    
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,    
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,    
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,    
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,    
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,    
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,    
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,    
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,    
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,    
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};    
    
uint8_t M[4][4] = {    
  {0x02, 0x03, 0x01, 0x01},    
  {0x01, 0x02, 0x03, 0x01},    
  {0x01, 0x01, 0x02, 0x03},    
  {0x03, 0x01, 0x01, 0x02}    
};    
    
uint8_t inv_M[4][4] = {    
  {0x0E, 0x0B, 0x0D, 0x09},    
  {0x09, 0x0E, 0x0B, 0x0D},    
  {0x0D, 0x09, 0x0E, 0x0B},    
  {0x0B, 0x0D, 0x09, 0x0E}    
};    
    
    
static const uint32_t rcon[10] = {    
  0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,    
  0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL    
};    
    
    
int KeyExpansion(uint8_t * key,AESKEY * aeskey){    
  uint32_t * w = aeskey ->eK;    
  uint32_t * v = aeskey ->dK;    
  for(int i=0 ; i<4 ; i++ ){    
      LOAD32(w[i], key+i*4);    
  }    
  for(int i=0;i<10;i++){    
      w[4]=w[0]^MIX(w[3])^rcon[i];    
      w[5]=w[1]^w[4];    
      w[6]=w[2]^w[5];    
      w[7]=w[3]^w[6];    
      w+=4;    
  }    
  w = (aeskey -> eK) + 40;    
  for(int j=0 ;j<11;j++){    
      for(int i = 0 ; i<4;i++){    
          v[i]=w[i];    
      }    
      v+=4;    
      w-=4;    
  }    
  return 0;    
}    
    
void loadStateArray(uint8_t (*state)[4],uint8_t *in){    
  for(int i=0;i<4;i++){    
      for(int j=0;j<4;j++){    
          state[j][i]=*in++;    
      }    
  }    
}    
    
void storeStateArray(uint8_t (*state)[4],uint8_t *out){    
  for(int i=0;i<4;i++){    
      for(int j=0;j<4;j++){    
          *out++=state[j][i];    
      }    
  }    
}    
    
void shiftRows(uint8_t (*state)[4]){    
  uint32_t temp[4]={0};    
  for(int i=0;i<4;i++){    
      LOAD32(temp[i], state[i]);    
      temp[i]=ROF32(temp[i], i*8);    
      STORE32(temp[i], state[i]);    
  }    
}    
    
void invShiftRows(uint8_t (*state)[4]) {    
  uint32_t temp[4] = {0};    
  for (int i = 0; i < 4; i++) {    
      LOAD32(temp[i], state[i]);    
      temp[i] = ROR32(temp[i], i*8);    
      STORE32(temp[i], state[i]);    
  }    
}    
    
uint8_t GMul(uint8_t u, uint8_t v) {    
  uint8_t p = 0;    
  for (int i = 0; i < 8; ++i) {    
      if (u & 0x01) {    //    
          p ^= v;    
      }    
      int flag = (v & 0x80);    
      v <<= 1;    
      if (flag) {    
          v ^= 0x1B;    
      }    
      u >>= 1;    
  }    
  return p;    
}    
    
void mixColumns(uint8_t (*state)[4]){    
  uint8_t tmp[4][4];    
      
  for (int i = 0; i < 4; ++i) {    
      for (int j = 0; j < 4; ++j){    
          tmp[i][j] = state[i][j];    
      }    
  }    
    
  for (int i = 0; i < 4; ++i) {    
      for (int j = 0; j < 4; ++j) {    
          state[i][j] = GMul(M[i][0], tmp[0][j]) ^    
                        GMul(M[i][1], tmp[1][j]) ^    
                        GMul(M[i][2], tmp[2][j]) ^    
                        GMul(M[i][3], tmp[3][j]) ;    
      }    
  }    
      
}    
    
void invMixColumns(uint8_t (*state)[4]){    
  uint8_t tmp[4][4];    
      
  for (int i = 0; i < 4; ++i) {    
      for (int j = 0; j < 4; ++j){    
          tmp[i][j] = state[i][j];    
      }    
  }    
    
  for (int i = 0; i < 4; ++i) {    
      for (int j = 0; j < 4; ++j) {    
          state[i][j] = GMul(inv_M[i][0], tmp[0][j]) ^    
                        GMul(inv_M[i][1], tmp[1][j]) ^    
                        GMul(inv_M[i][2], tmp[2][j]) ^    
                        GMul(inv_M[i][3], tmp[3][j]) ;    
      }    
  }    
      
}    
    
int addRoundKey(uint8_t (*state)[4], const uint32_t *key) {    
  uint8_t k[4][4];    
  for (int i = 0; i < 4; ++i) {    
      for (int j = 0; j < 4; ++j) {    
          k[j][i] = (uint8_t) BYTE(key[i], 3 - j); //按列异或秘钥    
          state[j][i] ^= k[j][i];    
      }    
  }    
    
  return 0;    
}    
    
int subBytes(uint8_t (*state)[4]) {    
  for (int i = 0; i < 4; ++i) {    
      for (int j = 0; j < 4; ++j) {    
          state[i][j] = S[state[i][j]];    
      }    
  }    
  return 0;    
}    
    
int invSubBytes(uint8_t (*state)[4]) {    
  for (int i = 0; i < 4; ++i) {    
      for (int j = 0; j < 4; ++j) {    
          state[i][j] = inv_S[state[i][j]];    
      }    
  }    
  return 0;    
}    
    
    
void aesEncryptBlock(uint8_t * mblock,uint8_t * cblock,uint8_t * key){    
  AESKEY aeskey;    
  uint8_t state[4][4]={0};    
  KeyExpansion(key, &aeskey);    
  loadStateArray(state, mblock);    
  uint32_t * ekPointer = aeskey.eK;    
  addRoundKey(state, ekPointer);    
  for(int i=1;i<10;i++){    
      ekPointer += 4;    
      subBytes(state);    
      shiftRows(state);    
      mixColumns(state);    
      addRoundKey(state, ekPointer);    
  }    
  ekPointer += 4;    
  subBytes(state);    
  shiftRows(state);    
  addRoundKey(state, ekPointer);    
  storeStateArray(state, cblock);    
}    
    
void aesDecryptBlock(uint8_t * mblock,uint8_t * cblock,uint8_t * key){    
  AESKEY aeskey;    
  uint8_t state[4][4]={0};    
  KeyExpansion(key, &aeskey);    
  loadStateArray(state, cblock);    
  uint32_t * dkPointer = aeskey.dK;    
  addRoundKey(state, dkPointer);    
      
  for(int i=1;i<10;i++){    
      dkPointer += 4;    
      invShiftRows(state);    
      invSubBytes(state);    
      addRoundKey(state, dkPointer);    
      invMixColumns(state);    
          
  }    
  dkPointer += 4;    
  invSubBytes(state);    
  invShiftRows(state);    
  addRoundKey(state, dkPointer);    
  storeStateArray(state, mblock);    
}    
    
    
int splitBlock(char * message,uint8_t ** blocks){    
  int len = (int)strlen(message);    
  int block_num = 2;    
  *blocks = (uint8_t *)malloc(block_num*16);    
  memcpy(*blocks, message, len);    
  //memset(*blocks+len,0,16-mod);    
  return block_num;    
}    
    
uint8_t * aesEncryptCBC(uint8_t * blocks,uint8_t * key,int block_num,uint8_t * iv){    
  uint8_t * tmp = iv;    
  for(int i = 0;i<block_num;i++){    
      for(int j = 0;j<16;j++){    
          blocks[16*i+j] ^= tmp[j];    
      }    
      aesEncryptBlock(blocks+16*i, blocks+16*i, key);    
      tmp = blocks+16*i;    
  }    
  return blocks;    
}    
    
void aesDecryptCBC(uint8_t * blocks,uint8_t * key,int block_num,uint8_t * iv){    
  uint8_t * tmp = blocks+(16*(block_num-2));    
  for(int i = block_num-1;i > -1;i--){    
      aesDecryptBlock(blocks+16*i, blocks+16*i, key);    
      for(int j = 0;j<16;j++){    
          blocks[16*i+j] ^= tmp[j];    
      }    
      if(i==1){    
          tmp = iv;    
      }else{    
          tmp -= 16;    
      }    
  }    
}    
    
void print(BYTE *s, int n)    
{    
	for(int i = 0; i < n; i++)    
		printf("0x%x, ", s[i]);    
	printf("\n");    
}    
    
int main()    
{    
	char message[]="\x2d\x18\x6a\x3e\x17\x2a\x14\x67\x37\x89\xf4\x99\xcd\x6c\xfb\xcd\x29\xb6\xc7\x3f\x4b\x4a\x27\xc2\x34\x64\x77\x68\x25\xaf\x90\xb2";    
	for(char a = 0x20; a < 0x7f; a++){    
		for(char b = 0x20; b < 0x7f; b++){    
			for(char c = 0x20; c < 0x7f; c++){    
				for(char d = 0x20; d < 0x7f; d++){    
					BYTE text1[5] = {a,b,c,d};    
					BYTE buf[SHA256_BLOCK_SIZE];    
					SHA256_CTX ctx;    
					sha256_init(&ctx);    
					sha256_update(&ctx, text1, strlen(text1));    
					sha256_final(&ctx, buf);					    
					char key[16];    
					char iv[16];    
					for(int i = 0; i < 16; i++)    
						key[i] = buf[i];    
					for(int i = 16; i < 32; i++)    
						iv[i-16] = buf[i];    
					uint8_t * blocks = NULL;    
					int block_num = splitBlock(message,&blocks);    
					aesDecryptCBC(blocks,key,block_num,iv);    
					if(strstr(blocks, "ByteCTF") != NULL){    
						printf("flag: %s\n", blocks);    
                      print(text1, 4);    
					    return 0;    
					}    
				}    
			}    
		}    
		printf("%c\n", a);    
	}    
	return(0);    
}    
```    
求出来输入`good`(填充到32+)可以获取flag    
## App1c    
解压出来的二进制文件中有一个`check`函数，显示需要读取`sandbox/secret`文件，读取出来的字符串做`md5`后`Aes256ECB`解密`MnRC6I9E0BbJ7LxLfrKhP6Xv5+c41AORjmG66eQxQks=`即可获取`flag`。在`run`函数中可以看到调用了`lua`脚本，解压出来存在一个叫`AppIcon.lua`的脚本，可以直接编辑模式打开看到上面一段可读的脚本内容：    
```python    
input = tostring(arg[1])    
sanboxPath = tostring(arg[2]).."/secret"    
debase64 = from_base64(input)    
secret = "0"    
if debase64 ~= nil then    
  secret = string.app1c(debase64)    
end    
file = io.open(sanboxPath, "w")    
io.output(file)    
io.write(tostring(secret))    
io.close(file)    
```    
本来我没注意到`string.app1c`这个函数的时候我觉得下面不可读的内容也是有用的，但是没办法反编译，我用这个反汇编了一下发现其实就是base64的包，我码一下用到的几个lua相关的链接    
基本知识与010Editor解析脚本：https://github.com/feicong/lua_re    
luadec: https://github.com/viruscamp/luadec    
还有个工具是unlua    
调用时`arg[1]`是用户输入的字符串，`arg[2]`是sandbox的路径。将输入解base64后经过`string.app1c`的处理写入`sandbox/secret`文件。这个`string.app1c`猜测是对lua的string包做了扩展，然后找到了下面这个例子：    
```cpp    
#include <stdio.h>    
#include <stdlib.h>    
#include "lua.h"    
#include "lualib.h"    
#include "lauxlib.h"    
#import <objc/runtime.h>    
#import <Foundation/Foundation.h>    
#import <UIKit/UIDevice.h>    
/*  库 open 函数的前置声明   */    
int luaopen_mt(lua_State *L);    
/* Function mt_get_device_name    
 * @return string device name    
 */    
static int mt_get_device_name(lua_State *L)    
{    
  NSString *name = [[UIDevice currentDevice] name];    
  const char * name_str = [name UTF8String];    
  lua_pushstring(L, name_str);    
  return 1;    
}    
//注册函数库    
static const luaL_Reg mt_lib[] = {    
  {"device_name", mt_get_device_name},    //获取设备名称    
  {NULL, NULL}    
};    
int luaopen_mt(lua_State *L)//注意, mt为扩展库的文件名    
{    
  luaL_newlib(L, mt_lib);//暴露给lua脚本的接口    
  return 1;    
}    
    
// PWNlua层里的调用方法为:    
    
local mt = require "mt"    
print(mt.device_name())    
```    
所以需要找一下`app1c`这个字符串指向的函数：    
```c    
__const:000246FC                 DCD aReverse            ; "reverse"    
__const:00024700                 DCD sub_19146+1    
__const:00024704                 DCD aSub_1              ; "sub"    
__const:00024708                 DCD sub_191BA+1    
__const:0002470C                 DCD aUpper              ; "upper"    
__const:00024710                 DCD sub_1923E+1    
__const:00024714                 DCD aApp1c_0            ; "app1c"    
__const:00024718                 DCD sub_192B4+1    
```    
`sub_192B4`这个函数要求输入字符串长度是4，且可转10进制数。所以直接爆破4位的十进制数。注意是AES256...不是128    
```python    
if __name__ == "__main__":    
  from Crypto.Cipher import AES    
  s = "MnRC6I9E0BbJ7LxLfrKhP6Xv5+c41AORjmG66eQxQks="    
  import base64, hashlib    
  enc = base64.decodestring(s)    
  for a in range(ord('0'), ord('9')+1, 1):    
      for b in range(ord('0'), ord('9')+1, 1):    
          for c in range(ord('0'), ord('9')+1, 1):    
              for d in range(ord('0'), ord('9')+1, 1):    
                  ss = chr(a)+chr(b)+chr(c)+chr(d)    
                  key = hashlib.md5(ss).hexdigest() # 就是这里，我还decode了一下所以一直不对，气死我了    
                  ci = AES.new(key,AES.MODE_ECB)    
                  strs = ci.decrypt(enc)    
                  if strs.find("ByteCTF") >= 0:    
                      print strs    
                      print chr(a)+chr(b)+chr(c)+chr(d)    
                      exit(0)    
```    
