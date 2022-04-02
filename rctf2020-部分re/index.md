# RCTF2020-部分re

  
## go-flag    
首先用IDAGolangHelper恢复符号    
恢复符号以后可以看到一共生成了3k多个goroutine，main_main_func1用来获取输入，每次读入一个字符，然后通过chan传给其他的rountine，发送字符到chan使用了`runtime_chansend1`, 从chan读取字符使用的是`runtime_chanrecv1`函数，x查找一下调用了`runtime_chanrecv1`函数的地方，这些函数的个数差不多就是flag的长度。    
选择一个调用`runtime_chanrecv1`的函数进行调试，发现距离这个函数不远的地方有字符判断操作    
![](/images/722dcfa9ed65509134320f2e9d7612e0/11884068-01d215c3222e7e78.png)    
然后调试到这个地方发现前几次出现的字符分别为`RCF`猜测就是正确flag，然后找到所有这种比较的函数把字符抄下来就行了。    
## cipher    
MIPS的程序用`ghidra`反编译可以看到加密逻辑，逆一下就可以了，注意端序和结束符问题。    
```c    
#include<cstdio>    
#define ulonglong unsigned long long     
#define longlong long long    
using namespace std;    
void encrypt(char *ciphertext,char *plain)    
{    
ulonglong p1,p2;    
ulonglong *in_a2;    
int cycle;    
ulonglong t1,t2,c1,c2;    
p1 = *(ulonglong *)plain;    
p2 = *(ulonglong *)(plain + 8);    
//printf("P1 %llX P2 %llX\n",p1,p2);    
t2 = 0;    
t1 = 0;    
c2 = ((p2>> 8) + (p2<< 0x38) + p1) ^ t2;    
c1 = ((p1 >> 0x3d) + (p1 << 3)) ^ c2;    
cycle = 0;    
while (cycle < 0x1f) {    
t1 = ((t1 >> 8) + (t1 << 0x38) + t2) ^ (longlong)cycle;    
t2 = ((t2 >> 0x3d) + (t2 << 3)) ^ t1;    
//printf("%llX %llX %llX\n",c1,c2,t2);    
c2 = ((c2 >> 8) + (c2 << 0x38) + c1) ^ t2;    
c1 = ((c1 >> 0x3d) + (c1 << 3)) ^ c2;    
cycle = cycle + 1;    
}    
printf("%llX %llX %llX %llX\n",c1,c2,t1,t2);    
*(ulonglong *)ciphertext = c1;    
*(ulonglong *)(ciphertext + 8) = c2;    
    
return;    
}    
ulonglong t1s[40],t2s[40];    
void genFlows(ulonglong k1,ulonglong k2)    
{    
	ulonglong t2 = k2,t1 = k1,cycle = 0;    
	while (cycle < 0x1f) {    
	t1 = (t1 >> 8) + (t1 << 0x38) + t2 ^ (longlong)cycle;    
	t2 = ((t2 >> 0x3d) + (t2 << 3)) ^ t1;    
	t1s[cycle]=t1;    
	t2s[cycle]=t2;    
	cycle+=1;    
	//printf("%d\n",cycle);    
	}    
//	printf("Get Key Flows\n");    
}    
void decrypt(ulonglong k1,ulonglong k2,char *ciphertext,char *plain)    
{    
	genFlows(k1,k2);    
	ulonglong c1,c2;    
	c1 = *(ulonglong *)ciphertext;    
c2 = *(ulonglong *)(ciphertext + 8);    
	longlong cycle = 0x1f;    
	while (cycle > 0) {    
	/*c2 = (c2 >> 8) + (c2 << 0x38) + c1 ^ t2s[cycle];    
	c1 = ((c1 >> 0x3d) + (c1 << 3)) ^ c2;*/    
	cycle = cycle - 1;    
	c1 ^= c2;    
	c1 = ((c1 << 0x3d) + (c1 >> 3));    
	c2 ^= t2s[cycle];    
	c2 -= c1;    
	c2 = (c2 << 8) + (c2 >> 0x38);    
	/*t1 = ((t1 >> 8) + (t1 << 0x38) + t2) ^ (longlong)cycle;    
	t2 = ((t2 >> 0x3d) + (t2 << 3)) ^ t1;*/    
	    
	    
	    
	}    
	//c2 = (p2>> 8) + (p2<< 0x38) + p1 ^ t2;    
	//c1 = (p1 >> 0x3d) + (p1 << 3) ^ c2;    
	c1 ^= c2;    
	c1 = ((c1 << 0x3d) + (c1 >> 3));    
	c2 ^= k2;    
	c2 -= c1;    
c2 = (c2 << 8) + (c2 >> 0x38);    
*(ulonglong *)plain = c1;    
*(ulonglong *)(plain + 8) = c2;    
}    
    
unsigned char cipherText[100]{    
0xc1,0x77,0x1d,0xe1,0x2b,0xf8,0x00,0x2a,0xf4,0x91,0xd5,0x23,0xfc,0x71,0xb1,0xc3,    
//0x57,0x59,0x88,0xc2,0x8b,0x1e,0xf1,0x30,0x75,0xeb,0x2f,0x42,0x77,0xab,0x94,0xd5    
//0xb9,0x98,0x6e,0x46,0xf0,0x76,0x5d,0xe1,0xf2,0x36,0x77,0x5d,0xb5,0xfd,0x51,0xb6    
};    
    
char dePlain[100]={0};    
int main()    
{	    
	for(ulonglong i=0;i<=0xFFFF;i++)    
	{    
		ulonglong k1=0,k2=(i<<48);    
		decrypt(k1,k2,(char*)cipherText,dePlain);    
		for(int i=0;i<16;i++)    
		{    
			printf("%s\n",dePlain);    
		}    
			    
	}    
	    
return 0;    
}    
```    
## play_the_game    
get flag的部分在libcalculate.so里面，so文件被平坦化了，本来想用angr去一下平坦化看看，但是发现好像不行。    
flag是dword_2B00C的md5值，这个值只在sub_76B0中被修改过，调试起来发现只有下棋赢了的时候这个值才会改变，然后只有当dword_2B008的值大于等于0x13f4f9f9的时候才会printlog出flag，因为这两个值只在sub76B0中被修改过了，所以直接dump出这个函数输出dword_2B008输出大于等于0x13f4f9f9时dword_2B00C的值即可。    
```c    
#include<math.h>    
#include<stdio.h>    
int dword_2B008 = 0x13F4E6A3;    
int dword_2B00C = 0xDEF984B1;    
int sub_76B0()    
{    
signed int v0; // r1    
char v1; // r2    
signed int v2; // r1    
signed int v3; // r12    
signed int v4; // lr    
signed int v5; // r1    
signed int v6; // r2    
signed int v7; // r3    
signed int v8; // r1    
char v9; // r2    
signed int v10; // r1    
signed int v11; // r12    
signed int v12; // lr    
signed int v13; // r1    
signed int v14; // r2    
signed int v15; // r3    
signed int v16; // r1    
signed int v17; // r12    
signed int v18; // lr    
signed int v19; // r1    
char v20; // lr    
signed int v21; // r2    
signed int v22; // r3    
signed int v23; // r1    
signed int v24; // r1    
signed int v25; // r12    
signed int v26; // lr    
signed int v27; // r1    
char v28; // lr    
signed int v29; // r2    
signed int v30; // r3    
signed int v31; // r1    
signed int v32; // r1    
signed int v33; // r12    
signed int v34; // lr    
signed int v35; // r1    
signed int v36; // r2    
signed int v37; // r3    
signed int v38; // r1    
signed int v39; // r2    
signed int v40; // r3    
signed int v41; // r1    
signed int v42; // r12    
signed int v43; // lr    
signed int v44; // r1    
signed int v45; // r12    
signed int v46; // lr    
signed int v47; // r1    
signed int v48; // r2    
signed int v49; // r3    
signed int v50; // r1    
signed int v51; // r2    
signed int v52; // r3    
signed int v53; // r1    
signed int v54; // r2    
signed int v55; // r3    
signed int v57; // [sp+14h] [bp-7Ch]    
int v58; // [sp+18h] [bp-78h]    
signed int v59; // [sp+6Ch] [bp-24h]    
char v60; // [sp+76h] [bp-1Ah]    
char v61; // [sp+77h] [bp-19h]    
    
v59 = (signed int)((sqrt((double)(8 * (dword_2B008 - 0x13F4E6A3) + 1)) - 1.0) / 2.0 + 1.0);    
dword_2B008 += v59;    
v58 = dword_2B008 % 4;    
v57 = 329878480;    
while ( 1 )    
{    
while ( 1 )    
{    
  while ( 1 )    
  {    
    while ( 1 )    
    {    
      while ( 1 )    
      {    
        while ( 1 )    
        {    
          while ( 1 )    
          {    
            while ( 1 )    
            {    
              while ( 1 )    
              {    
                while ( 1 )    
                {    
                  while ( 1 )    
                  {    
                    while ( 1 )    
                    {    
                      while ( 1 )    
                      {    
                        while ( 1 )    
                        {    
                          while ( v57 == -1902481392 )    
                          {    
                            v2 = 982494985;    
                            v3 = 0;    
                            v3 = 1;    
                            v4 = 0;    
                            v4 = 1;    
                            if ( (v3 & 1 ^ v4 & 1 | ~(~v3 | ~v4) & 1) & 1 )    
                              v2 = 631845012;    
                            v57 = v2;    
                          }    
                          if ( v57 != -1839432635 )    
                            break;    
                          v31 = -662380450;    
                          if ( v61 & 1 )    
                            v31 = -356495000;    
                          v57 = v31;    
                        }    
                        if ( v57 != -1690025818 )    
                          break;    
                        v57 = 972960622;    
                      }    
                      if ( v57 != -1673856231 )    
                        break;    
                      v57 = 1037163223;    
                    }    
                    if ( v57 != -1492608071 )    
                      break;    
                    v57 = 973492237;    
                  }    
                  if ( v57 != -1424285714 )    
                    break;    
                  v57 = -662380450;    
                }    
                if ( v57 != -1252652544 )    
                  break;    
                v38 = 834798273;    
                v39 = 0;    
                v39 = 1;    
                v40 = 0;    
                v40 = 1;    
                if ( (v39 & v40 | v39 ^ v40) & 1 )    
                  v38 = 1385700430;    
                v57 = v38;    
              }    
              if ( v57 != -1086664836 )    
                break;    
              v13 = 1181698316;    
              dword_2B00C *= v59;    
              v14 = 0;    
              v14 = 1;    
              v15 = 0;    
              v15 = 1;    
              if ( (v14 & v15 | v14 ^ v15) & 1 )    
                v13 = -854969644;    
              v57 = v13;    
            }    
            if ( v57 != -981935185 )    
              break;    
            dword_2B00C <<= v59 % 8;    
            v57 = -1252652544;    
          }    
          if ( v57 != -854969644 )    
            break;    
          v57 = 2074254629;    
        }    
        if ( v57 != -744507517 )    
          break;    
        v35 = -435027630;    
        dword_2B00C += dword_2B008;    
        v36 = 0;    
        v36 = 1;    
        v37 = 0;    
        v37 = 1;    
        if ( (v36 & v37 | v36 ^ v37) & 1 )    
          v35 = -1424285714;    
        v57 = v35;    
      }    
      if ( v57 != -662380450 )    
        break;    
      v57 = -1252652544;    
    }    
    if ( v57 != -435027630 )    
      break;    
    dword_2B00C += dword_2B008;    
    v57 = -744507517;    
  }    
  if ( v57 != -356495000 )    
    break;    
  v32 = -435027630;    
  v33 = 0;    
  v33 = 1;    
  v34 = 0;    
  v34 = 1;    
  if ( (~v33 ^ ~v34 | ~(~v33 | ~v34) & 1) & 1 )    
    v32 = -744507517;    
  v57 = v32;    
}    
if ( v57 == -7797833 )    
  break;    
switch ( v57 )    
{    
  case 187395956:    
    v10 = 1181698316;    
    v11 = 0;    
    v11 = 1;    
    v12 = 0;    
    v12 = 1;    
    if ( (v11 & 1 ^ v12 & 1 | ~(~v11 | ~v12) & 1) & 1 )    
      v10 = -1086664836;    
    v57 = v10;    
    break;    
  case 329878480:    
    v0 = 564872742;    
    v1 = 0;    
    if ( !(dword_2B008 % 4) )    
      v1 = 1;    
    if ( v1 & 1 )    
      v0 = -1902481392;    
    v57 = v0;    
    break;    
  case 413793462:    
    v57 = 973492237;    
    break;    
  case 475330195:    
    v57 = 1549997554;    
    break;    
  case 564872742:    
    v8 = 963397217;    
    v9 = 0;    
    if ( v58 == 1 )    
      v9 = 1;    
    if ( v9 & 1 )    
      v8 = 187395956;    
    v57 = v8;    
    break;    
  case 631845012:    
    v5 = 982494985;    
    dword_2B00C = (~dword_2B00C & 0x384FD424 | dword_2B00C & 0xC7B02BDB) ^ (~dword_2B008 & 0x384FD424 | dword_2B008 & 0xC7B02BDB);    
    v6 = 0;    
    v6 = 1;    
    v7 = 0;    
    v7 = 1;    
    if ( (v6 & v7 | v6 ^ v7) & 1 )    
      v5 = 413793462;    
    v57 = v5;    
    break;    
  case 792701847:    
    v23 = 851733706;    
    if ( v60 & 1 )    
      v23 = -981935185;    
    v57 = v23;    
    break;    
  case 834798273:    
    v57 = 1385700430;    
    break;    
  case 851733706:    
    v24 = 475330195;    
    v25 = 0;    
    v25 = 1;    
    v26 = 0;    
    v26 = 1;    
    if ( (v25 & 1 ^ v26 & 1 | ~(~v25 | ~v26) & 1) & 1 )    
      v24 = 1549997554;    
    v57 = v24;    
    break;    
  case 963397217:    
    v16 = -1690025818;    
    v17 = 0;    
    v17 = 1;    
    v18 = 0;    
    v18 = 1;    
    if ( (~v17 ^ ~v18 | ~(~v17 | ~v18) & 1) & 1 )    
      v16 = 972960622;    
    v57 = v16;    
    break;    
  case 972960622:    
    v19 = -1690025818;    
    v20 = 0;    
    if ( v58 == 2 )    
      v20 = 1;    
    v60 = v20 & 1;    
    v21 = 0;    
    v21 = 1;    
    v22 = 0;    
    v22 = 1;    
    if ( (v21 & v22 | v21 ^ v22) & 1 )    
      v19 = 792701847;    
    v57 = v19;    
    break;    
  case 973492237:    
    v50 = 1946369812;    
    v51 = 0;    
    v51 = 1;    
    v52 = 0;    
    v52 = 1;    
    if ( (v51 & v52 | v51 ^ v52) & 1 )    
      v50 = 2087024114;    
    v57 = v50;    
    break;    
  case 982494985:    
    dword_2B00C = dword_2B008 & ~dword_2B00C | dword_2B00C & ~dword_2B008;    
    v57 = 631845012;    
    break;    
  case 1037163223:    
    v47 = -1673856231;    
    v48 = 0;    
    v48 = 1;    
    v49 = 0;    
    v49 = 1;    
    if ( (v48 & v49 | v48 ^ v49) & 1 )    
      v47 = -1492608071;    
    v57 = v47;    
    break;    
  case 1181698316:    
    dword_2B00C *= v59;    
    v57 = -1086664836;    
    break;    
  case 1385700430:    
    v41 = 834798273;    
    v42 = 0;    
    v42 = 1;    
    v43 = 0;    
    v43 = 1;    
    if ( (~v42 ^ ~v43 | ~(~v42 | ~v43) & 1) & 1 )    
      v41 = 1848868637;    
    v57 = v41;    
    break;    
  case 1549997554:    
    v27 = 475330195;    
    v28 = 0;    
    if ( v58 == 3 )    
      v28 = 1;    
    v61 = v28 & 1;    
    v29 = 0;    
    v29 = 1;    
    v30 = 0;    
    v30 = 1;    
    if ( (v29 & v30 | v29 ^ v30) & 1 )    
      v27 = -1839432635;    
    v57 = v27;    
    break;    
  case 1848868637:    
    v57 = 2074254629;    
    break;    
  case 1946369812:    
    v57 = 2087024114;    
    break;    
  case 2074254629:    
    v44 = -1673856231;    
    v45 = 0;    
    v45 = 1;    
    v46 = 0;    
    v46 = 1;    
    if ( (v45 & 1 ^ v46 & 1 | ~(~v45 | ~v46) & 1) & 1 )    
      v44 = 1037163223;    
    v57 = v44;    
    break;    
  case 2087024114:    
    v53 = 1946369812;    
    v54 = 0;    
    v54 = 1;    
    v55 = 0;    
    v55 = 1;    
    if ( (v54 & v55 | v54 ^ v55) & 1 )    
      v53 = -7797833;    
    v57 = v53;    
    break;    
}    
}    
return 0;    
}    
int main()    
{    
while(dword_2B008 <= 0x13f4f9f8)    
    sub_76B0();    
printf("%x %x\n", dword_2B008, dword_2B00C);    
// 13f4f9f9 38fa7a28    
return 0;    
}    
```    

