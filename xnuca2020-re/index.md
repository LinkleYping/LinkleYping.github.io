# XNUCA2020-re

  
## unravelmfc   
flag长度66（输入66长度字符才能点击确定）点确定没反应，只有flag正确才会弹框  
首先使用下面的mfc的sig文件：  
http://s.wjk.moe/bt/tmp/unravelmfc/afx140d.sig  
在`CCmdTarget::OnCmdMsg`函数内部， 调用`_AfxDispatchCmdMsg`的call指令下断点，再点确定，即可在栈参数中找到对应的处理函数指针  
[MFC逆向](https://blog.csdn.net/zy_strive_2012/article/details/54311124)  
0x00CB1080 点确定后的处理函数 (程序基址我rebase到了0x00b10000)  
00CB127C 是flag正确  
  
直接看最下面的if，里面调用的两个函数。前33字符和后33字符分开判断检测。  
```c  
if ( (unsigned __int8)j_check1((int)v14, v13) && (unsigned __int8)j_check2((int)v14 + v13, v13) )  
```  
  
前33字节首先RC4，再base64  
```shell  
flag{dsdafasdfasdsddddddddddddddddddddddddddddddddddddddddddddddd}  
异或后：  
00ACE9F4  26 44 D7 3B A8 E0 2F 7E 81 7E 9C 4C 39 A8 97 C8  &D×;¨à/~.~.L9¨.È    
00ACEA04  59 35 27 E6 1E CD 38 87 80 2C 99 C1 DD 5D 1F B0  Y5'æ.Í8..,.ÁÝ].°    
00ACEA14  9A 00   
```  
base64是改了字符表的，在一个rc4加密的代码段里，x64dbg里将内存dump出来放到ida里用f5还勉强能看吧  
```python  
enc_real = "B=.NI;&3JBZ;$;?(I72'0&4GLZDS2V6&%AF.!5#+J[F^"  
import base64  
def decoder(local_base64):  
    import string  
    real_base64_charset = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'  
    tmp_charset = "#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`ab"  
    b64_str = ''  
    for i in local_base64:  
        t = real_base64_charset[tmp_charset.find(i)]  
        b64_str += t  
    return (base64.decodebytes(b64_str.encode()))  
  
def test1():  
    orig = b"&D\xd7;\xa8\xe0/~\x81~\x9cL9\xa8\x97\xc8Y5'\xe6\x1e\xcd8\x87\x80,\x99\xc1\xdd]\x1f\xb0\x9a"  
    encoded = ",G6:1]FC.Z]$BLT/1=E:U(GX,a;AV6E*C%U<S@X@*^%="  
    assert decoder(encoded) == orig  
  
test1()  
  
def derc4(inp):  
    moder_b =b'@(\xb6\\\xd3\x84\\\x1a\xe0\x18\xfd?]\xce\xf6\xbb=FC\x82z\xa9\\\xe3\xe4H\xfd\xa5\xb99{\xd4\xfe'  
    res = []  
    for i,j in zip(inp, moder_b):  
        res.append(i^j)  
    return bytes(res)  
  
def test2():  
    orig = b'flag{dsdafasdfasdsddddddddddddddd'  
  
    out = b"\x26\x44\xD7\x3B\xA8\xE0\x2F\x7E\x81\x7E\x9C\x4C\x39\xA8\x97\xC8\x59\x35\x27\xE6\x1E\xCD\x38\x87\x80\x2C\x99\xC1\xDD\x5D\x1F\xB0\x9A"  
  
    assert derc4(out) == orig  
  
test2()  
```  
前半部分flag就出来了。。。  
  
后33字符：第一个字符是f，后面三十二个字符单独加密  
是tea算法，只改了delta。  
需要解一个方程解出来是[0x2d46347f5e79f6f4, 0xDF3634AE2F9970FF, 0x6cacebd512c2fc6d, 0xe8e95dc6c558d3ec]  
  
```python  
import ctypes  
def encipher(v, k):  
    y, z = [ctypes.c_uint32(x)  
            for x in v]  
    sum = ctypes.c_uint32(0)  
    # delta = 0x9E3779B9  
    delta = 0x2433b95a  
  
    for n in range(32, 0, -1):  
        sum.value += delta  
        # z -- v8  
        # y -- v6  
        # y.value += ((z.value << 4) + k[0]) ^ (z.value + sum.value) ^ ((z.value >> 5) + k[1])  
        # z.value += ((y.value << 4)) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]  
        y.value += (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]  
        z.value += (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]  
    # print(hex(sum.value))  
    return [y.value, z.value]  
  
  
def decipher(v, k):  
    y, z = [ctypes.c_uint32(x) for x in v]  
    # sum = ctypes.c_uint32(0xC6EF3720)  
    sum = ctypes.c_uint32(0x86772b40)  
    # delta = 0x9E3779B9  
    delta = 0x2433b95a  
  
    for n in range(32, 0, -1):  
        z.value -= (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]  
        y.value -= (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]  
        sum.value -= delta  
  
    return [y.value, z.value]  
  
keys = [3647016194, 716023165, 2742368241, 3265149203, 3583257832, 1619840614, 1834562594, 568710898, 3980038709, 2645385924, 945185819, 1912036253, 3705592552, 3939684768, 3133470052, 3662115500]  
  
vv = [0x5e79f6f4, 0x2d46347f, 0x2F9970FF, 0xDF3634AE , 0x12c2fc6d, 0x6cacebd5, 0xc558d3ec, 0xe8e95dc6]  
  
data = []  
for i in range(4):  
    v = vv[2*i: 2*(i+1)]  
    v = v[::-1]  
    k = keys[4*i:4*(i+1)]  
    enc = decipher(v, k)  
    data.append(enc[0])  
    data.append(enc[1])  
  
flag = ""  
for d in data:  
    flag = flag + (hex(d).replace("0x", "")[:-1]).decode('hex')[::-1]  
print('f'+flag)  
```  
## hellowasm  
需要用node起一下直接点开不行  
```shell  
npm install http-server -g  
http-server -p 8080  
```  
长度是42  
这里可以直接用浏览器调试，还比较方便。  
然后做了个base64, 每四个字符一组，异或[0xa, 0xb, 0xc, 0xd]  
最后check的部分是个vm，算法是简单异或。  
一点点分析的过程，分析了一点以后直接在异或和比较的函数下了断点发现算法其实比较简单。  
```shell  
+4; -> IP  
+32 -> source  
+16 -> str_index  
+8 -> source[str_index]  
+24 ->   
  
初始IP: 2128  
202 -> IP + 5  
203 -> IP + 5  
204 -> IP + 1, load source  
207 -> ^ +12  save in 12, IP + 1  
201 -> next IP, save in 8, IP + 5  
  
opcode  
2128: 202  
2129: 0  
2130: 0  
2131: 0  
2132: 0  
2133: 203  
2134: 0  
2135: 0  
2136: 0  
2137: 0  
2138: 204  
2139: 207  
2140: 201  
2141: 238  
2142: 0  
2143: 0  
2144: 0  
2145: 207 -> // source[0] ^ 238  
2146: 209 -> 2160[index] == source[0] ^ 238  
```  
```python  
import base64  
result = {2160: 190, 2161: 54, 2162: 172, 2163: 39, 2164: 153, 2165: 79, 2166: 222, 2167: 68, 2168: 238, 2169: 95, 2170: 218, 2171: 11, 2172: 181, 2173: 23, 2174: 184, 2175: 104, 2176: 194, 2177: 78, 2178: 156, 2179: 74, 2180: 225, 2181: 67, 2182: 240, 2183: 34, 2184: 138, 2185: 59, 2186: 136, 2187: 91, 2188: 229, 2189: 84, 2190: 255, 2191: 104, 2192: 213, 2193: 103, 2194: 212, 2195: 6, 2196: 173, 2197: 11, 2198: 216, 2199: 80, 2200: 249, 2201: 88, 2202: 224, 2203: 111, 2204: 197, 2205: 74, 2206: 253, 2207: 47, 2208: 132, 2209: 54, 2210: 133, 2211: 82, 2212: 251, 2213: 115, 2214: 215, 2215: 13, 2216: 227}  
  
flag = []  
li = [0]  
for k in result.keys():  
    li.append(result[k])  
  
for i in range(1, len(li)):  
    flag.append(li[i-1] ^ li[i] ^ 238)  
ti = [0xa, 0xb, 0xc, 0xd]  
tar = ""  
for i in range(0, len(flag)-4, 4):  
    for j in range(4):  
        tar = tar + chr(ti[j] ^ flag[i+j])  
print(base64.decodestring(tar))  
```  
## babyarm  
主要验证部分在`sub_114D8`, xxtea稍微改了一点，一次加密了16轮...长度也是16  
```cpp  
#include <stdio.h>    
#include <stdint.h>    
#define DELTA 0x9e3779b9    
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))    
  
void btea(uint32_t *v, int n, uint32_t const key[4])    
{    
uint32_t y, z, sum;    
unsigned p, rounds, e;    
if (n > 1)            /* Coding Part */    
{    
    rounds = 6 + 52/n;    
    sum = 0;    
    z = v[n-1];    
    do    
    {    
        sum += DELTA;    
        e = (sum >> 2) & 3;    
        for (p=0; p<n-1; p++)    
        {    
            y = v[p+1];    
            z = v[p] += MX;    
        }    
        y = v[0];    
        z = v[n-1] += MX;    
    }    
    while (--rounds);    
}    
else if (n < -1)      /* Decoding Part */    
{    
    for(int i = 0; i < 16; i++)  
    {  
        n = 16;    
        rounds = 6 + 52/n;    
        sum = rounds*DELTA;    
        y = v[0];  
        do    
        {    
            e = (sum >> 2) & 3;    
            for (p=n-1; p>0; p--)    
            {    
                z = v[p-1];    
                y = v[p] -= MX;    
            }    
            z = v[n-1];    
            y = v[0] -= MX;    
            sum -= DELTA;    
        }    
        while (--rounds);    
    }  
}    
}    
  
  
int main()    
{    
uint32_t v[16]= {0xB061F013, 0xB3C8567E, 0x9952A3C7, 0x451C2D3F, 0x3EE32267, 0xE3E22B3E, 0x43E5A250, 0x59B28ED0, 0x0F8649DC, 0x9BF4D083, 0x8A578110, 0x8604EC4F, 0x2EB5A27F, 0x1217DDF3, 0x93C9B253, 0xDC7F8E43};    
uint32_t const k[4]= {2,2,3,4};    
int n= 16;  
// for(int i = 0; i < 16; i++)  
btea(v, -n, k);  
for(int i = 0; i < 16; i++)  
    printf("\"%x\", ", v[i]);  
return 0;    
}  
  
>>> s = ["67616c66", "6330447b", "37306261", "35346146", "36623241", "62376646", "41364541", "41624261", "64354635", "43336263", "43446639", "66613545", "34354665", "38434144", "30354138", "7d413339"]  
>>> flag = ""  
>>> for i in s:  
...     flag = flag + i.decode('hex')[::-1]  
...  
>>> flag  
'flag{D0cab07Fa45A2b6Ff7bAE6AaBbA5F5dcb3C9fDCE5afeF54DAC88A5093A}'  
```  

