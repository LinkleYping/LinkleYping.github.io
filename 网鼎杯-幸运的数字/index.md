# 网鼎杯-幸运的数字

   
## libgmp库    
静态链接去符号表文件，首先制作sig导入，但是可能因为库版本和libc版本问题，能够识别的函数并不是很多，只有参照源码+调试    
## 代码解析    
关键函数在`sub_401F8A`和`sub_401C7D`，其中`sub_401C7D`是一个RSA函数，处理后的`sub_401F8A`如下:    
```c    
_BOOL8 sub_401F8A()    
{    
char input_str; // [rsp+0h] [rbp-1F0h]    
int v2; // [rsp+60h] [rbp-190h]    
int v3; // [rsp+64h] [rbp-18Ch]    
char v4; // [rsp+70h] [rbp-180h]    
char v5; // [rsp+F0h] [rbp-100h]    
struct mpz_num n; // [rsp+110h] [rbp-E0h]    
struct mpz_num q; // [rsp+120h] [rbp-D0h]    
struct mpz_num p; // [rsp+130h] [rbp-C0h]    
char v9; // [rsp+140h] [rbp-B0h]    
char v10; // [rsp+150h] [rbp-A0h]    
char v11; // [rsp+160h] [rbp-90h]    
struct mpz_num v12; // [rsp+170h] [rbp-80h]    
char v13; // [rsp+180h] [rbp-70h]    
char v14; // [rsp+190h] [rbp-60h]    
struct mpz_num v15; // [rsp+1A0h] [rbp-50h]    
struct mpz_num v16; // [rsp+1B0h] [rbp-40h]    
char v17; // [rsp+1C0h] [rbp-30h]    
struct mpz_num input_n; // [rsp+1D0h] [rbp-20h]    
__int64 v19; // [rsp+1E8h] [rbp-8h]    
    
mpz_init(&v17);    
mpz_init_set_str((__int64)&v16, (__int64)"226", 0xAu);    
sub_47AC70(&v16, "226");    
sub_4430F0((unsigned __int64)&v5);    
v19 = sub_444530(&v5, "r");    
sub_444290(&v4, 128LL, v19);    
sub_443F20(v19);    
if ( !(unsigned int)sub_401098(&v4, "hdb") )    
  return 1LL;    
mpz_init(&v13);    
mpz_init(&v10);    
mpz_init(&v9);    
mpz_init(&v11);    
sub_403080(&v14, 2LL);    
mpz_init(&n);    
mpz_init(&v12);    
mpz_init_set_str((__int64)&v15, (__int64)"2", 0xAu);    
mpz_init_set_str((__int64)&p, (__int64)"170141183460469231731687303715884106303", 0xAu);    
mpz_init_set_str((__int64)&q, (__int64)"170141183460469231731687303715884106207", 0xAu);    
memset(&input_str, 0, 0x60uLL);    
v2 = 0;    
getinput((__int64)"%s", &input_str, &v3);    
mpz_init_set_str((__int64)&input_n, (__int64)&input_str, 0xAu);    
mpz_mul(&n.a1, (__int64)&p, (__int64)&q);     // n = p * q    
mpz_square((__int64)&input_n, (__int64)&v12); // v12 = inputn * inputn    
mpz_div((signed int *)&v11, (__int64)&input_n, (__int64)&v16);// v11 = inputn // 226    
mpz_mul((signed int *)&v11, (__int64)&v11, (__int64)&input_n);// v11 * inputn    
mpz_sub(&v9, &v12, &v11);                     // v9 = v12 - v11    
sub_404920(&v10, 1LL);                        // v10 = 1    
while ( (unsigned int)sub_402E20((__int64)&v15, (__int64)&v9) != 1 )// v15 <= v9    
{    
  mpz_pow(&v14, &v15, 3LL);                   // v14 = pow(v15, 3)    
  mpz_add(&v10, &v10, &v14);    
  mpz_add1(&v15.a1, (__int64)&v15, 1uLL);     // v15 = v15 + 1    
}    
mpz_mul(&n.a1, (__int64)&p, (__int64)&q);    
mpz_mod((__int64)&v10, (__int64)&v10, (__int64)&n);    
rsa((__int64)&v13, (__int64)&v10);    
gmp_printf((__int64)"%ZX\n", &v13);    
mpz_clear(&input_n.a1);    
mpz_clear((signed int *)&v17);    
mpz_clear(&v16.a1);    
mpz_clear((signed int *)&v11);    
mpz_clear((signed int *)&v13);    
mpz_clear(&v15.a1);    
mpz_clear((signed int *)&v10);    
mpz_clear((signed int *)&v9);    
mpz_clear(&p.a1);    
mpz_clear(&q.a1);    
mpz_clear(&v12.a1);    
sub_47AC70(&v12, &v13);    
sub_4430F0((unsigned __int64)&v5);    
v19 = sub_444530(&v5, "r");    
sub_444290(&v4, 128LL, v19);    
sub_443F20(v19);    
return (unsigned int)sub_401098(&v4, "hdb") == 0;    
}    
```    
RSA函数:    
```c    
__int64 __fastcall rsa(__int64 a1, __int64 a2)    
{    
__int64 result; // rax    
__int64 v3; // r8    
__int64 v4; // r9    
char v5; // [rsp+10h] [rbp-110h]    
char v6; // [rsp+90h] [rbp-90h]    
char v7; // [rsp+B0h] [rbp-70h]    
char e; // [rsp+C0h] [rbp-60h]    
char n; // [rsp+D0h] [rbp-50h]    
char v10; // [rsp+E0h] [rbp-40h]    
char q; // [rsp+F0h] [rbp-30h]    
char p; // [rsp+100h] [rbp-20h]    
__int64 v13; // [rsp+118h] [rbp-8h]    
    
mpz_init(&p);    
mpz_init(&q);    
mpz_init(&v10);    
mpz_init(&n);    
sub_403080(&e, 65537LL);    
mpz_init(&v7);    
sub_404600(&p, "170141183460469231731687303715884105757", 10LL);    
sub_404600(&q, "170141183460469231731687303715884106001", 10LL);    
mpz_mul((signed int *)&v10, (__int64)&p, (__int64)&q);    
sub_47AC70(&v10, &p);    
sub_4430F0((unsigned __int64)&v6);    
v13 = sub_444530(&v6, "r");    
sub_444290(&v5, 128LL, v13);    
sub_443F20(v13);    
result = sub_401098(&v5, "hdb");    
if ( !(_DWORD)result )    
  return result;    
sub_404DA0(&p, &p, 1LL);    
sub_404DA0(&q, &q, 1LL);    
mpz_mul((signed int *)&n, (__int64)&p, (__int64)&q);    
sub_402EC0(&v7, &e, &n);    
sub_403670((int *)a1, a2, (__int64)&e, (__int64)&v10, v3, v4);    
mpz_clear((signed int *)&q);    
mpz_clear((signed int *)&p);    
mpz_clear((signed int *)&v10);    
mpz_clear((signed int *)&n);    
mpz_clear((signed int *)&e);    
result = mpz_clear((signed int *)&v7);    
return result;    
}    
```    
从上面解析后的可以比较清晰的看到加密流程:    
```shell    
1. 输入inputn    
2. t = input // 226    
3. 计算a = input*input - t*input    
4. 计算(1^3 + 2^3 + 3^3 + ... + a^3) % n = b，可以化成: (a*(a+1)/2)^2 % n = b    
5. 对b进行rsa运算，各种参数在rsa函数中可见    
```    
## solve    
首先解RSA得到b:    
```python    
#coding=utf-8    
import gmpy2    
c = 0x37CFC2B07BF92321BFCEAF6330C667D217BB881B0911A8810D28D9986CA52E2F    
p = 170141183460469231731687303715884105757    
q = 170141183460469231731687303715884106001    
e = 65537    
n = p * q    
phi = (p-1)*(q-1)    
d = gmpy2.invert(e, phi)    
a = pow(c,d,n) # 解RSA    
```    
由于`(a*(a+1)/2)^2 % n = b`，类似Rabin加密算法，p,q已知，可以求得`a*(a+1)/2`的值    
```python    
p = 170141183460469231731687303715884106303    
q = 170141183460469231731687303715884106207    
n = p * q    
a1 = pow(a, (p+1)/4, p)    
a2 = pow(a, (q+1)/4, q)    
x = gmpy2.invert(p,q)    
y = gmpy2.invert(q,p)    
z = (y*q*a1+x*p*a2)%n    
k = (y*q*a1-x*p*a2)%n    
res = [-k%n, z%n, -y%n, x%n]    
print res    
```    
求出来有四个解，有符合条件的唯一解，需要试，然后`a*(a+1)/2`的值已知时，需要求a的值，方程是: `a^2 + a = 2n` => `(2a+1)^2=8n+1`， 求a:    
```python    
i = res[0]    
v = i * 8    
v = v + 1    
sq = gmpy2.iroot(v, 2)    
ceshi1 = sq[0] - 1    
num = gmpy2.c_div(ceshi1, 2)    
print num    
```    
其中`a = input*input - t*input` and `t = input // 226`可以求得input    
```python    
num1 = num * 226 // 225    
num1 = gmpy2.iroot(num1, 2)[0]    
x = "flag{"+str(num1) + "}"    
print x    
sha256 = hashlib.sha256()    
x = sha256.update(x.encode('utf-8'))    
h = sha256.hexdigest()    
print h    
# flag{244466666888888108}    
# 0a4b7f6c8baf4b16465975218d547f820a3802972b1512e8e6f704893cdccb2e    
```    
## 参考链接    
https://l0x1c.github.io/2020/05/15/2020-5-14/ 
