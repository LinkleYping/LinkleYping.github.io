# 钓鱼城杯2020-reg

    
是用`aardio`写的程序，没找到直接获取脚本的工具，先下载`aardio`的编译器尝试自己写脚本编译，查看生成的二进制文件。比较题目给的文件和自己生成的文件发现，代码部分几乎一模一样，应该全部都是`aardio`的解释器部分。在自己生成的文件中发现了使用的函数字符串，同样去查找题目给的文件，发现了下面一些关键信息：    
    
![](/images/144a6fe1c08235363bae1142e8e6dfdc/11884068-d188ac4771a55d13.png)    
    
    
从这些关键字可以看出题目使用的aes加密，设置了key和iv，然后使用Base64编码后输出。但是key和iv未知。`aardio`的基本都是基于winapi实现的，查看文件运行时导入表中有`cryptsp.dll`，对`cryptsp.dll`的`CryptSetKeyParam`函数下断点    
![](/images/144a6fe1c08235363bae1142e8e6dfdc/11884068-91a93e9b560eabab.png)    
    
可以得到加密使用的key和iv(需要到这个函数四次，第三次才是key，第四次是iv)。然后直接使用`aardio`进行解密:    
```python    
import console    
import crypt.aes    
import crypt.bin    
    
sstr = "8QAUFzIzw0gtrLeRUpesieQJDC6jxCujTszwcj/I9nU1h3J5LlMBcUS38IO5AHRY"    
str = crypt.bin.decodeBase64(sstr)    
    
keylist = string.pack(0xE3, 0xDF, 0xB2, 0x4A, 0x55, 0x53, 0xED, 0xAC, 0x13, 0xFF, 0x65, 0xAC, 0x7B, 0x5F, 0x31, 0x70)    
ivlist = string.pack(0x9d,0x25,0xdd,0xe0,0xc1,0x37,0x86,0x21,0x32,0xec,0x0c,0x32,0x4c,0xfb,0xf0,0x46)    
var des = crypt.aes()    
des.setPassword(keylist)    
des.setInitVector(ivlist)    
flag = des.decrypt(str)    
console.log(flag)    
console.pause(true)    
```    
Nu1L的wp中提供了`aardio`加密时使用的源代码，问了一下师傅说是自己写的提取工具，给跪了。    
```c    
keylist = {    
  18908379,    
  33159482,    
  16588432,    
  17582695,    
  33159482,    
  33159482,    
  33490903,    
  15925590,    
  32828061,    
  16257011,    
  16919853,    
  18245537,    
  18576958,    
  17914116,    
  16588432,    
  16257011,    
  16919853,    
  16588432,    
  33490903,    
  32828061,    
  15925590,    
  32828061,    
  16919853,    
  16588432,    
  17251274,    
  32828061,    
  33822324,    
  32496640,    
  33822324,    
  15925590,    
  17251274,    
  17914116,    
  33490903,    
  16919853,    
  33159482,    
  33822324,    
  32496640,    
  16588432,    
  17251274,    
  32165219,    
  17582695,    
  17582695,    
  17582695,    
  16919853,    
  33490903,    
  33159482,    
  32165219,    
  32828061,    
  16257011,    
  16919853,    
  33822324,    
  33822324,    
  17914116,    
  17582695,    
  32165219,    
  32828061,    
  18245537,    
  32496640,    
  17582695,    
  33822324,    
  16919853,    
  16257011,    
  18245537,    
  15925590    
}    
function deckey(owner)    
  local i, j    
  local ss = ""    
  for i = 1, 64 do    
      j = (keylist[i] - 17382) / 331421    
      ss = ss .. string:pack(j)    
  end    
  return ss    
end    
console:setTitle("reg")    
local flag = console:getText("Input your flag:")    
console:log("check your reg code:" .. flag)    
local secretstr = deckey(console)    
local aesiv = crypt.bin:decodeHex(string:left(secretstr, 32))    
local aeskey = crypt.bin:decodeHex(string:right(secretstr, 32))    
local aes = crypt:aes()    
aes:setPassword(aeskey)    
aes:setInitVector(aesiv)    
local cipher = aes:encrypt(flag)    
local output = crypt.bin:encodeBase64(cipher)    
string:save("output", output)    
console:log("cipher:", output)    
console:pause()    
```    
再贴一个其他师傅的wp: [https://www.52pojie.cn/thread-1255567-1-1.html](https://www.52pojie.cn/thread-1255567-1-1.html)    

