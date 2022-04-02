# sig制作

https://blog.csdn.net/Breeze_CAT/article/details/103788796  
工具: flair  
```shell  
./pelf libc.a libc.pat  
#如果这句话报错: Unknown relocation type 42 (offset in section=0x16).那么要加一个参数：  
./pelf -r42:0:0 libc.a libc.pat  
#如果有出现别的错误，继续添加这个参数 -r错误号:0:0  
./sigmake libc.pat libc.sig  
```  
然后查看是否成功，有时没有成功就是文件中签名有冲突，这时不会生成.sig而是生成了一个.exc文件  
![](/images/2778b3d1a9d8b0b764b5462c876eefd5/11884068-2bd05b775fe8b231.png)  
大概意思就是有些模块的签名是一样的，我们要选择使用哪个，看红框中的内容，大体意思就是在想要选择的模块前面标记’+’，在不确定的选择前面标’-’，什么也不做就会排除这个模块，最后要删掉这四行内容。  
![](/images/2778b3d1a9d8b0b764b5462c876eefd5/11884068-e1de621d1aa74419.png)
