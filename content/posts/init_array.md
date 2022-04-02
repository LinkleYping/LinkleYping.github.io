---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "调试android so的.init_array数组"  
date: 2021-09-01T15:22:45+08:00  
categories : [                                  
"notes",    
]   
draft: false  
---
## 在init_array中下断  
下面是网上的一般做法，感觉可能比较适合老一些的android版本，不过也应该都差不多  
- 从手机中pull出来linker  
- 搜索字符串"[ Calling %s @ %p for '%s' ]"(可能并不是一模一样，没找到的话部分搜索试试)  
- 查找引用这个字符串的地址，如果是直接pull出来的linker的话是保留符号信息的，找`call_array/call_function`相关的函数  
- 找字符串下方`BLX R4`的地方  
![](/images/init_array/1.jpg)  
  
## init_array下断原理  
android源码网站：[androidxref.com](http://androidxref.com/)  
loadlibrary的主要步骤  
1. 调用linker的dlopen完成加载  
2. 调用dlsym获取目标so的JniOnload地址并调用  
3. 初始化SharedLibrary对象并添加到表中, 下次加载相同的so则不在重复加载  
查看`dlopen`源码    
![](/images/init_array/2.1.png)  
  
调用`find_library`转载链接so文件，加载成功后返回soinfo对象指针，同时调用`call_constructors`函数来调用so中的`init_array`。    
![](/images/init_array/2.2.png)  
  
`call_constructors`先完成其他模块的加载,然后调用`call_array`来调用init_array数组中的函数。    
![](/images/init_array/2.png)  
  
`call_array`循环调用`call_funtion`来进行加载，最后call_function只是简单的调用传进来的函数指针, 可以看到我们上面的下断点的字符串就来自于这里。  
  
所以网上的一般做法可能适用情况有限，可以直接通过对照linker中的源码实现来最终定位，一般来说先找到`call_array`中的字符串找对应位置即可。    
对于64位so的情况相似，不过是`BLX R4`这条指令不同，但是肯定也是找到字符串以后定位寄存器直接调用的地方就行。  

## 参考链接  
[IDA调试 Android so文件的10个技巧](https://zhuanlan.zhihu.com/p/30308066)  