---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "Kotlin开发"  
date: 2020-09-13T15:22:45+08:00  
categories : [                                
"notes",  
]  
draft: false  
---
## Kotlin一些特性  
  
- var: 变量，val:常量  
- 定义变量时，可在类型后面加一个问号?，表示该变量是Nullable，不加表示该变量不可为null  
- 扩展(好神奇)  
- 继承  
- object: 类似java的匿名内部类  
- companion：Kotlin给Java开发者带来最大改变之一就是废弃了static修饰符。与Java不同的是在Kotlin的类中不允许你声明静态成员或方法。相反，你必须向类中添加Companion对象来包装这些静态引用  
  
## 参考  
[https://www.bilibili.com/video/BV1654y1X7Jo?from=search&seid=7649962615194993068](https://www.bilibili.com/video/BV1654y1X7Jo?from=search&seid=7649962615194993068)    
因为最近的项目需要Android开发的基础比较高，准备学习一下kotlin，先学习的是这个视频中的内容，在这里做个笔记。  
## 模块化  
模块化的作用  
- 业务分离  
- 通用化，代码复用  
  
如何实现模块化  
- 公用模块抽取  
- 业务模块抽取  
- 主工程组装业务模块  
  
模块间的通讯  
- 跨模块跳转  
- 跨模块接口调用  
- ARouter路由框架(alibaba)  
  
## MVP架构  
MVP 全称：Model - View - Presenter  
  
Model 表示数据层，View 表示视图层，Presenter 表示逻辑处理层  
在 MVP 模式中  
- View 不和 Model 进行直接交互，View 通过 Presenter 将前端数据传给 Model，或者通过 Presenter 从 Model 中获取数据，View 和 Model 所有的交互都发生在 Presenter 中  
- View 负责前端的展示以及与用户的交互  
- Model 负责数据的存储以及调用  
  
好处：能够有效解耦工程，分为各个独立模块，功能清晰，有利于重复使用，在调试过程中也能够快速定位错误  
缺陷：增加代码工作量  
  
[https://www.viseator.com/2017/05/25/android_google_mvp/](https://www.viseator.com/2017/05/25/android_google_mvp/)  
![android_mvp_uml.jpg](/images/977d40f26cf19a1c69cb03fa3aeb2a79/11884068-ac55b2b181ce11ac.jpg)  
  
## 技术选型  
### 视图层  
- kotlin-android-extensions  
- Butterknife  
  
### 业务层  
- RxKotlin  
- RxAndroid  
- RxLifecycle  
  
### 其他  
- Dagger2（依赖注入）  
- Gson（数据路由）  
- ARouter（模块路由）  
- Glide（图片加载）  
- takephoto（图片选择）  
- 七牛（数据云存储）  
- MultiStateView（多状态视图）  
- bga-refreshlayout（上下拉刷新）  
  
## Application与Library  
### 启动  
- Application作为应用程序启动: apply plugin: 'com.android.application'  
- Library作为库工程被引用: apply plugin: 'com.android.library'  
### 切换  
```java  
if(xxx.toBoolean()){  
apply plugin: 'com.android.library'  
}else{  
apply plugin: 'com.android.application'  
}  
```  
### 两套AndroidManifest  
- 一套用于Application时使用，配置主题及默认启动，位于debug目录  
- 一套用于Library时使用，注册组件及权限，位于release目录  
### AndroidManifest的切换  
```java  
sourceSers{  
main{  
    if(xxx.toBoolean()){  
        mainfest.srcFile 'src/main/release/AndroidManifest.xml'  
    }else{  
        mainfest.srcFile 'src/main/debug/AndroidManifest.xml'  
    }  
}  
}  
```  
## android-extensions介绍  
- 视图绑定，可直接使用XML中ID操作该控件  
- 插件级别，无需引入第三方库  
- 无需定义变量，极大减少代码  
- 适用于Activity, Fragment, Adapter及自定义View  
## Anko  
Anko组成部分：  
- Anko Commons  
- Anko Layouts  
- Anko SQLite：数据库  
- Anko Coroutines: 协程  
  
## RxJava  
下面这个是两个作者写的RxJava2.0的一系列教程    
https://maxwell-nc.github.io/categories.html    
https://www.jianshu.com/u/c50b715ccaeb  
  
## Retrofit  
官方网址：https://square.github.io/retrofit/  
  
## Dagger2:依赖注入  
- @Inject和@Component  
- @Module和@Provides  
- @Scope和@Singleton  
- @Qualifier和@Named  
依赖注入的含义：  
正常版：  
```java  
class ClassB{  
fun sayHello(){  
    println("hello")  
}  
}  
class ClassA{  
var mClassB: ClassB  
init{  
    mClassB = ClassB()  
}  
fun doSomething(){  
    mClassB.sayHello()  
}  
}  
```  
依赖注入版：  
```java  
class ClassB @Inject constructor{  
fun sayHello(){  
    println("hello")  
}  
}  
class ClassA{  
@Inject  
lateinit var mClassB: ClassB  
  
fun doSomething(){  
    mClassB.sayHello()  
}  
}  
```  
@Component  
- 注入器，连接目标类和依赖实例的桥梁  
- 以@Component标注的类必须是接口或者抽象类  
- Component依赖关系通过dependencier属性添加  
- App必须有一个Component用来管理全局实例  
  
@Module  
- 第三方库无法修改，不能在其构造函数添加@Inject  
- 接口不能实例化， 只能通过实现类实例化  
- Module是一个简单工厂，创建类实例的方法  
- Component通过Modules属性加入多个Module  
  
@Proivides  
- 在Module中，使用@Provides标注创建实例的方法  
- 实例化流程  
-- Component搜索@Inject注解的属性  
-- Component查找Module中以@Provides注解的对应方法，创建实例  
  
Inject和Module维度  
- Module优先级高于Inject构造函数  
- 查找到实例对象，依次查看其参数实例化  
- Module中存在创建实例方法，停止查找Inject维度，如果没有，查找Inject构造函数  
  
  
  
  
  
  
