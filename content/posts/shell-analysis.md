---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "Shell Analysis"  
date: 2021-04-07T10:55:45+08:00  
categories : [                                  
"notes",    
]  
draft: true  
---
  
## 反射  
  
Java 类的成员包括以下三类：属性字段、构造函数、方法。反射的 API 也是与这几个成员相关：  
  
- Field 类：提供有关类的属性信息，以及对它的动态访问权限。它是一个封装反射类的属性的类。  
- Constructor 类：提供有关类的构造方法的信息，以及对它的动态访问权限。它是一个封装反射类的构造方法的类。  
- Method 类：提供关于类的方法的信息，包括抽象方法。它是用来封装反射类方法的一个类。  
- Class 类：表示正在运行的 Java 应用程序中的类的实例。  
- Object 类：Object 是所有 Java 类的父类。所有对象都默认实现了 Object 类的方法。  
  
### 获取Class对象的三种方式  
第一种方法是通过类的全路径字符串获取 Class 对象，这也是我们平时最常用的反射获取 Class 对象的方法；  
第二种方法有限制条件：需要导入类的包；  
第三种方法已经有了 Student 对象，不再需要反射。  
```java  
// 1.通过字符串获取Class对象，这个字符串必须带上完整路径名  
Class studentClass = Class.forName("com.test.reflection.Student");  
// 2.通过类的class属性  
Class studentClass2 = Student.class;  
// 3.通过对象的getClass()函数  
Student studentObject = new Student();  
Class studentClass3 = studentObject.getClass();  
```  
.Class和Class.forName是编译时决定, 而.getClass()是运行时决定  
- .Class: JVM将使用类的类装载器, 将类装入内存(前提是:类还没有装入内存),不对类做类的初始化工作.返回类的Class的对象  
- .getClass(): 返回对象运行时的真正对象(有可能存在向上转换)所属的类  
Class.forName(): 装入类, 并做类的初始化  
  
### 获取类的成员变量  
获取字段有两个 API：getDeclaredFields和getFields。他们的区别是:getDeclaredFields用于获取所有声明的字段，包括公有字段和私有字段，getFields仅用来获取公有字段：  
```java  
// 1.获取所有声明的字段  
Field[] declaredFieldList = studentClass.getDeclaredFields();  
for (Field declaredField : declaredFieldList) {  
    System.out.println("declared Field: " + declaredField);  
}  
// 2.获取所有公有的字段  
Field[] fieldList = studentClass.getFields();  
for (Field field : fieldList) {  
    System.out.println("field: " + field);  
}  
```  
  
### 获取构造方法  
获取构造方法同样包含了两个 API：用于获取所有构造方法的 getDeclaredConstructors和用于获取公有构造方法的getConstructors:  
```java  
// 1.获取所有声明的构造方法  
Constructor[] declaredConstructorList = studentClass.getDeclaredConstructors();  
for (Constructor declaredConstructor : declaredConstructorList) {  
    System.out.println("declared Constructor: " + declaredConstructor);  
}  
// 2.获取所有公有的构造方法  
Constructor[] constructorList = studentClass.getConstructors();  
for (Constructor constructor : constructorList) {  
    System.out.println("constructor: " + constructor);  
}  
```  
  
### 获取非构造方法  
获取非构造方法的两个 API 是：获取所有声明的非构造函数的 getDeclaredMethods 和仅获取公有非构造函数的 getMethods：  
```java  
// 1.获取所有声明的函数  
Method[] declaredMethodList = studentClass.getDeclaredMethods();  
for (Method declaredMethod : declaredMethodList) {  
    System.out.println("declared Method: " + declaredMethod);  
}  
// 2.获取所有公有的函数  
Method[] methodList = studentClass.getMethods();  
for (Method method : methodList) {  
    System.out.println("method: " + method);  
}  
```  
  
### 实践  
以 Student 类为例，如果此类在其他的包中，并且我们的需求是要在程序中通过反射获取他的构造方法，构造出 Student 对象，并且通过反射访问他的私有字段和私有方法。  
```java  
package com.test.reflection;  
public class Student {  
    private String studentName;  
    public int studentAge;  
    public Student() {  
    }  
    private Student(String studentName) {  
        this.studentName = studentName;  
    }  
    public void setStudentAge(int studentAge) {  
        this.studentAge = studentAge;  
    }  
    private String show(String message) {  
        System.out.println("show: " + studentName + "," + studentAge + "," + message);  
        return "testReturnValue";  
    }  
}  
```  
```java  
// 1.通过字符串获取Class对象，这个字符串必须带上完整路径名  
Class studentClass = Class.forName("com.test.reflection.Student");  
// 2.获取声明的构造方法，传入所需参数的类名，如果有多个参数，用','连接即可  
Constructor studentConstructor = studentClass.getDeclaredConstructor(String.class);  
// 如果是私有的构造方法，需要调用下面这一行代码使其可使用，公有的构造方法则不需要下面这一行代码  
studentConstructor.setAccessible(true);  
// 使用构造方法的newInstance方法创建对象，传入构造方法所需参数，如果有多个参数，用','连接即可  
Object student = studentConstructor.newInstance("NameA");  
// 3.获取声明的字段，传入字段名  
Field studentAgeField = studentClass.getDeclaredField("studentAge");  
// 如果是私有的字段，需要调用下面这一行代码使其可使用，公有的字段则不需要下面这一行代码  
// studentAgeField.setAccessible(true);  
// 使用字段的set方法设置字段值，传入此对象以及参数值  
studentAgeField.set(student,10);  
// 4.获取声明的函数，传入所需参数的类名，如果有多个参数，用','连接即可  
Method studentShowMethod = studentClass.getDeclaredMethod("show",String.class);  
// 如果是私有的函数，需要调用下面这一行代码使其可使用，公有的函数则不需要下面这一行代码  
studentShowMethod.setAccessible(true);  
// 使用函数的invoke方法调用此函数，传入此对象以及函数所需参数，如果有多个参数，用','连接即可。函数会返回一个Object对象，使用强制类型转换转成实际类型即可  
Object result = studentShowMethod.invoke(student,"message");  
System.out.println("result: " + result);  
```  
  
## 加壳  
  
DexClassLoader-> BaseDexClassLoader->DexPathList->makeDexElements->loadDexFile->DexFile.loadDex()->openDexFile(返回mcookie)->openDexFileNative()->dvmRawDexFileOpen()->dvmOptimizeDexFile()->dexOpt->fromDex->rewriteDex()->dvmDexFileOpenPartial->dexFileParse  
  
- DexFileParse  
- dvmDexFileOpenPartial