---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "wasi使用笔记"    
date: 2020-10-20T15:22:45+08:00    
categories : [                                  
"writeup",    
]    
draft: false    
---
  
## .c编译成.wasm    
1. 第一个工具: wasmcc    
安装    
`curl https://raw.githubusercontent.com/wasienv/wasienv/master/install.sh | sh`    
https://github.com/wasienv/wasienv    
其中安装完成之后会包含很多个工具，wasirun可以运行wasm代码    
```shell    
$ wasirun hello.wasm    
Hello wasi    
```  
2. emscripten    
https://segmentfault.com/a/1190000014208777    
```shell    
git clone https://github.com/juj/emsdk.git    
cd emsdk    
emsdk update    
emsdk install latest    
emsdk activate latest    
//如果没有出现emcc命令:    
source ./emsdk_env.sh    
```  
编译命令：`emcc hello.c -s WASM=1 -o hello.wasm`    
## c代码调用wasm代码    
https://docs.wasmer.io/integrations/c/setup    
环境设置:    
```shell    
# Extract the contents to a dir    
mkdir wasmer-c-api    
tar -C wasmer-c-api -zxvf wasmer-c-api*.tar.gz    
    
export WASMER_C_API=`pwd`/wasmer-c-api    
    
# Update LD_LIBRARY_PATH to link against the libwasmer.so in the examples    
export LD_LIBRARY_PATH=`pwd`/wasmer-c-api/lib/:$LD_LIBRARY_PATH    
```  
编译命令:    
```shell    
静态链接：gcc test.c -I${WASMER_C_API}/include -L${WASMER_C_API}/lib -lwasmer -o test    
动态链接：gcc -static main.c -I${WASMER_C_API}/include -L${WASMER_C_API}/lib -lwasmer -lpthread -lm -ldl -o main    
```  
3. 例子    
在这里有很多wasi使用的例子    
https://docs.wasmer.io/integrations/c/setup    
但是没看见直接运行整个wasm代码的(例子是调用wasm函数的)    
```cpp    
// wasm部分    
#include<stdio.h>    
    
int main()    
{    
char s[20] = {0};    
scanf("%s", s);    
puts(s);    
return 0;    
}    
// c部分    
#include <stdio.h>    
#include "wasmer.h"    
#include <assert.h>    
#include <stdint.h>    
    
// Function to print the most recent error string from Wasmer if we have them    
void print_wasmer_error()    
{    
int error_len = wasmer_last_error_length();    
char *error_str = malloc(error_len);    
wasmer_last_error_message(error_str, error_len);    
printf("Error: `%s`\n", error_str);    
}    
    
int main()    
{    
FILE *file = fopen("hello.wasm", "r");    
assert(file != NULL);    
fseek(file, 0, SEEK_END);    
long len = ftell(file);    
uint8_t *bytes = (uint8_t*)malloc(len);    
fseek(file, 0, SEEK_SET);    
fread(bytes, 1, len, file);    
fclose(file);    
    
wasmer_module_t *module = NULL;    
wasmer_result_t compile_result = wasmer_compile(&module, bytes, len);    
if (compile_result != WASMER_OK)    
{    
    print_wasmer_error();    
    return -1;    
}    
wasmer_import_object_t *wasi_import_obj = wasmer_wasi_generate_default_import_object();    
    
// find out what version of WASI the module is    
Version wasi_version = wasmer_wasi_get_version(module);    
// char* progname = "ProgramName";    
// wasmer_byte_array args[] = { { .bytes = progname; .bytes_len = sizeof(progname); } };    
wasmer_import_object_t * import_object = wasmer_wasi_generate_import_object_for_version(wasi_version, 0, 1, NULL, 0, NULL, 0, NULL, 0);    
    
// Instantiate a WebAssembly Instance from Wasm bytes and imports    
wasmer_instance_t *instance = NULL;    
// clock_gettime(CLOCK_REALTIME, &start);    
wasmer_result_t instantiate_result = wasmer_module_import_instantiate(&instance, module, import_object);    
    
if(instantiate_result != WASMER_OK)    
{    
    print_wasmer_error();    
    return -1;    
}    
wasmer_value_t arguments[] = {0};    
wasmer_value_t results[] = {0};    
// Call the `sum` function with the prepared arguments and the return value.    
wasmer_result_t call_result = wasmer_instance_call(instance, "_start", arguments, 0, results, 1);    
int response_value = results[0].value.I32;     
printf("%d\n", response_value);    
wasmer_instance_destroy(instance);    
return 0;    
}    
```  
调用`_start`函数相当于运行整个wasm代码    
