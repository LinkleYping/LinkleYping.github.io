# ubuntu下LLVM开发环境的配置

### 安装clang和cmake  
`sudo apt-get install clang cmake`    
### 安装llvm  
`sudo apt-get install llvm`    
使用这种方法我默认安装上的llvm版本为3.8.0，安装后的文件目录为`/usr/share/llvm-3.8`    
### 修改LLVMConfig.cmake文件    
`set(LLVM_CMAKE_DIR "${LLVM_INSTALL_PREFIX}/share/llvm/cmake")`    
改为    
`set(LLVM_CMAKE_DIR "${LLVM_INSTALL_PREFIX}/share/llvm-3.8/cmake")`    
### 修改LLVMExports-relwithdebinfo.cmake文件    
由于权限问题不能直接打开修改，在命令行中写入:    
`sudo gedit LLVMExports-relwithdebinfo.cmake`    
对文件进行如下修改:  
```shell  
#Commands may need to know the format version.    
set(CMAKE_IMPORT_FILE_VERSION 1)  
set(_IMPORT_PREFIX "/usr/lib/llvm-3.8")  
```  
注释与Polly相关的库引用  
```shell  
# Import target "PollyISL" for configuration "RelWithDebInfo"                                                                                                                                                 
# set_property(TARGET PollyISL APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)                                                                                                                        
# set_target_properties(PollyISL PROPERTIES                                                                                                                                                                   
#   IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "C"                                                                                                                                                      
#   IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/libPollyISL.a"                                                                                                                                    
#   )                                                                                                                                                                                                         
#                                                                                                                                                                                                             
# list(APPEND _IMPORT_CHECK_TARGETS PollyISL )                                                                                                                                                                
# list(APPEND _IMPORT_CHECK_FILES_FOR_PollyISL "${_IMPORT_PREFIX}/lib/libPollyISL.a" )                                                                                                                        
#                                                                                                                                                                                                             
# # Import target "Polly" for configuration "RelWithDebInfo"                                                                                                                                                  
# set_property(TARGET Polly APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)                                                                                                                           
# set_target_properties(Polly PROPERTIES                                                                                                                                                                      
#   IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "CXX"                                                                                                                                                    
#   IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/libPolly.a"                                                                                                                                       
#   )                                                                                                                                                                                                         
#                                                                                                                                                                                                             
# list(APPEND _IMPORT_CHECK_TARGETS Polly )                                                                                                                                                                   
# list(APPEND _IMPORT_CHECK_FILES_FOR_Polly "${_IMPORT_PREFIX}/lib/libPolly.a" )                                                                                                                              
#                                                                                                                                                                                                             
# # Import target "LLVMPolly" for configuration "RelWithDebInfo"                                                                                                                                              
# set_property(TARGET LLVMPolly APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)                                                                                                                       
# set_target_properties(LLVMPolly PROPERTIES                                                                                                                                                                  
#   IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/LLVMPolly.so"                                                                                                                                     
#   IMPORTED_NO_SONAME_RELWITHDEBINFO "TRUE"                                                                                                                                                                  
#   )                                                                                                                                                                                                         
#                                                                                                                                                                                                             
# list(APPEND _IMPORT_CHECK_TARGETS LLVMPolly )                                                                                                                                                               
# list(APPEND _IMPORT_CHECK_FILES_FOR_LLVMPolly "${_IMPORT_PREFIX}/lib/LLVMPolly.so" )    
```  
### 使用LLVM进行开发    
新建文件夹: `HowToUseJIT`    
目录结构如下:    
```shell  
HowToUseJIT    
  -- src  
      +  -- HowToUseJIT.cpp  
  -- CMakeLists.txt  
  -- build  
```  
在`HowToUseJIT`文件夹下进行如下操作:    
```shell  
cd build  
cmake ..  
make  
```  
`HowToUseJIT.cpp`和`CMakeLists.txt`文件可以自己根据LLVM提供的API自行开发，也可以使用下面所给的例子：  
`HowToUseJIT.cpp`  
```c  
#include "llvm/IR/LLVMContext.h"  
#include "llvm/IR/Function.h"  
#include "llvm/IR/BasicBlock.h"  
#include "llvm/ADT/ArrayRef.h"  
#include "llvm/IR/Module.h"  
#include "llvm/IR/IRBuilder.h"  
#include <vector>  
#include <string>  
   
int main()  
{  
llvm::LLVMContext & context = llvm::getGlobalContext();  
llvm::Module *module = new llvm::Module("asdf", context);  
llvm::IRBuilder<> builder(context);  
   
llvm::FunctionType *funcType = llvm::FunctionType::get(builder.getVoidTy(), false);  
llvm::Function *mainFunc =   
  llvm::Function::Create(funcType, llvm::Function::ExternalLinkage, "main", module);  
llvm::BasicBlock *entry = llvm::BasicBlock::Create(context, "entrypoint", mainFunc);  
builder.SetInsertPoint(entry);  
   
llvm::Value *helloWorld = builder.CreateGlobalStringPtr("hello world!\n");  
   
std::vector<llvm::Type *> putsArgs;  
putsArgs.push_back(builder.getInt8Ty()->getPointerTo());  
llvm::ArrayRef<llvm::Type*>  argsRef(putsArgs);  
   
llvm::FunctionType *putsType =   
  llvm::FunctionType::get(builder.getInt32Ty(), argsRef, false);  
//llvm::Constant *putsFunc = module->getOrInsertFunction("puts", putsType);  
llvm::Function *putsFunc =   
  llvm::Function::Create(putsType, llvm::Function::ExternalLinkage, "puts", module);  
llvm::BasicBlock *putsentry = llvm::BasicBlock::Create(context, "entrypoint", putsFunc);  
builder.SetInsertPoint(putsentry);  
builder.CreateCall(putsFunc, helloWorld);  
builder.CreateRetVoid();  
module->dump();  
}  
```  
CMakeLists.txt  
```c  
cmake_minimum_required(VERSION 2.8)  
project(llvm_test)  
  
set(LLVM_TARGETS_TO_BUILD X86)  
set(LLVM_BUILD_RUNTIME OFF)  
set(LLVM_BUILD_TOOLS OFF)  
  
find_package(LLVM REQUIRED CONFIG)  
  
message(STATUS "Found LLVM ${LLVM_INCLUDE_DIRS}")  
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")  
  
  
SET (CMAKE_CXX_COMPILER_ENV_VAR "clang++")  
  
SET (CMAKE_CXX_FLAGS "-std=c++11")  
SET (CMAKE_CXX_FLAGS_DEBUG   "-g")  
SET (CMAKE_CXX_FLAGS_MINSIZEREL  "-Os -DNDEBUG")  
SET (CMAKE_CXX_FLAGS_RELEASE  "-O4 -DNDEBUG")  
SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")  
  
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)  
  
include_directories(${LLVM_INCLUDE_DIRS})  
add_definitions(${LLVM_DEFINITIONS})  
  
file(GLOB_RECURSE source_files "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")  
add_executable(llvm_test ${source_files})  
install(TARGETS llvm_test RUNTIME DESTINATION bin)  
  
# Find the libraries that correspond to the LLVM components  
# that we wish to use  
llvm_map_components_to_libnames(llvm_libs   
  Core  
  ExecutionEngine  
  Interpreter  
  MC  
  Support  
  nativecodegen)  
  
# Link against LLVM libraries  
target_link_libraries(llvm_test ${llvm_libs})  
```  
如果编译通过说明LLVM开发环境搭建成功，如果报一些库文件缺失的错误有可能是因为默认LLVM文件夹的文件名为`llvm`而安装LLVM后自带的文件名为`llvm-3.8`可以根据报错内容对`/usr/share/llvm-3.8`或`usr/lib/llvm-3.8`的文件名进行修改 
