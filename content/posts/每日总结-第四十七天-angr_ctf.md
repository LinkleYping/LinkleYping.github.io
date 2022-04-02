---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "angr使用"  
date: 2020-06-06T15:22:45+08:00  
categories : [                                
"notes",  
]  
draft: false  
---
<!--more-->
## 基础  
```python  
#coding=utf-8  
import angr  
import networkx as nx  
import matplotlib  
matplotlib.use('Agg')  
import matplotlib.pyplot as plt  
proj = angr.Project('/bin/true')  
print proj.filename  # 文件名  
print proj.arch  # 一个 archinfo.Arch 对象  
print hex(proj.entry)  # 入口点  
loader = proj.loader  
for obj in loader.all_objects:  # 程序加载时会将二进制文件和共享库映射到虚拟地址中,所有对象文件  
  print obj  
# 二进制文件本身是main_object  
print loader.main_object  
print hex(loader.main_object.min_addr)  
print hex(loader.main_object.max_addr)  
  
## 但是通常会选择关闭auto_load_libs,避免angr加载共享库  
proj = angr.Project('/bin/true', auto_load_libs=False)  
print proj.loader.all_objects  
# project.factory 提供了很多类对二进制文件进行分析  
# project.factory.block() 用于从给定地址解析一个 basic block，对象类型为 Block  
block = proj.factory.block(proj.entry)  
print block.pp() # 打印  
print block.instructions  # 指令数量  
print block.instruction_addrs # 指令地址  
# 将block类型转换为其他形式  
print block.capstone.pp()  
print block.vex.pp()  
# 程序的执行需要初始化一个模拟程序状态的 SimState 对象  
state = proj.factory.entry_state()  
# 该对象包含了程序的内存、寄存器、文件系统数据等等模拟运行时动态变化的数据  
print state.regs # 寄存器  
print state.regs.rip  # BV64对象  
print state.regs.rsp  
print state.regs.rsp.length  
print state.mem[proj.entry].int.resolved # 将入口点的内存解释为c语言的int类型  
# 这里的 BV，即 bitvectors，可以理解为一个比特串，用于在 angr 里表示 CPU 数据。看到在这里 rdi 有点特殊，它没有具体的数值，而是在符号执行中所使用的符号变量  
# python int与bitvector之间的转换  
bv = state.solver.BVV(0x1234, 32) # 创建一个32位的bitvector对象，值为0x1234  
print hex(state.solver.eval(bv))  
bv = state.solver.BVV(0x1234, 64) # 64位  
# bitvector之间的数学运算  
one = state.solver.BVV(1, 64)  
one_hundred = state.solver.BVV(2, 64)  
print one + one_hundred # 位数相同时可以直接运算  
five = state.solver.BVV(5, 27)  
print one + five.zero_extend(64 - 27) # 位数不同时需要进行扩展  
print one + five.sign_extend(64 - 27)  # 有符号扩展  
# 使用 bitvectors 可以直接来设置寄存器和内存的值，当传入的是 Python int 时，angr 会自动将其转换成 bitvectors  
# >>> state.regs.rsi = state.solver.BVV(3, 64)  
# >>> state.regs.rsi  
# <BV64 0x3>  
# >>> state.mem[0x1000].long = 4          # 在地址 0x1000 存放一个 long 类型的值 4  
# >>> state.mem[0x1000].long.resolved     # .resolved 获取 bitvectors  
# <BV64 0x4>  
# >>> state.mem[0x1000].long.concrete     # .concrete 获得 Python int  
# 4L  
# 初始化的 state 可以经过模拟执行得到一系列的 states，模拟管理器（Simulation Managers）的作用就是对这些 states 进行管理  
simgr = proj.factory.simulation_manager(state)  
print simgr.active # 当前状态  
simgr.step() # 模拟执行一个basic block  
print simgr.active # 当前状态被更新  
print simgr.active[0].regs.rip # active[0] 是当前 state  
# attention: 被改变的仅仅是simgr的状态，原始状态并不会被改变  
print state.regs.rip  
# angr 提供了大量函数用于程序分析，在这些函数在 Project.analyses.  
p = angr.Project('/bin/true', load_options={'auto_load_libs': False})  
cfg = p.analyses.CFGFast()  
nx.draw(cfg.graph)                  # 画图  
plt.savefig('temp.png')    
```  
## 00_angr_find  
find的使用  
```python  
import angr, sys  
  
def main():  
    filename = "00_angr_find"  
    proj = angr.Project(filename)  
    initial_state = proj.factory.entry_state()  
    simgr = proj.factory.simgr(initial_state)  
    address = 0x8048675  
    simgr.explore(find=address)  
    if simgr.found:  
        solution = simgr.found[0]  
        print(solution.posix.dumps(sys.stdin.fileno()))  
  
if __name__ == "__main__":  
    main()  
```  
## 01_angr_avoid  
avoid的使用  
```python  
import angr, sys  
  
def main():  
    filename = "01_angr_avoid"  
    proj = angr.Project(filename)  
    initial_state = proj.factory.entry_state()  
    simgr = proj.factory.simgr(initial_state)  
    address = 0x80485B5  
    simgr.explore(find=address, avoid=0x80485A8)  
    if simgr.found:  
        solution = simgr.found[0]  
        print(solution.posix.dumps(sys.stdin.fileno()))  
  
if __name__ == "__main__":  
    main()  
```  
## 带参数执行  
```python  
import angr, claripy  
proj = angr.Project('./angr2', auto_load_libs=False)  
argv1 = claripy.BVS("argv1", 9 * 8) // 这里用的单位是bit，因此需要乘以8  
state = proj.factory.entry_state(args=['./angr2', argv1]) // 导入参数  
simgr = proj.factory.simgr(state)  
print(simgr.explore(find=0x4007DC, avoid=0x4007EA))  
print(simgr.found[0].solver.eval(argv1, cast_to=bytes)) // 直接输出是ascii码，用cast_to=bytes转为bytes类型  
```  
## 02_angr_find_condition  
find 跟 avoid 参数可以是一个你已经确定感兴趣或要避免的地址（或者是地址列表）或者是一个可以动态选择“是否感兴趣”的函数。  
```python  
import angr, sys  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno()) # (1)  
    if b'Good Job.' in stdout_output: # (2)  
        return True # (3)  
    else:  
        return False  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno())     
    if b'Try again.' in  stdout_output:  
        return True  
    else:  
        return False  
  
def main():  
    filename = "02_angr_find_condition"  
    proj = angr.Project(filename)  
    initial_state = proj.factory.entry_state()  
    simgr = proj.factory.simgr(initial_state)  
    simgr.explore(find=is_successful, avoid=should_abort)  
    if simgr.found:  
        solution = simgr.found[0]  
        print(solution.posix.dumps(sys.stdin.fileno()))  
  
if __name__ == "__main__":  
    main()  
```  
## 03_angr_symbolic_registers  
当调用` scanf()`的时候，angr无法处理复杂的格式。可以将符号值注入寄存器。也可以自己选择开始执行的地址，不一定要从entry开始执行，需要用 blank_state() 方法替代了entry_state()。  
```python  
#coding=utf-8  
import angr, sys, claripy  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno()) # (1)  
    if b'Good Job.' in stdout_output: # (2)  
        return True # (3)  
    else:  
        return False  
  
    def should_abort(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno())     
    if b'Try again.' in  stdout_output:  
        return True  
    else:  
        return False  
  
def main():  
    filename = "03_angr_symbolic_registers"  
    proj = angr.Project(filename)  
    start_address = 0x8048980  
    initial_state = proj.factory.blank_state(addr=start_address)  
    # 用 claripy 通过 BVS() 方法生成三个位向量。这个方法需要两个参数：第一个参数表示符号名，第二个参数表示这个符号的长度 单位bit。位数与寄存器的位数相同，是32位  
    password_size_in_bits = 32  
    password0 = claripy.BVS('password0', password_size_in_bits)  
    password1 = claripy.BVS('password1', password_size_in_bits)  
    password2 = claripy.BVS('password2', password_size_in_bits)  
    # 更新寄存器的内容  
    initial_state.regs.eax = password0  
    initial_state.regs.ebx = password1  
    initial_state.regs.edx = password2  
    simgr = proj.factory.simgr(initial_state)  
    simgr.explore(find=is_successful, avoid=should_abort)  
    if simgr.found:  
        solution_state = simgr.found[0]  
        # 根据注入的三个符号值调用求解引擎的 eval()方法； format() 方法格式化解并去掉16进制的 “0x”。  
        solution0 = format(solution_state.solver.eval(password0), 'x') # (1)  
        solution1 = format(solution_state.solver.eval(password1), 'x')  
        solution2 = format(solution_state.solver.eval(password2), 'x')  
        solution = solution0 + " " + solution1 + " " + solution2  
        print("[+] Success! Solution is: {}".format(solution))  
    else:  
        raise Exception('Could not find the solution')  
  
if __name__ == "__main__":  
    main()  
```  
## 04_angr_symbolic_stack  
上面一个是变量储存在寄存器上，所以可以直接设置寄存器，这里是变量储存在栈上。针对栈的操作需要注意调整一下栈空间.  
```python  
#coding=utf-8  
import angr, sys, claripy  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno()) # (1)  
    if b'Good Job.' in stdout_output: # (2)  
        return True # (3)  
    else:  
        return False  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno())     
    if b'Try again.' in  stdout_output:  
        return True  
    else:  
        return False  
  
def main():  
    filename = "04_angr_symbolic_stack"  
    proj = angr.Project(filename)  
    start_address = 0x08048697  
    initial_state = proj.factory.blank_state(addr=start_address)  
    initial_state.regs.ebp = initial_state.regs.esp  # 模拟mov ebp, esp  
  
    # esp减8再push进两个4字节的变量，相当于sub esp, 0x10  
    padding_length_in_bytes = 8  
    initial_state.regs.esp -= padding_length_in_bytes  
    password0 = claripy.BVS('password0', 32)  
    password1 = claripy.BVS('password1', 32)  
    # 压栈  
    initial_state.stack_push(password0)   
    initial_state.stack_push(password1)  
  
    simgr = proj.factory.simgr(initial_state)  
    simgr.explore(find=is_successful, avoid=should_abort)  
    if simgr.found:  
        solution_state = simgr.found[0]  
        solution0 = format(solution_state.solver.eval(password0), 'x') # (1)  
        solution1 = format(solution_state.solver.eval(password1), 'x')  
        solution = solution0 + " " + solution1  
        print("[+] Success! Solution is: {}".format(solution))  
    else:  
        raise Exception('Could not find the solution')  
  
if __name__ == "__main__":  
    main()  
```  
## 05_angr_symbolic_memory  
angr处理内存  
```python  
#coding=utf-8  
import angr, sys, claripy  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno()) # (1)  
    if b'Good Job.' in stdout_output: # (2)  
        return True # (3)  
    else:  
        return False  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno())     
    if b'Try again.' in  stdout_output:  
        return True  
    else:  
        return False  
  
def main():  
    filename = "05_angr_symbolic_memory"  
    proj = angr.Project(filename)  
    start_address = 0x80485FE  
    initial_state = proj.factory.blank_state(addr=start_address)  
    password = claripy.BVS('password', 256)  
    user_input_address = 0xA1BA1C0  
    # 将内容写入内存  
    initial_state.memory.store(user_input_address, password)  
  
    simgr = proj.factory.simgr(initial_state)  
    simgr.explore(find=is_successful, avoid=should_abort)  
    if simgr.found:  
        solution_state = simgr.found[0]  
        solution = solution_state.solver.eval(password, cast_to=bytes)  
        print("[+] Success! Solution is: {}".format(solution.decode('utf-8')))  
    else:  
        raise Exception('Could not find the solution')  
  
if __name__ == "__main__":  
    main()  
```  
## 06_angr_symbolic_dynamic_memory  
上面05中是把输入的内容直接存储在user_inout处的固定地址上，而这道题中，buffer0和buffer1中存储的是malloc分配内存的地址，这个地址是动态的，地址指向的内容才是真正的输入。所以首先要将输入符号存储在内存中，然后将内存地址写入buffer0和buffer1。  
```python  
#coding=utf-8  
import angr, sys, claripy  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno()) # (1)  
    if b'Good Job.' in stdout_output: # (2)  
        return True # (3)  
    else:  
        return False  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno())     
    if b'Try again.' in  stdout_output:  
        return True  
    else:  
        return False  
  
def main():  
    filename = "06_angr_symbolic_dynamic_memory"  
    proj = angr.Project(filename)  
    start_address = 0x8048696  
    initial_state = proj.factory.blank_state(addr=start_address)  
    password0 = claripy.BVS('password0', 64)  
    password1 = claripy.BVS('password1', 64)  
  
    fake_heap_address0 = 0xffffc93c # (1)  
    pointer_to_malloc_memory_address0 = 0xabcc8a4 # (2)  
    fake_heap_address1 = 0xffffc94c # (3)  
    pointer_to_malloc_memory_address1 = 0xabcc8ac # (4)  
  
    # 将buffer0, buffer1中写入虚假的堆地址  
    initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=proj.arch.memory_endness) # (5)  
    initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=proj.arch.memory_endness) # (6)  
  
    # 在堆地址中写入输入的符号内容  
    initial_state.memory.store(fake_heap_address0, password0) # (7)  
    initial_state.memory.store(fake_heap_address1, password1) # (8)  
  
    simgr = proj.factory.simgr(initial_state)  
    simgr.explore(find=is_successful, avoid=should_abort)  
    if simgr.found:  
        solution_state = simgr.found[0]  
        solution0 = solution_state.solver.eval(password0, cast_to=bytes)  
        solution1 = solution_state.solver.eval(password1, cast_to=bytes)  
        solution = solution0 + b" " + solution1  
        print("[+] Success! Solution is: {}".format(solution.decode('utf-8')))  
    else:  
        raise Exception('Could not find the solution')  
  
if __name__ == "__main__":  
    main()  
```  
## 07_angr_symbolic_file  
符号化文件中的内容  
```python  
import angr  
import sys  
  
def main(argv):  
    bin_path = argv[1]  
  
    project = angr.Project(bin_path)  
    start_addr = 0x080488D6  
    init_state = project.factory.blank_state(addr = start_addr)  
  
    filename = "OJKSQYDP.txt"  
    file_size = 0x40  
  
    password = init_state.solver.BVS("password", file_size)  
  
    # SimFile是构造文件信息，包括文件名，文件内容和文件大小  
    simgr_file = angr.storage.SimFile(  
        filename, content=password, size=file_size)  
  
    # angr.fs.insert是将文件插入到文件系统中，需要文件名与符号化的文件  
    init_state.fs.insert(filename, simgr_file)  
  
    simgr = project.factory.simgr(init_state)  
  
def is_successful(state):  
    return b"Good Job." in state.posix.dumps(1)  
  
def should_abort(state):  
    return b"Try again." in state.posix.dumps(1)  
  
print(simgr.explore(find=is_successful, avoid=should_abort))  
if simgr.found:  
    print(simgr.found[0].solver.eval(password,  cast_to=bytes))  
else:  
    raise(Exception("Solution not found."))  
if __name__ == "__main__":  
    main(sys.argv)  
```  
## 08_angr_constraints  
自己添加约束条件  
```c  
int __cdecl main(int argc, const char **argv, const char **envp)  
{  
    signed int i; // [esp+Ch] [ebp-Ch]  
  
    password = 1146115393;  
    dword_804A044 = 1380994638;  
    dword_804A048 = 1381647695;  
    dword_804A04C = 1112233802;  
    memset(&buffer, 0, 0x11u);  
    printf("Enter the password: ");  
    __isoc99_scanf("%16s", &buffer);  
    for ( i = 0; i <= 15; ++i )  
    *(_BYTE *)(i + 134520912) = complex_function(*(char *)(i + 134520912), 15 - i);  
    if ( check_equals_AUPDNNPROEZRJWKB((int)&buffer, 0x10u) )  
    puts("Good Job.");  
    else  
    puts("Try again.");  
    return 0;  
}  
```  
原函数`check_equals_AUPDNNPROEZRJWKB`是一个比较简单的函数，但是因为字符一个一个比较会产生路径爆炸问题，所以当执行到这个函数里面时，我们用自己的方法来实现，实现的方法是添加约束add_constraints  
```python  
import angr  
import sys  
  
def main(argv):  
    bin_path = argv[1]  
    project = angr.Project(bin_path)  
  
    start_addr = 0x08048625  
    init_state = project.factory.blank_state(addr = start_addr)  
  
    buff_addr = 0x0804A050  
    password = init_state.solver.BVS("password", 16 * 8)  
  
    init_state.memory.store(buff_addr, password)  
  
    simgr = project.factory.simgr(init_state)  
  
    check_addr = 0x08048565  
          
    # 当找到这个函数时  
    simgr.explore(find = check_addr)  
  
    if simgr.found:  
        check_state = simgr.found[0]  
        desired_string = "AUPDNNPROEZRJWKB"  
        check_param1 =  buff_addr  
        check_param2 = 0x10  
        # 获取内存地址处的值  
        check_bvs = check_state.memory.load(check_param1, check_param2)  
        check_constraint = desired_string == check_bvs  
        check_state.add_constraints(check_constraint)  
        print(check_state.solver.eval(password, cast_to = bytes))  
  
if __name__ == "__main__":  
    main(sys.argv)  
```  
也可以直接对check函数进行hook  
```python  
import angr  
import claripy  
import sys  
  
def main(argv):  
    bin_path = argv[1]  
    project = angr.Project(bin_path)  
  
    initial_state = project.factory.entry_state()  
    # call    check_equals_AUPDNNPROEZRJWKB处的地址  
    check_equals_called_address = 0x8048673  
  
    instruction_to_skip_length = 5  
  
@project.hook(check_equals_called_address, length=instruction_to_skip_length)  
def skip_check_equals_(state):  
    user_input_buff_address = 0x804a054  
    user_input_buff_length = 16  
    user_input_string = state.memory.load(  
        user_input_buff_address,  
        user_input_buff_length  
    )  
  
    check_against_string = "XKSPZSJKJYQCQXZV"  
    # 函数对比的结果保存在eax中返回  
    state.regs.eax = claripy.If (  
        user_input_string == check_against_string,  
        claripy.BVV(1, 32),  
        claripy.BVV(0, 32)  
    )  
  
    simulation = project.factory.simgr(initial_state)  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Good Job." in stdout_output  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Try again." in stdout_output  
  
simulation.explore(find = is_successful, avoid = should_abort)  
  
if simulation.found:  
    print(simulation.found[0].posix.dumps(0))  
else:  
    raise(Exception("Could not find the solution"))  
  
if __name__ == "__main__":  
    main(sys.argv)  
```  
## 10_angr_simprocedures  
使用函数名进行hook(出现多个地方call func的时候对每个call指令地址进行hook太麻烦，针对有符号的函数)  
```python     
import angr  
import claripy  
import sys  
  
def main(argv):  
    bin_path = argv[1]  
    project = angr.Project(bin_path)  
  
initial_state = project.factory.entry_state()  
  
class mySimPro(angr.SimProcedure):  
    def run(self, user_input, user_input_length):  
        angr_bvs = self.state.memory.load (  
            user_input,  
            user_input_length  
        )  
  
        check_string = "ORSDDWXHZURJRBDH"  
  
        return claripy.If (  
            check_string == angr_bvs,  
            claripy.BVV(1, 32),  
            claripy.BVV(0, 32)  
        )  
  
check_symbol = "check_equals_ORSDDWXHZURJRBDH"  
project.hook_symbol(check_symbol, mySimPro())  
  
simulation = project.factory.simgr(initial_state)  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Good Job." in stdout_output  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Try again." in stdout_output  
  
simulation.explore(find = is_successful, avoid = should_abort)  
  
if simulation.found:  
    print(simulation.found[0].posix.dumps(0))  
else:  
    raise(Exception("Could not find the solution"))  
  
if __name__ == "__main__":  
    main(sys.argv)  
```  
还可以用符号hook scanf函数  
```python  
import angr  
import claripy  
import sys  
  
def main(argv):  
    bin_path = argv[1]  
    project = angr.Project(bin_path)  
  
    initial_state = project.factory.entry_state()  
  
class ReplacementScanf(angr.SimProcedure):  
    def run(self, format_string, scanf0_address, scanf1_address):  
        scanf0 = claripy.BVS('scanf0', 32)  
        scanf1 = claripy.BVS('scanf1', 32)  
  
        self.state.memory.store(scanf0_address, scanf0, endness = project.arch.memory_endness)  
        self.state.memory.store(scanf1_address, scanf1, endness = project.arch.memory_endness)  
  
        self.state.globals['solutions'] = (scanf0, scanf1)  
  
scanf_symbol = "__isoc99_scanf"  
  
project.hook_symbol(scanf_symbol, ReplacementScanf())  
  
simulation = project.factory.simgr(initial_state)  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Good Job." in stdout_output  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Try again." in stdout_output  
  
simulation.explore(find = is_successful, avoid = should_abort)  
  
if simulation.found:  
    solution_state = simulation.found[0]  
    stored_solutions = solution_state.globals['solutions']  
    scanf0_solution = solution_state.solver.eval(stored_solutions[0], cast_to = bytes)  
    scanf1_solution = solution_state.solver.eval(stored_solutions[1], cast_to = bytes)  
    print(scanf0_solution, scanf1_solution)  
else:  
    raise(Exception("Could not find the solution"))  
  
if __name__ == "__main__":  
    main(sys.argv)  
```  
## 12_angr_veritesting  
学习使用Veritesting的技术解决路径爆炸问题  
  
Python  
Veritesting  
- 结合静态符号执行和动态符号执行  
- 把限制式全部合并到一条路径上  
- 减少 path explosion 的影响  
  
`project.factory.simgr(initial_state, veritesting=True)`  
IDA打开，其中这个循环会在二叉决策的时候导致路径爆炸  
```c  
for ( i = 0; i <= 31; ++i )  
{  
    v5 = *((char *)s + i + 3);  
    if ( v5 == complex_function(75, i + 93) )  
    ++v15;  
}  
```  
```python  
import angr  
import claripy  
import sys  
  
def main(argv):  
    bin_path = argv[1]  
    project = angr.Project(bin_path)  
  
initial_state = project.factory.entry_state()  
  
simulation = project.factory.simgr(initial_state, veritesting = True)  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Good Job." in stdout_output  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Try again." in stdout_output  
  
simulation.explore(find = is_successful, avoid = should_abort)  
  
if simulation.found:  
    solution_state = simulation.found[0]  
    print(solution_state.posix.dumps(0))  
else:  
    raise(Exception("Could not find the solution"))  
  
if __name__ == "__main__":  
    main(sys.argv)  
```  
## 13_angr_static_binary  
针对静态编译的程序，angr提供了一些常用库函数的实现,eg:  
```shell  
# angr.SIM_PROCEDURES['libc']['malloc']  
# angr.SIM_PROCEDURES['libc']['fopen']  
# angr.SIM_PROCEDURES['libc']['fclose']  
# angr.SIM_PROCEDURES['libc']['fwrite']  
# angr.SIM_PROCEDURES['libc']['getchar']  
# angr.SIM_PROCEDURES['libc']['strncmp']  
# angr.SIM_PROCEDURES['libc']['strcmp']  
# angr.SIM_PROCEDURES['libc']['scanf']  
# angr.SIM_PROCEDURES['libc']['printf']  
# angr.SIM_PROCEDURES['libc']['puts']  
# angr.SIM_PROCEDURES['libc']['exit']  
```  
需要找到这些函数进行hook  
```python  
import angr  
import claripy  
import sys  
  
  
def main(argv):  
    bin_path = argv[1]  
    project = angr.Project(bin_path)  
  
    initial_state = project.factory.entry_state()  
  
    simulation = project.factory.simgr(initial_state)  
  
    project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())  
    project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())  
    project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())  
    project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())  
  
  
def is_successful(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Good Job." in stdout_output  
  
def should_abort(state):  
    stdout_output = state.posix.dumps(1)  
    return b"Try again." in stdout_output  
  
simulation.explore(find = is_successful, avoid = should_abort)  
  
if simulation.found:  
    solution_state = simulation.found[0]  
    print(solution_state.posix.dumps(0))  
else:  
    raise(Exception("Could not find the solution"))  
  
if __name__ == "__main__":  
    main(sys.argv)  
```  
## 参考链接  
https://xz.aliyun.com/t/6557  
https://lantern.cool/2020/05/15/note-tool-angr/  
https://xz.aliyun.com/t/7117  
https://github.com/firmianay/CTF-All-In-One/blob/master/doc/5.3.1_angr.md  