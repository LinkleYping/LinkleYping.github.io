# 虎符2020部分re

    
## game    
根据python的反汇编代码可以得到下面的逻辑：    
- check0 每个字符为32 - 128    
- check1(s): len(s) < 100 && (len * len % 777) ^ 233 == 513  > len(s) = 39    
- check2(s): ((s[0]*128 + s[1])) * 128) + s[2]...s[5]=3533889469877 -> s[5]='5'    
- check3:    
arr = map(ord(s))    
a = arr[slice(6, 30, 3)]    
for i in range(len(a))    
  (a[i]*17684 + 372511)% 257 == arr0[i]    
b = arr[slice(-2, 33, -1)] * 5    
c = map(lambda x[0] ^ x[1], zip(b, arr[slice(7, 27)]))    
if c != arr1:    
  p = 0    
  for i in range(28, 34):    
      (arr[i] + 107) / 16 + 77 == arr2[p]    
      (arr[i] + 117) % 16 + 99 == arr2[p + 1]    
      p = p + 2    
```python    
arr0 = [249, 91, 149, 113, 16, 91, 53, 41]    
arr1 = [43, 1, 6, 69, 20, 62, 6, 44, 24, 113, 6, 35, 0, 3, 6, 44, 20, 22, 127, 60]    
arr2 = [90, 100, 87, 109, 86, 108, 86, 105, 90, 104, 88, 102]    
flag6_30_3 = []    
for i in range(len(arr0)):    
  for t in range(32, 128):    
      if (t*17684 + 372511)% 257 == arr0[i]:    
          flag6_30_3.append(chr(t))    
          continue    
flag_35 = chr(arr1[2] ^ ord(flag6_30_3[1]))    
flag_36 = chr(arr1[5] ^ ord(flag6_30_3[2]))    
flag_37 = chr(arr1[8] ^ ord(flag6_30_3[3]))    
flag_34 = chr(arr1[11] ^ ord(flag6_30_3[4]))    
b = [ord(flag_37), ord(flag_36), ord(flag_35), ord(flag_34)] * 5    
flag_7_27 = []    
for i in range(len(arr1)):    
  flag_7_27.append(chr(b[i] ^ arr1[i]))    
flag_28_34 = []    
p = 0    
for i in range(28, 34):    
  for t in range(32, 128):    
      if (t + 107) / 16 + 77 == arr2[p] and (t + 117) % 16 + 99 == arr2[p + 1]:    
          flag_28_34.append(chr(t))    
          continue    
  p = p + 2    
s1 = "".join(i for i in flag_7_27)    
s2 = "".join(i for i in flag_28_34)    
s3 = "".join([flag_34, flag_35,flag_36,flag_37])    
flag = 'flag{5'+flag6_30_3[0]+s1+flag6_30_3[-2]+s2+s3+'}'    
print flag    
```    
## vm    
是个逻辑很清楚的vm，但是wtcl比赛时间对我来说有点短不够我翻译的...后面才做出来的，根据逻辑写出parser    
```python    
def parser(code):    
  f = open('opcode.txt', 'w')    
  pc = 0    
  ins = 40    
  stack = []    
  reg = [0]*4    
  store = [0]*300    
  while pc < len(code):    
      c = code[pc]    
      if c == 1:    
          f.write("push inputc ")    
          stack.append(ins)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 2:    
          f.write("pop --> ")    
          f.write("outputc %d "%stack[-1])    
          f.write("--> now stack:" + str(stack)+'\n')    
          print store    
          del stack[-1]    
          pc = pc + 1    
      elif c == 3:    
          f.write("nop")    
          pc = pc + 1    
      elif c == 4:    
          f.write("push %d "%code[pc+1])    
          stack.append(code[pc + 1])    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc += 2    
      elif c == 5:    
          f.write("push reg[%d] "%code[pc+1])    
          stack.append(reg[code[pc+1]])    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc += 2    
      elif c == 6:    
          f.write("pop reg[%d] "%(code[pc+1]))    
          reg[code[pc+1]] = stack[-1]    
          del stack[-1]    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc += 2    
      elif c == 7:    
          f.write("push store[%d]"%(code[pc+1]))    
          stack.append(store[code[pc+1]])    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 2    
      elif c == 8:    
          f.write("pop store[%d]"%(code[pc+1]))    
          store[code[pc+1]] = stack[-1]    
          del stack[-1]    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 2    
      elif c == 9:    
          f.write("add")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append((a+b)&0xff)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0xa:    
          f.write("sub")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append((b-a)&0xff)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0xb:    
          f.write("mul")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append((a*b)&0xff)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0xc:    
          f.write("div")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append((b/a)&0xff)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0xd:    
          f.write("mod")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append(b%a)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0xe:    
          f.write("xor")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append(b ^ a)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0xf:    
          f.write("and")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append(b&a)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0x10:    
          f.write("or")    
          a = stack[-1]    
          b = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          stack.append(b | a)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0x11:    
          f.write("-")    
          a = stack[-1]    
          del stack[-1]    
          stack.append((-a)&0xff)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc += 1    
      elif c == 0x12:    
          f.write("~")    
          a = stack[-1]    
          del stack[-1]    
          stack.append((~a)&0xff)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc += 1    
      elif c == 0x13:    
          a = stack[-2]    
          b = stack[-1]    
          del stack[-1]    
          del stack[-1]    
          f.write("cmp")    
          if a != b:    
              f.write("not equal, go on")    
              f.write("--> now stack:" + str(stack)+'\n')    
              pc = pc + 2    
          else:    
              f.write("equal, jmp")    
              f.write("--> now stack:" + str(stack)+'\n')    
              if code[pc+1] <= 0x7f:    
                  pc = pc + code[pc+1]    
              else:    
                  pc = pc - (256 - code[pc + 1])    
      elif c == 0x14:    
          a = stack[-2]    
          b = stack[-1]    
          del stack[-1]    
          del stack[-1]    
          f.write("cmp")    
          if a == b:    
              f.write("equal, go on")    
              f.write("--> now stack:" + str(stack)+'\n')    
              pc = pc + 2    
          else:    
              f.write("not equal, jump")    
              f.write("--> now stack:" + str(stack)+'\n')    
              if code[pc+1] <= 0x7f:    
                  pc = pc + code[pc+1]    
              else:    
                  pc = pc - (256 - code[pc + 1])    
      elif c == 0x15:    
          a = stack[-2]    
          b = stack[-1]    
          del stack[-1]    
          del stack[-1]    
          f.write("cmp")    
          if a<=b:    
              f.write("less or equal, go on")    
              pc = pc + 2    
              f.write("--> now stack:" + str(stack)+'\n')    
          else:    
              f.write("not less or equal, jump")    
              f.write("--> now stack:" + str(stack)+'\n')    
              if code[pc+1] <= 0x7f:    
                  pc = pc + code[pc+1]    
              else:    
                  pc = pc - (256 - code[pc + 1])    
      elif c == 0x16:    
          a = stack[-2]    
          b = stack[-1]    
          del stack[-1]    
          del stack[-1]    
          f.write("cmp")    
          if a < b:    
              f.write("less, go on")    
              f.write("--> now stack:" + str(stack)+'\n')    
              pc = pc + 2    
          else:    
              f.write("not less, jump")    
              f.write("--> now stack:" + str(stack)+'\n')    
              if code[pc+1] <= 0x7f:    
                  pc = pc + code[pc+1]    
              else:    
                  pc = pc - (256 - code[pc + 1])    
      elif c == 0x17:    
          a = stack[-2]    
          b = stack[-1]    
          del stack[-1]    
          del stack[-1]    
          f.write("cmp")    
          if a >= b:    
              f.write("great or equal, go on")    
              f.write("--> now stack:" + str(stack)+'\n')    
              pc = pc + 2    
          else:    
              f.write("not great or equal, jump")    
              f.write("--> now stack:" + str(stack)+'\n')    
              if code[pc+1] <= 0x7f:    
                  pc = pc + code[pc+1]    
              else:    
                  pc = pc - (256 - code[pc + 1])    
      elif c == 0x18:    
          a = stack[-2]    
          b = stack[-1]    
          del stack[-1]    
          del stack[-1]    
          f.write("cmp")    
          if a > b:    
              f.write("greate, go on")    
              f.write("--> now stack:" + str(stack)+'\n')    
              pc = pc + 2    
          else:    
              f.write("not greate, jump")    
              f.write("--> now stack:" + str(stack)+'\n')    
              if code[pc+1] <= 0x7f:    
                  pc = pc + code[pc+1]    
              else:    
                  pc = pc - (256 - code[pc + 1])    
      elif c == 0x19:    
          f.write("push store[%d]"%(stack[-1]))    
          a = store[stack[-1]]    
          del stack[-1]    
          stack.append(a)    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0x1a:    
          f.write("pop store[%d]"%(stack[-1]))    
          store[stack[-1]] = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif c == 0x1b:    
          f.write("push reg[%d]"%(stack[-1]))    
          a = stack[-1]    
          del stack[-1]    
          stack.append(reg[a])    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc += 1    
      elif c == 0x1c:    
          f.write("pop reg[%d]"%(stack[-1]))    
          reg[stack[-1]] = stack[-2]    
          del stack[-1]    
          del stack[-1]    
          f.write("--> now stack:" + str(stack)+'\n')    
          pc = pc + 1    
      elif 0x1d:    
          if pc+1 >= len(code):    
              print hex(pc+1)    
              break    
          if code[pc+1] <= 0x7f:    
              pc_t = pc + code[pc+1]    
          else:    
              pc_t = pc - (256 - code[pc + 1])    
          pc = pc_t    
          f.write("jmp %d\n"%pc_t)    
      else:    
          f.write("Error")    
          break    
    
with open('code', 'rb') as f:    
  code = f.read()    
  c = []    
  for i in code:    
      c.append(ord(i))    
  parser(c)    
```    
根据parser解析的结果分析加密逻辑就能写出解密的代码    
```python    
def enc(s):    
  s1 = [0] * 42    
  for i in range(7):    
      for j in range(6):    
          a = s[i*6+j]    
          b = (j+2)*i    
          k = ((~a)&0xff) & b    
          m = a & ((~b)&0xff)    
          n = k ^ m    
          s1[j*7+i] = n    
  for i in range(1, 42):    
      if i % 2 != 0:    
          a = s1[i]    
          s1[i] = (a * 107)&0xff    
      else:    
          s1[i] = (s1[i] + s1[i-1])&0xff    
  return s1    
    
def dec(c):    
  message = [0]*42    
  for i in range(1,len(c)-1,2):    
      c[i+1] = (c[i+1] - c[i])&0xff    
      for h in range(255):    
          if (h*107)&0xff == c[i]:    
              c[i] = h    
              break    
  i = 41    
  for h in range(255):    
      if (h*107)&0xff == c[i]:    
          c[i] = h    
          break    
  for i in range(7):    
      for j in range(6):    
          e = c[j*7+i]    
          b = (j+2)*i    
          for a in range(20,127):    
              k = ((~a)&0xff) & b    
              m = a & ((~b)&0xff)    
              n = k ^ m    
              if n == e:    
                  message[i*6+j] = a    
                  break    
  return message    
data = [102, 78, 169, 253, 60, 85, 144, 36, 87, 246, 93, 177, 1, 32, 129, 253, 54, 169, 31, 161, 14, 13, 128, 143, 206, 119, 232, 35, 158, 39, 96, 47, 165, 207, 27, 189, 50, 219, 255, 40, 164, 93]    
flag = dec(data)    
print "".join(chr(f) for f in flag)    
```    

