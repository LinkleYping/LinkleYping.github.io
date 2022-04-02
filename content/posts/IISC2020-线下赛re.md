---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "IISC2020-线下赛re"  
date: 2020-11-07T15:22:45+08:00  
categories : [                                  
"writeup",    
]   
draft: false  
---
帮忙做了一个re题，题目挺简单的，是python 的exe解包，做了还是写写吧hhh  
## python exe解包  
首先利用pyinstxtractor脚本将.exe文件转为.pyc文件，指令格式为  
```shell  
python pyinstxtractor.py  exe文件名称  
```  
执行完成之后会生成一个`xxx_extracted`文件夹，反编译之前先把`struct`文件中`E3`之前的字符复制到想要反编译的文件中  
![](/images/6e1ddf3433fac03345c9f122ebc54d01/11884068-de8194d2b63b7386.png)  
这道题需要反编译的文件是`snake`  
![before.png](/images/6e1ddf3433fac03345c9f122ebc54d01/11884068-f57fbd400ab6bb23.png) ![after.png](/images/6e1ddf3433fac03345c9f122ebc54d01/11884068-d5cb9e9cc8db5b64.png)  
补完头部信息之后可以用uncompyle6反编译`uncompyle6 snake.pyc > snake.py`  
```python  
# uncompyle6 version 3.7.4  
# Python bytecode 3.7 (3394)  
# Decompiled from: Python 3.8.3 (default, Jul  2 2020, 17:30:36) [MSC v.1916 64 bit (AMD64)]  
# Embedded file name: snake.py  
# Compiled at: 1995-09-28 00:18:56  
# Size of source mod 2**32: 272 bytes  
import hashlib, sys, random, time  
maze = [  
 [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  
 [1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],  
 [0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0],  
 [0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0],  
 [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0],  
 [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],  
 [0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0],  
 [0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0],  
 [0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0],  
 [0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],  
 [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],  
 [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 9]]  
s = str(input())  
seed = time.time()  
random.seed(seed)  
random.seed(random.randint(0, 999999))  
maze[1][1] = random.randint(987, 1000)  
maze[3][4] = random.randint(345, 356)  
maze[7][7] = random.randint(107, 116)  
maze[11][8] = random.randint(833, 856)  
for i in range(12):  
  for j in range(12):  
      tmp = 12 * i + j  
      if maze[i][j] == 0:  
          maze[i][j] = 3456 + tmp  
          continue  
      if tmp % 4 == 0:  
          random.seed(maze[1][1])  
          for cnt in range(tmp):  
              random.randint(0, 999)  
  
          maze[i][j] = random.randint(0, 999)  
      elif tmp % 4 == 1:  
          random.seed(maze[3][4])  
          for cnt in range(tmp):  
              random.randint(555, 1234)  
  
          maze[i][j] = random.randint(555, 1234)  
      elif tmp % 4 == 2:  
          random.seed(maze[7][7])  
          for cnt in range(tmp):  
              random.randint(777, 888)  
  
          maze[i][j] = random.randint(777, 888)  
      elif tmp % 4 == 3:  
          random.seed(maze[11][8])  
          for cnt in range(tmp):  
              random.randint(369, 777)  
  
          maze[i][j] = random.randint(369, 777)  
  
maze[11][11] = 9  
if len(s) != 56:  
  sys.exit(-1)  
idx1 = 0  
idx2 = 0  
for i in s:  
  if i == 'w':  
      idx1 -= 1  
  else:  
      if i == 's':  
          idx1 += 1  
      else:  
          if i == 'a':  
              idx2 -= 1  
          else:  
              if i == 'd':  
                  idx2 += 1  
  if not 0 <= maze[idx1][idx2] <= 1234:  
      print('Where are you going?')  
      sys.exit(2)  
  
if maze[idx1][idx2] != 9:  
  print('You lost in the maze!')  
result = ''  
for xx in maze:  
  for xxx in xx:  
      result += str(xxx)  
  
hash_res = hashlib.sha256(result.encode('latin-1')).hexdigest()  
print(hash_res)  
if hash_res == 'f1793dcf5ad3858512b944ac34413725a27c63e25618858231e88b9686466b00':  
  flag1 = str(maze[1][1]) + str(maze[7][7]) + str(maze[11][8]) + str(maze[3][4])  
  flag2 = hashlib.sha256(s.encode('latin-1')).hexdigest()  
  flag = flag2[::-1] + flag1[::-1]  
  final_flag = hashlib.sha256(flag.encode('latin-1')).hexdigest()  
  print('flag{' + final_flag[0:32] + '}')  
# okay decompiling snake.pyc  
```  
## 逆向  
从文件逻辑可以看出来这道题需要走迷宫和爆破这个迷宫(因为有要求迷宫的hash值)  
爆破迷宫的话只需要爆破`maze[1][1]`, `maze[3][4]`, `maze[7][7]`, `maze[11][8]`的值就可以了，因为这几个值确定了以后整个迷宫就确定了。  
爆破迷宫  
```python  
import hashlib, sys, random, time  
flag = 0  
for a in range(987, 1001):  
  for b in range(345, 357):  
      for c in range(107, 117):  
          for d in range(833, 857):  
              maze = [  
                  [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  
                  [1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],  
                  [0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0],  
                  [0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0],  
                  [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0],  
                  [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],  
                  [0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0],  
                  [0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0],  
                  [0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0],  
                  [0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],  
                  [0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],  
                  [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 9]]  
              maze[1][1] = a  
              maze[3][4] = b  
              maze[7][7] = c  
              maze[11][8] = d  
              for i in range(12):  
                  for j in range(12):  
                      tmp = 12 * i + j  
                      if maze[i][j] == 0:  
                          maze[i][j] = 3456 + tmp  
                          continue  
                      if tmp % 4 == 0:  
                          random.seed(maze[1][1])  
                          for cnt in range(tmp):  
                              random.randint(0, 999)  
  
                          maze[i][j] = random.randint(0, 999)  
                      elif tmp % 4 == 1:  
                          random.seed(maze[3][4])  
                          for cnt in range(tmp):  
                              random.randint(555, 1234)  
  
                          maze[i][j] = random.randint(555, 1234)  
                      elif tmp % 4 == 2:  
                          random.seed(maze[7][7])  
                          for cnt in range(tmp):  
                              random.randint(777, 888)  
  
                          maze[i][j] = random.randint(777, 888)  
                      elif tmp % 4 == 3:  
                          random.seed(maze[11][8])  
                          for cnt in range(tmp):  
                              random.randint(369, 777)  
  
                          maze[i][j] = random.randint(369, 777)  
              maze[11][11] = 9  
              result = ''  
              for xx in maze:  
                  for xxx in xx:  
                      result += str(xxx)  
              hash_res = hashlib.sha256(result.encode('latin-1')).hexdigest()  
              if hash_res == 'f1793dcf5ad3858512b944ac34413725a27c63e25618858231e88b9686466b00':  
                  flag = 1  
                  print(a, b, c, d)  
              if flag:  
                  break  
          if flag:  
              break  
      if flag:  
          break  
  if flag:  
      break  
  print(a)  
"""  
爆破出来的值：  
maze[1][1] = 996  
maze[3][4] = 352  
maze[7][7] = 113  
maze[11][8] = 849  
"""  
```  
走迷宫:   
```python  
#coding=utf-8  
MIN = 9999999  
  
a = [[0 for col in range(50)] for row in range(50)]#迷宫最大数组  
book = [[0 for col in range(50)] for row in range(50)]#标记数组  
lujing = ['*']*100  
index_step = ['d', 's', 'a', 'w']  
def dfs(start_x,start_y,end_x,end_y,migong_array,step):  
  '''  
  :param start_x: 起始横坐标  
  :param start_y: 起始纵坐标  
  :param end_x: 终点横坐标  
  :param end_y: 终点纵坐标  
  :param migong_array: 迷宫的数组  
  :return:  
  '''  
  next_step = [[0,1],  #向右走  
          [1,0],  #向下走  
          [0,-1], #向左走  
          [-1,0]  #向上走  
          ]  
  if (start_x == end_x and start_y == end_y):  
      global MIN  
      if(step < MIN):  
          MIN = step  
      return 1  
  
  for i in range(len(next_step)):  
      next_x = start_x + next_step[i][0]  
      next_y = start_y + next_step[i][1]  
      if(next_x < 0 or next_y < 0 or next_x > len(migong_array) or next_y > len(migong_array[0])):  
          continue  
      if(0<= a[next_x][next_y] <= 1234 and book[next_x][next_y] == 0):  
          book[next_x][next_y] = 1  
          if dfs(next_x,next_y,end_x,end_y,migong_array,step+1):  
              lujing[step] = index_step[i]  
              return 1  
          book[next_x][next_y] = 0  
  return 0  
  
if __name__ == '__main__':  
  start_x = 0  
  start_y = 0  
  end_x = 11  
  end_y = 11  
  migong_array = [[545, 3457, 3458, 3459, 3460, 3461, 3462, 3463, 3464, 3465, 3466, 3467], [239, 796, 3470, 3471, 640, 948, 831, 3475, 3476, 3477, 3478, 3479], [3480, 1095, 843, 3483, 766, 3485, 848, 464, 95, 703, 3490, 3491], [3492, 3493, 864, 627, 8, 3497, 3498, 3499, 3500, 1064, 3502, 3503], [3504, 3505, 3506, 3507, 3508, 3509, 881, 600, 985, 706, 3514, 3515], [3516, 3517, 3518, 3519, 3520, 3521, 864, 3523, 3524, 3525, 3526, 3527], [3528, 1214, 779, 709, 804, 3533, 813, 403, 861, 1096, 829, 3539], [3540, 628, 3542, 3543, 494, 3545, 3546, 395, 3548, 3549, 798, 3551], [3552, 988, 3554, 3555, 485, 3557, 3558, 3559, 3560, 674, 777, 3563], [3564, 761, 802, 3567, 412, 568, 829, 721, 217, 1137, 3574, 3575], [3576, 3577, 853, 763, 3580, 3581, 3582, 3583, 3584, 3585, 3586, 3587], [3588, 3589, 3590, 372, 962, 923, 785, 502, 368, 707, 795, 9]]   #初始化迷宫  
  
  for i in range(len(migong_array)):  
      for j in range(len(migong_array[0])):  
          a[i][j] = migong_array[i][j]  #将迷宫数组写入a中  
  book[start_x][start_y] = 1  #将第一步标记为1，证明走过了。避免重复走  
  
  dfs(start_x,start_y,end_x,end_y,migong_array,0)  
  
  print('The min length of path is : {}'.format(MIN))  
  print("".join(i for i in lujing)[:MIN])  
```  
