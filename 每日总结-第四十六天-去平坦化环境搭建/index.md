# 去平坦化环境搭建

   
rctf的那道play the game对安卓native文件用了平坦化的混淆，我开始准备用Bird的脚本去掉平坦化的，但是失败了，因为angr、python的各种原因环境搭建的并不顺利，最后搭建起来了但是没能去掉混淆，不过还是记录一下环境搭建的过程。(不过我这篇里面写的这个工程是可以的，比赛的时候用的那个应该是有点问题)    
## Tips    
选择python3选择python3选择python3    
重要的事情说三遍    
## 安装virtualenvwrapper    
```shell    
# 安装    
python3 -m pip install virtualenvwrapper    
# 修改~/.bashrc文件，将下面的内容加入~/.bashrc    
export VIRTUALENVWRAPPER_PYTHON=/usr/local/bin/python3    
export WORKON_HOME=~/Envs    
source /usr/local/bin/virtualenvwrapper.sh    
# 修改完成    
source ~/.bashrc    
# 创建一个虚拟环境    
mkvirtualenv env-angr    
# 再记录一些virtualenv的基本操作    
# 指定python版本    
mkvirtualenv --python=/usr/local/python3.5.3/bin/python venv    
# 查看当前虚拟环境    
workon    
# 虚拟环境直接的切换    
workon env-angr    
# 退出虚拟环境    
deactivate    
# 删除虚拟环境    
rmvirtualenv venv    
```    
windows下的参考这个: https://blog.csdn.net/huangbx_tx/article/details/80683515    
## 安装angr    
```shell    
python3 -m pip install angr    
# 如果很慢的话可以换个源    
# python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple angr    
```    
## 去除平坦化    
[https://github.com/cq674350529/deflat](https://github.com/cq674350529/deflat)    
直接按照这个github上面写的运行即可，里面还有一个可以用来去除虚假控制流的，但是我用在这个so文件上的效果并不好，去除平坦化的效果还是可以的。    

