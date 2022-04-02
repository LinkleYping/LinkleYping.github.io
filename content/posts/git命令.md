---
author: "EP"  
authorLink: "https://linkleyping.top"  
title: "git使用"  
date: 2021-04-13T09:30:48+08:00  
categories : [                                  
"notes",    
]  
draft: false  
---
- 提交  
  
  - `git commit`  
  
- 创建和切换分支  
  
  - `git branch bugFix` // 创建  
  - `git checkout bugFix`  // 切换  
  
- 合并分支-merge  
  
  - `git checkout bugFix; git merge master` // 将master分支合并到bugFix  
  
- 合并分支`rebase`  
  
  - `git checkout bugFix`  
  - `git commit`  
  - `git rebase master`  
  
- head分离，让head指向某个提交记录而不是分支名  
  
  - `git checkout C1` // C1是一次提交记录，一般用哈希值表示节点名称  
  - `git checkout master^`  
  
- 强制修改分支位置  
  
  - `git branch -f master HEAD~3` // 将master强制指向HEAD的第3级父提交  
  
- 撤销变更  
  
  - `git reset`  
    - 通过把分支记录回退几个提交记录来实现撤销改动。`git reset` 向上移动分支，原来指向的提交记录就跟从来没有提交过一样。在reset后，原本分支所做的变更还在，但是处于未加入暂存区状态。  
    - `git reset HEAD~1`  
  - `git revert`  
    - `git reset`的方式只对本地分支有用，对远程分支无用。为了撤销更改并分享给其他人，需要用`git revert`  
    - `git revert HEAD`  
    - 使用`revert`撤销会引入一个新的提交，这个新提交的更改是用来撤销上一步提交的(但是reset是回溯)  
  
- 整理提交记录  
  
  - `git cherry-pick <提交号>`  
    - 用来将一些提交复制到当前所在的位置(`HEAD`)下面。  
    - `git cherry-pick C2 C4`：将提交记录`C2`, `C4`放到当前`master`分支下  
  
- 交互式rebase  
  
  - 交互式 rebase 指的是使用带参数 `--interactive` 的 rebase 命令, 简写为 `-i`  
  - `git rebase -i C2`  
  
- 本地栈式提交  
  
  - >  来看一个在开发中经常会遇到的情况：我正在解决某个特别棘手的 Bug，为了便于调试而在代码中添加了一些调试命令并向控制台打印了一些信息。  
    >  
    > 这些调试和打印语句都在它们各自的提交记录里。最后我终于找到了造成这个 Bug 的根本原因，解决掉以后觉得沾沾自喜！  
    >  
    > 最后就差把 `bugFix` 分支里的工作合并回 `master` 分支了。你可以选择通过 fast-forward 快速合并到 `master` 分支上，但这样的话 `master` 分支就会包含我这些调试语句了。你肯定不想这样，应该还有更好的方式……  
  
  - 只要让 Git 复制解决问题的那一个提交记录就可以了。跟之前我们在“整理提交记录”中学到的一样，我们可以使用  
  
    - `git rebase -i`  
    - `git cherry-pick`  
  
- 提交技巧  
  
  - > 接下来这种情况也是很常见的：你之前在 `newImage` 分支上进行了一次提交，然后又基于它创建了 `caption` 分支，然后又提交了一次。  
    >  
    > 此时你想对的某个以前的提交记录进行一些小小的调整。比如设计师想修改一下 `newImage` 中图片的分辨率，尽管那个提交记录并不是最新的了。  
  
    - 先用 `git rebase -i` 将提交重新排序，然后把我们想要修改的提交记录挪到最前  
    - 然后用 `commit --amend` 来进行一些小修改  
    - 接着再用 `git rebase -i` 来将他们调回原来的顺序  
    - 最后我们把 `master` 移到修改的最前端（用你自己喜欢的方法），就大功告成啦！  
  
  - 使用`git cherry-pick`来进行上面的提交，避免可能导致的冲突  
  
    - cherry-pick 可以将提交树上任何地方的提交记录取过来追加到 HEAD 上（只要不是 HEAD 上游的提交就没问题）。  
      - （这个好像要先用`git checkout`把master分支跟HEAD分离  
  
- `git tag`  
  
  - > 可以（在某种程度上 —— 因为标签可以被删除后重新在另外一个位置创建同名的标签）永久地将某个特定的提交命名为里程碑，然后就可以像分支一样引用了。  
    >  
    > 更难得的是，它们并不会随着新的提交而移动。你也不能检出到某个标签上面进行修改提交，它就像是提交树上的一个锚点，标识了某个特定的位置。  
  
  - `git tag v1 C1`将C1这个标签命名为C1，如果不指定提交记录，会直接用HEAD指向的位置  
  
- `git describe`  
  
  - > Git Describe 能帮你在提交历史中移动了多次以后找到方向；当你用 `git bisect`（一个查找产生 Bug 的提交记录的指令）找到某个提交记录时，或者是当你坐在你那刚刚度假回来的同事的电脑前时， 可能会用到这个命令。  
  
  - `git describe <ref>`  
  
  - `<ref>` 可以是任何能被 Git 识别成提交记录的引用，如果你没有指定的话，Git 会以你目前所检出的位置（`HEAD`）。  
  
    它输出的结果是这样的：  
  
    ```bash  
    <tag>_<numCommits>_g<hash>  
    ```  
  
    `tag` 表示的是离 `ref` 最近的标签， `numCommits` 是表示这个 `ref` 与 `tag` 相差有多少个提交记录， `hash` 表示的是你所给定的 `ref` 所表示的提交记录哈希值的前几位。  
  
    当 `ref` 提交记录上有某个标签时，则只输出标签名称  
  
- `git rebase`  
  
  - `git rebase master branche1`  
  
- 选择父提交记录  
  
  - > 操作符 `^` 与 `~` 符一样，后面也可以跟一个数字。  
    >  
    > 但是该操作符后面的数字与 `~` 后面的不同，并不是用来指定向上返回几代，而是指定合并提交记录的某个父提交。还记得前面提到过的一个合并提交有两个父提交吧，所以遇到这样的节点时该选择哪条路径就不是很清晰了。  
    >  
    > Git 默认选择合并提交的“第一个”父提交，在操作符 `^` 后跟一个数字可以改变这一默认行为。  
  
  - `git branch bugWork master~^2~`  
  
- 纠缠不清的分支  
  
  - > 在我们的 `master` 分支是比 `one`、`two` 和 `three` 要多几个提交。出于某种原因，我们需要把 `master` 分支上最近的几次提交做不同的调整后，分别添加到各个的分支上。  
    >  
    > `one` 需要重新排序并删除 `C5`，`two` 仅需要重排排序，而 `three` 只需要提交一次。  
  
  - `$ git checkout one`  
  
    `$ git cherry-pick C4 C3 C2`  
  
    `$ git checkout two`  
  
    `$ git cherry-pick C5 C4 C3 C2`  
  
    `$ git branch -f three C2`  
  
- 远程: `git clone`  
   - git clone`后，本地会多一个叫做`o/master`的分支，叫做远程分支`  
   -  `远程分支命名规范: `<remote name>/<branch name>`， 所以上一步的o实际上是指`origin`  
  
    - `git checkout o/master; git commit`以后`o/master`并不会改变。  
     
- `git fetch`  
  
   - 从远程仓库获取数据  
  
   - > `git fetch` 完成了仅有的但是很重要的两步:  
      >  
      > - 从远程仓库下载本地仓库中缺失的提交记录  
      > - 更新远程分支指针(如 `o/master`)  
      >  
      > `git fetch` 实际上将本地仓库中的远程分支更新成了远程仓库相应分支最新的状态。  
      >  
      > 远程分支反映了远程仓库在你**最后一次与它通信时**的状态，`git fetch` 就是你与远程仓库通信的方式了！  
  
   - > `git fetch` 并不会改变你本地仓库的状态。它不会更新你的 `master` 分支，也不会修改你磁盘上的文件。  
      >  
      > 理解这一点很重要，因为许多开发人员误以为执行了 `git fetch` 以后，他们本地仓库就与远程仓库同步了。它可能已经将进行这一操作所需的所有数据都下载了下来，但是**并没有**修改你本地的文件。  
      >  
      > 所以, 你可以将 `git fetch` 的理解为单纯的下载操作。  
  
- `git pull`  
  
   - `git fetch; git merge o/master`相当于`git pull`  
   - `git pull` 就是 `git fetch` 和 `git merge <just-fetched-branch>` 的缩写  
  
- `git push`  
  
   - > 假设你周一克隆了一个仓库，然后开始研发某个新功能。到周五时，你新功能开发测试完毕，可以发布了。但是 —— 天啊！你的同事这周写了一堆代码，还改了许多你的功能中使用的 API，这些变动会导致你新开发的功能变得不可用。但是他们已经将那些提交推送到远程仓库了，因此你的工作就变成了基于项目**旧版**的代码，与远程仓库最新的代码不匹配了。  
      >  
      > 这种情况下, `git push` 就不知道该如何操作了。如果你执行 `git push`，Git 应该让远程仓库回到星期一那天的状态吗？还是直接在新代码的基础上添加你的代码，异或由于你的提交已经过时而直接忽略你的提交？  
      >  
      > 因为这情况（历史偏离）有许多的不确定性，Git 是不会允许你 `push` 变更的。实际上它会强制你先合并远程最新的代码，然后才能分享你的工作。  
  
      - 使用`rebase`调整本地工作状态  
         - `git fetch; git rebase o/master; git push`  
         - 我们用 `git fetch` 更新了本地仓库中的远程分支，然后用 rebase 将我们的工作移动到最新的提交记录下，最后再用 `git push` 推送到远程仓库。  
      - 也可以使用`merge`在远程仓库变更了以后更新本地工作状态  
         - `git fetch; git merge o/master; git push`  
         - 我们用 `git fetch` 更新了本地仓库中的远程分支，然后**合并**了新变更到我们的本地分支（为了包含远程仓库的变更），最后我们用 `git push` 把工作推送到远程仓库  
      - `git pull --rebase`  
         - `git fetch && git rebase`的缩写  
         - `git pull --rebase; git push`  
  
- 远程跟踪分支  
  
   - > Git 好像知道 `master` 与 `o/master` 是相关的。当然这些分支的名字是相似的，可能会让你觉得是依此将远程分支 master 和本地的 master 分支进行了关联。这种关联在以下两种情况下可以清楚地得到展示：  
      >  
      > - pull 操作时, 提交记录会被先下载到 o/master 上，之后再合并到本地的 master 分支。隐含的合并目标由这个关联确定的。  
      > - push 操作时, 我们把工作从 `master` 推到远程仓库中的 `master` 分支(同时会更新远程分支 `o/master`) 。这个推送的目的地也是由这种关联确定的！  
  
   - > 你可以让任意分支跟踪 `o/master`, 然后该分支会像 `master` 分支一样得到隐含的 push 目的地以及 merge 的目标。 这意味着你可以在分支 `totallyNotMaster` 上执行 `git push`，将工作推送到远程仓库的 `master` 分支上。  
      >  
      > 有两种方法设置这个属性，第一种就是通过远程分支检出一个新的分支，执行:  
      >  
      > ```  
      > git checkout -b totallyNotMaster o/master  
      > ```  
      >  
      > 就可以创建一个名为 `totallyNotMaster` 的分支，它跟踪远程分支 `o/master`。  
  
   - 切换  
  
      - `git checkout -b foo o/master; git commit; git push;`  
  
      - 另一种设置远程追踪分支的方法就是使用：`git branch -u` 命令，执行：  
  
         ```bash  
         git branch -u o/master foo  
         ```  
  
         这样 `foo` 就会跟踪 `o/master` 了。如果当前就在 foo 分支上, 还可以省略 foo：  
  
         ```bash  
         git branch -u o/master  
         ```  
  
- 可以为`git push`指定参数，语法是: `git push <remote> <place>`  
  
  - > ```  
    > git push origin master  
    > ```  
    >  
    > 把这个命令翻译过来就是：  
    >  
    > *切到本地仓库中的“master”分支，获取所有的提交，再到远程仓库“origin”中找到“master”分支，将远程仓库中没有的提交记录都添加上去，搞定之后告诉我。*  
    >  
    > 我们通过“place”参数来告诉 Git 提交记录来自于 master, 要推送到远程仓库中的 master。它实际就是要同步的两个仓库的位置。  
  
  - > 要同时为源和目的地指定 `<place>` 的话，只需要用冒号 `:` 将二者连起来就可以了：  
    >  
    > ```bash  
    > git push origin <source>:<destination>  
    > ```  
  
- `git fetch`  
  
  - 如果你像如下命令这样为 git fetch 设置 <place> 的话：  
  
    ```  
    git fetch origin foo  
    ```  
  
    Git 会到远程仓库的 `foo` 分支上，然后获取所有本地不存在的提交，放到本地的 `o/foo` 上。  
  
- source  
  
  - > Git 有两种关于 `<source>` 的用法是比较诡异的，即你可以在 git push 或 git fetch 时不指定任何 `source`，方法就是仅保留冒号和 destination 部分，source 部分留空。  
    >  
    > - `git push origin :side`  
    > - `git fetch origin :bugFix`  
  
  - `git push origin :foo`: 如果foo在本地则会删除这个远程分支  
  
  - `git fetch origin :bugFix`：如果bugFix在本地不存在则会新建这个本地分支  
  
- `git pull`  
  
  - > 以下命令在 Git 中是等效的:  
    >  
    > `git pull origin foo` 相当于：  
    >  
    > ```  
    > git fetch origin foo; git merge o/foo  
    > ```  
    >  
    > 还有...  
    >  
    > `git pull origin bar~1:bugFix` 相当于：  
    >  
    > ```  
    > git fetch origin bar~1:bugFix; git merge bugFix  
    > ```  
    >  
    > 看到了? git pull 实际上就是 fetch + merge 的缩写, git pull 唯一关注的是提交最终合并到哪里（也就是为 git fetch 所提供的 destination 参数）