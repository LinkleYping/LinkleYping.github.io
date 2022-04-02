# LaunchAnywhere 和 BroadcastAnywhere



看起来是好久远的两个洞了，Android 5.0上的。因为字节的比赛了解了一下，就写一下具体原理。

## LaunchAnywhere

Intend Based提取漏洞，可以突破应用间的权限隔离，达到调用任意私有Activity(exported=false)的目的。

### AccountManager

帐号管理器，集中管理apps注册的不同类型的帐号。  
不同类型的帐号服务会使用不同的帐号登录和鉴权方式，所以`AccountManager`为不同类型的帐号提供一个插件式`authenticator`模块，`authenticators`自己处理帐号登录/认证的具体细节，也可以自己存储帐号信息。   

`AccountManager`是一个面向应用程序开发的组件，它提供了一套对应于`IAccountManager`协议的应用程序接口；这组接口通过Binder机制与系统服务`AccountManagerService`进行通信，协作完成帐号相关的操作。同时，`AccountManager`接收`authenticators`提供的回调，以便在帐号操作完成之后向调用此帐号服务的业务返回对应的接口，同时触发这个业务对结果的处理。  

- `authenticators`即注册帐号服务的app；  
- 业务调用方 即使用`authenticators`提供的帐号服务的第三方，也可以是`authenticator`自己 

具体过程：

![](/images/anywhere/1.png)

### 漏洞原理

AccountManager.addAccount:

![](/images/anywhere/addAccount.png)

最后执行一个`AmsTask`的异步任务。`mRespone`是一个Binder对象，当`AuthenticationService`指定Intent后，就是把Intent保存到这个respone对象里。

![](/images/anywhere/mResponse.png)

然后在Response中直接startActivity

对于有系统权限的用户可以不管组件是否是`exported=true`都可以直接调用:

![](/images/anywhere/permission.png)

如图，System用户直接返回`PERMISSION_GRANTED`

根据以上分析可知，理论上`AuthenticationService`可以随意指定Intent。如果可以让系统Setting(uid是system进程)调用`addAccount`方法，`EvilAuthenService`就可以指定任何Intent。

### 利用

> 1. AppA请求添加一个特定类型的网络账号
> 2. 系统查询到AppB可以提供一个该类型的网络账号服务，系统向AppB发起请求
> 3. AppB返回了一个intent给系统，系统把intent转发给appA
> 4. AccountManagerResponse在AppA的进程空间内调用 startActivity(intent)调起一个Activity，AccountManagerResponse是FrameWork中的代码， AppA对这一调用毫不知情。

如果AppA是一个system权限应用，比如Settings，那么AppA能够调用起任意AppB指定的未导出Activity.

Settings提供调用addAccount的接口。只要调用com.android.settings.accounts.AddAccountSettings，并给Intent带上特定的参数，即可让Settings触发launchAnyWhere：

```java
Intent intent1 = new Intent();
intent1.setComponent(new ComponentName(
        "com.android.settings",
        "com.android.settings.accounts.AddAccountSettings"));
intent1.setAction(Intent.ACTION_RUN);
intent1.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
String authTypes[] = {Constants.ACCOUNT_TYPE};
intent1.putExtra("account_types", authTypes);
AuthenticatorActivity.this.startActivity(intent1);
```

过程：

![](/images/anywhere/account.png)

因为可以调用任意组件。所以存在以下应用场景：

- 重置pin码：直接打开重置pin码的页面绕过pin码认证界面
- 调用微信内置浏览器
- 调用支付宝钱包内置浏览器

### 修复

检查`AuthenticationService`返回的Intent所指向的Activity是否与AppB具有相同的签名。

## BroadcastAnywhere

与LaunchAnywhere原理相似，通过这个漏洞，攻击者可以无视BroadcastReceiver组件访问限制，以system用户的身份发送广播。

### 漏洞原理

`AddAccountSettings`的`addAccount`方法：

![](/images/anywhere/AddAccountSetting.png)

`mPendingIntent`用来做身份识别，其中intent部分为简单的`new Intent()`即空的Intent对象。

PendingIntent对象可以按预先指定的动作进行触发，当这个对象传递（通过Binder）到其他进程（不同uid的用户）,其他进程利用这个PendingIntent对象，可以原进程的身份权限执行指定的触发动作。另外，由于触发的动作是由系统进程执行的，因此哪怕原进程已经不存在了，PendingIntent对象上的触发动作依然有效。

比如说A进程作为发起端，它可以从系统“获取”一个PendingIntent，然后A进程可以将PendingIntent对象通过binder机制“传递”给B进程，再由B进程在未来某个合适时机，“回调”PendingIntent对象的send()动作，完成激发。

在Android系统中，最适合做集中性管理的组件就是AMS（Activity Manager Service）, 由它承担起管理所有PendingIntent的职责。具体可见参考链接中的【说说PendingIntent的内部机制】

> ​	我们先要理解，所谓的“发起端获取PendingIntent”到底指的是什么。难道只是简单new一个PendingIntent对象吗？当然不是。此处的“获取”动作其实还含有向AMS“注册”intent的语义。
>
> ​    在PendingIntent.java文件中，我们可以看到有如下几个比较常见的静态函数：
>
> - public static PendingIntent **getActivity**(Context context, int requestCode, Intent intent, int flags)
> - public static PendingIntent **getBroadcast**(Context context, int requestCode, Intent intent, int flags)
> - public static PendingIntent **getService**(Context context, int requestCode, Intent intent, int flags)
> - public static PendingIntent **getActivities**(Context context, int requestCode, Intent[] intents, int flags)
> - public static PendingIntent **getActivities**(Context context, int requestCode, Intent[] intents, int flags, Bundle options)
>
> 它们就是我们常用的获取PendingIntent的动作了。
>
> 上面的getActivity()的意思其实是，获取一个PendingIntent对象，而且该对象日后激发时所做的事情是启动一个新activity。也就是说，当它异步激发时，会执行类似Context.startActivity()那样的动作。相应地，getBroadcast()和getService()所获取的PendingIntent对象在激发时，会分别执行类似Context..sendBroadcast()和Context.startService()这样的动作。至于最后两个getActivities()，用得比较少，激发时可以启动几个activity。

PendingIntent.getBroadcast源码：

![](/images/anywhere/pendingIntent_1.png)

实际调用了ActivityManagerService中的`getIntentSender`方法。关键代码如下：

```java
public IIntentSender getIntentSender(int type, String packageName, IBinder token, String resultWho, int requestCode, Intent[] intents, String[] resolvedTypes, int flags, Bundle options, int userId) {
 
    enforceNotIsolatedCaller("getIntentSender");
    ...
    ...
    synchronized(this) {
        int callingUid = Binder.getCallingUid();
        int origUserId = userId;
        userId = handleIncomingUser(Binder.getCallingPid(), callingUid, userId,
                    type == ActivityManager.INTENT_SENDER_BROADCAST, false,
                    "getIntentSender", null);
        ...
        ...
 
        return getIntentSenderLocked(type, packageName, callingUid, userId, token, resultWho, requestCode, intents, resolvedTypes, flags, options);
 
            } catch (RemoteException e) {
                throw new SecurityException(e);
            }
        }
    }
}
IIntentSender getIntentSenderLocked(int type, String packageName, int callingUid, int userId, IBinder token, String resultWho, int requestCode, Intent[] intents, String[] resolvedTypes, int flags, Bundle options) {
 
    if (DEBUG_MU)
        Slog.v(TAG_MU, "getIntentSenderLocked(): uid=" + callingUid);
    ActivityRecord activity = null;
    ...
    PendingIntentRecord.Key key = new PendingIntentRecord.Key(type, packageName, activity, resultWho, requestCode, intents, resolvedTypes, flags, options, userId); //依据调用者的信息，生成PendingIntentRecord.Key对象

    WeakReference<PendingIntentRecord> ref;
    ref = mIntentSenderRecords.get(key);
    PendingIntentRecord rec = ref != null ? ref.get() : null;
    ...
    rec = new PendingIntentRecord(this, key, callingUid); //最后生成PendingIntentRecord对象
    mIntentSenderRecords.put(key, rec.ref); //保存
    ...
    return rec; //并返回
}
```

AMS会把生成PenddingIntent的进程（Caller）信息保存到PendingIntentRecord.Key。并为其维护一个PendingIntentRecord对象。

PendingIntent的send方法最终调用到PendingIntentRecord的sendInner方法。

```java
int sendInner(int code, Intent intent, String resolvedType,
        IIntentReceiver finishedReceiver, String requiredPermission,
        IBinder resultTo, String resultWho, int requestCode,
        int flagsMask, int flagsValues, Bundle options) {
 
    synchronized(owner) {
        if (!canceled) {
            sent = true;
            if ((key.flags&PendingIntent.FLAG_ONE_SHOT) != 0) {
                owner.cancelIntentSenderLocked(this, true);
                canceled = true;
            }
            Intent finalIntent = key.requestIntent != null
                    ? new Intent(key.requestIntent) : new Intent();
            if (intent != null) {
                int changes = finalIntent.fillIn(intent, key.flags); //用传进来的intent进行填充finalIntent
                if ((changes&Intent.FILL_IN_DATA) == 0) {
                    resolvedType = key.requestResolvedType;
                }
            } else {
                resolvedType = key.requestResolvedType;
            }
 
            ...
            ...
 
            switch (key.type) {
                ...
                case ActivityManager.INTENT_SENDER_BROADCAST:
                    try {
                        // If a completion callback has been requested, require
                        // that the broadcast be delivered synchronously
                        owner.broadcastIntentInPackage(key.packageName, uid,
                                finalIntent, resolvedType,
                                finishedReceiver, code, null, null,
                            requiredPermission, (finishedReceiver != null), false, userId);
                        sendFinish = false;
                    } catch (RuntimeException e) {
                        Slog.w(ActivityManagerService.TAG,
                                "Unable to send startActivity intent", e);
                    }
                    break;
                ...
            }
 
            ...     
 
            return 0;
        }
    }
    return ActivityManager.START_CANCELED;
}
```

可以看到，如果`intent!=null`满足的话，就会用传入的intent对finalIntent执行`fillIn`方法，如果是`INTENT_SENDER_BROADCAST`类型就会广播出去。

```java
public int fillIn(Intent other, int flags) {
    int changes = 0;
    if (other.mAction != null
            && (mAction == null || (flags&FILL_IN_ACTION) != 0)) {
        mAction = other.mAction;
        changes |= FILL_IN_ACTION;
    }
    if ((other.mData != null || other.mType != null)
            && ((mData == null && mType == null)
                    || (flags&FILL_IN_DATA) != 0)) {
        mData = other.mData;
        mType = other.mType;
        changes |= FILL_IN_DATA;
    }
    if (other.mCategories != null
            && (mCategories == null || (flags&FILL_IN_CATEGORIES) != 0)) {
        if (other.mCategories != null) {
            mCategories = new ArraySet<String>(other.mCategories);
        }
        changes |= FILL_IN_CATEGORIES;
    }
    if (other.mPackage != null
            && (mPackage == null || (flags&FILL_IN_PACKAGE) != 0)) {
        // Only do this if mSelector is not set.
        if (mSelector == null) {
            mPackage = other.mPackage;
            changes |= FILL_IN_PACKAGE;
        }
    }
    // Selector is special: it can only be set if explicitly allowed,
    // for the same reason as the component name.
    if (other.mSelector != null && (flags&FILL_IN_SELECTOR) != 0) {
        if (mPackage == null) {
            mSelector = new Intent(other.mSelector);
            mPackage = null;
            changes |= FILL_IN_SELECTOR;
        }
    }
    if (other.mClipData != null
            && (mClipData == null || (flags&FILL_IN_CLIP_DATA) != 0)) {
        mClipData = other.mClipData;
        changes |= FILL_IN_CLIP_DATA;
    }
    // Component is special: it can -only- be set if explicitly allowed,
    // since otherwise the sender could force the intent somewhere the
    // originator didn't intend.
    if (other.mComponent != null && (flags&FILL_IN_COMPONENT) != 0) {
        mComponent = other.mComponent;
        changes |= FILL_IN_COMPONENT;
    }
    mFlags |= other.mFlags;
    if (other.mSourceBounds != null
            && (mSourceBounds == null || (flags&FILL_IN_SOURCE_BOUNDS) != 0)) {
        mSourceBounds = new Rect(other.mSourceBounds);
        changes |= FILL_IN_SOURCE_BOUNDS;
    }
    if (mExtras == null) {
        if (other.mExtras != null) {
            mExtras = new Bundle(other.mExtras);
        }
    } else if (other.mExtras != null) {
        try {
            Bundle newb = new Bundle(other.mExtras);
            newb.putAll(mExtras);
            mExtras = newb;
        } catch (RuntimeException e) {
            // Modifying the extras can cause us to unparcel the contents
            // of the bundle, and if we do this in the system process that
            // may fail.  We really should handle this (i.e., the Bundle
            // impl shouldn't be on top of a plain map), but for now just
            // ignore it and keep the original contents. :(
            Log.w("Intent", "Failure filling in extras", e);
        }
    }
    return changes;
}
```

之前传入的finalIntent为`new Intent()`，mAction, mData, mType均为null，所以可以被任意指定fillIntent的内容(除了component之外)。

所以大多数情况下，PendingIntent的安全风险主要发生在下面两个条件同时满足的场景下：

1. 构造PendingIntent时的原始Intent既没有指定Component，也没有指定action
2. 将PendingIntent泄露给第三方

原因是，如果原始Intent的Component与action都为空（“双无”Intent），B就可以通过修改action来将Intent发送向那些声明了intent filter的组件，如果A是一个有高权限的APP（如settings就具有SYSTEM权限），B就可以以A的身份做很多事情。

### 利用

接收pendingIntent并send一个恶意的广播信息

```java
// the exploit of broadcastAnyWhere
final String KEY_CALLER_IDENTITY = "pendingIntent";
PendingIntent pendingintent = options.getParcelable(KEY_CALLER_IDENTITY);
Intent intent_for_broadcast = new Intent("android.intent.action.BOOT_COMPLETED");
intent_for_broadcast.putExtra("info", "I am bad boy");
 
try {
    pendingintent.send(mContext, 0, intent_for_broadcast);
} catch (CanceledException e) {
    e.printStackTrace();
}
```

尽管普通APP无法访问其他APP的notification，但利用AccessiblyService或者 NotificationListenerService，一个APP可能可以获取其他notification中的pendingintent，导致权限泄露(例子就是bytectf2021中mediumdroid)。

### 修复

用填充的identityIntent代替双无Intent

```java
Intent identityIntent = new Intent();
identityIntent.setComponent(new ComponentName(SHOULD_NOT_RESOLVE, SHOULD_NOT_RESOLVE));
identityIntent.setAction(SHOULD_NOT_RESOLVE);
identityIntent.addCategory(SHOULD_NOT_RESOLVE);

mPendingIntent = PendingIntent.getBroadcast(this, 0, identityIntent, 0);
```

## 参考链接

[launchAnyWhere: Activity组件权限绕过漏洞解析(Google Bug 7699048 )](https://blogs.360.cn/post/launchanywhere-google-bug-7699048.html)

[Android LaunchAnyWhere (Google Bug 7699048)漏洞详解及防御措施](https://blog.csdn.net/l173864930/article/details/38755621)

[Android BroadcastAnyWhere(Google Bug 17356824)漏洞具体分析](https://www.bbsmax.com/A/ZOJPp2oaJv/)

[BroadcastAnywhere漏洞分析](https://wooyun.js.org/drops/%E5%AE%89%E5%8D%93Bug%2017356824%20BroadcastAnywhere%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html)

[说说PendingIntent的内部机制](https://my.oschina.net/youranhongcha/blog/196933)


