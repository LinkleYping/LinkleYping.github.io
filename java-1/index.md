# Java 泛型与回调

# Java泛型  
一个最基础的例子  
```java  
List<String> arrayList = new ArrayList<String>();  
```  
泛型有三种使用方式，分别为：泛型类、泛型接口、泛型方法  
## 泛型类  
泛型类型用于类的定义中，被称为泛型类。通过泛型可以完成对一组类的操作对外开放相同的接口。最典型的就是各种容器类，如：List、Set、Map。    
一个最普通的泛型类:  
```java  
//此处T可以随便写为任意标识，常见的如T、E、K、V等形式的参数常用于表示泛型  
//在实例化泛型类时，必须指定T的具体类型  
public class Generic<T>{   
  //key这个成员变量的类型为T,T的类型由外部指定    
  private T key;  
  
  public Generic(T key) { //泛型构造方法形参key的类型也为T，T的类型由外部指定  
      this.key = key;  
  }  
  
  public T getKey(){ //泛型方法getKey的返回值类型为T，T的类型由外部指定  
      return key;  
  }  
}  
  
public static void main(String[] args)  
{  
  //泛型的类型参数只能是类类型（包括自定义类），不能是简单类型:eg:不能用int只能用Integer  
  //传入的实参类型需与泛型的类型参数类型相同，即为Integer.  
  Generic<Integer> genericInteger = new Generic<Integer>(123456);  
  
  //传入的实参类型需与泛型的类型参数类型相同，即为String.  
  Generic<String> genericString = new Generic<String>("key_vlaue");  
  Log.d("泛型测试","key is " + genericInteger.getKey());  
  Log.d("泛型测试","key is " + genericString.getKey());  
}  
```  
**泛型的类型参数只能是类类型（包括自定义类），不能是简单类型**    
在定义泛型类的时候并不一定要传输参数类型，在使用泛型的时候如果传入泛型实参，则会根据传入的泛型实参做相应的限制，此时泛型才会起到本应起到的限制作用。如果不传入泛型类型实参的话，在泛型类中使用泛型的方法或成员变量定义的类型可以为任何的类型。    
```java  
Generic generic = new Generic("111111");  
Generic generic1 = new Generic(4444);  
//同样不会报错  
```  
## 泛型接口  
泛型接口与泛型类的定义及使用基本相同    
```java  
//定义一个泛型接口  
public interface Generator<T> {  
  public T next();  
}  
```  
当实现泛型接口的类，未传入泛型实参时：  
```java  
/**  
 * 未传入泛型实参时，与泛型类的定义相同，在声明类的时候，需将泛型的声明也一起加到类中  
 * 即：class FruitGenerator<T> implements Generator<T>{  
 * 如果不声明泛型，如：class FruitGenerator implements Generator<T>，编译器会报错："Unknown class"  
 */  
class FruitGenerator<T> implements Generator<T>{  
  @Override  
  public T next() {  
      return null;  
  }  
}  
```  
当实现泛型接口的类，传入泛型实参时：  
```java  
/**  
 * 传入泛型实参时：  
 * 定义一个生产器实现这个接口,虽然我们只创建了一个泛型接口Generator<T>  
 * 但是我们可以为T传入无数个实参，形成无数种类型的Generator接口。  
 * 在实现类实现泛型接口时，如已将泛型类型传入实参类型，则所有使用泛型的地方都要替换成传入的实参类型  
 * 即：Generator<T>, public T next();中的的T都要替换成传入的String类型。  
 */  
public class FruitGenerator implements Generator<String> {  
  
  private String[] fruits = new String[]{"Apple", "Banana", "Pear"};  
  
  @Override  
  public String next() {  
      Random rand = new Random();  
      return fruits[rand.nextInt(3)];  
  }  
}  
```  
## 泛型方法  
泛型类，是在实例化类的时候指明泛型的具体类型；泛型方法，是在调用方法的时候指明泛型的具体类型.  
```java  
public class GenericTest {  
 //这个类是个泛型类，在上面已经介绍过  
 public class Generic<T>{       
      private T key;  
  
      public Generic(T key) {  
          this.key = key;  
      }  
  
      //我想说的其实是这个，虽然在方法中使用了泛型，但是这并不是一个泛型方法。  
      //这只是类中一个普通的成员方法，只不过他的返回值是在声明泛型类已经声明过的泛型。  
      //所以在这个方法中才可以继续使用 T 这个泛型。  
      public T getKey(){  
          return key;  
      }  
  }  
  
  /**   
   * 这才是一个真正的泛型方法。  
   * 首先在public与返回值之间的<T>必不可少，这表明这是一个泛型方法，并且声明了一个泛型T  
   * 这个T可以出现在这个泛型方法的任意位置.  
   * 泛型的数量也可以为任意多个   
   *    如：public <T,K> K showKeyName(Generic<T> container){  
   *        ...  
   *        }  
   */  
  public <T> T showKeyName(Generic<T> container){  
      System.out.println("container key :" + container.getKey());  
      //当然这个例子举的不太合适，只是为了说明泛型方法的特性。  
      T test = container.getKey();  
      return test;  
  }  
  
  //这也不是一个泛型方法，这就是一个普通的方法，只是使用了Generic<Number>这个泛型类做形参而已。  
  public void showKeyValue1(Generic<Number> obj){  
      Log.d("泛型测试","key value is " + obj.getKey());  
  }  
  
  //这也不是一个泛型方法，这也是一个普通的方法，只不过使用了泛型通配符?  
  //同时这也印证了泛型通配符章节所描述的，?是一种类型实参，可以看做为Number等所有类的父类  
  public void showKeyValue2(Generic<?> obj){  
      Log.d("泛型测试","key value is " + obj.getKey());  
  }  
}  
```  
在泛型类中使用泛型方法的时候，泛型方法的参数类型不需要与泛型类的类型相同   
泛型方法与可变参数  
```java  
public <T> void printMsg( T... args){  
  for(T t : args){  
      Log.d("泛型测试","t is " + t);  
  }  
}  
printMsg("111",222,"aaaa","2323.4",55.55);  
```  
  
# Java回调  
回调的概念：举个例子就是，我们想要问别人一道题，我们把题跟对方说了一下，对方说好，等我做完这道题，我就告诉你，这个时候就用到了回调，因为我们并不知道对方什么时候会做完，而是对方做完了来主动找我们。    
同步回调:代码运行到某一个位置的时候，如果遇到了需要回调的代码，会在这里等待，等待回调结果返回后再继续执行。    
异步回调:代码执行到需要回调的代码的时候，并不会停下来，而是继续执行，当然可能过一会回调的结果会返回回来。    
```java  
Callback.java  
  
public interface Callback {  
  void printFinished(String msg);  
}  
  
Printer.java  
  
public class Printer {  
  public void print(Callback callback, String text) {  
      System.out.println("正在打印 . . . ");  
      try {  
          Thread.currentThread();  
          Thread.sleep(3000);// 毫秒  
      } catch (Exception e) {  
      }  
      callback.printFinished("打印完成");  
  }  
}  
  
  
People.java  
  
public class People {  
  
  Printer printer = new Printer();  
  
  /*  
   * 同步回调  
   */  
  public void goToPrintSyn(Callback callback, String text) {  
      printer.print(callback, text);  
  }  
  
  /*  
   * 异步回调  
   */  
  public void goToPrintASyn(Callback callback, String text) {  
      new Thread(new Runnable() {  
          public void run() {  
              printer.print(callback, text);  
          }  
      }).start();  
  }  
}  
  
Main.java  
  
public class Main {//测试类，同步回调  
  public static void main(String[] args) {  
      People people = new People();  
      Callback callback = new Callback() {  
          @Override  
          public void printFinished(String msg) {  
              System.out.println("打印机告诉我的消息是 ---> " + msg);  
          }  
      };  
      System.out.println("需要打印的内容是 ---> " + "打印一份简历");  
      people.goToPrintSyn(callback, "打印一份简历");  
      System.out.println("我在等待 打印机 给我反馈");  
  }  
}  
  
Main.java  
  
public class Main {//异步回调  
  public static void main(String[] args) {  
      People people = new People();  
      Callback callback = new Callback() {  
          @Override  
          public void printFinished(String msg) {  
              System.out.println("打印机告诉我的消息是 ---> " + msg);  
          }  
      };  
      System.out.println("需要打印的内容是 ---> " + "打印一份简历");  
      people.goToPrintASyn(callback, "打印一份简历");  
      System.out.println("我在等待 打印机 给我反馈");  
  }  
}  
```  
android中实现回调  
```java  
private  OnCampaignClickListener mListener;  
//定义接口，不考虑方法实现，方法实现由调用者去考虑  
public  interface OnCampaignClickListener{  
  
  void onClick(View view,Campaign campaign);  
  
}  
  
//暴露一个方法给调用者来注册接口回调，通过接口来获得回调者对接口方法的实现  
public void setOnCampaignClickListener(OnCampaignClickListener listener){  
  this.mListener = listener;  
}  
  
  
 imageViewBig.setOnClickListener(this);  
 imageViewSmallTop.setOnClickListener(this);  
 imageViewSmallBottom.setOnClickListener(this);    
  
    //对这些组件的点击事件设置点击效果  
  @Override  
  public void onClick( View v) {  
      anim(v);  
  }  
  
      //**为三个组件添加点击事件，调用接口中的方法，待需要回调时，会有具体的实现**  
    private void anim(final  View v){  
  
        //通过ObjectAnimator设置动画属性  
        ObjectAnimator animator = ObjectAnimator.ofFloat(v,"rotationX",0.0F,360.0F)  
                .setDuration(200);  
  
        animator.addListener(new AnimatorListenerAdapter() {  
            //动画效果结束后回调  
            @Override  
            public void onAnimationEnd(Animator animation) {  
                super.onAnimationEnd(animation);  
  
  
                HomeCampaign homeCampaign = mDatas.get(getLayoutPosition());  
                if(mListener !=null){  
  
                    switch (v.getId()){  
  
                        case  R.id.imgview_big:  
                            mListener.onClick(v,homeCampaign.getCpOne());  
                            break;  
  
                        case  R.id.imgview_small_top:  
                            mListener.onClick(v,homeCampaign.getCpTwo());  
                            break;  
  
                        case  R.id.imgview_small_bottom:  
                            mListener.onClick(v,homeCampaign.getCpThree());  
                            break;  
  
  
  
                    }  
                }  
  
  
            }  
        });  
        animator.start();  
  
    }  
  
}  
**实现接口回调**  
**调用者需要实现接口，完成接口的方法，将接口对象传入到被调用者暴露出来的注册方法中，从而完成回调**  
 //对商品拥有点击事件,跳转到WareListActivity  
  mAdatper.setOnCampaignClickListener(new HomeCatgoryAdapter.OnCampaignClickListener() {  
      @Override  
      public void onClick(View view, Campaign campaign) {  
  
          Intent intent = new Intent(getContext(), WareListActivity.class);  
          //把value值传入intent，key需要用常量来标记  
          intent.putExtra(Constants.COMPAINGAIN_ID,campaign.getId());  
  
          startActivity(intent);  
  
  
  
      }  
  });  
```
