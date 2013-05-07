#Readme
===

## 1.说明

### 1.1 初衷
自2011年爆出传的较为夸张打开记事本都能中招的dll劫持漏洞以来，dll劫持火速升温。在这种情况下，配合PBC同学，一起尝试对常用软件的DLL劫持风险做个评估。而这几行代码主要是用来在前期做个初步尝试。

### 1.2 思路

思路较为简单，通过逆向分析dll的加载过程，找到关键点，看程序尝试加载那些dll，然后这些dll中那些存在劫持的风险，找到存在风险的dll路径。（包括新劫持、旧劫持）。

### 1.3 效果

不测不知道，一测吓一跳。各种软件的DLL劫持漏洞一堆一堆的，包括但不限于IE、power point、WPS、迅雷等。造成的危险显而易见——dll劫持,特定情况下的任意代码执行。

需要补充的是：IE、power point的两个dll劫持，利用简单，只需要把特定dll和相应的html文件、pptx文件放在一个目录，然后打开正常双击打开该文档文件，然后...(不知算不算0day或首发，至少打了所有补丁，仍然存在；至少此前没看到有人公布这个)

### 1.3 存在的问题及补充说明

 * 硬编码： 对dll加载过程中的未导出函数进行了硬编码hook（简单且非主流的hook，纯粹是为了做实验，原谅我吧，阿门...）
 * 日志输出略凌乱
 * 后来PBC同学做了更加完善的、底层的内核检测，本人无版权，故不予发布
 * 还会完善或修改么？——99.9% 不会
 * 还有什么？——放的太久了，不知道还有啥问题


## 2.致谢
 
 感谢PBC同学的指导与合作:)
