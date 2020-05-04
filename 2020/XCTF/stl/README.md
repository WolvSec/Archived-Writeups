# STL Container

* [Info](#info)
* [Description](#descr)
* [TLDR](#tldr)
* [Writeup](#write)

<h2 id="info">Information</h2>

Points: 158
Category: pwn

<h2 id="descr">Description</h2>

STL容器测试
stl container test
nc 134.175.239.26 8848
链接：https://share.weiyun.com/5UpX5tH 密码：dhb79p
https://drive.google.com/file/d/1LqhjayCBPfeEf0Gmh1508IfhLy0Ccpdl/view?usp=sharing

<h2 id="tldr">TL;DR</h2>

* Leak a libc address via use after free
* Obtain RCE by overwriting __free_hook__

<h2 id="write">Writeup</h2>

![Menu][1]

For each data structure (DS), you are allowed to create two objects.
Creating an object for a DS calls malloc to allocate 0x98 bytes on the heap.
For the list and vector DS you can delete by index.
Deleting an object calls free on that malloced chunk.




[1]: menu.png


