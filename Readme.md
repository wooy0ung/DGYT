FROM ubuntu:16.04

# Apt packages

RUN  sed -i s@/archive.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list
RUN  apt-get clean

RUN dpkg --add-architecture i386 && apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git nasm  python \
    build-essential \
    python-dev python-pip python-setuptools \
    libc6-dbg \
    libc6-dbg:i386 \
    gcc-multilib \
    gdb-multiarch \
    gcc \
    wget \
    curl \
    glibc-source \
    cmake \
    python-capstone \
    socat \
    netcat \
    ruby \
    lxterminal \
    fish
    # apt-get clean && \
    # rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # cd ~ && tar -xvf /usr/src/glibc/glibc-2.23.tar.xz

# python/ruby packages & gdb-plugin
RUN pip install --no-cache-dir pwntools ropper ancypatch swpwn && \
    gem install one_gadget && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# git installaing package
# RUN cd ~/ && \
#     git clone https://github.com/pwndbg/pwndbg.git && \
#     cd ~/pwndbg/ && ./setup.sh && \
#     rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN cd ~/ && \
    git clone https://github.com/longld/peda.git && \
    echo "source ~/peda/peda.py" >> ~/.gdbinit

RUN cd ~/ && \
    git clone https://github.com/scwuaptx/Pwngdb.git && \
    cp ~/Pwngdb/.gdbinit ~/




ENV LANG C.UTF-8

VOLUME ["/pwn"]
WORKDIR /pwn

CMD ["/bin/bash"]


Content:
pwn题型：栈溢出、格式化字符串、堆溢出、内核提权、IoT

栈溢出：覆盖返回地址、ROP、SROP、BROP、Ret2libc、Ret2dl
格式化字符串(fmt利用)：任意读、任意写、泄露二进制文件

printf
sprintf
scanf

printf_s
sprintf_s
scanf_s


example:
read(0, name, 0x10);
printf(name)

name = "%p%p%p%p%p%p%p%p"

name = "%100$unknown+AAAA"+p64(addr)



堆溢出：
malloc(1)   ---> 申请大chunk  267633267 bytes

x64
fastbin (size <= 0x70)
addr = malloc(0x20)   # 1
malloc(0x20)   # 2
malloc(0x20)   # 3

free(1)
free(2)
free(3)

gets(addr) # chunk1
AAAAAAAAAAAAAAAA

(chunk1)
pre_size
size
(fd)AAAAAAAA
AAAAAAAA
AAAAAAAA
AAAAAAAA
(chunk2)
AAAAAAAA
AAAAAAAA               |
(fd)AAAAAAAA ---|
AAAAAAAA
AAAAAAAA
AAAAAAAA
(chunk3)
pre_size
size                |
(fd)target_addr ----|
11111111
11111111
11111111

stack_ret


malloc(0x20)
add2 = malloc(0x20)


global[addr1,addr2,addr3,stack_ret]

edit(4, system)
---> fastbin attack

!!!!!!!!!!!fastbins:
0x20 -->
0x30 -->    # --> 2 --> 1
0x40 -->
...
0x70 -->

malloc(0x20)


chunk1

------------
pre_size 8byte
------------
size 8byte 0x31
------------
fd 8byte
------------
0x18 byte


!!!!!!!!!!!!!!!unsorted bin (size > 0x70)
0x80 <--> 2 <--> 1  -->| 
|<--------------------

0x90

0xa0
....


addr = malloc(0x70)
malloc(0x70)

free(1)
free(2)




Challenge List:
