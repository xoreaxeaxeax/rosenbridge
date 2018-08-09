#
# project:rosenbridge
# domas // @xoreaxeaxeax
#

# the deis assembler #

# a minimal subset of the deis instructions have been analyzed to reveal the
# bitfields necessary to create a working privilege escalation payload.  work on
# analyzing the deis instruction set is far from complete, but this assembler
# provides enough functionality to flexibly write kernel manipulation payloads.

# the datasets for analyzing deis instructions are found in the rosenbridge_data
# repository.

# deis instructions:

# lgd: load base address of gdt into register
# mov: copy register contents
# izx: load 2 byte immediate, zero extended
# isx: load 2 byte immediate, sign extended
# ra4: shift eax right by 4
# la4: shift eax left by 4
# ra8: shift eax right by 8
# la8: shift eax left by 8
# and: bitwise and of two registers, into eax
# or:  bitwise or of two registers, into eax
# ada: add register to eax
# sba: sub register from eax
# ld4: load 4 bytes from kernel memory
# st4: store 4 bytes into kernel memory
# ad4: increment a register by 4
# ad2: increment a register by 2
# ad1: increment a register by 1
# zl3: zero low 3 bytes of register
# zl2: zero low 2 bytes of register
# zl1: zero low byte of register
# cmb: shift lo word of source into lo word of destination

# bit key:
#   V probable opcode
#   ? unknown purpose
#   x possible don't-care
#   v probable operand

import ctypes
from ctypes import c_uint32
import sys

reg_bits = {
        "eax": 0b0000,
        "ebx": 0b0011,
        "ecx": 0b0001,
        "edx": 0b0010,
        "esi": 0b0110,
        "edi": 0b0111,
        "ebp": 0b0101,
        "esp": 0b0100,
        }

class deis_bits(ctypes.LittleEndianStructure):
    pass 

class deis_insn(ctypes.Union):
    TEMPLATE = 0
    _fields_ = [("bits", deis_bits), ("insn", c_uint32)]
    def __str__(self):
        return "%08x" % self.insn

# mov #

#             VVVV VVVV  ???? vvvv  ?vvv vxxx  xxxx xxxx
# ac169f51  [ 1010 1100  0001 0110  1001 1111  0101 0001 ]:   esi -> ebx

class deis_mov_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 11),
        ("dst", c_uint32, 4),
        ("field_2", c_uint32, 1),
        ("src", c_uint32, 4),
        ("field_3", c_uint32, 12),
    ]

class deis_mov(deis_insn):
    TEMPLATE = 0xac169f51  
    _fields_ = [("bits", deis_mov_bits), ("insn", c_uint32)]
    def __init__(self, src, dst):
        self.insn = self.TEMPLATE
        self.bits.src = reg_bits[src]
        self.bits.dst = reg_bits[dst]

# lgd #

#             VVVV VVVV  ???? vvvv  ???? ????  xxxx xxxx
# a313075b  [ 1010 0011  0001 0011  0000 0111  0101 1011 ]

class deis_lgd_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 16),
        ("dst", c_uint32, 4),
        ("field_2", c_uint32, 12),
    ]

class deis_lgd(deis_insn):
    TEMPLATE = 0xa313075b
    _fields_ = [("bits", deis_lgd_bits), ("insn", c_uint32)]
    def __init__(self, dst):
        self.insn = self.TEMPLATE
        self.bits.dst = reg_bits[dst]

# izx #

#             VVVV VVVV  ???? vvvv  vvvv vvvv  vvvv vvvv
# 2412baf2  [ 0010 0100  0001 0010  1011 1010  1111 0010 ]:   edx: 0841fec3 -> 0000baf2

class deis_izx_bits(deis_bits):
    _fields_ = [
        ("src", c_uint32, 16),
        ("dst", c_uint32, 4),
        ("field_1", c_uint32, 12),
    ]

class deis_izx(deis_insn):
    TEMPLATE = 0x2412baf2  
    _fields_ = [("bits", deis_izx_bits), ("insn", c_uint32)]
    def __init__(self, src, dst):
        self.insn = self.TEMPLATE
        if type(src) is str:
            src = int(src, 16)
        self.bits.src = src
        self.bits.dst = reg_bits[dst]

# isx #

#             VVVV VVVV  ???? vvvv  vvvv vvvv  vvvv vvvv
# 24b43402  [ 0010 0100  1011 0100  0011 0100  0000 0010 ]:   esp: 5643a332 -> ffff3402

class deis_isx_bits(deis_bits):
    _fields_ = [
        ("src", c_uint32, 16),
        ("dst", c_uint32, 4),
        ("field_1", c_uint32, 12),
    ]

class deis_isx(deis_insn):
    TEMPLATE = 0x24b43402    
    _fields_ = [("bits", deis_isx_bits), ("insn", c_uint32)]
    def __init__(self, src, dst):
        self.insn = self.TEMPLATE
        if type(src) is str:
            src = int(src, 16)
        self.bits.src = src
        self.bits.dst = reg_bits[dst]

# la4 #

#             VVVV ????  ???? ????  ???? ????  ???? ????
# 840badc7  [ 1000 0100  0000 1011  1010 1101  1100 0111 ]:   eax: 0804c555 -> 804c5550

class deis_la4_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 32),
    ]

class deis_la4(deis_insn):
    TEMPLATE = 0x840badc7      
    _fields_ = [("bits", deis_la4_bits), ("insn", c_uint32)]
    def __init__(self):
        self.insn = self.TEMPLATE

# ra4 #

#             VVVV ????  ???? ????  ???? ????  ???? ????
# 813c65c3  [ 1000 0001  0011 1100  0110 0101  1100 0011 ]:   eax: 0804c555 -> 00804c55

class deis_ra4_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 32),
    ]

class deis_ra4(deis_insn):
    TEMPLATE = 0x813c65c3        
    _fields_ = [("bits", deis_ra4_bits), ("insn", c_uint32)]
    def __init__(self):
        self.insn = self.TEMPLATE


# la8 #

#             VVVV ????  ???? ????  ???? ????  ???? ????
# 844475e0  [ 1000 0100  0100 0100  0111 0101  1110 0000 ]:   eax: 0804c555 -> 04c55500

class deis_la8_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 32),
    ]

class deis_la8(deis_insn):
    TEMPLATE = 0x844475e0  
    _fields_ = [("bits", deis_la8_bits), ("insn", c_uint32)]
    def __init__(self):
        self.insn = self.TEMPLATE

# ra8 #

#             VVVV ????  ???? ????  ???? ????  ???? ????
# 84245de2  [ 1000 0100  0010 0100  0101 1101  1110 0010 ]:   eax: 0804c555 -> 000804c5

class deis_ra8_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 32),
    ]

class deis_ra8(deis_insn):
    TEMPLATE = 0x84245de2    
    _fields_ = [("bits", deis_ra8_bits), ("insn", c_uint32)]
    def __init__(self):
        self.insn = self.TEMPLATE

# and #

#             VVVV VVVv  vvv? vvvv  ???? ????  ???? VVVV
# 82748114  [ 1000 0010  0111 0100  1000 0001  0001 0100 ]:   ebx: 3fc499bc ... esp: f44ed78e -> eax: 3444918c

class deis_and_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 16),
        ("src1", c_uint32, 4),
        ("field_2", c_uint32, 1),
        ("src2", c_uint32, 4),
        ("field_3", c_uint32, 7),
    ]

class deis_and(deis_insn):
    TEMPLATE = 0x82748114      
    _fields_ = [("bits", deis_and_bits), ("insn", c_uint32)]
    def __init__(self, src1, src2):
        self.insn = self.TEMPLATE
        self.bits.src1 = reg_bits[src1]
        self.bits.src2 = reg_bits[src2]

# or #

#             VVVV VVVv  vvv? vvvv  ???? ????  ???? VVVV
# 8213e5d5  [ 1000 0010  0001 0011  1110 0101  1101 0101 ]:   eax: 0804c389 ... ebx: dfd52762 -> eax: dfd5e7eb

class deis_or_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 16),
        ("src1", c_uint32, 4),
        ("field_2", c_uint32, 1),
        ("src2", c_uint32, 4),
        ("field_3", c_uint32, 7),
    ]

class deis_or(deis_insn):
    TEMPLATE = 0x8213e5d5        
    _fields_ = [("bits", deis_or_bits), ("insn", c_uint32)]
    def __init__(self, src1, src2):
        self.insn = self.TEMPLATE
        self.bits.src1 = reg_bits[src1]
        self.bits.src2 = reg_bits[src2]

# ada #

#             VVVV VVVV  ???? vvvv  ???? ????  xxxx ????
# 80d2c5d0  [ 1000 0000  1101 0010  1100 0101  1101 0000 ]:   edx: 30300a77 ... eax: 0804c2e9 -> eax: 3834cd60

class deis_ada_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 16),
        ("src", c_uint32, 4),
        ("field_2", c_uint32, 12),
    ]

class deis_ada(deis_insn):
    TEMPLATE = 0x80d2c5d0          
    _fields_ = [("bits", deis_ada_bits), ("insn", c_uint32)]

    def __init__(self, src):
        self.insn = self.TEMPLATE
        self.bits.src = reg_bits[src]

# sub #

#             VVVV VVVV  xxxx vvvv  xxxx xxxx  ???? ????
# 8012e5f2  [ 1000 0000  0001 0010  1110 0101  1111 0010 ]:   eax: 0804c2e9 ... edx: 262e3d2e -> eax: e1d685bb

class deis_sba_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 16),
        ("src", c_uint32, 4),
        ("field_2", c_uint32, 12),
    ]

class deis_sba(deis_insn):
    TEMPLATE = 0x8012e5f2            
    _fields_ = [("bits", deis_sba_bits), ("insn", c_uint32)]

    def __init__(self, src):
        self.insn = self.TEMPLATE
        self.bits.src = reg_bits[src]

# zl3 #

#             VVVV VVV?  xxxx xxxx  ?vvv v???  ???? ????
# c5e9a0d7  [ 1100 0101  1110 1001  1010 0000  1101 0111 ]: zl3 esp
# c5caa8de  [ 1100 0101  1100 1010  1010 1000  1101 1110 ]: zl3 ebp
# c5ca88de  [ 1100 0101  1100 1010  1000 1000  1101 1110 ]: zl3 ecx
# c451b0c6  [ 1100 0100  0101 0001  1011 0000  1100 0110 ]: zl3 esi
# c45190c6  [ 1100 0100  0101 0001  1001 0000  1100 0110 ]: zl3 edx

class deis_zl3_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 11),
        ("reg", c_uint32, 4),
        ("field_2", c_uint32, 17),
    ]

class deis_zl3(deis_insn):
    TEMPLATE = 0xc5e9a0d7              
    _fields_ = [("bits", deis_zl3_bits), ("insn", c_uint32)]

    def __init__(self, reg):
        self.insn = self.TEMPLATE
        self.bits.reg = reg_bits[reg]

# zl2 #

#             VVVV VVV?  xxxx xxxx  ?vvv v???  ???? ????
# c64ea11c  [ 1100 0110  0100 1110  1010 0001  0001 1100 ]: zl2 esp

class deis_zl2_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 11),
        ("reg", c_uint32, 4),
        ("field_2", c_uint32, 17),
    ]

class deis_zl2(deis_insn):
    TEMPLATE = 0xc64ea11c                
    _fields_ = [("bits", deis_zl2_bits), ("insn", c_uint32)]

    def __init__(self, reg):
        self.insn = self.TEMPLATE
        self.bits.reg = reg_bits[reg]

# zl1 #

#             VVVV VVV?  xxxx xxxx  ?vvv v???  ???? ????
# 8676ba54  [ 1000 0110  0111 0110  1011 1010  0101 0100 ]: zl1 edi
# 86769a5c  [ 1000 0110  0111 0110  1001 1010  0101 1100 ]: zl1 ebx

class deis_zl1_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 11),
        ("reg", c_uint32, 4),
        ("field_2", c_uint32, 17),
    ]

class deis_zl1(deis_insn):
    TEMPLATE = 0x8676ba54                
    _fields_ = [("bits", deis_zl1_bits), ("insn", c_uint32)]

    def __init__(self, reg):
        self.insn = self.TEMPLATE
        self.bits.reg = reg_bits[reg]

# ld4 #

#                        off  src    dst       len?
#             VVVV VVVV  vvv? vvvv  ?vvv v???  vv?? ????
# c8138c89  [ 1100 1000  0001 0011  1000 1100  1000 1001 ]:   ecx: 00000000 -> 44332211

class deis_ld4_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 11),
        ("dst", c_uint32, 4),
        ("field_2", c_uint32, 1),
        ("src", c_uint32, 4),
        ("field_3", c_uint32, 1),
        ("off", c_uint32, 3),
        ("field_4", c_uint32, 8),
    ]

class deis_ld4(deis_insn):
    TEMPLATE = 0xc8138c89              
    _fields_ = [("bits", deis_ld4_bits), ("insn", c_uint32)]

    def __init__(self, src, dst):
        self.insn = self.TEMPLATE
        self.bits.src = reg_bits[src]
        self.bits.dst = reg_bits[dst]

# st4 #

#                        off  dst    src       len?
#             VVVV VVVV  vvv? vvvv  ?vvv v???  vv?? ????
# e0138dfd  [ 1110 0000  0001 0011  1000 1101  1111 1101 ]:  11223344 -> b642f0c7
# e2539dfd  [ 1110 0010  0101 0011  1001 1101  1111 1101 ]:  11223344 -> b542f0c7

class deis_st4_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 11),
        ("src", c_uint32, 4),
        ("field_2", c_uint32, 1),
        ("dst", c_uint32, 4),
        ("field_3", c_uint32, 1),
        ("off", c_uint32, 3),
        ("field_4", c_uint32, 8),
    ]

class deis_st4(deis_insn):
    TEMPLATE = 0xe0138dfd                
    _fields_ = [("bits", deis_st4_bits), ("insn", c_uint32)]
    def __init__(self, src, dst):
        self.insn = self.TEMPLATE
        self.bits.src = reg_bits[src]
        self.bits.dst = reg_bits[dst]

# ad4 #

#                     reg       val
#             VVVV VVVv  vvv? ??vv  xxxx xxxx  xxxx xxxx
# 0a3b118a  [ 0000 1010  0011 1011  0001 0001  1000 1010 ]:   ecx: 0841fec2 -> 0841fec6

class deis_ad4_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 21),
        ("reg", c_uint32, 4),
        ("field_2", c_uint32, 7),
    ]

class deis_ad4(deis_insn):
    TEMPLATE = 0x0a3b118a
    _fields_ = [("bits", deis_ad4_bits), ("insn", c_uint32)]

    def __init__(self, reg):
        self.insn = self.TEMPLATE
        self.bits.reg = reg_bits[reg]

# ad2 #

#                     reg       val
#             VVVV VVVv  vvv? ??vv  xxxx xxxx  xxxx xxxx
# 0a3af97f  [ 0000 1010  0011 1010  1111 1001  0111 1111 ]:   ecx: 0841fec2 -> 0841fec4

class deis_ad2_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 21),
        ("reg", c_uint32, 4),
        ("field_2", c_uint32, 7),
    ]

class deis_ad2(deis_insn):
    TEMPLATE = 0x0a3af97f  
    _fields_ = [("bits", deis_ad2_bits), ("insn", c_uint32)]

    def __init__(self, reg):
        self.insn = self.TEMPLATE
        self.bits.reg = reg_bits[reg]

# ad1 #

#                     reg       val
#             VVVV VVVv  vvv? ??vv  xxxx xxxx  xxxx xxxx
# 0a29a7a0  [ 0000 1010  0010 1001  1010 0111  1010 0000 ]:   ecx: a212dce8 -> a212dce9

class deis_ad1_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 21),
        ("reg", c_uint32, 4),
        ("field_2", c_uint32, 7),
    ]

class deis_ad1(deis_insn):
    TEMPLATE = 0x0a29a7a0    
    _fields_ = [("bits", deis_ad1_bits), ("insn", c_uint32)]

    def __init__(self, reg):
        self.insn = self.TEMPLATE
        self.bits.reg = reg_bits[reg]

# cmb #

#             VVVV VVVV  ???? vvvv  ?vvv v???  ???? ????
# a2528c33  [ 1010 0010  0101 0010  1000 1100  0011 0011 ]
# a2528c33  [ 1010 0010  0101 0010  1000 1100  0011 0011 ]:   edx: 1b6a2620, ecx: 7b0c160d -> 2620160d
# a252ac33  [ 1010 0010  0101 0010  1010 1100  0011 0011 ]:   edx: 8c69f5e2, ebp: f9291fe1 -> f5e21fe1

class deis_cmb_bits(deis_bits):
    _fields_ = [
        ("field_1", c_uint32, 11),
        ("dst", c_uint32, 4),
        ("field_2", c_uint32, 1),
        ("src", c_uint32, 4),
        ("field_3", c_uint32, 12),
    ]

class deis_cmb(deis_insn):
    TEMPLATE = 0xa2528c33      
    _fields_ = [("bits", deis_cmb_bits), ("insn", c_uint32)]

    def __init__(self, src, dst):
        self.insn = self.TEMPLATE
        self.bits.src = reg_bits[src]
        self.bits.dst = reg_bits[dst]


if __name__ == "__main__":
    if "--test" in sys.argv:
        print deis_mov("eax", "ebx")
        print deis_mov("ebx", "edx")
        print deis_lgd("esi")
        print deis_izx(0x1122, "edi")
        print deis_isx(0x1122, "esp")
        print deis_ra4()
        print deis_la4()
        print deis_ra8()
        print deis_la8()
        print deis_and("edx", "ecx")
        print deis_or("esi", "edi")
        print deis_ada("edx")
        print deis_sba("ecx")
        print deis_ld4("eax", "eax")
        print deis_ad4("edx")
        print deis_zl3("esi")
        print deis_zl2("esi")
        print deis_zl1("esi")
        print deis_cmb("esi", "edi")
    else:
        with open(sys.argv[1], "r") as f:
            lines = f.readlines()
        print "/* automatically generated with deis_asm.py */"
        print "/* you are strongly encouraged to not modify this file directly */"
        for l in lines:
            l = l.split("#", 1)[0].strip()
            if l:
                s = l.split(" ", 1)
                op = s[0]
                if len(s) > 1:
                    args = s[1].split(",")
                else:
                    args = []

                op = op.strip()
                args = [a.strip() for a in args]

                # probably don't use this on untrusted source :)
                asm = getattr(sys.modules[__name__], "deis_%s" % op)(*args)

                print "__asm__ (\"bound  %%eax,0x%08x(,%%eax,1)\");" % asm.insn
