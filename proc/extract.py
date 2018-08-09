#
# project:rosenbridge
# domas // @xoreaxeaxeax
#

# the pattern extractor #

# this utility is used to process the logs generated from the deis instruction
# fuzzer.  by looking at changes in the system state, it identifies basic
# patterns in an instruction, such as 'adds two registers' or 'loads a value
# from memory'.  it then groups instructions based on overlapping patterns; for
# example, it may find a group that both writes a value to memory, and
# decrements a register by 4 - we might then infer that these are 'push'
# instructions.

# the script should be run with pypy, and may use very large (>16 gb) amounts of
# memory.

import re
import operator
import sys
import random

ALL_RUNS = 4 # 1 for search kernel
MEM_RUNS = 2 # 1 for search kernel

registers = { 
        "eax":32, "ebx":32, "ecx":32, "edx":32, "esi":32, "edi":32, "ebp":32, "esp":32, 
        "mm0":64, "mm1":64, "mm2":64, "mm3":64, "mm4":64, "mm5":64, "mm6":64, "mm7":64, 
        "cr0":32, "cr2":32, "cr3":32, "cr4":32, 
        "dr0":32, "dr1":32, "dr2":32, "dr3":32, "dr4":32, "dr5":32, "dr6":32, "dr7":32, 
        "eflags":32,
        }

sprs = [
        "cr0", "cr2", "cr3", "cr4", 
        "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", 
        "eflags",
        ]

class insn:
    def __init__(self, instruction, input_state, output_state, input_mem, output_mem, run, lines=""):
        self.instruction = instruction
        self.input_state = input_state
        self.output_state = output_state
        self.input_mem = input_mem
        self.output_mem = output_mem
        self.run = run
        self.lines = lines

    def bits(self):
        b = "{0:032b}".format(self.instruction)
        n = 4
        b = " ".join([b[i:i+n] for i in xrange(0, len(b), n)])
        n = 10
        b = " ".join([b[i:i+n] for i in xrange(0, len(b), n)])
        return b

    def __str__(self):
        return "%08x  [ %s ]" % (self.instruction, self.bits())

instructions = []

if len(sys.argv) < 2:
    print "usage: parse_log.py log"
    exit(-1)

with open(sys.argv[1], "r") as f:
    state = None
    instruction = None
    i_lines = None
    run = None

    # loading
    lines = f.readlines()

    # cleaning
    HEADER = "> device <.*, unknown>: "
    cleaned_lines = []
    for l in lines:
        l = l.replace("\r\n", "\n")
        if "debian kernel" in l:
            # remove kernel messages, which can appear in between others
            continue
        # temporary hack to correct missing spaces in mmx headers
        if "mm0" in l or "mm4" in l:
            l = l[:-1] + "  " + "\n"
        if re.match(HEADER, l):
            l = l[re.search(HEADER, l).end():]
        if l.strip(): 
            #cleaned_lines.append(l.strip() + '\n')
            cleaned_lines.append(l.rstrip("\r\n") + '\n')
    lines = cleaned_lines

    # parsing
    skip = False
    for (i, l) in enumerate(lines):
        if l.startswith(">------------------"):
            # parse start
            i_lines = []
            state_in = {}
            state_out = {}
            i_mem = []
            o_mem = []
            run = None
        elif l.startswith("<------------------") or "(timeout - aborting)" in l:
            # parse end
            if not skip:
                if instruction and state_in and state_out and i_mem and o_mem and run is not None:
                    instructions.append(insn(instruction, state_in, state_out, i_mem, o_mem, run, i_lines))
            skip = False
        elif l.startswith("(run"):
            # parse run
            run = int(re.search("^\(run (\d+)\)", l).group(1))
        elif l.startswith(". L("):
            # parse instruction
            instruction = int(re.search("^. L\((.{8})\)", l).group(1), 16)
        elif "00           04           08           0c" in l:
            # parse memory
            i_mem_l = lines[i+1][len(". inject: "):]
            o_mem_l = lines[i+2][len(". result: "):]
            try:
                i_mem = [int(x, 16) for x in i_mem_l.split()]
                o_mem = [int(x, 16) for x in o_mem_l.split()]
            except:
                print "warning: skipping corrupted line %d" % i
                skip = True
                break
        elif any(r in l for r in registers):
            # parse state
            for r in registers:
                if r not in l:
                    continue
                k = l.index(r)
                reg_len = re.search("[^ ]", l[k + len(r):]).start() + len(r)
                try:
                    reg_in = int(lines[i+1][k:k+reg_len].replace(" ", ""), 16)
                    reg_out = int(lines[i+2][k:k+reg_len].replace(" ", ""), 16)
                except:
                    print "warning: skipping corrupted line %d" % i
                    skip = True
                    break
                state_in[r] = reg_in
                state_out[r] = reg_out
                for k in xrange(3):
                    if lines[i + k] not in i_lines:
                        i_lines.append(lines[i + k])

# shortcut, just print all instructions
if "-ll" in sys.argv:
    l = []
    for ins in instructions:
        l.append("%08x" % ins.instruction)
    print "uint32_t twiddle_ins_source[]={"
    for i in sorted(set(l)):
        print "  0x%s," % i
    print "};"
    exit(0)

# group multiple runs
ins_runs = {}
for ins in instructions:
    if ins.instruction in ins_runs:
        ins_runs[ins.instruction].append(ins)
    else:
        ins_runs[ins.instruction] = [ins]

ins_to_patterns = {}
patterns_to_ins = {}
def add_ins_to_pattern(ins, pattern):
    # remove old pattern 
    if ins in ins_to_patterns:
        p = ins_to_patterns[ins]
        if p in patterns_to_ins:
            patterns_to_ins[p].remove(ins)

    # add new pattern
    if ins in ins_to_patterns:
        ins_to_patterns[ins] = ins_to_patterns[ins].union([pattern])
    else:
        ins_to_patterns[ins] = frozenset([pattern])

    p = ins_to_patterns[ins]

    if p in patterns_to_ins:
        patterns_to_ins[p].append(ins)
    else:
        patterns_to_ins[p] = [ins]

def hiword(val):
    return (val & 0xffff0000) >> 16

def loword(val):
    return val & 0xffff

MIN_RUNS = 1 
pattern_name = "word swap"
print
print "==== %s ====" % pattern_name
o = []
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        for ri, vi in ins.input_state.items():
            vo = ins.output_state[ri]
            # ignore target registers that didn't change
            if vo == vi:
                continue
            if loword(vi) == hiword(vo) and hiword(vi) == loword(vo):
                if vo != 0: # filter 0 transfers
                    passed.append((ins, "%s:   %s: %08x -> %08x" % (ins, ri, vi, vo)))
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))


MIN_RUNS = ALL_RUNS 
pattern_name = "lo word copy"
print
print "==== %s ====" % pattern_name
o = []
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        for ri, vi in ins.input_state.items():
            for ro, vo in ins.output_state.items():
                # ignore identical regs
                if ri == ro:
                    continue
                # ignore target registers that didn't change
                if ins.input_state[ro] == vo:
                    continue
                if loword(vi) == loword(vo) and \
                        hiword(ins.input_state[ro]) == hiword(vo):
                    if vo != 0: # filter 0 transfers
                        passed.append((ins, "%s:   %s: %08x, %s: %08x -> %08x" % (ins, ri, vi, ro, ins.input_state[ro], vo)))
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

MIN_RUNS = ALL_RUNS 
pattern_name = "hi word copy"
print
print "==== %s ====" % pattern_name
o = []
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        for ri, vi in ins.input_state.items():
            for ro, vo in ins.output_state.items():
                # ignore identical regs
                if ri == ro:
                    continue
                # ignore target registers that didn't change
                if ins.input_state[ro] == vo:
                    continue
                if loword(vi) == hiword(vo) and \
                        loword(ins.input_state[ro]) == loword(vo):
                    if vo != 0: # filter 0 transfers
                        passed.append((ins, "%s:   %s: %08x, %s: %08x -> %08x" % (ins, ri, vi, ro, ins.input_state[ro], vo)))
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

MIN_RUNS = ALL_RUNS
pattern_name = "ins imm load"
print
print "==== %s ====" % pattern_name
o = []
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        for ro, vo in ins.output_state.items():
            # ignore target registers that didn't change
            if ins.input_state[ro] == vo:
                continue
            if (ins.instruction & 0xffff) == (vo & 0xffff):
                if vo != 0: # filter 0 transfers
                    passed.append((ins, "%s:   %s: %08x -> %08x" % (ins, ro, ins.input_state[ro], vo)))
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

MIN_RUNS = ALL_RUNS # for reg/reg xfer, expect all runs to succeed
pattern_name = "(pre) register to register xfers"
print
print "==== %s ====" % pattern_name
o = []
#for ins in instructions:
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        '''
        if RUN_2_ARITHMETIC and ins.run != 2:
            # only use the randomized run.  runs with bit patterns are too
            # difficult to separate arithmetic from other effects
            continue
        '''
        for ri, vi in ins.input_state.items():
            for ro, vo in ins.output_state.items():
                if ri == ro:
                    continue
                # ignore aliases
                if ri == "dr5" and ro == "dr7" or ri == "dr7" and ro == "dr5" or \
                        ri == "dr4" and ro == "dr6" or ri == "dr6" and ro == "dr4":
                    continue
                # ignore target registers that didn't change
                if ins.input_state[ro] == vo:
                    continue
                if vi == vo:
                    if vi != 0: # filter 0 transfers
                        passed.append((ins, "%s:   %s -> %s" % (ins, ri, ro)))
                        #o.append("%s:   %s -> %s" % (ins, ri, ro))
                        #add_ins_to_pattern(ins, pattern_name)
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        '''
        for (ins, result) in passed:
            o.append(result)
            add_ins_to_pattern(ins, pattern_name)
        '''
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

# detects some instructions wherein one instruction modifies a register, then
# transfers the result to another
MIN_RUNS = ALL_RUNS # for reg/reg xfer, expect all runs to succeed
pattern_name = "(post) register to register xfers"
print
print "==== %s ====" % pattern_name
o = []
#for ins in instructions:
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        '''
        if RUN_2_ARITHMETIC and ins.run != 2:
            # only use the randomized run.  runs with bit patterns are too
            # difficult to separate arithmetic from other effects
            continue
        '''
        ignore = []
        found = False
        for ri, vi in ins.input_state.items():
            for ro, vo in ins.output_state.items():
                if ri == ro:
                    continue
                # ignore aliases
                if ri == "dr5" and ro == "dr7" or ri == "dr7" and ro == "dr5" or \
                        ri == "dr4" and ro == "dr6" or ri == "dr6" and ro == "dr4":
                    continue
                if (ri, ro) in ignore:
                    # we've already found this pair
                    continue
                # if the new value for one register is equal to the new value of
                # another register, and the value for the first register changed, 
                # and the value for the second register changed
                if ins.output_state[ri] == ins.output_state[ro] and \
                    ins.output_state[ri] != ins.input_state[ri] and \
                    ins.output_state[ro] != ins.input_state[ro]:
                    if ins.output_state[ri] != 0: # filter 0 "transfers"
                        # note that there is no easy way to determine the
                        # transfer direction
                        '''
                        o.append("%s:   %s <-> %s" % (ins, ri, ro))
                        add_ins_to_pattern(ins, pattern_name)
                        ignore.append((ri, ro))
                        ignore.append((ro, ri))
                        '''
                        passed.append((ins, "%s:   %s <-> %s" % (ins, ri, ro)))
                        found = True # stop on first found, no need to record all
                        break
                if found:
                    break
            if found:
                break
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        '''
        for (ins, result) in passed:
            o.append(result)
            add_ins_to_pattern(ins, pattern_name)
        '''
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

MIN_RUNS = MEM_RUNS # expect non-pointer runs to fail
pattern_name = "memory writes"
print
print "==== %s ====" % pattern_name
o = []
#for ins in instructions:
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        for (i, b) in enumerate(ins.input_mem):
            if b != ins.output_mem[i]:
                # find the last changed byte
                for k in xrange(len(ins.input_mem) - 1, i - 1, -1):
                    if ins.output_mem[k] != ins.input_mem[k]:
                        break
                r = "%s:   %s -> %s" % (ins, "".join("%02x" % x for x \
                            in ins.input_mem[i:k+1]), "".join("%02x" % x for x in ins.output_mem[i:k+1]))
                passed.append((ins, r))
                break
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        '''
        for (ins, result) in passed:
            o.append(result)
            add_ins_to_pattern(ins, pattern_name)
        '''
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

# memory reads
def WORD(mem, n):
    v = 0
    for s in xrange(n):
        v = v + (mem[s] << (s * 8))
    return v

for n in [1, 2, 4, 8]:
    MIN_RUNS = MEM_RUNS # allow failing on non-memory runs
    pattern_name = "memory reads, %d byte" % n
    print
    print "==== %s ====" % pattern_name
    o = []
    #for ins in instructions:
    for ins_run in ins_runs.values():
        passed = []
        for ins in ins_run:
            if n == 1 and ins.run > 1:
                continue
            found = False
            for x in [WORD(ins.input_mem[i:], n) for i in xrange(len(ins.input_mem)-n)]:
                if n == 1 and (x == 0 or x == 0xff):
                    continue
                for k, v in ins.output_state.items():
                    # only counts if the register changed
                    if ins.input_state[k] == v:
                        continue
                    # don't expect a read into an spr
                    if k in sprs:
                        continue
                    # check for other bytes unchanged, zeroed, or oned
                    if v == x or v == ((ins.input_state[k] & ~((1 << (n * 8)) - 1)) | x) \
                            or v == (~((1 << (n * 8)) - 1)) | x:
                        r = "%s:   %s: %08x -> %08x" % (ins, k, ins.input_state[k], ins.output_state[k])
                        '''
                        o.append(r)
                        add_ins_to_pattern(ins, pattern_name)
                        '''
                        passed.append((ins, r))
                        found = True # only get one match
                    if found:
                        break
                if found:
                    break
        # if all runs had the same behavior
        if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
            '''
            for (ins, result) in passed:
                o.append(result)
                add_ins_to_pattern(ins, pattern_name)
            '''
            # record only the first, don't need all
            (ins, result) = passed[0]
            o.append(result)
            add_ins_to_pattern(ins, pattern_name)

    print "\n".join(sorted(list(set(o))))

def binop_name(s):
    return re.findall("^<built-in function (.*)>$", s)[0]

# increments, decrements, push, pop
MIN_RUNS = MEM_RUNS # allow failing on non-memory runs
for v in [1, 2, 4, 8]:
    binops = [operator.add, operator.sub]
    for b in binops:
        o = []
        pattern_name = "%s, %d" % (binop_name(str(b)), v)
        print
        print "==== %s ====" % pattern_name
        #for ins in instructions:
        for ins_run in ins_runs.values():
            passed = []
            for ins in ins_run:
                '''
                if RUN_2_ARITHMETIC and ins.run != 2:
                    # only use the randomized run.  runs with bit patterns are too
                    # difficult to separate arithmetic from other effects
                    continue
                '''
                done = False
                for ki1, vi1 in ins.input_state.items():
                    # don't expect arithmetic on sprs
                    if ki1 in sprs:
                        continue
                    if b(vi1, v) == ins.output_state[ki1]:
                        r = "%s:   %s: %08x -> %08x" % (\
                                ins, ki1, vi1, ins.output_state[ki1])
                        '''
                        o.append(r)
                        add_ins_to_pattern(ins, pattern_name)
                        '''
                        passed.append((ins, r))
                    if done:
                        break
            # if all runs had the same behavior
            if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
                '''
                for (ins, result) in passed:
                    o.append(result)
                    add_ins_to_pattern(ins, pattern_name)
                '''
                # record only the first, don't need all
                (ins, result) = passed[0]
                o.append(result)
                add_ins_to_pattern(ins, pattern_name)

        print "\n".join(sorted(list(set(o))))

# write eip

def DWORD(mem):
    return mem[0] + (mem[1]<<8) + (mem[2]<<16) + (mem[3]<<24)
MIN_RUNS = MEM_RUNS # allow failing on non-memory runs
pattern_name = "call (write next eip)"
print
print "==== %s ====" % pattern_name
o = []
DEIS_LENGTH = 7 # 4 plus wrapper
#for ins in instructions:
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        eip = ins.input_state["eax"] + DEIS_LENGTH
        #for x in [DWORD(ins.output_mem[i:]) for i in xrange(len(ins.input_mem)-4)]:
        for i in xrange(len(ins.output_mem) - 4):
            x = DWORD(ins.output_mem[i:])
            if x == eip:
                #o.append("%s:   %08x -> %08x" % (ins, DWORD(ins.input_mem[i:]), x))
                #add_ins_to_pattern(ins, pattern_name)
                r = "%s:   %08x -> %08x" % (ins, DWORD(ins.input_mem[i:]), x)
                passed.append((ins, r))
                break # some instructions seem to double write eip, only count them once
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        '''
        for (ins, result) in passed:
            o.append(result)
            add_ins_to_pattern(ins, pattern_name)
        '''
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

# shifts
MIN_RUNS = ALL_RUNS # expect all runs to succeed
for v in xrange(1,16): # shifts beyond 16 are too hard to distinguish from random small numbers
    binops = [operator.lshift, operator.rshift]
    for b in binops:
        o = []
        pattern_name = "%s, %d" % (binop_name(str(b)), v)
        print
        print "==== %s ====" % pattern_name
        #for ins in instructions:
        for ins_run in ins_runs.values():
            passed = []
            for ins in ins_run:
                '''
                if RUN_2_ARITHMETIC and ins.run != 2:
                    # only use the randomized run.  runs with bit patterns are too
                    # difficult to separate arithmetic from other effects
                    continue
                '''
                for ki1, vi1 in ins.input_state.items():
                    # don't expect arithmetic on sprs
                    if ki1 in sprs:
                        continue
                    # shifts to 0 are probably not shifts
                    if not ins.output_state[ki1]:
                        continue
                    #TODO: is it worth exploring shifts into other registers?
                    result = b(vi1, v) & ((1<<registers[ki1])-1) # mask to register size
                    if result == ins.output_state[ki1]:
                        '''
                        o.append("%s:   %s: %08x -> %08x" % (\
                                ins, ki1, vi1, ins.output_state[ki1]))
                        add_ins_to_pattern(ins, pattern_name)
                        '''
                        r = "%s:   %s: %08x -> %08x" % (\
                                ins, ki1, vi1, ins.output_state[ki1])
                        passed.append((ins, r))
                        break
            # if all runs had the same behavior
            if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
                '''
                for (ins, result) in passed:
                    o.append(result)
                    add_ins_to_pattern(ins, pattern_name)
                '''
                # record only the first, don't need all
                (ins, result) = passed[0]
                o.append(result)
                add_ins_to_pattern(ins, pattern_name)
        print "\n".join(sorted(list(set(o))))

# 90s
# currently the fuzzer has a nop-sled after the fuzzed instruction (to catch
# short forward jumps, and generally stabalize the system) ... reading 90's into
# a register suggests an immediate load from a nearby location (similar to ARM)
MIN_RUNS = MEM_RUNS # allow failing on non-memory runs
pattern_name = "immediate load"
print
print "==== %s ====" % pattern_name
o = []
#for ins in instructions:
for ins_run in ins_runs.values():
    passed = []
    for ins in ins_run:
        for k, v in ins.output_state.items():
            if v == 0x90909090:
                '''
                o.append("%s:   %s -> %08x" % (ins, k, v))
                add_ins_to_pattern(ins, pattern_name)
                '''
                r = "%s:   %s -> %08x" % (ins, k, v)
                passed.append((ins, r))
                break
    # if all runs had the same behavior
    if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
        '''
        for (ins, result) in passed:
            o.append(result)
            add_ins_to_pattern(ins, pattern_name)
        '''
        # record only the first, don't need all
        (ins, result) = passed[0]
        o.append(result)
        add_ins_to_pattern(ins, pattern_name)

print "\n".join(sorted(list(set(o))))

# binary operations
# these are just insanely slow, do them last
MIN_RUNS = ALL_RUNS # expect all runs to succeed
binops = [operator.add, operator.div, operator.mul, operator.sub, operator.mod, operator.xor, operator.and_, operator.or_]
for b in binops:
    pattern_name = "%s" % binop_name(str(b))
    print
    print "==== %s ====" % pattern_name
    o = []
    #for ins in instructions:
    for ins_run in ins_runs.values():
        passed = []
        for ins in ins_run:
            found = False
            '''
            if ins.run != 2: # regardless of RUN_2_ARITHMETIC 
                # only use the randomized run.  runs with bit patterns are too
                # difficult to separate arithmetic from other effects
                continue
            '''
            for ki1, vi1 in ins.input_state.items():
                if ki1 in sprs: # don't expect arithmetic on sprs
                    continue
                for ki2, vi2 in ins.input_state.items():
                    # disallow identical values (some ops indestinguishable from bit shifts)
                    if ki1 == ki2:
                        continue
                    if ki2 in sprs: # don't expect arithmetic on sprs
                        continue
                    for ko, vo in ins.output_state.items():
                        if ko in sprs: # don't expect arithmetic on sprs
                            continue
                         
                        # check result, mask to register size
                        try:
                            result = b(vi1, vi2) & ((1<<registers[ko])-1)
                        except:
                            # probably a divide by zero or similar
                            continue

                        if result < 0x1000 or result > 0xffff0000 or result == vi1 or result == vi2:
                            # too often coincidental (e.g. mod/div by large number)
                            continue
                        
                        if result == vo:
                            '''
                            o.append("%s:   %s: %08x ... %s: %08x -> %s: %08x" % (\
                                    ins, ki1, vi1, ki2, vi2, ko, vo))
                            add_ins_to_pattern(ins, pattern_name)
                            '''
                            found = True
                            r = "%s:   %s: %08x ... %s: %08x -> %s: %08x" % (\
                                    ins, ki1, vi1, ki2, vi2, ko, vo)
                            passed.append((ins, r))
                            break
                    if found:
                        break
                if found:
                    break
        # if all runs had the same behavior
        if len(passed) == len(ins_run) and len(passed) >= MIN_RUNS:
            '''
            for (ins, result) in passed:
                o.append(result)
                add_ins_to_pattern(ins, pattern_name)
            '''
            # record only the first, don't need all
            (ins, result) = passed[0]
            o.append(result)
            add_ins_to_pattern(ins, pattern_name)
    print "\n".join(sorted(list(set(o))))

# summarize pattern groups

print
print "=" * 30 + " summary " + "=" * 30
print

# sort groups by number of patters
pattern_groups = reversed(sorted(patterns_to_ins.items(), key=lambda t: len(t[0])))
for k in pattern_groups:
    if not patterns_to_ins[k[0]]:
        continue
    print "==== pattern ===="
    for p in k[0]:
        print "  p: %s" % p
    o = ["%s" % i for i in patterns_to_ins[k[0]]]
    for i in sorted(list(set(o))):
        print "     %s" % i
    print

# show all grouped instructions
final = sorted(list(set(str(i) for i in ins_to_patterns)))
print "==== final list (%d instructions) ====" % len(final)
for i in final:
    print i
