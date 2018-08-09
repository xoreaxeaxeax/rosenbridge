import sys
import paramiko
import time
import socket
import random
import collections

import power.power as power
import util.indent as indent
import generator
from device.device import Device

TASK_TIME = 3 # seconds
PING_TIME = 1 # seconds

USERNAME = "user"
PASSWORD = "password"
COMMAND = "~/_research/rosenbridge/fuzz/exit/fuzz_exit.sh"

SIM = False

systems = [Device(0, "192.168.3.169", "unknown")]

if SIM:
    systems = [Device(0, "localhost", "unknown")]
    USERNAME = "deltaop"
    PASSWORD = "xxx"

#TODO: maybe alternate between strategies?  the strategy needs to be integrated
# into the master generator, so that each instruction is tried with both
# strategies
JUMP_STRATEGY = 2

#TODO: want to be able to assign a device to a specific SHARED strategy ...
# that is, we're not generating data for just that device, we generate it for a
# strategy, and then many devices can pull from that data
strategy_set_0 = [
    #generator.strategy_left_bits(),
    #generator.strategy_right_bits(),
    generator.strategy_edge_bits(),
    #generator.strategy_random_bits(),
    #generator.strategy_random_right_bits(),
    #generator.strategy_random_left_bits(),
    #generator.strategy_random_edge_bits(),
]

def strategy_set(ss):
    while True:
        for s in ss:
            yield s.next()

#TODO: enlarge this, probably
#TODO: is it better to shuffle the instruction set after it is generated?  i'm
# worried that e.g. one pattern of bits (e.g. first 4 bits 0) will all fail, so
# you'll have long runs of completely failing on the first instruction.
# randomizing gets around this. << it's better IF you think all instructions in
# your set are equally 'good'.  if the set deteriorates as it goes, then you
# don't want to shuffle.
INSTRUCTIONS = 200000 # optimized for fuzzing edge bits
def generate_instructions():
    print "generating instructions..."
    s = strategy_set(strategy_set_0)
    i = [next(s) for _ in xrange(INSTRUCTIONS)]
    i = list(collections.OrderedDict.fromkeys(i)) 
    print "...done"
    return i
instructions = generate_instructions()
on_instruction = 0

#TODO: probably enlarge this too
RUN_INSTRUCTIONS = 1000
def generate_run(device):
    # a run consists of the top instruction in the instruction list, and a
    # random RUN_INSTRUCTIONS-1 instructions following it
    global on_instruction
    device.dprint("generating run...")
    r = [instructions[on_instruction]]
    r.extend(random.sample(instructions[on_instruction+1:], RUN_INSTRUCTIONS-1))
    on_instruction = on_instruction + 1
    device.dprint("...done")
    return r

def device_up(device):
    import os
    device.dprint("pinging %s" % device.ip)
    response = os.system("timeout 1 ping -c 1 " + device.ip + " > /dev/null 2>&1")
    return response == 0

# assumes device is powered off
def task(device):
    on_round = 0
    while True:
        on_round = on_round + 1
        start = time.time()
        SIM or power.power_on(device.relay)

        while not device.up:
            time.sleep(PING_TIME)
            device.up = device_up(device)

        device.dprint("device up")

        retry = True
        while retry:
            try:
                device.dprint("connecting to device")

                device.dprint("(debug) create client")
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                device.dprint("(debug) connect")
                client.connect(device.ip, port=22, username=USERNAME, password=PASSWORD)

                device.dprint("(debug) exec")
                stdin, stdout, stderr = client.exec_command(
                        COMMAND,
                        timeout=TASK_TIME,
                        get_pty=True
                        )

                device.dprint("=============== connected ===============")
                for l in iter(lambda: stdout.readline().strip(), ""):
                    device.dprint("% " + l)
                    if l == ">":
                        break
                device.dprint("================= done. =================")

                device.dprint("(debug) generating run")
                r = generate_run(device)

                device.dprint("(debug) selecting jump strategy")
                j = JUMP_STRATEGY
                device.dprint("(debug) selected jump strategy %d" % j)

                device.dprint("(debug) sending test cases")
                stdin.write("%d\n" % j)
                for t in r:
                    stdin.write("%08x\n" % t)
                stdin.write("-\n")
                
                device.dprint("=============== log ===============")
                for l in iter(lambda: stdout.readline().strip(), ""):
                    device.dprint("% " + l)
                    #if l == ">":
                    #    break
                device.dprint("=============== end ===============")

                retry = False
            except socket.error as e:
                # the device is not yet up
                device.dprint("except %s" % e)
                device.dprint("(retrying)")
                retry = True
            except socket.timeout as e:
                # we successfully connected and launched a command, but the
                # device restarted
                device.dprint("except %s" % e)
                retry = False
            except:
                device.dprint("generic exception")
                e = sys.exc_info()[0]
                device.dprint("except %s" % e)
                retry = True
            finally:
                client.close()

        #TODO: if the device freezes, does holding down power cause a reboot or
        #      a power off?
        SIM or power.power_off(device.relay)

        time.sleep(1)

        end = time.time()

        device.dprint("! round %d, %.2f seconds" % (on_round, end - start))

if __name__ == "__main__":
    indent.initialize_indent()

    SIM or power.initialize_power()

    '''
    print "powering on systems..."
    for s in systems:
        power.power_on(s.relay)
    print "...done"

    print "waiting for systems..."
    while any(not s.up for s in systems):
        for s in systems:
            if not s.up:
                s.up = device_up(s)
    print "...done"

    time.sleep(5)

    print "powering off systems..."
    for s in systems:
        power.power_off(s.relay)
    print "...done"
    '''

    task(systems[0])
