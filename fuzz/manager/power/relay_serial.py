# this utility controls the attached relays
# it seems to be fickle (works on some systems, not others), may depend on exact
# version of libftdi installed?

# if this fails, unplug and replug
# if still fails, use ./drcontrol.py -l
#   and 
#   ./drcontrol/trunk/drcontrol.py -d AI053AH4 -c off -r all -v
#   ./drcontrol/trunk/drcontrol.py -d AI053AH4 -c on -r all -v
# seemed to get everything happy

import serial
import time
import struct

from pylibftdi import Driver

DEVICE = "/dev/ttyUSB0"
BAUD = 9600
BYTE_SIZE = serial.EIGHTBITS
PARITY = serial.PARITY_NONE
STOP_BITS = serial.STOPBITS_ONE

PRODUCT = "FT245R USB FIFO"
RELAYS = 8

relay_state = [0] * RELAYS

s = None

def open_serial():
    global s
    print "opening serial..."
    s = serial.Serial(
             port=DEVICE,
             baudrate=BAUD,
             bytesize=BYTE_SIZE,
             parity=PARITY,
             stopbits=STOP_BITS,
             timeout=None
             )
    if s.isOpen():
        print "...done"
    else:
        print "FAILURE"
        exit(1)

def set_relays():
    print "setting relay state..."
    k = 0
    for i in xrange(RELAYS):
        k = k | (relay_state[i] << i)
    k = struct.pack("B", k)
    s.write([k, k])
    print "...done"

def open_relay(relay):
    print "opening relay %d..." % relay
    relay_state[relay] = 1
    set_relays()
    print "...done"

def close_relay(relay):
    print "closing relay %d..." % relay
    relay_state[relay] = 0
    set_relays()
    print "...done"

def retry():
    # mostly so that output indentation is handled by our wrapper
    print "... retrying ..."

def reset_device():
    print "locating device..."
    found = False
    while not found:
        for device in Driver().list_devices():
            device = map(lambda x: x.decode('latin1'), device)
            vendor, product, serial = device
            print product
            if product == PRODUCT:
                found = True
                break
        else:
            retry() 
    print "...done"

if __name__ == "__main__":
    open_serial()
    reset_device()
    open_relay(0)
    time.sleep(1)
    close_relay(0)
    time.sleep(1)
