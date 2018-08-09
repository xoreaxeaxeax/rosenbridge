#!/usr/bin/python

# this utility serves the same purpose as relay_serial.py, but uses the
# pylibftdi driver to control the relays.  it seems to work fairly well across
# different systems.

from pylibftdi import Driver
from pylibftdi import BitBangDevice

#import struct
import sys
import time

DEVICE="AI053AH4"

RELAYS = 8

relay_state = [0] * RELAYS

s = None

def list_devices():
    print "Vendor\t\tProduct\t\t\tSerial"
    dev_list = []
    for device in Driver().list_devices():
        device = map(lambda x: x.decode('latin1'), device)
        vendor, product, serial = device
        print "%s\t\t%s\t\t%s" % (vendor, product, serial)

def set_relays():
    print "setting relay state..."
    k = 0
    for i in xrange(RELAYS):
        k = k | (relay_state[i] << i)
    #k = struct.pack("B", k)

    try:
        with BitBangDevice(DEVICE) as bb:
            bb.port = k
    except Exception, err:
        print "Error: " + str(err)
        sys.exit(1)

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

if __name__ == "__main__":
    relay = 0
    delay = 1

    if len(sys.argv) > 1:
        relay = int(sys.argv[1])
    if len(sys.argv) > 2:
        delay = int(sys.argv[2])

    open_relay(relay)
    time.sleep(delay)
    close_relay(relay)
    time.sleep(1)
