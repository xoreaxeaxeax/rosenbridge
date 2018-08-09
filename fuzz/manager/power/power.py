from relay_ftdi import *
import time
import sys

RELEASE_TIME = .5
ON_TIME = 1
OFF_TIME = 6

def initialize_power():
    #open_serial()
    #reset_device()
    pass

def power_on(device):
    print "powering on device %d..." % device
    close_relay(device)
    time.sleep(RELEASE_TIME)
    open_relay(device)
    time.sleep(ON_TIME)
    close_relay(device)
    print "...done"

def power_off(device):
    print "shutting down device %d..." % device
    close_relay(device)
    time.sleep(RELEASE_TIME)
    open_relay(device)
    time.sleep(OFF_TIME)
    close_relay(device)
    print "...done"

if __name__ == "__main__":
    initialize_power()
    power_on(int(sys.argv[1]))
    time.sleep(5)
    power_off(int(sys.argv[1]))
