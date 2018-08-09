# manages the fuzz_deis tool on a remote target

import os
import sys
import paramiko
import time
import socket
import random
import collections
from threading import Thread

import power.power as power
import util.indent as indent
from device.device import Device

TASK_TIMEOUT = 600 # max time to run the fuzz script (seconds)
PING_DELAY   = 1   # time to wait in between pings (seconds)
BOOT_TIMEOUT = 120 # max time for the target to boot (aka respond to pings) (seconds)

REMOTE_COMMAND = "~/_research/rosenbridge/fuzz/deis/fuzz_deis.sh"

SIM = False

systems = [
            Device(3, "192.168.3.160", "delta", "password", "unknown"),
            Device(2, "192.168.3.161", "delta", "password", "unknown"),
            Device(1, "192.168.3.162", "delta", "password", "unknown"),
            Device(5, "192.168.3.163", "delta", "password", "unknown"),
            Device(6, "192.168.3.164", "delta", "password", "unknown"),
            Device(7, "192.168.3.165", "delta", "password", "unknown"),
            Device(0, "192.168.3.166", "delta", "password", "unknown"),
        ]

if SIM:
    systems = [Device(1, "localhost", "deltaop", "xxx", "unknown")]

def device_up(device):
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

        start_time = time.time()
        device.up = False
        while not device.up and time.time() - start_time < BOOT_TIMEOUT:
            time.sleep(PING_DELAY)
            device.up = device_up(device)

        if not device.up:
            device.dprint("device exceeded reboot time, resetting")

            # this power down seems to interfere with the power on button push
            # in general, if the device hasn't booted, it's just because the
            # power on didn't take.  just try the power on again instead.
            '''
            # power off
            SIM or power.power_off(device.relay)

            # target device seems to (sometimes) not recognize the power on, if not
            # enough time has elapsed after the shut down
            time.sleep(30) # needs to be large 
            '''

            continue

        device.dprint("device up")

        # just because the device responds to pings doesn't mean it is
        # completely booted.  give the device a bit longer before trying.
        time.sleep(10)

        retry = True
        while retry:
            try:
                device.dprint("connecting to device")

                device.dprint("(debug) create client")
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                device.dprint("(debug) connect")
                client.connect(device.ip, port=22, username=device.username,
                        password=device.password)

                # after sshd starts, the system still has a bit to do before
                # it's done booting.  don't want to spam the logs with
                # irrelevant kernel messages - wait a bit.
                device.dprint("(waiting)")
                time.sleep(10)

                device.dprint("(debug) exec")
                stdin, stdout, stderr = client.exec_command(
                        REMOTE_COMMAND,
                        timeout=TASK_TIMEOUT,
                        get_pty=True
                        )

                device.dprint("=============== log ===============")

                while True:
                    M_TIMEOUT = 10
                    abort = False

                    start_time = time.time()
                    while True:
                        if stdout.channel.in_buffer:
                            break
                        if time.time() - start_time > M_TIMEOUT:
                            device.dprint("(timeout - aborting)")
                            abort = True
                            break
                        time.sleep(.2)

                    if abort:
                        break

                    time.sleep(1) # accumulate rest of buffer

                    m = stdout.read(len(stdout.channel.in_buffer))

                    device.dprint(m)

                device.dprint("=============== end ===============")

                retry = False
            except socket.error as e:
                # the device is not yet up (probably, it is responding to pings,
                # but sshd has not been started)
                device.dprint("except %s" % e)
                device.dprint("(retrying)")
                retry = True
                time.sleep(5) # don't spam the device
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

        SIM or power.power_off(device.relay)

        # target device seems to (sometimes) not recognize the power on, if not
        # enough time has elapsed after the shut down
        time.sleep(10) # needs to be large

        end = time.time()

        device.dprint("! round %d, %.2f seconds" % (on_round, end - start))

if __name__ == "__main__":
    indent.initialize_indent()

    SIM or power.initialize_power()

    threads = []

    print "launching tasks"
    for s in systems:
        t = Thread(target=task, args=(s,))
        threads.append(t)
        t.start()
        time.sleep(2)
    print "completed task launch"

    for t in threads:
        t.join()
