#!/bin/sh

# call the bridge from a wrapper, so that if it crashes we can still send out a
# message

# assumes no password required for sudo
# (add 'username ALL=(ALL) NOPASSWD: ALL' to sudoers)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "== unlocking backdoor =="
sudo modprobe msr
$DIR/../../lock/bin/unlock
echo "== launching kern.log =="
sudo tail -f /var/log/kern.log &
echo "== launching bridge =="
$DIR/bin/fuzz_exit
echo "~~ to hell and back ~~"
