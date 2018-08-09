#!/bin/bash

# assumes no password required for sudo
# (add 'username ALL=(ALL) NOPASSWD: ALL' to sudoers)

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "== unlocking backdoor =="
sudo modprobe msr
sudo $DIR/../../lock/bin/unlock
echo "== loading privregs =="
sudo insmod $DIR/../../kern/privregs/privregs.ko
echo "== loading deis kernel =="
sudo insmod $DIR/../../kern/deis_kernel.ko
echo "== recording kernel log =="
sudo tail -f /var/log/kern.log &
echo "== launching deis =="
sudo $DIR/bin/fuzz_deis | grep --color -E '\^|$'
echo "== end launch deis =="
