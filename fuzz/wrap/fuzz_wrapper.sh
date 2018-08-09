#!/bin/bash

modprobe msr
../../lock/bin/unlock
./bin/fuzz_wrapper
