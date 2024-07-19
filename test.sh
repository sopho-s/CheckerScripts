#!/bin/bash

# Trace the 'ls' command and store the output in a variable
trace_output=$(strace ls 2>&1)

# Do something with the output, for example, print it
echo "The strace output of 'ls' is:"