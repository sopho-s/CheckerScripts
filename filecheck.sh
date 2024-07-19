#!/bin/sh

GetNoFileCalls () {
    STRACEIN=$1
    NoFile=$(echo "$STRACEIN" | grep -iE "open|access|no such file")
    echo $NoFile
}

TRACER=$1

if ! hash strace 2> /dev/null
then
    echo "strace is not found, exiting"
    exit 0
fi

if ! hash ltrace 2> /dev/null
then
    echo "ltrace is not found, exiting"
    exit 0
fi

echo "tracing files"


STRACEOUT=$(strace $TRACER 2>&1)
LTRACEOUT=$(ltrace $TRACER 2>&1)

GetNoFileCalls "$STRACEOUT"