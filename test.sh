#!/bin/bash

echo "root    /home/milesdyson/backups/backup.sh" | grep -oP "(?<=root\s{4}).*$" | grep -oP ".*\.sh"