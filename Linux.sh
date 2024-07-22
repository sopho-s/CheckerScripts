#!/bin/bash

Legend () {
    printf "Back ground colour ref:\n"
    printf "Low importance\n"
    printf "\e[48;5;11m\e[4m\e[1mMid importance\e[0m\n"
    printf "\e[48;5;210m\e[4m\e[1mHigh importance\e[0m\n"
    printf "\e[48;5;124m\e[4m\e[1mCritical importance\e[0m\n"
}

FileObjectHijacks () {
    STRACEIN=$1
    NOFILE=$(echo "$STRACEIN" | grep -iE "no such file")
    MISSING=$(echo "$NOFILE" | grep -E "\.so[^\.]" | grep -o '".*"' | sed 's/"//g')
    while IFS= read -r line
    do
        if  ! [ -z "$line" ]
        then
            printf "\e[103m\e[30m$line is a missing object file and this file calls it\e[0m\n"
        fi
    done <<< "$MISSING"

    FILEUSE=$(echo "$STRACEIN" | grep -iE "open|access" | grep --invert-match "No such file or directory")
    USEDFILES=$(echo "$FILEUSE" | grep -E "\.so[^\.]" | grep -o '".*"' | sed 's/"//g')
    while IFS= read -r line
    do
        if ! [ -z "$line" ]
        then
            if [ -w "$line" ]
            then
                printf "\e[103m\e[30m$line is an object and is writeable with current permissions\e[0m\n"
            fi
        fi
    done <<< "$USEDFILES"
}

SUIDObjectInjects () {
    TRACER=$1

    

    STRACEOUT=$(strace $TRACER 2>&1)

    PFILEOBJECTHIJACKS=$(FileObjectHijacks "$STRACEOUT" 2>&1)
    SPACES=$((100 - ${#TRACER}))

    if [ -z "$PFILEOBJECTHIJACKS" ]
    then
        printf "\e[91m$TRACER"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    else
        printf "\e[1m\e[92m$TRACER"
        printf "%*s" $SPACES ""
        printf "\xE2\x9C\x94\e[0m\n"
        echo "This file may be vulnerable because:"
        while IFS= read -r line
        do
            if  ! [ -z "$line" ]
            then
                printf "$line\n"
            fi
        done <<< "$PFILEOBJECTHIJACKS"
    fi
}

ShadowChecks () {
    printf "\e[3m\e[34m================Checking Shadow================\e[0m\n"
    if [ -w "/etc/shadow" ]
    then
        SHADOW="writeable"
        SPACES=$((100 - ${#SHADOW}))
        printf "\e[92m\e[48;5;124m\e[4m\e[1m$SHADOW\e[0m\e[92m"
        printf "%*s" $SPACES ""
        printf "\xE2\x9C\x94\e[0m\n"
    else
        SHADOW="not writeable"
        SPACES=$((100 - ${#SHADOW}))
        printf "\e[91m$SHADOW"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    fi

    if [ -r "/etc/shadow" ]
    then
        SHADOW="readable"
        SPACES=$((100 - ${#SHADOW}))
        printf "\e[92m\e[48;5;210m\e[4m\e[1m$SHADOW\e[0m\e[92m"
        printf "%*s" $SPACES ""
        printf "\xE2\x9C\x94\e[0m\n"
        echo "shadow contents:"
        printf "\e[35m"
        cat "/etc/shadow"
        printf "\e[0m"
    else
        SHADOW="not readable"
        SPACES=$((100 - ${#SHADOW}))
        printf "\e[91m$SHADOW"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    fi
}

PasswdChecks () {
    printf "\e[3m\e[34m================Checking Passwd================\e[0m\n"
    if [ -w "/etc/passwd" ]
    then
        PASSWD="writeable"
        SPACES=$((100 - ${#PASSWD}))
        printf "\e[92m\e[48;5;124m\e[4m\e[1m$PASSWD\e[0m\e[92m"
        printf "%*s" $SPACES ""
        printf "\xE2\x9C\x94\e[0m\n"
    else
        PASSWD="not writeable"
        SPACES=$((100 - ${#PASSWD}))
        printf "\e[91m$PASSWD"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    fi

    if [ -r "/etc/passwd" ]
    then
        PASSWD="readable"
        SPACES=$((100 - ${#PASSWD}))
        printf "\e[92m\e[48;5;11m\e[4m\e[1m$PASSWD\e[0m\e[92m"
        printf "%*s" $SPACES ""
        printf "\xE2\x9C\x94\e[0m\n"
        echo "passwd contents:"
        printf "\e[35m"
        cat "/etc/passwd"
        printf "\e[0m"
    else
        PASSWD="not readable"
        SPACES=$((100 - ${#PASSWD}))
        printf "\e[91m$PASSWD"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    fi
}

SSHChecks () {
    printf "\e[3m\e[34m===========Locating All .ssh Folders===========\e[0m\n"  
    SSHFOLDERS=$(find / -type d -name ".ssh" 2>&1 | grep -Ev "Permission denied|No such file or directory")

    if [ -z $SSHFOLDERS ]
    then
        SSHNOTFOUND="no .ssh files found"
        SPACES=$((100 - ${#SSHNOTFOUND}))
        printf "\e[91m$SSHNOTFOUND"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    else
        printf "\e[35m$SSHFOLDERS\e[0m\n"
        printf "\e[3m\e[34m=======Displaying readable files in .ssh=======\e[0m\n"
        while IFS= read -r folder
        do
            FILES=$(ls -lA $folder 2>&1 | grep -oE "[^ ]*$" | sed '1d')
            while IFS= read -r file
            do
                if [ -r "$folder/$file" ]
                then
                    printf "\e[35m$folder/$file\e[0m\n"
                fi
            done <<< "$FILES"
        done <<< "$SSHFOLDERS"
    fi
}

SensitiveFilesChecks() {
    printf "\e[3m\e[34m====Searching For Potential Password Files=====\e[0m\n"
    PASSWORDFILES=$(find / -iregex ".*passwords*[^/]*$" 2>&1)
    while IFS= read -r file
    do
        file=$(echo "$file" 2>&1 | grep -iEv "snap|metasploit|seclists|games|steam")
        FILENAME=$(echo "$file" 2>&1 | grep -oE "[^/]*$" | grep -E "^\.*((?:[a-zA-Z0-9]+-)*[a-zA-Z0-9]+)(\.(txt|csv|log|list|key|tar|gz|zip|pdf|doc|docx|bak|old))?$" 2>/dev/null)
        if ! [ "${#FILENAME}" = "0" ]
        then
            if [ -r "$file" ]
            then
                printf "\e[35m$file\e[0m\n"
            fi
        fi
    done <<< "$PASSWORDFILES"
    printf "\e[3m\e[34m=====Searching For Potential id_rsa Files======\e[0m\n"
    IDRSAFILES=$(find / -iregex ".*id_rsa[^/]*$" 2>&1)
    while IFS= read -r file
    do
        file=$(echo "$file" 2>&1 | grep -iEv "snap|metasploit|seclists|games|steam")
        FILENAME=$(echo "$file" 2>&1 | grep -oE "[^/]*$" | grep -E "^\.*((?:[a-zA-Z0-9]+-)*[a-zA-Z0-9]+)(\.(txt|csv|log|list|key|tar|gz|zip|pdf|doc|docx|bak|old))?$" 2>/dev/null)
        if ! [ "${#FILENAME}" = "0" ]
        then
            if [ -r "$file" ]
            then
                printf "\e[35m\e[48;5;210m\e[4m\e[1m$file\e[0m\n"
            fi
        fi
    done <<< "$IDRSAFILES"
    printf "\e[3m\e[34m=====Searching For Potential Flag Files=====\e[0m\n"
    FLAGFILES=$(find / -iregex ".*flags*[^/]*$" 2>&1)
    while IFS= read -r file
    do
        file=$(echo "$file" 2>&1 | grep -iEv "snap|metasploit|seclists|games|steam")
        FILENAME=$(echo "$file" 2>&1 | grep -oE "[^/]*$" | grep -E "^\.*((?:[a-zA-Z0-9]+-)*[a-zA-Z0-9]+)(\.(txt))?$" 2>/dev/null)
        if ! [ "${#FILENAME}" = "0" ]
        then
            if [ -r "$file" ]
            then
                printf "\e[35m$file\e[0m\n"
            fi
        fi
    done <<< "$FLAGFILES"
}

GTFOBins () {
    printf "\e[34m===========Checking Files On GTFOBins==========\e[0m\n"
    while IFS= read -r line
    do
        SUIDFILE=$(echo "$line" | grep -oE "[^/]*$" | grep -E "^aa-exec$|^ab$|^agetty$|^alpine$|^aria2c$|^arj$|^ar$|^arp$|^ascii-xfr$|^ash$|^as$|^aspell$|^atobm$|^awk$|^base32$|^base64$|^basenc$|^basez$|^bash$|^batcat$|^bc$|^bridge$|^busctl$|^busybox$|^byebug$|^bzip2$|^cabal$|^capsh$|^cat$|^chmod$|^choom$|^chown$|^chroot$|^clamscan$|^cmp$|^column$|^comm$|^composer$|^cpio$|^cp$|^cpulimit$|^csh$|^csplit$|^csvtool$|^cupsfilter$|^curl$|^cut$|^dash$|^date$|^dc$|^dd$|^debugfs$|^dialog$|^diff$|^dig$|^distcc$|^dmsetup$|^docker$|^dosbox$|^dvips$|^ed$|^efax$|^elvish$|^emacs$|^env$|^eqn$|^espeak$|^expand$|^expect$|^file$|^find$|^fish$|^flock$|^fmt$|^fold$|^gawk$|^gcore$|^gdb$|^genie$|^genisoimage$|^gimp$|^ginsh$|^git$|^grep$|^gtester$|^gzip$|^hd$|^head$|^hexdump$|^highlight$|^hping3$|^iconv$|^iftop$|^install$|^ionice$|^ip$|^ispell$|^jjs$|^joe$|^join$|^jq$|^jrunscript$|^julia$|^ksh$|^ksshell$|^kubectl$|^latex$|^ldconfig$|^ld.so$|^less$|^lftp$|^links$|^logsave$|^look$|^lualatex$|^lua$|^luatex$|^make$|^mawk$|^minicom$|^more$|^mosquitto$|^msgattrib$|^msgcat$|^msgconv$|^msgfilter$|^msgmerge$|^msguniq$|^multitime$|^mv$|^mysql$|^nano$|^nasm$|^nawk$|^ncdu$|^ncftp$|^nc$|^nft$|^nice$|^nl$|^nmap$|^nm$|^node$|^nohup$|^ntpdate$|^octave$|^od$|^openssl$|^openvpn$|^pandoc$|^paste$|^pdflatex$|^pdftex$|^perf$|^perl$|^pexec$|^pg$|^php$|^pic$|^pico$|^pidstat$|^posh$|^pr$|^pry$|^psftp$|^ptx$|^python$|^rake$|^rc$|^readelf$|^restic$|^rev$|^rlwrap$|^rpmdb$|^rpm$|^rpmquery$|^rpmverify$|^rsync$|^rtorrent$|^run-parts$|^runscript$|^rview$|^rvim$|^sash$|^scanmem$|^scp$|^scrot$|^sed$|^setarch$|^setfacl$|^setlock$|^shuf$|^slsh$|^socat$|^soelim$|^softlimit$|^sort$|^sqlite3$|^ssh-agent$|^ssh-keygen$|^ssh-keyscan$|^sshpass$|^ss$|^start-stop-daemon$|^stdbuf$|^strace$|^strings$|^sysctl$|^systemctl$|^tac$|^tail$|^tar$|^taskset$|^tasksh$|^tbl$|^tclsh$|^tdbtool$|^tee$|^telnet$|^terraform$|^tex$|^tftp$|^tic$|^time$|^timeout$|^tmate$|^troff$|^ul$|^unexpand$|^uniq$|^unshare$|^unsquashfs$|^unzip$|^update-alternatives$|^uudecode$|^uuencode$|^vagrant$|^varnishncsa$|^view$|^vigr$|^vimdiff$|^vim$|^vipw$|^w3m$|^watch$|^wc$|^wget$|^whiptail$|^xargs$|^xdotool$|^xelatex$|^xetex$|^xmodmap$|^xmore$|^xxd$|^xz$|^yash$|^zip$|^zsh$|^zsoelim$")
        FILEPATH=$(echo "$line" | grep -oE "[^ ]*$")
        SPACES=$((100 - ${#FILEPATH}))
        if [ -z "$SUIDFILE" ]
        then
            printf "\e[91m$FILEPATH"
            printf "%*s" $SPACES ""
            printf "\xE2\x9D\x8C\e[0m\n"
        else
            printf "\e[48;5;210m\e[4m\e[1m\e[1m\e[92m$FILEPATH"
            printf "%*s" $SPACES ""
            printf "\xE2\x9C\x94\e[0m\n"
        fi
    done <<< "$1"
}

SUIDKernelCalls () {
    printf "\e[34m=============Checking Kernel calls=============\e[0m\n"
    if ! hash strace 2> /dev/null
    then
        STRACENOTFOUND="strace is not found, can't analyse kernel calls"
        SPACES=$((100 - ${#STRACENOTFOUND}))
        printf "\e[91m$STRACENOTFOUND"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    else
        while IFS= read -r line
        do
            SUIDFILE=$(echo "$line" | grep -o '/.*')
            VALID=$(echo "$SUIDFILE" | grep 'newgrp' 2>&1)
            if [ -z "$VALID" ]
            then
                SUIDObjectInjects "$SUIDFILE"
            fi
        done <<< "$1"
    fi
}

Legend

echo
echo

printf "\e[1m=======Scraping Computer for useful data=======\e[0m\n"

printf "\e[1m\e[93m===================User data===================\e[0m\n"

ShadowChecks

PasswdChecks

SSHChecks

SensitiveFilesChecks

echo 
echo
echo 
echo

printf "\e[1m=====Checking Possible Privilege Escalation====\e[0m\n"

printf "\e[1m\e[93m==============Checking SUID Files==============\e[0m\n"


SUIDFILES=$(find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null)
printf "\e[35m$SUIDFILES\e[0m\n"

GTFOBins "$SUIDFILES"

#SUIDKernelCalls "$SUIDFILES"

