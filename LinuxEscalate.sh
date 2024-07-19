#!/bin/bash


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


printf "\e[1m\e[93m==============Checking SUID Files==============\e[0m\n"

printf "\e[3m\e[34m===================SUID Files==================\e[0m\n"

SUIDFILES=$(find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null)
printf "\e[35m$SUIDFILES\e[35m\n"

printf "\e[34m===========Checking Files On GTFOBins==========\e[0m\n"

while IFS= read -r line
do
    SUIDFILE=$(echo "$line" | grep -oE "[^/]*$" | grep -E "^7z$|^aa-exec$|^ab$|^agetty$|^alpine$|^ansible-playbook$|^ansible-test$|^aoss$|^apache2ctl$|^apt-get$|^apt$|^aria2c$|^arj$|^ar$|^arp$|^ascii85$|^ascii-xfr$|^ash$|^as$|^aspell$|^at$|^atobm$|^awk$|^aws$|^base32$|^base58$|^base64$|^basenc$|^basez$|^bash$|^batcat$|^bc$|^bconsole$|^bpftrace$|^bridge$|^bundle$|^bundler$|^busctl$|^busybox$|^byebug$|^bzip2$|^c89$|^c99$|^cabal$|^cancel$|^capsh$|^cat$|^cdist$|^certbot$|^check_by_ssh$|^check_cups$|^check_log$|^check_memory$|^check_raid$|^check_ssl_cert$|^check_statusfile$|^chmod$|^choom$|^chown$|^chroot$|^clamscan$|^cmp$|^cobc$|^column$|^comm$|^composer$|^cowsay$|^cowthink$|^cpan$|^cpio$|^cp$|^cpulimit$|^crash$|^crontab$|^csh$|^csplit$|^csvtool$|^cupsfilter$|^curl$|^cut$|^dash$|^date$|^dc$|^dd$|^debugfs$|^dialog$|^diff$|^dig$|^distcc$|^dmesg$|^dmidecode$|^dmsetup$|^dnf$|^docker$|^dos2unix$|^dosbox$|^dotnet$|^dpkg$|^dstat$|^dvips$|^easy_install$|^eb$|^ed$|^efax$|^elvish$|^emacs$|^enscript$|^env$|^eqn$|^espeak$|^exiftool$|^ex$|^expand$|^expect$|^facter$|^file$|^find$|^finger$|^fish$|^flock$|^fmt$|^fold$|^fping$|^ftp$|^gawk$|^gcc$|^gcloud$|^gcore$|^gdb$|^gem$|^genie$|^genisoimage$|^ghci$|^ghc$|^gimp$|^ginsh$|^git$|^grc$|^grep$|^gtester$|^gzip$|^hd$|^head$|^hexdump$|^highlight$|^hping3$|^iconv$|^iftop$|^install$|^ionice$|^ip$|^irb$|^ispell$|^jjs$|^joe$|^join$|^journalctl$|^jq$|^jrunscript$|^jtag$|^julia$|^knife$|^ksh$|^ksshell$|^ksu$|^kubectl$|^latex$|^latexmk$|^ldconfig$|^ld.so$|^less$|^lftp$|^links$|^ln$|^loginctl$|^logsave$|^look$|^lp$|^ltrace$|^lualatex$|^lua$|^luatex$|^lwp-download$|^lwp-request$|^mail$|^make$|^man$|^mawk$|^minicom$|^more$|^mosquitto$|^mount$|^msfconsole$|^msgattrib$|^msgcat$|^msgconv$|^msgfilter$|^msgmerge$|^msguniq$|^mtr$|^multitime$|^mv$|^mysql$|^nano$|^nasm$|^nawk$|^ncdu$|^ncftp$|^nc$|^neofetch$|^nft$|^nice$|^nl$|^nmap$|^nm$|^node$|^nohup$|^npm$|^nroff$|^nsenter$|^ntpdate$|^octave$|^od$|^openssl$|^openvpn$|^openvt$|^opkg$|^pandoc$|^paste$|^pax$|^pdb$|^pdflatex$|^pdftex$|^perf$|^perlbug$|^perl$|^pexec$|^pg$|^php$|^pic$|^pico$|^pidstat$|^pip$|^pkexec$|^pkg$|^posh$|^pr$|^pry$|^psftp$|^psql$|^ptx$|^puppet$|^pwsh$|^python$|^rake$|^rc$|^readelf$|^redcarpet$|^redis$|^red$|^restic$|^rev$|^rlogin$|^rlwrap$|^rpmdb$|^rpm$|^rpmquery$|^rpmverify$|^rsync$|^rtorrent$|^ruby$|^run-mailcap$|^run-parts$|^runscript$|^rview$|^rvim$|^sash$|^scanmem$|^scp$|^screen$|^script$|^scrot$|^sed$|^service$|^setarch$|^setfacl$|^setlock$|^sftp$|^sg$|^shuf$|^slsh$|^smbclient$|^snap$|^socat$|^socket$|^soelim$|^softlimit$|^sort$|^split$|^sqlite3$|^sqlmap$|^ssh-agent$|^ssh-keygen$|^ssh-keyscan$|^ssh$|^sshpass$|^ss$|^start-stop-daemon$|^stdbuf$|^strace$|^strings$|^sudo$|^su$|^sysctl$|^systemctl$|^systemd-resolve$|^tac$|^tail$|^tar$|^task$|^taskset$|^tasksh$|^tbl$|^tclsh$|^tcpdump$|^tdbtool$|^tee$|^telnet$|^terraform$|^tex$|^tftp$|^tic$|^timedatectl$|^time$|^timeout$|^tmate$|^tmux$|^top$|^torify$|^torsocks$|^troff$|^tshark$|^ul$|^unexpand$|^uniq$|^unshare$|^unsquashfs$|^unzip$|^update-alternatives$|^uudecode$|^uuencode$|^vagrant$|^valgrind$|^varnishncsa$|^view$|^vigr$|^vi$|^vimdiff$|^vim$|^vipw$|^virsh$|^volatility$|^w3m$|^wall$|^watch$|^wc$|^wget$|^whiptail$|^whois$|^wireshark$|^wish$|^xargs$|^xdg-user-dir$|^xdotool$|^xelatex$|^xetex$|^xmodmap$|^xmore$|^xpad$|^xxd$|^xz$|^yarn$|^yash$|^yelp$|^yum$|^zathura$|^zip$|^zsh$|^zsoelim$|^zypper$")
    FILEPATH=$(echo "$line" | grep -oE "[^ ]*$")
    SPACES=$((100 - ${#FILEPATH}))
    if [ -z "$SUIDFILE" ]
    then
        printf "\e[91m$FILEPATH"
        printf "%*s" $SPACES ""
        printf "\xE2\x9D\x8C\e[0m\n"
    else
        printf "\e[1m\e[92m$FILEPATH"
        printf "%*s" $SPACES ""
        printf "\xE2\x9C\x94\e[0m\n"
    fi
done <<< "$SUIDFILES"

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
    done <<< "$SUIDFILES"
fi

