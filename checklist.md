Ubuntu 16 Checklist

Red means important. Blue is for terminal commands. Green text gets
added to files. Purple is for existing text in files.

\* \* To run scripts:

sudo apt install git

git clone
[[https://github.com/wjtaylor-games/cyberpatriot-linux-2020.git]{.ul}](https://github.com/wjtaylor-games/cyberpatriot-linux-2020.git)

cd cyberpatriot-linux-2020

./\<filename\>

To update: git pull

-   FORENSICS QUESTIONS!!!! \<\<\< DO THIS FIRST OR ELSE!!!!

    -   To see members of a group: "members \<group\>"

    -   To see the name of the host: "hostname"

    -   To see long listing of all files in current directory: ls -la

    -   To see user's UID: id -u username

    -   To see user's GID: id -g username

    -   

-   UPDATES!!!!

    -   Open the update manager

    -   Click Settings

        -   Go to the Updates Tab

        -   Set automatically check for updates to "Daily"

        -   Apply the changes

        -   Install available updates

-   Install antivirus

    -   sudo apt-get install clamav-daemon

-   Delete unauthorized users

-   Add any users mentioned in the ReadMe

-   Check and change admins and standard accounts to match the ReadMe

    -   Check for files for users that should not be administrators in
        > /etc/sudoers.d

        -   ls -a /etc/sudoers.d

-   Add/check account groups if necessary

    -   List groups: cat /etc/group

    -   Add groups: addgroup \[groupname\]

    -   Add a user to a group: adduser \[username\] \[groupname\]

-   Disable guest account **\[scripted\]**

    -   sudo gedit /etc/lightdm/lightdm.conf

    -   Add line: allow-guest=false to the end of the file

    -   Restart the VM

-   Disable root login if in the ReadMe

    -   sudo usermod -L root

    -   sudo gedit /etc/passwd

        -   On the line containing "root," change /bin/bash to
            > /sbin/nologin

-   Set up firewall

    -   Install GUFW (may already be installed) **\[scripted\]**

        -   sudo apt-get install gufw

    -   Turn it on **\[scripted\]**

    -   Incoming: Deny

    -   Outgoing: Allow

    -   Enable logging on full

-   Delete non-work related files

    -   Pictures

    -   Videos

    -   Music

    -   Games

    -   "Hacking tools"

        -   Password crackers

        -   Wireshark \--purge

        -   Nmap/Zenmap

        -   Finger

        -   Mail

    -   Browsers other than those mentioned in ReadMe

-   Go to settings, Set check for updates to "daily"

-   Cracklib **\[scripted\]**

    -   sudo apt-get install libpam-cracklib

    -   sudo gedit /etc/pam.d/common-password

    -   Add remember=5 to the end of the line containing pam_unix.so

    -   Add minlen=14 to the end of the line containing pam_unix.so

    -   Add ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 to the end of
        > line containing pam_cracklib.so

    -   Add sha512 to the end of the line containing pam_unix.so

-   Password history **\[scripted\]**

    -   sudo gedit /etc/login.defs **\[scripted\]**

    -   Search in the file (Ctrl+F): PASS_MAX **\[scripted\]**

        -   PASS_MAX_AGE **\[scripted\]**

            -   PASS_MAX_DAYS 90 **\[scripted\]**

            -   PASS_MIN_DAYS 10 **\[scripted\]**

            -   PASS_WARN_AGE 7 **\[scripted\]**

    -   useradd -D -f 30 **\[scripted\]**

-   Ensure system accounts are non-login

    -   Use Script Non-login.sh

-   Set GID 0 as default group for root account

    -   usermod -g 0 root

-   Set default user umask as 027

    -   sudo gedit /etc/bash.bashrc

    -   sudo gedit /etc/profile

    -   sudo gedit /etc/profile.d/\*.sh

        -   umask 027

-   Set default user shell timeout to 900 seconds or less

    -   sudo gedit /etc/bashrc

    -   sudo gedit /etc/profile

        -   TMOUT=600

-   Account policy **\[scripted\]**

    -   gedit /etc/pam.d/common-auth **\[scripted\]**

    -   Add this line to the end of the file **\[scripted\]**

        -   auth required pam_tally2.so deny=5 onerr=fail
            > unlock_time=1800 **\[scripted\]**

-   Cookie protection

    -   gedit /etc/sysctl.conf or gedit /etc/sysctl.d/\*

        -   net.ipv4.tcp_syncookies = 1

        -   sysctl -w net.ipv4.conf.all.tcp_syncookies = 1

        -   sysctl -w net.ipv4.route.flush = 1

-   Browser Settings

    -   Set Firefox as default if in the ReadMe

    -   Go to updates section and select "automatically install updates"

    -   Under "privacy and security" tab, set content blocking to
        > "strict"

    -   Select "always" for "do not track"

    -   Scroll down to the "Permissions" section. Ensure the following
        > are checked:

        -   "Block websites from automatically playing sound."

        -   "Block pop-up windows."

        -   "Warn you when websites try to install add-ons."

        -   "Prevent accessibility services from accessing your
            > browser."

        -   Plug-ins under "Add-ons"

-   Disable any services mentioned in ReadMe

    -   apt-get install bum

    -   bum

    -   Click on service to be disabled and select "deactivate service
        > and apply now"

    -   Disable Bluetooth

    -   Disable Cups

-   Ensure that files have correct permissions

    -   ls -l

        -   Passwd file should be "read only" to users

        -   Users should not have access to shadow file

    -   To change:

        -   Chmod \[u, g, or o\](user, group, or, others)\[+ or -\](add
            > or subtract permissions)\[r, w, or x\](read, write, or
            > execute)

-   Disable unused filesystems

    -   sudo gedit /etc/modprobe.d/CIS.conf

    -   Add install \<filesystem_name\> /bin/true

    -   rmmod \<filesystem_name\>

    ```{=html}
    <!-- -->
    ```
    -   Filesystems to disable:

        -   Cramfs

        -   Freevxfs

        -   Jffs2

        -   Hfs

        -   Hfsplus

        -   Udf

-   Separate partition for /tmp

    -   Audit:

        -   mount \| grep /tmp tmpfs on /tmp type tmpfs

            -   Output should be:

                -   (rw,nosuid,nodev,noexec,realtime)

    -   Remediation:

        -   Create partition and gedit /etc/fstab

            -   Add to 4th field (mounting options):

                -   nodev

                -   nosuid

        -   mount -o remount,nodev /tmp

        -   mount -o remount,nosuid /tmp

-   Separate partition for /var

    -   Audit:

        -   mount \| grep /var /dev/evdg1 on /var type ext4

            -   Output should be:

                -   (rw,relatime,data=ordered)

    -   Remediation:

        -   Create partition and gedit /etc/fstab

-   Separate partition for /var/tmp

    -   Audit:

        -   mount \| grep /var/tmp \<device\> on /var/tmp type ext4

            -   Output should be:

                -   (rw,nosuid,nodev,noexec,relatime)

    -   Remediation:

        -   Create partition and gedit /etc/fstab

            -   Add to 4th field (mounting options):

                -   nodev

                -   nosuid

                -   noexec

        -   mount -o remount,nodev /var/tmp

        -   mount -o remount,nosuid /var/tmp

        -   mount -o remount,noexec /var/tmp

-   Separate partition for /var/log

    -   Audit:

        -   mount \| grep /var/log /dev/xvdh1 on /var/log type ext4

            -   Output should be:

                -   (rw,relatime,data=ordered

    -   Remediation:

        -   Create partition and gedit /etc/fstab

-   Separate partition for /var/log/audit

    -   Audit:

        -   mount \| grep /var/log/audit /dev/xvdi1 on /var/log/audit
            > type ext4

            -   Output should be:

                -   (rw,relatime,data=ordered)

    -   Remediation:

        -   Create partition and gedit /etc/fstab

-   Separate partition for /home

    -   Audit:

        -   mount \| grep /home /dev/xvdf1 on /home type ext4

            -   Output should be:

                -   (rw,nodev,relatime,data=ordered)

    -   Remediation:

        -   Create partition and gedit /etc/fstab

            -   Add to 4th field (mounting options):

                -   nodev

        -   mount -o remount,nodev /home

-   Ensure nodev, nosuid, and noexec option set on /dev/shm partition

    -   gedit /etc/fstab

        -   Add to 4th field (mounting options):

            -   nodev

            -   nosuid

            -   noexec

    -   mount -o remount,nodev /dev/shm

    -   mount -o remount,nosuid /dev/shm

    -   mount -o remount,noexec /dev/shm

-   Ensure nodev, nosuid, and noexec option set on removable media
    > partitions

    -   gedit /etc/fstab

        -   Add to 4th field (mounting options). Look for entries with
            > mount points that have floppy or cdrom :

            -   nodev

            -   nosuid

            -   noexec

-   Set sticky bit on all world-writable directories

    -   df \--local -P \| awk {'if (NR!=1) print \$6'} \| xargs -I '{}'
        > -xdev -type d -perm -0002 2\>/dev/null \| xargs chmod a+t

-   Disable Automounting

    -   systemctl disable autofs

-   Install AIDE

    -   apt-get install aide aide-common

    -   aideinit

-   Regularly check filesystem integrity

    -   Audit:

        -   crontab -u root -1 \| grep aide

        -   grep -r aide /etc/cron.\* /etc/crontab

    -   Remediation:

        -   crontab -u root -e

        -   Add 0 5 \* \* \* /usr/bin/aide \--config /etc/aide/aide.conf
            > \--check

-   Configure bootloader permissions

    -   chown root:root /boot/grub/grub.cfg

    -   chmod og-rwx /boot/grub/grub.cfg

-   Set bootloader password

    -   grub-mkpasswd-pbkdf2

        -   Enter password: Boot1234!)@(\#\*\$&

        -   Re-enter password: Boot1234!)@(\#\*\$&

        -   Your PBKDF2 is \<encrypted-password\>

    -   sudo gedit /etc/grub.d/00_header

        -   Add:

            -   cat \<\<EOF

            -   set superusers="\<username\>"

            -   password pbkdf2 \<username\> \<encrypted-password\>

            -   EOF

    -   update-grub

-   Restrict core dumps

    -   sudo gedit/etc/security/limits.conf

    -   Add \* hard core 0

    -   sudo gedit /etc/sysctl.conf

        -   Set fs.suid_dumpable = 0

    -   sysctl -w fs.suid_dumpable=0

-   Enable ASLR (Address Space Layout Randomization)

    -   sudo gedit /etc/sysctl.conf

        -   kernel.randomize_va_space = 2

        ```{=html}
        <!-- -->
        ```
        -   sysctl -w kernel.randomize_va_space = 2

-   Disable prelink

    -   prelink -ua

    -   apt-get remove prelink

-   Enable SELinux

    -   sudo gedit /etc/default/grub

    -   Remove all instance of selinux=0 and enforcing=0 from
        > GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\" and
        > GRUB_CMDLINE_LINUX=\"\"

    -   update-grub

-   Configure SELinux

    -   gedit /etc/selinux/config

    -   Add SELINUX=enforcing

    -   Add SELINUXTYPE=ubuntu

-   Ensure no unconfined daemons exist

    -   Audit: ps -eZ \| egrep \"initrc\" \| egrep -vw
        > \"tr\|ps\|egrep\|bash\|awk\" \| tr \':\' \' \' \| awk \'{
        > print \$NF }\'

        -   Should be no output

    -   Remediation: Investigate any unconfined daemons found

-   Install SELinux

    -   apt-get install selinux

-   Configure message of the day

    -   sudo gedit /etc/motd

        -   Remove \\m, \\r, \\s, \\v

-   Configure local login warning banner

    -   sudo gedit /etc/issue

        -   Remove \\m, \\r, \\s, \\v

        -   Add echo \"Authorized uses only. All activity may be
            > monitored and reported.\" \> /etc/issue

-   Configure remote login warning banner

    -   sudo gedit /etc/issue.net

        -   Remove \\m, \\r, \\s, \\v

        -   Add echo \"Authorized uses only. All activity may be
            > monitored and reported.\" \> /etc/issue.net

-   Configure permissions on /etc/motd

    -   chown root:root /etc/motd

    -   chmod 644 /etc/motd

-   Configure permissions on /etc/issue

    -   chown root:root /etc/issue

    -   chmod 644 /etc/issue

-   Configure permissions on /etc/issue.net

    -   chown root:root /etc/issue.net

    -   chmod 644 /etc/issue.net

-   Services

    -   gedit /etc/inetd.conf

        -   Remove any lines starting with chargen, daytime, discard,
            > echo, time, shell, login, exec, talk, ntalk, telnet, or
            > tftp

    -   gedit /etc/inetd.d/\*

        -   Remove any lines starting with chargen, daytime, discard,
            > echo, time, shell, login, exec, talk, ntalk, telnet, or
            > tftp

    -   gedit /etc/xinetd.conf

        -   For all chargen, daytime, discard, echo, time, shell, login,
            > exec, talk, ntalk, telnet, or tftp services, set disable =
            > yes

    -   gedit /etc/xinetd.d/\*

        -   For all chargen, daytime, discard, echo, time, shell, login,
            > exec, talk, ntalk, telnet, or tftp services, set disable =
            > yes

-   Disable Xinetd

    -   systemctl disable xinetd

-   Uninstall openbsd-inetd

    -   apt-get remove openbsd-inetd

-   Install NTP

    -   apt-get install ntp

-   Configure ntp

    -   gedit /etc/ntp.conf

        -   restrict -4 default kod nomodify notrap nopeer noquery

        -   restrict -6 default kod nomodify notrap nopeer noquery

    -   gedit /etc/init.d/ntp

        -   RUNASUSER=ntp

-   Uninstall X Window System

    -   apt-get remove xserver-xorg\*

-   Disable Avahi Server

    -   systemctl disable avahi-daemon

-   Disable CUPS

    -   systemctl disable cups

-   Disable DHCP Server :

    -   systemctl disable isc-dhcp-server

    -   systemctl disable isc-dhcp-server6

-   Disable LDAP Server

    -   systemctl disable slapd

-   Disable NFS and RPC

    -   systemctl disable nfs-server

    -   systemctl disable rpcbind

-   Disable DNS Server

    -   systemctl disable bind9

-   Disable FTP Server

    -   systemctl disable vsftpd

-   Disable HTTP Server

    -   systemctl disable apache2

-   Disable IMAP and POP3 Servers:

    -   systemctl disable dovecot

-   Disable Samba

    -   systemctl disable smbd

-   Disable HTTP Proxy Server

    -   systemctl disable squid

-   Disable SNMP Server

    -   systemctl disable snmpd

-   Configure mail transfer agent for local-only mode

    -   gedit /etc/postfix/main.cf

        -   Add to the RECEIVING MAIL section:

            -   inet_interfaces = loopback-only

    -   systemctl restart postfix

-   Disable rsync

    -   systemctl disable rsync

-   Disable NIS Server

    -   systemctl disable nis

-   Uninstall NIS client

    -   apt-get remove nis

-   Uninstall RSH client

    -   apt-get remove rsh-client rsh-redone-client

-   Uninstall talk client

    -   apt-get remove talk

-   Uninstall telnet client

    -   apt-get remove telnet

-   Uninstall LDAP client

    -   apt-get remove ldap-utils

-   Disable IP forwarding

    -   gedit /etc/sysctl.conf

        -   net.ipv4.ip_forward = 0

        ```{=html}
        <!-- -->
        ```
        -   gedit /etc/sysctl.d/\*

            -   net.ipv4.ip_forward = 0

        -   sysctl -w net.ipv4.ip_forward=0

        -   sysctl -w net.ipv4.route.flush=1

-   Disable packet redirect sending

    -   gedit /etc/sysctl.conf

        -   net.ipv4.conf.all.send_redirects = 0

        -   net.ipv4.conf.default.send_redirects = 0

    -   sysctl -w net.ipv4.conf.all.send_redirects=0

    -   sysctl -w net.ipv4.conf.default.send_redirects=0

    -   sysctl -w net.ipv4.route.flush=1

-   Deny source routed packets

    -   gedit /etc/sysctl.conf

        -   net.ipv4.conf.all.accept_source_route = 0

        -   net.ipv4.conf.default.accept_source_route = 0

    -   sysctl -w net.ipv4.conf.all.accept_source_route=0

    -   sysctl -w net.ipv4.conf.default.accept_source_route=0

    -   sysctl -w net.ipv4.route.flush=1

-   Deny ICMP redirects

    -   gedit /etc/sysctl.conf

        -   net.ipv4.conf.all.accept_redirects = 0

        -   net.ipv4.conf.default.accept_redirects = 0

    -   sysctl -w net.ipv4.conf.all.accept_redirects=0

    -   sysctl -w net.ipv4.conf.default.accept_redirects=0

    -   sysctl -w net.ipv4.route.flush=1

-   Deny secure ICMP redirects

    -   gedit /etc/sysctl.conf

        -   net.ipv4.conf.all.secure_redirects = 0

        -   net.ipv4.conf.default.secure_redirects = 0

    -   sysctl -w net.ipv4.conf.all.secure_redirects=0

    -   sysctl -w net.ipv4.conf.default.secure_redirects=0

    -   sysctl -w net.ipv4.route.flush=1

-   Log suspicious packets

    -   gedit /etc/sysctl.conf

        -   net.ipv4.conf.all.log_martians = 1

        -   net.ipv4.conf.default.log_martians = 1

    -   sysctl -w net.ipv4.conf.all.log_martians=1

    -   sysctl -w net.ipv4.conf.default.log_martians=1

    -   sysctl -w net.ipv4.route.flush=1

-   Ignore broadcast ICMP requests

    -   gedit /etc/sysctl.conf

        -   net.ipv4.icmp_echo_ignore_broadcasts = 1

    -   sysctl -w net.ipv4.conf.all.icmp_echo_ignore_broadcasts=1

    -   sysctl -w net.ipv4.route.flush=1

-   Ignore bogus ICMP responses

    -   gedit /etc/sysctl.conf

        -   net.ipv4.icmp_ignore_bogus_error_responses = 1

    -   sysctl -w net.ipv4.conf.all.icmp_ignore_bogus_error_responses=1

    -   sysctl -w net.ipv4.route.flush=1

-   Enable Reverse Path Filtering

    -   gedit /etc/sysctl.conf

        -   net.ipv4.conf.all.rp_filter = 1

        -   net.ipv4.conf.default.rp_filter = 1

    -   sysctl -w net.ipv4.conf.all.rp_filter=1

    -   sysctl -w net.ipv4.conf.default.rp_filter=1

    -   sysctl -w net.ipv4.route.flush=1

-   Deny IPv6 router ads and redirects

    -   gedit /etc/sysctl.conf

        -   net.ipv6.conf.all.accept_ra = 0

        -   net.ipv6.conf.default.accept_ra = 0

        -   net.ipv6.conf.all.accept_redirects = 0

        -   net.ipv6.conf.default.accept_redirects = 0

        ```{=html}
        <!-- -->
        ```
        -   sysctl -w net.ipv6.conf.all.accept_ra=0

        -   sysctl -w net.ipv6.conf.default.rpaccept_ra_filter=0

        -   sysctl -w net.ipv6.route.flush=1

        -   sysctl -w net.ipv6.conf.all.accept_redirects=0

        -   sysctl -w net.ipv6.conf.default.accept_redirects=0

        -   sysctl -w net.ipv6.route.flush=1

-   Disable IPv6

    -   Sudo gedit /etc/default/grub

        -   GRUB_CMDLINE_LINUX=ipv6.disable=1

    -   update-grub

-   Install TCP Wrappers

    -   apt-get install tcpd

-   Configure /etc/hosts.allow

    -   Audit:

        -   cat /etc/hosts.allow

    -   Remediation:

        -   echo "ALL: \<net\>/\<mask\>, \<net\>/\<mask\>,
            > ..." \>/etc/hosts.allow

-   Configure /etc/hosts.deny

    -   Audit:

        -   cat /etc/hosts.deny

            -   Output should be:

                -   ALL: ALL

    -   Remediation:

        -   echo "All: ALL" \>\> /etc/hosts.deny

-   Configure permissions on /etc/hosts.allow

    -   chown root:root /etc/hosts.allow

    -   chmod 644 /etc/hosts.allow

-   Configure permissions on /etc/hosts.deny

    -   chown root:root /etc/hosts.deny

    -   chmod 644 /etc/hosts.deny

-   Disable DCCP, SCTP, RDS, TIPC

    -   sudo gedit /etc/modprobe.d/CIS.conf

        -   Add install dccp /bin/true

        -   Add install sctp /bin/true

        -   Add install rds /bin/true

        -   Add install tipc /bin/true

-   Install Iptables

    -   apt-get install iptables

-   Configure Firewall

    -   Run script 3_6.sh

-   Ensure firewall rules exist for all open ports

    -   Audit:

        -   netstat -ln (determines open ports)

        -   iptables -L INPUT -v -n (determines firewall rules)

            -   Any open port listening on non-localhost address should
                > have at least one firewall rule

    -   Remediation:

        -   iptables -A INPUT -p \--dport -m state \--state NEW -j
            > ACCEPT

-   Disable wireless interfaces

    -   Audit:

        -   iwconfig

        -   ip link show up

    -   Remediation:

        -   ip link set \<interface\> down for any interfaces returned

-   Install and Enable auditd service

    -   apt-get install auditd

    -   update -rc.d auditd enable

-   Disable system when audit logs are full and ensure audit logs are
    > not automatically deleted

    -   gedit /etc/audit/auditd.conf

        -   space_left_action = email

        -   action_mail_acct = root

        -   admin_space_left_action = halt

        -   max_log_file_action = keep_logs

-   Enable auditing for processes before auditd

    -   gedit /etc/default/grub

        -   GRUB_CMDLINE_LINUX="audit=1"

    -   update-grub

-   Collect time/date, user/group, network environment, MAC,
    > login/logout, initiation information, and discretionary access
    > control permission modification events; Collect unauthorized file
    > access attempts, successful system mounts, file deletions, changes
    > to sudoers, sudologs, and kernel module loading/unloading; Ensure
    > audit configuration is immutable

    -   sudo gedit /etc/audit/audit.rules

        -   Use Configure_logs.txt

    -   service auditd reload

-   Enable rsyslog service

    -   systemctl enable rsyslog

-   Configure rsyslog default file permissions

    -   gedit /etc/rsyslog.conf

        -   \$FileCreateMode 0640

    -   gedit /etc/rsyslog.d/\*.conf

        -   \$FileCreateMode 0640

-   Install rsyslog

    -   apt-get install rsyslog

-   Configure permissions for all log files

    -   chmod -R g-wx,o-rwx /var/log/\*

-   Enable cron

    -   systemctl enable cron

-   Configure permissions for /etc/crontab

    -   chown root:root /etc/crontab

    -   chmod og-rwx /etc/crontab

-   Configure permissions for /etc/cron.hourly

    -   chown root:root /etc/cron.hourly

    -   chmod og-rwx /etc/cron.hourly

-   Configure permissions for /etc/cron.daily

    -   chown root:root /etc/cron.daily

    -   chmod og-rwx /etc/cron.daily

-   Configure permissions for /etc/cron.weekly

    -   chown root:root /etc/cron.weekly

    -   chmod og-rwx /etc/cron.weekly

-   Configure permissions for /etc/cron.monthly

    -   chown root:root /etc/cron.monthly

    -   chmod og-rwx /etc/cron.monthly

-   Configure permissions for /etc/cron.d

    -   chown root:root /etc/cron.d

    -   chmod og-rwx /etc/cron.d

-   Restrict at/cron to authorized users

    -   rm /etc/cron.deny

    -   rm /etc/at.deny

    -   touch /etc/cron.allow

    -   touch /etc/at.allow

    -   chmod /etc/cron.allow

    -   chmod /etc/at.allow

    -   chown /etc/cron.allow

    -   chown /etc/at.allow

-   If not mentioned in ReadMe as needed, remove SSH Server and skip
    > section\*\*\*

    -   apt-get install ssh

    -   apt-get purge openssh-server -y -qq

    -   Configure permissions on /etc/ssh/sshd_config

        -   chown root:root /etc/ssh/sshd config

        -   chmod og-rwx /etc/ssh/sshd_config

    -   Configure SSH

        -   sudo gedit /etc/ssh/sshd_config

            -   Use Configure_SSH.txt

        -   systemctl reload sshd \*\*\*

-   Configure permissions for /etc/passwd

    -   chown root:root /etc/passwd

    -   chmod 644 /etc/passwd

-   Configure permissions for /etc/shadow

    -   chown root:root /etc/shadow

    -   chmod o-rwx,g-wx /etc/shadow

-   Configure permissions for /etc/group

    -   chown root:root /etc/group

    -   chmod 644 /etc/group

-   Configure permissions for /etc/gshadow

    -   chown root:shadow /etc/gshadow

    -   chmod o-rwx,g-rw /etc/gshadow

-   Configure permissions for /etc/passwd-

    -   chown root:root /etc/passwd-

    -   chmod u-x,go-wx /etc/passwd-

-   Configure permissions for /etc/shadow-

    -   chown root:root /etc/shadow-

    -   Chown root:shadow /etc/shadow-

    -   chmod o-rwx,g-rw /etc/shadow-

-   Configure permissions for /etc/group-

    -   chown root:root /etc/group-

    -   chmod u-x,go-wx /etc/group-

-   Configure permissions for /etc/gshadow-

    -   chown root:root /etc/gshadow-

    -   chown root:shadow /etc/gshadow-

    -   chmod o-rwx,g-rw /etc/gshadow-

-   Ensure no world writable files exist

    -   Audit:

        -   df \--local -P \| awk {\'if (NR!=1) print \$6\'} \| xargs -I
            > \'{}\' find \'{}\' -xdev -type f -perm -0002

            -   No files should be returned

    -   Remediation:

        -   chmod o-w \<filename\> for name of file returned

-   Ensure no unowned files/directories exist

    -   Audit:

        -   df \--local -P \| awk {\'if (NR!=1) print \$6\'} \| xargs -I
            > \'{}\' find \'{}\' -xdev -nouser

            -   No files should be returned

    -   Remediation:

        -   Chown \<user\> \<filename\> for name of user and file
            > returned

-   Ensure no ungrouped files or directories exist

    -   Audit:

        -   df \--local -P \| awk {\'if (NR!=1) print \$6\'} \| xargs -I
            > \'{}\' find \'{}\' -xdev -nogroup

    -   Remediation:

        -   Chown \<user\> \<filename\> for name of user and file
            > returned

-   Ensure no legacy "+" entries exist in /etc/passwd, /etc/shadow, or
    > /etc/group

    -   Audit:

        -   grep \'\^\\+:\' /etc/passwd

        -   grep \'\^\\+:\' /etc/shadow

        -   grep \'\^\\+:\' /etc/group

            -   No output should be returned

    -   Remediation:

        -   Remove any legacy "+" entries from /etc/passwd, /etc/shadow,
            > or /etc/group

-   Ensure root is only UID 0 account

    -   Audit:

        -   cat /etc/passwd \| awk -F: \'(\$3 == 0) { print \$1 }\' root

            -   Only "root" should be returned

    -   Remediation: Remove any users other than root with UID 0

-   Ensure all users' home directories exist

    -   Audit: Run script Users_HD_exist.sh

    -   Remediation:

        -   Create home directories for results returned and make user
            > owner

-   Ensure users own their home directories

    -   Audit: Run script Users_own_HD.sh

    -   Remediation:

        -   chown user filename for results returned

-   Ensure shadow group is empty

    -   Audit:

        -   grep \^shadow:\[\^:\]\*:\[\^:\]\*:\[\^:\]+ /etc/group

        -   awk -F: '(\$4 == "\<shadow-gid\>") { print }' /etc/passwd

    -   Remediation:

        -   Remove all users from the shadow group

-   Disable reboot with Ctrl-Alt-Del

    -   systemctl mask ctrl-alt-del.target

    -   systemctl daemon-reload

-   Backdoors

    -   Check for backdoors

        -   Ensure **login, telnetd, ftpd,** and **rshd** have not been
            > altered

        -   Check the **.rhosts** file for each user or superuser

        -   Ensure the **/etc/fstab** file has not been tampered with to
            > disable the **nosuid** designator

        -   Ensure the mail system has no aliases

        -   Ensure the owner of the **/etc** directory has not been
            > changed

        -   Ensure the **/dev/kmem** permissions do not allow non-root
            > users to modify them

        -   Remove non-essential shells

        -   Ensure the network service settings have not been changed

-   Superusers

    -   Ensure no user is **su**

    -   Check the **/bin/login** file and the **su** system to ensure
        > they have not been modified to record password keystrokes

    -   Ensure all filesystems that should be read-only have not been
        > remounted as read/write
