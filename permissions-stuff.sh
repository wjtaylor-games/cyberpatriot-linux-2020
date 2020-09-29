#!/bin/bash
# Change the permissions for a bunch of files:

chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:root /etc/shadow
chmod o-rwx,g-wx /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-
chown root:root /etc/shadow-
chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
chown root:root /etc/gshadow-
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-
Configure permissions on /etc/motd

chown root:root /etc/motd
chmod 644 /etc/motd
permissions on /etc/issue
chown root:root /etc/issue
chmod 644 /etc/issue
permissions on /etc/issue.net
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
