#!/bin/bash

# Uninstall openbsd-inetd
apt-get remove openbsd-inetd

# Uninstall X Window System
apt-get remove xserver-xorg\*

# remove clients:
apt-get remove nis
apt-get remove rsh-client rsh-redone-client
apt-get remove talk
apt-get remove telnet
apt-get remove ldap-utils

# Disable prelink
prelink -ua
apt-get remove prelink
