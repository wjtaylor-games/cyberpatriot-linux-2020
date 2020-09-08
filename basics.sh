#!/bin/bash

# This does some of the basic stuff.
# See https://s3.amazonaws.com/cpvii/Training+materials/Unit+Eight+-+Ubuntu+Security.pdf for the source of these settings.
# Run this with sudo to apply the settings.


# Disable the guest account
printf "allow-guest=false\n" >> /etc/lightdm/lightdm.conf

# Password history of 5 and length of 8:
sed -i '/pam_unix\.so/s/$/\tremember=5\tminlength=8' /etc/pam.d/common-password
# Passwords must be complicated.
sed -i '/pam_cracklib\.so/s/$/\tucredit=-1\tlcredit=-1\tdcredit=-1\tocredit=-1' /etc/pam.d/common-password

# Set password durations.
sed -i '/^PASS_MAX_DAYS\s*[0-9]+/s/[0-9]+/90'  # Maximum
sed -i '/^PASS_MIN_DAYS\s*[0-9]+/s/[0-9]+/10'  # Minimum
sed -i '/^PASS_WARN_AGE\s*[0-9]+/s/[0-9]+/7'  # Days before expiration to warn user.

# account lockout policies.
# this sets the number of failed login attempts to 5
# and the lockout duration to 1800 seconds (30 minutes).
printf "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800\n" >> /etc/pam.d/common-auth

# setup audits
apt-get install auditd
auditctl -e 1

# setup firewall
ufw enable
apt install gufw  # a gui option.
