#-----------------------------------------------------------------------------------------#
# FILE:    CIS_RHEL7_8_9_Benchmark_v2_2_10_Remediation.sh (BASH)                          #
#                                                                                         #
# PURPOSE: Script for remediation of RHEL 7/8 baseline SCA configurations                 #
#                                                                                         #
# AUTHOR:  Zscaler Cloud Security Posture Management ZCSPM                                #
#          Rasika Kariyawasam RK                                                          #
#                                                                                         #
# CREATED: 06-AUG-2021 ZCSPM                                                              #
#                                                                                         #
# THREAD:  1.0 06-AUG-2021 ZCSPM Baselined           ZCSPM                                #
#          1.1 03-OCT-2022 Validating and Changing   RK                                   #
#          1.2 28-OCT-2022 Updated                   RK                                   #  
#          1.3 18-MAY-2023 Updated                   RK                                   #
#          1.4 07-Jun-2023 Added /tmp mounting       RK                                   #
#          1.5 11-JAN-2024 Change SSH configuration  RK                                   #
#          1.6 24-Mar-2024 Change the NTP server and rearrangement RK                     #
#                                                                                         #
# OS    :  RHEL7,8/CentOS7,8/Amazon Linux 2                                               #
#                                                                                         #
# NB    :  Procution Ready.When you are going to apply on production check with the server#
#          and get an idea about which applications are running on those servers.         #
#          E.g. 1. httpd service will be uninstalled by this scripts that can be affect to#
#                  their application                                                      #
#               2. Core dumps will be restricted by this scripts. A core dump is taken    #
#                  mainly for the purpose of debugging a program.                         #
#               3. Check whether there are NFS mount points on the servers.If there are   #
#                  nfs mounts then those will be not fuctioning after remeving NFS and    #
#                  rpcbind if they are using NFS v4 then rpcbind is not required.         #
#               4. After removing xorg-x11, XRDP and X11 Forwarding will not be worked.   #
#                  If the user is using GUI/graphical.target, then that will be changed   #
#                  to a multi-user target.                                                #
#-----------------------------------------------------------------------------------------#

#!/bin/bash
: '
#SYNOPSIS
    Quick win script for remediation of RHEL 7 baseline misconfigurations.
.DESCRIPTION
    This script aims to remediate all possible OS baseline misconfigurations for RHEL 7 based Virtual machines.
 
.NOTES
 
    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
    Version: 1.0
    # PREREQUISITE
 
.EXAMPLE
    Command to execute : bash CIS_RHEL7_Benchmark_v2_2_0_Remediation.sh
.INPUTS
 
.OUTPUTS
    None
'

TIMESTAMP=$(date +"%d-%b-%Y-%H%M-%Z" | tr [a-z] [A-Z])
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'
success=0
fail=0

###########################################################################################################################

##Category 1.1 Initial Setup - Filesystem Configuration
# 9705 Status of the cramfs Filesystems (modprobe) / 9712 Status of the cramfs Filesystems (lsmod)

echo 
echo -e "${BLUE}1.1 Initial Setup - Filesystem Configuration${NC}"
ls /etc/modprobe.d/CIS.conf || touch /etc/modprobe.d/CIS.conf #added by RK

# Ensure mounting of cramfs filesystems is disabled
# Changed by RK

echo
echo -e "${RED}1.1.1.1${NC} Ensure mounting of cramfs filesystems is disabled"
touch /etc/modprobe.d/CIS.conf ; 
rhel_1_1_1_1="$(modprobe -n -v cramfs | grep "^install /bin/true$" || egrep -q "^\s*install\s+cramfs\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_1=$?
rhel_1_1_1_2="$(modprobe -n -v cramfs | grep "^install /bin/false$" || egrep -q "^\s*install\s+cramfs\s+\/bin\/false(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install cramfs /bin/false" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_2=$?

lsmod | egrep "^cramfs\s" && rmmod cramfs
if [[ "$rhel_1_1_1_1" -eq 0 ]] && [[ "$rhel_1_1_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of cramfs filesystems is disabled"
  fail=$((fail + 1))
fi

# Ensure mounting of freevxfs filesystems is disabled
# 9705 Status of the cramfs Filesystems (modprobe) / 9712 Status of the cramfs Filesystems (lsmod)
# Changed by RK
echo
echo -e "${RED}1.1.1.2${NC} Ensure mounting of freevxfs filesystems is disabled"
rhel_1_1_1_2="$(modprobe -n -v freevxfs | grep "^install /bin/true$" || egrep -q "^\s*install\s+freevxfs\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_2=$?
lsmod | egrep "^freevxfs\s" && rmmod freevxfs
if [[ "$rhel_1_1_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of freevxfs filesystems is disabled"
  fail=$((fail + 1))
fi

# Ensure mounting of jffs2 filesystems is disabled
# 9705 Status of the cramfs Filesystems (modprobe) / 9712 Status of the cramfs Filesystems (lsmod)
# Changed by RK
echo
echo -e "${RED}1.1.1.3${NC} Ensure mounting of jffs2 filesystems is disabled"
rhel_1_1_1_3="$(modprobe -n -v jffs2 | grep "^install /bin/true$" || egrep -q "^\s*install\s+jffs2\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_3=$?
lsmod | egrep "^jffs2\s" && rmmod jffs2
if [[ "$rhel_1_1_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of jffs2 filesystems is disabled"
  fail=$((fail + 1))
fi

# Ensure mounting of hfs filesystems is disabled
# 9705 Status of the cramfs Filesystems (modprobe) / 9712 Status of the cramfs Filesystems (lsmod)
# Changed by RK
echo 
echo -e "${RED}1.1.1.4${NC} Ensure mounting of hfs filesystems is disabled"
rhel_1_1_1_4="$(modprobe -n -v hfs | grep "^install /bin/true$" || egrep -q "^\s*install\s+hfs\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_4=$?
lsmod | egrep "^hfs\s" && rmmod hfs
if [[ "$rhel_1_1_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfs filesystems is disabled"
  fail=$((fail + 1))
fi

# Ensure mounting of hfsplus filesystems is disabled
# 9705 Status of the cramfs Filesystems (modprobe) / 9712 Status of the cramfs Filesystems (lsmod)
# Changed by RK
echo
echo -e "${RED}1.1.1.5${NC} Ensure mounting of hfsplus filesystems is disabled"
rhel_1_1_1_5="$(modprobe -n -v hfsplus | grep "^install /bin/true$" || egrep -q "^\s*install\s+hfsplus\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_5=$?
lsmod | egrep "^hfsplus\s" && rmmod hfsplus
if [[ "$rhel_1_1_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfsplus filesystems is disabled"
  fail=$((fail + 1))
fi

# Ensure mounting of squashfs filesystems is disabled
# 9705 Status of the cramfs Filesystems (modprobe) / 9712 Status of the cramfs Filesystems (lsmod)
# Changed by RK
echo
echo -e "${RED}1.1.1.6${NC} Ensure mounting of squashfs filesystems is disabled"
rhel_1_1_1_6="$(modprobe -n -v squashfs | grep "^install /bin/true$" || egrep -q "^\s*install\s+squashfs\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_6=$?
lsmod | egrep "^squashfs\s" && rmmod squashfs
if [[ "$rhel_1_1_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of squashfs filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of squashfs filesystems is disabled"
  fail=$((fail + 1))
fi

# Ensure mounting of udf filesystems is disabled
# 9711 Status of the udf Filesystems (modprobe)/9718 Status of the udf Filesystems (lsmod)
# Changed by RK
echo
echo -e "${RED}1.1.1.7${NC} Ensure mounting of udf filesystems is disabled"
rhel_1_1_1_7="$(modprobe -n -v udf | grep "^install /bin/true$" || egrep -q "^\s*install\s+udf\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_7=$?
lsmod | egrep "^udf\s" && rmmod udf
if [[ "$rhel_1_1_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of udf filesystems is disabled" 
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of udf filesystems is disabled" 
  fail=$((fail + 1))
fi

# Ensure mounting of usb-storage filesystems is disabled
# 17275 Status of 'usb-storage' kernel module in modprobe
# Changed by RK

echo
echo -e "${RED}1.1.1.8${NC} Ensure mounting of FAT filesystems is disabled"
rhel_1_1_1_8="$(modprobe -n -v usb-storage | grep "^install /bin/true$" || egrep -q "^\s*install\s+usb-storage\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install usb-storage /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_8=$?
lsmod | egrep "^usb-storage\s" && rmmod usb-storage
if [[ "$rhel_1_1_1_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of FAT filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of FAT filesystems is disabled"
  fail=$((fail + 1))
fi


# Ensure mounting of FAT filesystems is disabled
# 9705 Status of the cramfs Filesystems (modprobe)/9712 Status of the cramfs Filesystems (lsmod)
# /boot/efi mount point is mounted as vfat
# Changed by RK
echo
echo -e "${RED}1.1.1.9${NC} Ensure mounting of FAT filesystems is disabled"
#rhel_1_1_1_9="$(modprobe -n -v vfat | grep "^install /bin/true$" || egrep -q "^\s*install\s+vfat\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf ||  echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_1_1_1_9=$?
#lsmod | egrep "^vfat\s" && rmmod vfat
if [[ "$rhel_1_1_1_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of FAT filesystems is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of FAT filesystems is disabled"
  fail=$((fail + 1))
fi

# Ensure system accounts are non-login
# Changed by RK
echo
echo "${RED}5.4.2${NC} Ensure system accounts are non-login"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ] 
  then
    /usr/sbin/usermod -L $user
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]&& [ $user != "nxautomation" ] &&  [ $user != "omsagent" ]
    then
      /usr/sbin/usermod -s /sbin/nologin $user
    fi
  fi
done

echo -e "${GREEN}Remediated:${NC} Ensure system accounts are non-login"
success=$((success + 1))

# 1.1.20 Ensure sticky bit is set on all world-writable directories
# Changed by RK
echo
echo -e "${RED}1.1.20${NC} Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | xargs chmod a+t
crontab -u root -l | grep -- "-type d" || (crontab -l 2>/dev/null || true; echo "0 */6 * * * df --local -P | awk {'if (NR!=1) print "\$"6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t") | crontab -
crontab -u root -l | grep -- "-type f" || (crontab -l 2>/dev/null || true; echo "0 */6 * * * df --local -P | awk {'if (NR!=1) print "\$"6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | xargs chmod a+t") | crontab -

policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure sticky bit is set on all world-writable directories"
fi


# 1.1.20 Ensure sticky bit is set on all world-writable directories
# Changed by RK
echo
echo -e "${RED}1.1.20${NC} Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | xargs chmod a+t
crontab -u root -l | grep -- "-type d" || (crontab -l 2>/dev/null || true; echo "0 */6 * * * df --local -P | awk {'if (NR!=1) print "\$"6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t") | crontab -
crontab -u root -l | grep -- "-type f" || (crontab -l 2>/dev/null || true; echo "0 */6 * * * df --local -P | awk {'if (NR!=1) print "\$"6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | xargs chmod a+t") | crontab -

policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure sticky bit is set on all world-writable directories"
fi



# Disable Automounting
# 9893 Status of the service autofs using systemd
echo
echo -e "${RED}1.1.22${NC} Disable Automounting"
rhel_1_1_22="$(systemctl disable autofs.service)"
rhel_1_1_22=$?
if [[ "$rhel_1_1_22" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Disable Automounting"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Disable Automounting"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 1.2 Initial Setup - Configure Software Updates
echo
echo -e "${BLUE}1.2 Initial Setup - Configure Software Updates${NC}"

# Ensure gpgcheck is globally activated
# 7410 Status of the 'gpgcheck' setting within the main (global) section of the '/etc/yum.conf'
echo
echo -e "${RED}1.2.2${NC} Ensure gpgcheck is globally activated"
rhel_1_2_2="$(egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" /etc/yum.conf && sed -ri "s/^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/\1gpgcheck=1\2/" /etc/yum.conf || echo "gpgcheck=1" >> /etc/yum.conf)"
rhel_1_2_2=$?
rhel_1_2_2_temp=0
for file in /etc/yum.repos.d/*; do
  rhel_1_2_2_temp_2="$(egrep -q "^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$" $file && sed -ri "s/^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/\1gpgcheck=1\2/" $file || echo "gpgcheck=1" >> $file)"
  rhel_1_2_2_temp_2=$?
  if [[ "$rhel_1_2_2_temp_2" -eq 0 ]]; then
    ((rhel_1_2_2_temp=rhel_1_2_2_temp+1))
  fi
done
rhel_1_2_2_temp_2="$( ls -1q /etc/yum.repos.d/* | wc -l)"
if [[ "$rhel_1_2_2" -eq 0 ]] && [[ "$rhel_1_2_2_temp" -eq "rhel_1_2_2_temp_2" ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure gpgcheck is globally activated"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure gpgcheck is globally activated"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 1.3 Initial Setup - Filesystem Integrity Checking
# 7411 Status of the currently installed 'AIDE' (advanced intrusion detection environment)package on the host
echo
echo -e "${BLUE}1.3 Initial Setup - Filesystem Integrity Checking${NC}"

# Ensure AIDE is installed
echo
echo -e "${RED}1.3.1${NC} Ensure AIDE is installed"
rhel_1_3_1="$(rpm -q aide || yum -y install aide)"
rhel_1_3_1=$?
if [[ "$rhel_1_3_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure AIDE is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure AIDE is installed"
  fail=$((fail + 1))
fi

# Ensure filesystem integrity is regularly checked
# 10859 Status of the 'periodically scheduled (crontab)' aide check (/etc/cron.* and /etc/crontab)
# Changed by RK
echo
echo -e "${RED}1.3.2${NC} Ensure filesystem integrity is regularly checked"
rhel_1_3_2="$(crontab -u root -l | egrep  "/usr/sbin/aide" || (crontab -l 2>/dev/null || true; echo "0 5 * * sat /usr/sbin/aide --check") | crontab -)"
rhel_1_3_2=$?
if [[ "$rhel_1_3_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure filesystem integrity is regularly checked"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure filesystem integrity is regularly checked"
  fail=$((fail + 1))
fi

# Ensure permissions on bootloader config are configured
# Changed by RK
echo
echo -e "${RED}1.3.2${NC} Ensure permissions on bootloader config are configured\n"
rhel_1_4_1="$(chown root:root /boot/grub2/grub.cfg; chmod g-r-w-x,o-r-w-x /boot/grub2/grub.cfg)"
rhel_1_4_1=$?
if [[ "$rhel_1_4_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on bootloader config are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 1.4 Initial Setup - Secure Boot Settings
echo
echo -e "${BLUE}1.4 Initial Setup - Secure Boot Settings${NC}"

# Ensure permissions on bootloader config are configured
# Permissions set on the file /boot/grub2/grub.cfg
# Changed by RK
echo
echo -e "${RED}1.4.1${NC} Ensure permissions on bootloader config are configured"
rhel_1_4_1="$(chown root:root /boot/grub2/grub.cfg && chmod og-rwx /boot/grub2/grub.cfg)"
rhel_1_4_1=$?
if [[ "$rhel_1_4_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on bootloader config are configured"
  fail=$((fail + 1))
fi

# Ensure authentication required for single user mode
# 12755 Status of 'ExecStart' setting in the /usr/lib/systemd/system/emergency.service (single user mode)
# 12754 Status of 'ExecStart' setting in the /usr/lib/systemd/system/rescue.service (single user mode)

echo
echo -e "${RED}1.4.3${NC} Ensure authentication required for single user mode"
rhel_1_4_3_rule1="$(egrep -q "^\s*ExecStart" /usr/lib/systemd/system/rescue.service && sed -ri "s/(^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*).*$/\1-\/bin\/sh -c \"\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default\"/" /usr/lib/systemd/system/rescue.service || echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/rescue.service)"
rhel_1_4_3_rule1=$?
rhel_1_4_3_rule2="$(egrep -q "^\s*ExecStart" /usr/lib/systemd/system/emergency.service && sed -ri "s/(^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*).*$/\1-\/bin\/sh -c \"\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default\"/" /usr/lib/systemd/system/emergency.service || echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/emergency.service)"
rhel_1_4_3_rule1=$?
if [[ "$rhel_1_4_3_rule1" -eq 0 ]] && [[ "$rhel_1_4_3_rule2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure authentication required for single user mode"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure authentication required for single user mode"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 1.5 Initial Setup - Additional Process Hardening
echo
echo -e "${BLUE}1.5 Initial Setup - Additional Process Hardening${NC}"

# Ensure core dumps are restricted
# 12785 Status of the 'fs.suid_dumpable' parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories
# Changed by RK
echo
echo -e "${RED}1.5.1${NC} Ensure core dumps are restricted"
rhel_1_5_1_temp_1="$(egrep -q "^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$" /etc/security/limits.conf && sed -ri "s/^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$/\1* hard core 0\2/" /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf)"
rhel_1_5_1_temp_1=$?
rhel_1_5_1_temp_2="$(egrep -q "^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$" /etc/security/limits.d/* && sed -ri "s/^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$/\1* hard core 0\2/" /etc/security/limits.d/* || echo "* hard core 0" >> /etc/security/limits.d/*)"
rhel_1_5_1_temp_2=$?
rhel_1_5_1_temp_3="$(egrep -q "^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$/\1fs.suid_dumpable = 0\2/" /etc/sysctl.conf || echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf)"
rhel_1_5_1_temp_3=$?
rhel_1_5_1_temp_4="$(egrep -q "^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.d/* && sed -ri "s/^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$/\1fs.suid_dumpable = 0\2/" /etc/sysctl.d/*  || echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/*)"
rhel_1_5_1_temp_4=$?
rhel_1_5_1_temp_5="$(sysctl -w fs.suid_dumpable=0)"
rhel_1_5_1_temp_5=$?
if [[ "$rhel_1_5_1_temp_1" -eq 0 ]] && [[ "$rhel_1_5_1_temp_2" -eq 0 ]] && [[ "$rhel_1_5_1_temp_3" -eq 0 ]] && [[ "$rhel_1_5_1_temp_4" -eq 0 ]] && [[ "$rhel_1_5_1_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure core dumps are restricted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure core dumps are restricted"
  fail=$((fail + 1))
fi

# Ensure address space layout randomization (ASLR) is enabled
# 12786 Status of the 'kernel.randomize_va_space' parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories
# Changed by RK
echo
echo -e "${RED}1.5.2${NC} Ensure address space layout randomization (ASLR) is enabled"
rhel_1_5_2_temp_1="$(egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf)"
rhel_1_5_2_temp_1=$?
rhel_1_5_2_temp_2="$(egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.d/* && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.d/* || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/*)"
rhel_1_5_2_temp_2=$?
rhel_1_5_2_temp_3="$(sysctl -w kernel.randomize_va_space=2)"
rhel_1_5_2_temp_3=$?
if [[ "$rhel_1_5_2_temp_1" -eq 0 ]] && [[ "$rhel_1_5_2_temp_2" -eq 0 ]] && [[ "$rhel_1_5_2_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure address space layout randomization (ASLR) is enabled"
  fail=$((fail + 1))
fi


# Ensure Storage and ProcessSizeMax value on coredump
# 17222 Status of the 'Storage' setting in '/etc/systemd/coredump.conf' file
# 17223 Status of the 'ProcessSizeMax' setting in '/etc/systemd/coredump.conf' file
# Added by RK

echo
echo -e "${RED}1.5.3${NC} Ensure Storage and ProcessSizeMax value on coredump"
rhel_1_5_3_temp_1="$(egrep -q "^(\s*)ProcessSizeMax\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/coredump.conf && sed -ri "s/^(\s*)ProcessSizeMax\s*=\s*\S+(\s*#.*)?\s*$/\1ProcessSizeMax=0\2/" /etc/systemd/coredump.conf || sed -ri "1,/#ProcessSizeMax\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#ProcessSizeMax\s*=\s*\S+(\s*#.*)?\s*$/\1ProcessSizeMax=0\2/" /etc/systemd/coredump.conf && egrep -q "^(\s*)ProcessSizeMax\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/coredump.conf ||  echo "ProcessSizeMax=0" >> /etc/systemd/coredump.conf)"
rhel_1_5_3_temp_1=$?
rhel_1_5_3_temp_2="$(egrep -q "^(\s*)Storage\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/coredump.conf && sed -ri "s/^(\s*)Storage\s*=\s*\S+(\s*#.*)?\s*$/\1Storage=none\2/" /etc/systemd/coredump.conf || sed -ri "1,/#Storage\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#Storage\s*=\s*\S+(\s*#.*)?\s*$/\1Storage=none\2/" /etc/systemd/coredump.conf && egrep -q "^(\s*)Storage\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/coredump.conf ||  echo "Storage=none" >> /etc/systemd/coredump.conf)"
rhel_1_5_3_temp_2=$?


if [[ "$rhel_1_5_3_temp_1" -eq 0 ]] && [[ "$rhel_1_5_3_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Storage and ProcessSizeMax value on coredump"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Storage and ProcessSizeMax value on coredump"
  fail=$((fail + 1))
fi

# Ensure prelink is disabled
# 9223 Status of the 'Prelink' package
echo
echo -e "${RED}1.5.4${NC} Ensure prelink is disabled"
rhel_1_5_4="$(rpm -q prelink && yum -y remove prelink)"
rhel_1_5_4=$?
if [[ "$rhel_1_5_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure prelink is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure prelink is disabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 1.6 Initial Setup - Mandatory Access Control

echo
echo -e "${BLUE}1.6 Initial Setup - Mandatory Access Control${NC}"

# Ensure SELinux is installed
# 10662 Status of the 'SELinux' package on the host
echo
echo -e "${RED}1.6.2${NC} Ensure SELinux is installed"
rhel_1_6_2="$(rpm -q libselinux || yum -y install libselinux)"
rhel_1_6_2=$?
if [[ "$rhel_1_6_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SELinux is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SELinux is installed"
  fail=$((fail + 1))
fi

# Ensure SETroubleshoot is not installed
# 7427 Status of the currently installed 'setroubleshoot' packages on the host
echo
echo -e "${RED}1.6.1.4${NC} Ensure SETroubleshoot is not installed"
rhel_1_6_1_4="$(rpm -q setroubleshoot && yum -y remove setroubleshoot)"
rhel_1_6_1_4=$?
if [[ "$rhel_1_6_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SETroubleshoot is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SETroubleshoot is not installed"
  fail=$((fail + 1))
fi

# Ensure the MCS Translation Service (mcstrans) is not installed
# 9376 Status of the MCS Translation Service (mcstrans)

echo
echo -e "${RED}1.6.1.5${NC} Ensure the MCS Translation Service (mcstrans) is not installed"
rhel_1_6_1_5="$(rpm -q mcstrans && yum -y remove mcstrans)"
rhel_1_6_1_5=$?
if [[ "$rhel_1_6_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure the MCS Translation Service (mcstrans) is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the MCS Translation Service (mcstrans) is not installed"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 1.7 Initial Setup - Warning Banners
echo
echo -e "${BLUE}1.7 Initial Setup - Warning Banners${NC}"

# Ensure message of the day is configured properly
# 3868 Status of the contents of the login banner in '/etc/motd'
echo
echo -e "${RED}1.7.1.1${NC} Ensure message of the day is configured properly"
rhel_1_7_1_1="$(sed -ri 's/(\\v|\\r|\\m|\\s)//g' /etc/motd)"
rhel_1_7_1_1=$?
if [[ "$rhel_1_7_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure message of the day is configured properly"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure message of the day is configured properly"
  fail=$((fail + 1))
fi

# Ensure local login warning banner is configured properly
# 8122 Status of the hardware architecture and operating system information (os release, os name, os version) contained in the warning banner in the '/etc/issue' file on the host
# Added by RK
echo
echo -e "${RED}1.7.1.2${NC} Ensure local login warning banner is configured properly"
rhel_1_7_1_2=
cat > /etc/issue << 'EOF'
/-------------------------------------------------------------------------\
|*** STATUTORY WARNINGS ***                                               |
|      __     __  ___   ____    _____   _   _   ____       _              |
|      \ \   / / |_ _| |  _ \  |_   _| | | | | / ___|     / \             |
|       \ \ / /   | |  | |_) |   | |   | | | | \___ \    / _ \            |
|        \ V /    | |  |  _ <    | |   | |_| |  ___) |  / ___ \           |
|         \_/    |___| |_| \_\   |_|    \___/  |____/  /_/   \_\          |
|                                                                         |
|                                                                         |
| As part of my remote working, I give my consent to the Remote work      |
|Agreement uploaded in, https://www.virtusa.com/remoteworkagreement,      |
|and will comply with this agreement., This computer system (including    |
|all hardware software, related equipment networks and network devices)   |
|is the property of Virtusa Corporation, including its direct and indirect|
|subsidiaries, and is provided for authorized business purpose only.      |
|                                                                         |
| All actions performed using this asset may be monitored for all lawful  |
|purpose including ensuring, authorized use for management of the system  |
|to facilitate protection against unauthorized access,prevent data leakage|
|and to verify security procedures and operational procedures.            |
|                                                                         |
| The monitoring on this system shall include audits by Company authorized|
|personnel or its representatives to test or verify the validity, security|
|and survivability of this system. During monitoring, information may be  |
|examined, recorded, copied and used for, authorized purposes.            |
|                                                                         |
| All information placed on or sent to this system may be subject to such |
|monitoring procedures without any prior notice or intimation to you.     |
|Use of this computer system constitutes consent to such monitoring.      |
|I will refrain from circumventing any security measure, control or system|
|which has been implemented to restrict access to secure area, computers, |
|networks, systems or information. Any unauthorized access use or         |
|modification of the computer system can result in disciplinary action    |
|including termination or possible civil or criminal penalties.           |
\-------------------------------------------------------------------------/
EOF
rhel_1_7_1_2=$?
if [[ "$rhel_1_7_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure local login warning banner is configured properly"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure local login warning banner is configured properly"
  fail=$((fail + 1))
fi

# Ensure remote login warning banner is configured properly
# 8124 Status of the hardware architecture and operating system information (os release, os name, os version) contained in the '/etc/issue.net' file on the host
# Added by RK

echo
echo -e "${RED}1.7.1.3${NC} Ensure remote login warning banner is configured properly"
rhel_1_7_1_3=
cat > /etc/issue.net << 'EOF'
/-------------------------------------------------------------------------\
|*** STATUTORY WARNINGS ***                                               |
|      __     __  ___   ____    _____   _   _   ____       _              |
|      \ \   / / |_ _| |  _ \  |_   _| | | | | / ___|     / \             |
|       \ \ / /   | |  | |_) |   | |   | | | | \___ \    / _ \            |
|        \ V /    | |  |  _ <    | |   | |_| |  ___) |  / ___ \           |
|         \_/    |___| |_| \_\   |_|    \___/  |____/  /_/   \_\          |
|                                                                         |
|                                                                         |
| As part of my remote working, I give my consent to the Remote work      |
|Agreement uploaded in, https://www.virtusa.com/remoteworkagreement,      |
|and will comply with this agreement., This computer system (including    |
|all hardware software, related equipment networks and network devices)   |
|is the property of Virtusa Corporation, including its direct and indirect|
|subsidiaries, and is provided for authorized business purpose only.      |
|                                                                         |
| All actions performed using this asset may be monitored for all lawful  |
|purpose including ensuring, authorized use for management of the system  |
|to facilitate protection against unauthorized access,prevent data leakage|
|and to verify security procedures and operational procedures.            |
|                                                                         |
| The monitoring on this system shall include audits by Company authorized|
|personnel or its representatives to test or verify the validity, security|
|and survivability of this system. During monitoring, information may be  |
|examined, recorded, copied and used for, authorized purposes.            |
|                                                                         |
| All information placed on or sent to this system may be subject to such |
|monitoring procedures without any prior notice or intimation to you.     |
|Use of this computer system constitutes consent to such monitoring.      |
|I will refrain from circumventing any security measure, control or system|
|which has been implemented to restrict access to secure area, computers, |
|networks, systems or information. Any unauthorized access use or         |
|modification of the computer system can result in disciplinary action    |
|including termination or possible civil or criminal penalties.           |
\-------------------------------------------------------------------------/
EOF
rhel_1_7_1_3=$?
if [[ "$rhel_1_7_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure remote login warning banner is configured properly"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure remote login warning banner is configured properly"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/motd are configured
# 2265 Permissions set for the '/etc/motd' file
echo
echo -e "${RED}1.7.1.4${NC} Ensure permissions on /etc/motd are configured"
rhel_1_7_1_4="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/motd)"
rhel_1_7_1_4=$?
if [[ "$rhel_1_7_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/motd are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/motd are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/issue are configured
# 2264 Permissions set for the '/etc/issue' file
echo
echo -e "${RED}1.7.1.5${NC} Ensure permissions on /etc/issue are configured"
rhel_1_7_1_5="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/issue)"
rhel_1_7_1_5=$?
if [[ "$rhel_1_7_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/issue.net are configured
# 2263 Permissions set for the '/etc/issue.net' file
echo
echo -e "${RED}1.7.1.6${NC} Ensure permissions on /etc/issue.net are configured"
rhel_1_7_1_6="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/issue.net)"
rhel_1_7_1_6=$?
if [[ "$rhel_1_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue.net are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/issue.net are configured"
  fail=$((fail + 1))
fi

# Ensure motod login warning banner is configured properly
# 8122 Status of the hardware architecture and operating system information (os release, os name, os version) contained in the warning banner in the '/etc/motod' file on the host
# Added by RK

echo
echo -e "${RED}1.7.1.2${NC} Ensure local login warning banner is configured properly"
rhel_1_7_1_7="$(echo -en "\033[0;31m" > /etc/motd ; echo "VIRTUSA CORPORATION AUTHORIZED USE ONLY" >> /etc/motd ; echo -en "\033[0m" >> /etc/motd)"
rhel_1_7_1_7=$?
if [[ "$rhel_1_7_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure motd login warning banner is configured properly"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure motd login warning banner is configured properly"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 2.1 Services - inetd Services
echo
echo -e "${BLUE}2.1 Services - inetd Services${NC}"

# Ensure chargen services are not enabled
echo
echo -e "${RED}2.1.1${NC} Ensure chargen services are not enabled"
rhel_2_1_1="$(chkconfig chargen off)"
rhel_2_1_1=$?
if [[ "$rhel_2_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure chargen services are not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure chargen services are not enabled"
  fail=$((fail + 1))
fi 

# Ensure daytime services are not enabled
echo
echo -e "${RED}2.1.2${NC} Ensure daytime services are not enabled"
rhel_2_1_2="$(chkconfig daytime off)"
rhel_2_1_2=$?
if [[ "$rhel_2_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure daytime services are not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure daytime services are not enabled"
  fail=$((fail + 1))
fi

# Ensure discard services are not enabled
echo
echo -e "${RED}2.1.3${NC} Ensure discard services are not enabled"
rhel_2_1_3="$(chkconfig discard off)"
rhel_2_1_3=$?
if [[ "$rhel_2_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure discard services are not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure discard services are not enabled"
  fail=$((fail + 1))
fi

# Ensure echo services are not enabled
echo
echo -e "${RED}2.1.4${NC} Ensure echo services are not enabled"
rhel_2_1_4="$(chkconfig echo off)"
rhel_2_1_4=$?
if [[ "$rhel_2_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure echo services are not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure echo services are not enabled"
  fail=$((fail + 1))
fi

# Ensure time services are not enabled
echo
echo -e "${RED}2.1.5${NC} Ensure time services are not enabled"
rhel_2_1_5="$(chkconfig time off)"
rhel_2_1_5=$?
if [[ "$rhel_2_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure time services are not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure time services are not enabled"
  fail=$((fail + 1))
fi

# Ensure tftp server is not enabled
echo
echo -e "${RED}2.1.6${NC} Ensure tftp server is not enabled"
rhel_2_1_6="$(chkconfig tftp off)"
rhel_2_1_6=$?
systemctl disable tftp.socket.service
if [[ "$rhel_2_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure tftp server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure tftp server is not enabled"
  fail=$((fail + 1))
fi

# Ensure xinetd is not enabled
echo
echo -e "${RED}2.1.7${NC} Ensure xinetd is not enabled"
rhel_2_1_7="$(systemctl disable xinetd.service)"
rhel_2_1_7=$?
if [[ "$rhel_2_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure xinetd is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure xinetd is not enabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 2.2 Services - Special Purpose Services
cp -a /etc/ntp.conf /etc/ntp_$TIMESTAMP
cp -a /etc/chrony.conf /etc/chrony.conf_$TIMESTAMP

echo
echo -e "${BLUE}2.2 Services - Special Purpose Services${NC}"

# Ensure time synchronization is in use
# Changed by RK

echo
echo -e "${RED}2.2.1.1${NC} Ensure time synchronization is in use"
rhel_2_2_1_1="$(rpm -q ntp || rpm -q chrony || yum -y install chrony)"
rhel_2_2_1_1=$?
if [[ "$rhel_2_2_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure time synchronization is in use"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure time synchronization is in use"
  fail=$((fail + 1))
fi

# Ensure ntp is configured
# 7457 Status of the 'OPTIONS' setting in the '/etc/sysconfig/ntpd' file
# 7451 Status of the 'restrict -6 default' setting in the '/etc/ntp.conf' file
# 10480 Status of the 'restrict -4 default' setting in the '/etc/ntp.conf' file
# 4997 Current list of 'NTP servers' defined within '/etc/ntp.conf'
# 13137 Status of the 'pool' setting in '/etc/ntp.conf'
# Changed by RK
# Change IP with the which can be reachable AD IPs (Port 123 should be allowed)

echo
echo -e "${RED}2.2.1.2${NC} Ensure ntp is configured"
 rhel_2_2_1_1_ntpd="$(rpm -q chrony)"
 rhel_2_2_1_1_ntpd=$? 
if rpm -q ntp >/dev/null; then
  rhel_2_2_1_1_temp_1="$(egrep -q "^\s*restrict\s+-4\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict\s+-4\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict -4 default kod nomodify notrap nopeer noquery\3/" /etc/ntp.conf || echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_1=$?
  rhel_2_2_1_1_temp_2="$(egrep -q "^\s*restrict\s+-6\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict\s+-6\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict -6 default kod nomodify notrap nopeer noquery\3/" /etc/ntp.conf || echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_2=$?
  rhel_2_2_1_1_temp_3="$(sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u ntp:ntp\"\3/ }' /etc/sysconfig/ntpd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u ntp:ntp\3\"\4/" /etc/sysconfig/ntpd && egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/ntpd || echo "OPTIONS=\"-g -u ntp:ntp\"" >> /etc/sysconfig/ntpd)"
  rhel_2_2_1_1_temp_3=$?
  rhel_2_2_1_1_temp_4="$(
sed -ri '/^server/{x;//!c\
server 10.66.165.10 iburst\
server 10.66.165.10 iburst\
server 10.62.10.14 iburst
d}' /etc/ntp.conf)"
  rhel_2_2_1_1_temp_4=$?
  if [[ "$rhel_2_2_1_1_temp_1" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_2" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_3" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_4" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure ntp is configured"
    success=$((success + 1))
    systemctl restart ntpd
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure ntp is configured"
    fail=$((fail + 1))
  fi
else
   if [[ "$rhel_2_2_1_1_ntpd" -eq 1 ]]; then
   yum install ntp -y && systemctl enable ntpd
  rhel_2_2_1_1_temp_1="$(egrep -q "^\s*restrict\s+-4\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict\s+-4\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict -4 default kod nomodify notrap nopeer noquery\3/" /etc/ntp.conf || echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_1=$?
  rhel_2_2_1_1_temp_2="$(egrep -q "^\s*restrict\s+-6\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict\s+-6\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict -6 default kod nomodify notrap nopeer noquery\3/" /etc/ntp.conf || echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf)"
  rhel_2_2_1_1_temp_2=$?
  rhel_2_2_1_1_temp_3="$(sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u ntp:ntp\"\3/ }' /etc/sysconfig/ntpd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u ntp:ntp\3\"\4/" /etc/sysconfig/ntpd && egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/ntpd || echo "OPTIONS=\"-g -u ntp:ntp\"" >> /etc/sysconfig/ntpd)"
  rhel_2_2_1_1_temp_3=$?
  rhel_2_2_1_1_temp_4="$(
sed -ri '/^server/{x;//!c\
server 10.66.165.10 iburst\
server 10.66.165.10 iburst\
server 10.62.10.14 iburst
d}' /etc/ntp.conf)"
  rhel_2_2_1_1_temp_4=$?
   else
     echo -e "${RED}UnableToRemediate:${NC} Chrony is already installed"
   fi
  if [[ "$rhel_2_2_1_1_temp_1" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_2" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_3" -eq 0 ]] && [[ "$rhel_2_2_1_1_temp_4" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure ntp is configured"
    success=$((success + 1))
    systemctl restart ntpd
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure ntp is configured"
    fail=$((fail + 1))
  fi
 fi
 
# Ensure chrony is configured
# 10664 Status of the 'OPTIONS' setting within '/etc/sysconfig/chronyd' file
# 10663 Status of the 'server' setting within 'chrony.conf' file
# 13138 Status of the 'pool' setting in '/etc/chrony.conf' 
# Changed by RK
# Change IP with the which can be reachable AD IPs (Port 123 should be allowed)

echo
echo -e "${RED}2.2.1.3${NC} Ensure chrony is configured"
rhel_2_2_1_1_chrony="$(rpm -q ntp)"
rhel_2_2_1_1_chrony=$?
if rpm -q chrony >/dev/null; then
  rhel_2_2_1_2="$(sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u chrony\"\3/ }' /etc/sysconfig/chronyd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u chrony\3\"\4/" /etc/sysconfig/chronyd && egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/chronyd  || echo "OPTIONS=\"-u chrony\"" >> /etc/sysconfig/chronyd)"
  rhel_2_2_1_2=$?
  rhel_2_2_1_3="$(
sed -ri '/^server/{x;//!c\
server 10.66.165.10 iburst\
server 10.66.165.14 iburst\
server 10.62.10.6 iburst
d}' /etc/chrony.conf)"
   rhel_2_2_1_3=$?
   rhel_2_2_1_4="$(
sed -ri '/^pool/{x;//!c\
server 10.66.165.10 iburst\
server 10.66.165.14 iburst\
server 10.62.10.6 iburst
d}' /etc/chrony.conf)"
   rhel_2_2_1_4=$? 
  if [[ "$rhel_2_2_1_2" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure chrony is configured"
    success=$((success + 1))
    systemctl restart chronyd
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure chrony is configured"
    fail=$((fail + 1))
  fi
else
  if [[ "$rhel_2_2_1_1_chrony" -eq 1 ]]; then
   yum install chrony -y && systemctl start chronyd && systemctl enable chronyd
  rhel_2_2_1_2="$(sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u chrony\"\3/ }' /etc/sysconfig/chronyd && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u chrony\3\"\4/" /etc/sysconfig/chronyd && egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/sysconfig/chronyd  || echo "OPTIONS=\"-u chrony\"" >> /etc/sysconfig/chronyd)"
  rhel_2_2_1_2=$?
  rhel_2_2_1_3="$(
sed -ri '/^server/{x;//!c\
server 10.66.165.10 iburst\
server 10.66.165.14 iburst\
server 10.62.10.6 iburst
d}' /etc/chrony.conf)"
   rhel_2_2_1_3=$?
   rhel_2_2_1_4="$(
sed -ri '/^pool/{x;//!c\
server 10.66.165.10 iburst\
server 10.66.165.14 iburst\
server 10.62.10.6 iburst
d}' /etc/chrony.conf)"
   rhel_2_2_1_4=$? 
  else
   echo -e "${RED}UnableToRemediate:${NC} NTP is already installed"
  fi
 if [[ "$rhel_2_2_1_2" -eq 0 ]] && [[ "$rhel_2_2_1_3" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure chrony is configured"
    success=$((success + 1))
    systemctl restart chronyd
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure chrony is configured"
    fail=$((fail + 1))
  fi
fi

####################################################################################################
# Ensure X Window System is not installed
# Check whether the user is using GUI or X11,uncomment if they are not using

echo
echo -e "${RED}2.2.2${NC} Ensure X Window System is not installed"
#rhel_2_2_2="$(yum -y remove xorg-x11*)"
rhel_2_2_2=$?
if [[ "$rhel_2_2_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure X Window System is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure X Window System is not installed"
  fail=$((fail + 1))
fi
########################################################################################################


# Ensure Avahi Server is not enabled
echo
echo -e "${RED}2.2.3${NC} Ensure Avahi Server is not enabled"
rhel_2_2_3="$(systemctl disable avahi-daemon.service || yum erase avahi -y)"
rhel_2_2_3=$?
if [[ "$rhel_2_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Avahi Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure CUPS is not enabled
echo
echo -e "${RED}2.2.4${NC} Ensure CUPS is not enabled"
rhel_2_2_4="$(systemctl disable cups.service  || yum erase cups -y)"
rhel_2_2_4=$?
if [[ "$rhel_2_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure CUPS is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure CUPS is not enabled"
  fail=$((fail + 1))
fi
0
#####################################################################################################
# Ensure DHCP Server is not enabled
# There are dependency on this service.

echo
echo -e "${RED}2.2.5${NC} Ensure DHCP Server is not enabled"
#rhel_2_2_5="$(systemctl disable dhcpd.service || yum erase dhcpd -y)"
rhel_2_2_5=$?
if [[ "$rhel_2_2_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DHCP Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DHCP Server is not enabled"
  fail=$((fail + 1))
fi
######################################################################################################

# Ensure LDAP server is not enabled
# There are dependency on this service.
# Check whether the user is using services,uncomment if they are not using

echo
echo -e "${RED}2.2.6${NC} Ensure LDAP server is not enabled"
#rhel_2_2_6="$(systemctl disable slapd.service || yum erase slapd -y)" 
rhel_2_2_6=$?
if [[ "$rhel_2_2_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure LDAP server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure LDAP server is not enabled"
  fail=$((fail + 1))
fi

# Ensure NFS and RPC are not enabled
# There are dependency on this service.
# Check whether the user is using nfs mount points
# Check whether the user is using services, uncomment if they are not using

echo
echo -e "${RED}2.2.7${NC} Ensure NFS and RPC are not enabled"
#rhel_2_2_7_temp_1="$(systemctl disable nfs.service || yum erase nfs -y)"
rhel_2_2_7_temp_1=$?
#r0hel_2_2_7_temp_2="$(systemctl disable rpcbind.service || systemctl stop rpcbind.service)"
rhel_2_2_7_temp_2=$?
if [[ "$rhel_2_2_7_temp_1" -eq 0 ]] && [[ "$rhel_2_2_7_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NFS and RPC are not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NFS and RPC are not enabled"
  fail=$((fail + 1))
fi

# Ensure DNS Server is not enabled
# Check whether the user is using services,uncomment if they are not using

echo
echo -e "${RED}2.2.8${NC} Ensure DNS Server is not enabled"
#rhel_2_2_8="$(systemctl disable named.service || yum erase named -y)"
rhel_2_2_8=$?
if [[ "$rhel_2_2_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DNS Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DNS Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure FTP Server is not enabled
# Check whether the user is using services, uncomment if they are not using

echo
echo -e "${RED}2.2.9${NC} Ensure FTP Server is not enabled"
#rhel_2_2_9="$(systemctl disable vsftpd.service || yum erase vsftpd -y)"
rhel_2_2_9=$?
if [[ "$rhel_2_2_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure FTP Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure FTP Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure HTTP server is not enabled
# Check whether the user is using services, uncomment if they are not using

echo
echo -e "${RED}2.2.10${NC} Ensure HTTP server is not enabled"
#rhel_2_2_10="$(systemctl disable httpd.service || yum erase httpd -y)"
rhel_2_2_10=$?
if [[ "$rhel_2_2_10" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure HTTP server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure HTTP server is not enabled"
  fail=$((fail + 1))
fi

# Ensure IMAP and POP3 server is not enabled
# Check whether the user is using services, uncomment if they are not using

echo
echo -e "${RED}2.2.11${NC} Ensure IMAP and POP3 server is not enabled"
#rhel_2_2_11="$(systemctl disable dovecot.service || yum erase dovecot -y)"
rhel_2_2_11=$?
if [[ "$rhel_2_2_11" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IMAP and POP3 server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IMAP and POP3 server is not enabled"
  fail=$((fail + 1))
fi

# Ensure Samba is not enabled
# Check whether the user is using services, uncomment if they are not using

echo
echo -e "${RED}2.2.12${NC} Ensure Samba is not enabled"
#rhel_2_2_12="$(systemctl disable smb.service || yum erase smb -y)"
rhel_2_2_12=$?
if [[ "$rhel_2_2_12" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Samba is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Samba is not enabled"
  fail=$((fail + 1))
fi

# Ensure HTTP Proxy Server is not enabled
# Check whether the user is using services, uncomment if they are not using

echo
echo -e "${RED}2.2.13${NC} Ensure HTTP Proxy Server is not enabled"
#rhel_2_2_13="$(systemctl disable squid.service || yum erase squid -y)"
rhel_2_2_13=$?
if [[ "$rhel_2_2_13" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure HTTP Proxy Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure HTTP Proxy Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure SNMP Server is not enabled
# Check whether the user is using services, uncomment if they are not using

echo
echo -e "${RED}2.2.14${NC} Ensure SNMP Server is not enabled"
#rhel_2_2_14="$(systemctl disable snmpd.service || yum erase snmpd -y)"
rhel_2_2_14=$?
if [[ "$rhel_2_2_14" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SNMP Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SNMP Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure NIS Server is not enabled
echo
echo -e "${RED}2.2.16${NC} Ensure NIS Server is not enabled"
rhel_2_2_16="$(systemctl disable ypserv.service || yum erase ypserv -y)"
rhel_2_2_16=$?
if [[ "$rhel_2_2_16" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NIS Server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NIS Server is not enabled"
  fail=$((fail + 1))
fi

# Ensure rsh server is not enabled
echo
echo -e "${RED}2.2.17${NC} Ensure rsh server is not enabled"
rhel_2_2_17_1="$(systemctl disable rsh.socket.service || yum erase rsh -y)"
rhel_2_2_17_1=$?
rhel_2_2_17_2="$(systemctl disable rlogin.socket.service && systemctl disable rexec.socket.service)"
rhel_2_2_17_2=$?
if [[ "$rhel_2_2_17_1" -eq 0 ]] && [[ "$rhel_2_2_17_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh server is not enabled"
  fail=$((fail + 1))
fi

# Ensure talk server is not enabled
echo
echo -e "${RED}2.2.18${NC} Ensure talk server is not enabled"
rhel_2_2_18="$(systemctl disable ntalk.service || yum erase ntalk -y)"
rhel_2_2_18=$?
if [[ "$rhel_2_2_18" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure talk server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure talk server is not enabled"
  fail=$((fail + 1))
fi

# Ensure telnet server is not enabled
echo
echo -e "${RED}2.2.19${NC} Ensure telnet server is not enabled"
rhel_2_2_19="$(systemctl disable telnet.socket.service || yum erase telnet -y)"
rhel_2_2_19=$?
if [[ "$rhel_2_2_19" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure telnet server is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure telnet server is not enabled"
  fail=$((fail + 1))
fi

# Ensure rsync service is not enabled
# There are dependency
# Changed by RK
echo
echo -e "${RED}2.2.21${NC} Ensure rsync service is not enabled"
#rhel_2_2_21="$(systemctl disable rsyncd.service || yum erase rsync -y)"
rhel_2_2_21=$?
if [[ "$rhel_2_2_21" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsync service is not enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsync service is not enabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 2.3 Services - Service Clients
echo
echo -e "${BLUE}2.3 Services - Service Clients${NC}"

# Ensure NIS Client is not installed
echo
echo -e "${RED}2.3.1${NC} Ensure NIS Client is not installed"
rhel_2_3_1="$(rpm -q ypbind && yum -y erase ypbind)"
rhel_2_3_1=$?
if [[ "$rhel_2_3_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure NIS Client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure NIS Client is not installed"
  fail=$((fail + 1))
fi

# Ensure rsh client is not installed
echo
echo -e "${RED}2.3.2${NC} Ensure rsh client is not installed"
rhel_2_3_2="$(rpm -q rsh && yum -y erase rsh)"
rhel_2_3_2=$?
if [[ "$rhel_2_3_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsh client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsh client is not installed"
  fail=$((fail + 1))
fi

# Ensure talk client is not installed
echo
echo -e "${RED}2.3.3${NC} Ensure talk client is not installed"
rhel_2_3_3="$(rpm -q talk && yum -y erase talk)"
rhel_2_3_3=$?
if [[ "$rhel_2_3_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure talk client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure talk client is not installed"
  fail=$((fail + 1))
fi

# Ensure telnet client is not installed
echo
echo -e "${RED}2.3.4${NC} Ensure telnet client is not installed"
rhel_2_3_4="$(rpm -q telnet && yum -y erase telnet)"
rhel_2_3_4=$?
if [[ "$rhel_2_3_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure telnet client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure telnet client is not installed"
  fail=$((fail + 1))
fi

# Ensure LDAP client is not installed
echo
echo -e "${RED}2.3.5${NC} Ensure LDAP client is not installed"
rhel_2_3_5="$(rpm -q openldap-clients && yum -y erase openldap-clients)"
rhel_2_3_5=$?
if [[ "$rhel_2_3_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure LDAP client is not installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure LDAP client is not installed"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 3.1 Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}3.1 Network Configuration - Network Parameters (Host Only)${NC}"
ls /etc/sysctl.d/99-sysctl.conf || touch /etc/sysctl.d/99-sysctl.conf # Added by RK
# Ensure IP forwarding is disabled
echo
echo -e "${RED}3.1.1${NC} Ensure IP forwarding is disabled"
rhel_3_1_1_temp_1="$(egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf)"
rhel_3_1_1_temp_1=$?
rhel_3_1_1_temp_2="$(egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.d/* && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.d/* || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/*)"
rhel_3_1_1_temp_2=$?
rhel_3_1_1_temp_3="$(sysctl -w net.ipv4.ip_forward=0)"
rhel_3_1_1_temp_3=$?
rhel_3_1_1_temp_4="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_1_1_temp_4=$?
if [[ "$rhel_3_1_1_temp_1" -eq 0 ]] && [[ "$rhel_3_1_1_temp_2" -eq 0 ]] && [[ "$rhel_3_1_1_temp_3" -eq 0 ]] && [[ "$rhel_3_1_1_temp_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IP forwarding is disabled"
  fail=$((fail + 1))
fi

# Ensure packet redirect sending is disabled
echo
echo -e "${RED}3.1.2${NC} Ensure packet redirect sending is disabled"
rhel_3_1_2_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_1_2_temp_1=$?
rhel_3_1_2_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_1_2_temp_2=$?
rhel_3_1_2_temp_3="$(sysctl -w net.ipv4.conf.all.send_redirects=0)"
rhel_3_1_2_temp_3=$?
rhel_3_1_2_temp_4="$(sysctl -w net.ipv4.conf.default.send_redirects=0)"
rhel_3_1_2_temp_4=$?
rhel_3_1_2_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_1_2_temp_5=$?
if [[ "$rhel_3_1_2_temp_1" -eq 0 ]] && [[ "$rhel_3_1_2_temp_2" -eq 0 ]] && [[ "$rhel_3_1_2_temp_3" -eq 0 ]] && [[ "$rhel_3_1_2_temp_4" -eq 0 ]] && [[ "$rhel_3_1_2_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure packet redirect sending is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure packet redirect sending is disabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 3.2 Network Configuration - Network Parameters (Host and Router)
echo
echo -e "${BLUE}3.2 Network Configuration - Network Parameters (Host and Router)${NC}"

# Ensure source routed packets are not accepted
echo
echo -e "${RED}3.2.1${NC} Ensure source routed packets are not accepted"
rhel_3_2_1_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf)"
rhel_3_2_1_temp_1=$?
rhel_3_2_1_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf)"
rhel_3_2_1_temp_2=$?
rhel_3_2_1_temp_3="$(sysctl -w net.ipv4.conf.all.accept_source_route=0)"
rhel_3_2_1_temp_3=$?
rhel_3_2_1_temp_4="$(sysctl -w net.ipv4.conf.default.accept_source_route=0)"
rhel_3_2_1_temp_4=$?
rhel_3_2_1_temp_5="$sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_1_temp_5=$?
if [[ "$rhel_3_2_1_temp_1" -eq 0 ]] && [[ "$rhel_3_2_1_temp_2" -eq 0 ]] && [[ "$rhel_3_2_1_temp_3" -eq 0 ]] && [[ "$rhel_3_2_1_temp_4" -eq 0 ]] && [[ "$rhel_3_2_1_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure source routed packets are not accepted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure source routed packets are not accepted"
  fail=$((fail + 1))
fi

# Ensure ICMP redirects are not accepted
# 1768 Status of the 'all.accept_redirects' setting within the '/etc/sysctl.conf' file
# 1769 Status of the 'default.accept_redirects' setting within the '/etc/sysctl.conf' file
# 1779 Status of the 'net.ipv4.conf.all.send_redirects' setting within the '/etc/sysctl.conf' file

echo
echo -e "${RED}3.2.2${NC} Ensure ICMP redirects are not accepted"
rhel_3_2_2_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_2_temp_1=$?
rhel_3_2_2_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_2_temp_2=$?
rhel_3_2_2_temp_3="$(sysctl -w net.ipv4.conf.all.accept_redirects=0)"
rhel_3_2_2_temp_3=$?
rhel_3_2_2_temp_4="$(sysctl -w net.ipv4.conf.default.accept_redirects=0)"
rhel_3_2_2_temp_4=$?
rhel_3_2_2_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_2_temp_5=$?
if [[ "$rhel_3_2_2_temp_1" -eq 0 ]] && [[ "$rhel_3_2_2_temp_2" -eq 0 ]] && [[ "$rhel_3_2_2_temp_3" -eq 0 ]] && [[ "$rhel_3_2_2_temp_4" -eq 0 ]] && [[ "$rhel_3_2_2_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure ICMP redirects are not accepted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure ICMP redirects are not accepted"
  fail=$((fail + 1))
fi

# Ensure secure ICMP redirects are not accepted
# 1770 Status of the 'all_secure_redirects' setting within the '/etc/sysctl.conf' file
# 1771 Status of the 'default.secure_redirects' setting within the '/etc/sysctl.conf' file

echo
echo -e "${RED}3.2.3${NC} Ensure secure ICMP redirects are not accepted"
rhel_3_2_3_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_3_temp_1=$?
rhel_3_2_3_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_2_3_temp_2=$?
rhel_3_2_3_temp_3="$(sysctl -w net.ipv4.conf.all.secure_redirects=0)"
rhel_3_2_3_temp_3=$?
rhel_3_2_3_temp_4="$(sysctl -w net.ipv4.conf.default.secure_redirects=0)"
rhel_3_2_3_temp_4=$?
rhel_3_2_3_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_3_temp_5=$?
if [[ "$rhel_3_2_3_temp_1" -eq 0 ]] && [[ "$rhel_3_2_3_temp_2" -eq 0 ]] && [[ "$rhel_3_2_3_temp_3" -eq 0 ]] && [[ "$rhel_3_2_3_temp_4" -eq 0 ]] && [[ "$rhel_3_2_3_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure secure ICMP redirects are not accepted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure secure ICMP redirects are not accepted"
  fail=$((fail + 1))
fi

# Ensure suspicious packets are logged
# 2276 Status of the 'net.ipv4.conf.all.log_martians' setting within /etc/sysctl.conf
# 5966 Status of the 'net.ipv4.conf.all.log_martians' network parameter
# 12796 Status of the 'net.ipv4.conf.all.log_martians' network parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories

echo
echo -e "${RED}3.2.4${NC} Ensure suspicious packets are logged"
rhel_3_2_4_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf)"
rhel_3_2_4_temp_1=$?
rhel_3_2_4_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf)"
rhel_3_2_4_temp_2=$?
rhel_3_2_4_temp_3="$(sysctl -w net.ipv4.conf.all.log_martians=1)"
rhel_3_2_4_temp_3=$?
rhel_3_2_4_temp_4="$(sysctl -w net.ipv4.conf.default.log_martians=1)"
rhel_3_2_4_temp_4=$?
rhel_3_2_4_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_4_temp_5=$?
if [[ "$rhel_3_2_4_temp_1" -eq 0 ]] && [[ "$rhel_3_2_4_temp_2" -eq 0 ]] && [[ "$rhel_3_2_4_temp_3" -eq 0 ]] && [[ "$rhel_3_2_4_temp_4" -eq 0 ]] && [[ "$rhel_3_2_4_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure suspicious packets are logged"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure suspicious packets are logged"
  fail=$((fail + 1))
fi

# Ensure broadcast ICMP requests are ignored
# 962 Status of the current setting for 'net.ipv4.icmp_echo_ignore_broadcasts' network parameter

echo
echo -e "${RED}3.2.5${NC} Ensure broadcast ICMP requests are ignored"
rhel_3_2_5_temp_1="$(egrep -q "^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_echo_ignore_broadcasts = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf)"
rhel_3_2_5_temp_1=$?
rhel_3_2_5_temp_2="$(sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1)"
rhel_3_2_5_temp_2=$?
rhel_3_2_5_temp_3="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_5_temp_3=$?
if [[ "$rhel_3_2_5_temp_1" -eq 0 ]] && [[ "$rhel_3_2_5_temp_2" -eq 0 ]] && [[ "$rhel_3_2_5_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure broadcast ICMP requests are ignored"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure broadcast ICMP requests are ignored"
  fail=$((fail + 1))
fi

# Ensure bogus ICMP responses are ignored
# 6836 Status of the 'icmp_ignore_bogus_error_responses' setting
# 10158 Status of the 'net.ipv4.icmp_ignore_bogus_error_responses' setting within the '/etc/sysctl.conf' file
# 12799 Status of the 'net.ipv4.icmp_ignore_bogus_error_responses' network parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories


echo
echo -e "${RED}3.2.6${NC} Ensure bogus ICMP responses are ignored"
rhel_3_2_6_temp_1="$(egrep -q "^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_ignore_bogus_error_responses = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf)"
rhel_3_2_6_temp_1=$?
rhel_3_2_6_temp_2="$(sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1)"
rhel_3_2_6_temp_2=$?
rhel_3_2_6_temp_3="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_6_temp_3=$?
if [[ "$rhel_3_2_6_temp_1" -eq 0 ]] && [[ "$rhel_3_2_6_temp_2" -eq 0 ]] && [[ "$rhel_3_2_6_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure bogus ICMP responses are ignored"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure bogus ICMP responses are ignored"
  fail=$((fail + 1))
fi

# Ensure Reverse Path Filtering is enabled
# 1776 Status of the 'net.ipv4.conf.default.rp_filter' setting within the '/etc/sysctl.conf' file
# 10736 Status of the 'net.ipv4.conf.all.rp_filter ' setting within the '/etc/sysctl.conf' file
# 5958 Status of the current setting for 'net.ipv4.conf.default.rp_filter' network parameter
# 12801 Status of the 'net.ipv4.conf.default.rp_filter' network parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories

echo
echo -e "${RED}3.2.7${NC} Ensure Reverse Path Filtering is enabled"
rhel_3_2_7_temp_1="$(egrep -q "^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf)"
rhel_3_2_7_temp_1=$?
rhel_3_2_7_temp_2="$(egrep -q "^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf)"
rhel_3_2_7_temp_2=$?
rhel_3_2_7_temp_3="$(sysctl -w net.ipv4.conf.all.rp_filter=1)"
rhel_3_2_7_temp_3=$?
rhel_3_2_7_temp_4="$(sysctl -w net.ipv4.conf.default.rp_filter=1)"
rhel_3_2_7_temp_4=$?
rhel_3_2_7_temp_5="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_7_temp_5=$?
if [[ "$rhel_3_2_7_temp_1" -eq 0 ]] && [[ "$rhel_3_2_7_temp_2" -eq 0 ]] && [[ "$rhel_3_2_7_temp_3" -eq 0 ]] && [[ "$rhel_3_2_7_temp_4" -eq 0 ]] && [[ "$rhel_3_2_7_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Reverse Path Filtering is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Reverse Path Filtering is enabled"
  fail=$((fail + 1))
fi

# Ensure TCP SYN Cookies is enabled
# 1777 Status of the 'tcp_syncookies' setting within the '/etc/sysctl.conf' file
# 7096 Status of the current setting for 'net.ipv4.tcp_syncookies' network parameter
# 12802 Status of the 'net.ipv4.tcp_syncookies' network parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories

echo
echo -e "${RED}3.2.8${NC} Ensure TCP SYN Cookies is enabled"
rhel_3_2_8_temp_1="$(egrep -q "^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.tcp_syncookies = 1\2/" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf)"
rhel_3_2_8_temp_1=$?
rhel_3_2_8_temp_2="$(sysctl -w net.ipv4.tcp_syncookies=1)"
rhel_3_2_8_temp_2=$?
rhel_3_2_8_temp_3="$(sysctl -w net.ipv4.route.flush=1)"
rhel_3_2_8_temp_3=$?
if [[ "$rhel_3_2_8_temp_1" -eq 0 ]] && [[ "$rhel_3_2_8_temp_2" -eq 0 ]] && [[ "$rhel_3_2_8_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TCP SYN Cookies is enabled"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 3.3 Network Configuration - IPv6
echo
echo -e "${BLUE}3.3 Network Configuration - IPv6${NC}"

# Ensure IPv6 router advertisements are not accepted
# 7478 Status of the current setting for 'net.ipv6.conf.all.accept_ra' network parameter
# 10488 Status of the 'net.ipv6.conf.all.accept_ra' setting within the '/etc/sysctl.conf' file
# 12804 Status of the 'net.ipv6.conf.default.accept_ra' network parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories
# 7500 Status of the 'net.ipv6.conf.default.accept_ra' network parameter on the host
# 10489 Status of the 'net.ipv6.conf.default.accept_ra' setting within the '/etc/sysctl.conf' file
# 7506 Status of the 'net.ipv6.conf.default.accept_redirects' network parameter on the host
# 10491 Status of the 'net.ipv6.conf.default.accept_redirects' setting within the '/etc/sysctl.conf' file
# 12806 Status of the 'net.ipv6.conf.default.accept_redirects' network parameter configuredunder '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories

echo
echo -e "${RED}3.3.1${NC} Ensure IPv6 router advertisements are not accepted"
rhel_3_3_1_temp_1="$(egrep -q "^(\s*)net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf)"
rhel_3_3_1_temp_1=$?
rhel_3_3_1_temp_2="$(egrep -q "^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf)"
rhel_3_3_1_temp_2=$?
rhel_3_3_1_temp_3="$(sysctl -w net.ipv6.conf.all.accept_ra=0)"
rhel_3_3_1_temp_3=$?
rhel_3_3_1_temp_4="$(sysctl -w net.ipv6.conf.default.accept_ra=0)"
rhel_3_3_1_temp_4=$?
rhel_3_3_1_temp_5="$(sysctl -w net.ipv6.route.flush=1)"
rhel_3_3_1_temp_5=$?
if [[ "$rhel_3_3_1_temp_1" -eq 0 ]] && [[ "$rhel_3_3_1_temp_2" -eq 0 ]] && [[ "$rhel_3_3_1_temp_3" -eq 0 ]] && [[ "$rhel_3_3_1_temp_4" -eq 0 ]] && [[ "$rhel_3_3_1_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IPv6 router advertisements are not accepted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IPv6 router advertisements are not accepted"
  fail=$((fail + 1))
fi

# Ensure IPv6 redirects are not accepted
# 7505 Status of the 'net.ipv6.conf.all.accept_redirects' network parameter on the host
# 7506 Status of the 'net.ipv6.conf.default.accept_redirects' network parameter on the host
# 10490 Status of the 'net.ipv6.conf.all.accept_redirects' setting within the '/etc/sysctl.conf' file
# 12805 Status of the 'net.ipv6.conf.all.accept_redirects' network parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories
# 10491 Status of the 'net.ipv6.conf.default.accept_redirects' setting within the '/etc/sysctl.conf'file
# 12806 Status of the 'net.ipv6.conf.default.accept_redirects' network parameter configured under '/etc/sysctl.d/', '/run/sysctl.d/' or '/usr/lib/sysctl.d/' directories


echo
echo -e "${RED}3.3.2${NC} Ensure IPv6 redirects are not accepted"
rhel_3_3_2_temp_1="$(egrep -q "^(\s*)net.ipv6.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_3_2_temp_1=$?
rhel_3_3_2_temp_2="$(egrep -q "^(\s*)net.ipv6.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf)"
rhel_3_3_2_temp_2=$?
rhel_3_3_2_temp_3="$(sysctl -w net.ipv6.conf.all.accept_redirects=0)"
rhel_3_3_2_temp_3=$?
rhel_3_3_2_temp_4="$(sysctl -w net.ipv6.conf.default.accept_redirects=0)"
rhel_3_3_2_temp_4=$?
rhel_3_3_2_temp_5="$(sysctl -w net.ipv6.route.flush=1)"
rhel_3_3_2_temp_5=$?
if [[ "$rhel_3_3_2_temp_1" -eq 0 ]] && [[ "$rhel_3_3_2_temp_2" -eq 0 ]] && [[ "$rhel_3_3_2_temp_3" -eq 0 ]] && [[ "$rhel_3_3_2_temp_4" -eq 0 ]] && [[ "$rhel_3_3_2_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure IPv6 redirects are not accepted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure IPv6 redirects are not accepted"
  fail=$((fail + 1))
fi


#####
#20632 Status of the current setting for 'kernel.yama.ptrace_scope' parameter

echo
echo -e "${RED}3.3.4${NC} Status of the current setting for 'kernel.yama.ptrace_scope' parameter"
rhel_3_3_4_temp_1="$(egrep -q "^(\s*)kernel.yama.ptrace_scope\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.yama.ptrace_scope\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.yama.ptrace_scope = 1\2/" /etc/sysctl.conf || echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf)"
rhel_3_3_4_temp_1=$?
rhel_3_3_4_temp_2="$(sysctl -w kernel.yama.ptrace_scope=1)"
rhel_3_3_4_temp_2=$?
if [[ "$rhel_3_3_4_temp_1" -eq 0 ]] && [[ "$rhel_3_3_4_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Status of the current setting for 'kernel.yama.ptrace_scope' parameter"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} EStatus of the current setting for 'kernel.yama.ptrace_scope' parameter"
  fail=$((fail + 1))
fi



############################################################################################################################

##Category 3.4 Network Configuration - TCP Wrappers
echo
echo -e "${BLUE}3.4 Network Configuration - TCP Wrappers${NC}"

# Ensure TCP Wrappers is installed
# 11726 Status of the default firewall zone
# 9334 Status of the firewalld service

echo
echo -e "${RED}3.4.1${NC} Ensure TCP Wrappers is installed"
rhel_3_4_1_temp_1="$(rpm -q tcp_wrappers || yum -y install tcp_wrappers)"
rhel_3_4_1_temp_1=$?
rhel_3_4_1_temp_2="$(rpm -q tcp_wrappers-libs || yum -y install tcp_wrappers-libs)"
rhel_3_4_1_temp_2=$?
if [[ "$rhel_3_4_1_temp_1" -eq 0 ]] && [[ "$rhel_3_4_1_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TCP Wrappers is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TCP Wrappers is installed"
  fail=$((fail + 1))
fi

# Ensure /etc/hosts.allow is configured
# 11726 Status of the default firewall zone

echo
echo -e "${RED}3.4.2${NC} Ensure /etc/hosts.allow is configured"
rhel_3_4_2="$(touch /etc/hosts.allow)"
rhel_3_4_2=$?
if [[ "$rhel_3_4_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure /etc/hosts.allow is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure /etc/hosts.allow is configured"
  fail=$((fail + 1))
fi

# Ensure /etc/hosts.deny is configured
# 11726 Status of the default firewall zone

echo
echo -e "${RED}3.4.3${NC} Ensure /etc/hosts.deny is configured"
rhel_3_4_3="$(touch /etc/hosts.deny)"
rhel_3_4_3=$?
if [[ "$rhel_3_4_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure /etc/hosts.deny is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure /etc/hosts.deny is configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/hosts.allow are configured
# 11726 Status of the default firewall zone

echo
echo -e "${RED}3.4.4${NC} Ensure permissions on /etc/hosts.allow are configured"
rhel_3_4_4="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/hosts.allow)"
rhel_3_4_4=$?
if [[ "$rhel_3_4_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/hosts.allow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/hosts.allow are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/hosts.deny are 644
# 11726 Status of the default firewall zone

echo
echo -e "${RED}3.4.5${NC} Ensure permissions on /etc/hosts.deny are configured"
rhel_3_4_5="$(chmod -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/hosts.deny)"
rhel_3_4_5=$?
if [[ "$rhel_3_4_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/hosts.deny are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/hosts.deny are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 3.5 Network Configuration - Uncommon Network Protocols

echo
echo -e "${BLUE}3.5 Network Configuration - Uncommon Network Protocols${NC}"

# Ensure DCCP is disabled
echo
echo -e "${RED}3.5.1${NC} Ensure DCCP is disabled"
rhel_3_5_1="$(modprobe -n -v dccp | grep "^install /bin/true$" || egrep -q "^\s*install\s+dccp\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_1=$?
lsmod | egrep "^dccp\s" && rmmod dccp
if [[ "$rhel_3_5_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure DCCP is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure DCCP is disabled"
  fail=$((fail + 1))
fi

# Ensure SCTP is disabled
echo
echo -e "${RED}3.5.2${NC} Ensure SCTP is disabled"
rhel_3_5_2="$(modprobe -n -v sctp | grep "^install /bin/true$" || egrep -q "^\s*install\s+sctp\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf ||  echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_2=$?
lsmod | egrep "^sctp\s" && rmmod sctp
if [[ "$rhel_3_5_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SCTP is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SCTP is disabled"
  fail=$((fail + 1))
fi

# Ensure RDS is disabled
echo
echo -e "${RED}3.5.3${NC} Ensure RDS is disabled"
rhel_3_5_3="$(modprobe -n -v rds | grep "^install /bin/true$" || egrep -q "^\s*install\s+rds\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_3=$?
lsmod | egrep "^rds\s" && rmmod rds
if [[ "$rhel_3_5_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure RDS is disabled"
  fail=$((fail + 1))
fi

# Ensure TIPC is disabled
echo
echo -e "${RED}3.5.4${NC} Ensure TIPC is disabled"
rhel_3_5_4="$(modprobe -n -v tipc | grep "^install /bin/true$" || egrep -q "^\s*install\s+tipc\s+\/bin\/true(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf)"
rhel_3_5_4=$?
lsmod | egrep "^tipc\s" && rmmod tipc
if [[ "$rhel_3_5_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TIPC is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TIPC is disabled"
  fail=$((fail + 1))
fi

############################################################################################################################
 
##Category 3.6 Network Configuration - Firewall Configuration
echo
echo -e "${BLUE}3.6 Network Configuration - Firewall Configuration${NC}"

# Ensure iptables is installed
echo
echo -e "${RED}3.6.1${NC} Ensure iptables is installed"
rhel_3_6_1="$(rpm -q iptables || rpm -q firewalld || yum -y install iptables)"
rhel_3_6_1=$?
if [[ "$rhel_3_6_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure iptables is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure iptables is installed"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 4.1 Logging and Auditing - Configure System Accounting (auditd)

cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.$TIMESTAMP # Added by RK

echo
echo -e "${BLUE}4.1 Logging and Auditing - Configure System Accounting (auditd)${NC}"

# Ensure system is disabled when audit logs are full
echo
echo -e "${RED}4.1.1.2${NC} Ensure system is disabled when audit logs are full"
rhel_4_1_1_2_temp_1="$(egrep -q "^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1space_left_action = email\2/" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf)"
rhel_4_1_1_2_temp_1=$?
rhel_4_1_1_2_temp_2="$(egrep -q "^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$/\1action_mail_acct = root\2/" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf)"
rhel_4_1_1_2_temp_2=$?
rhel_4_1_1_2_temp_3="$(egrep -q "^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1admin_space_left_action = halt\2/" /etc/audit/auditd.conf || echo "admin_space_left_action = single" >> /etc/audit/auditd.conf)"
rhel_4_1_1_2_temp_3=$?
if [[ "$rhel_4_1_1_2_temp_1" -eq 0 ]] && [[ "$rhel_4_1_1_2_temp_2" -eq 0 ]] && [[ "$rhel_4_1_1_2_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure system is disabled when audit logs are full"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure system is disabled when audit logs are full"
  fail=$((fail + 1))
fi

# Ensure audit logs are not automatically deleted
# Changed by RK
echo
echo -e "${RED}4.1.1.3${NC} Ensure audit logs are not automatically deleted"
rhel_4_1_1_3="$(egrep -q "^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$/\1max_log_file_action = rotate\2/" /etc/audit/auditd.conf)"
rhel_4_1_1_3=$?
if [[ "$rhel_4_1_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure audit logs are not automatically deleted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure audit logs are not automatically deleted"
  fail=$((fail + 1))
fi

# Ensure auditd service is enabled

echo
echo -e "${RED}4.1.2${NC} Ensure auditd service is enabled"
rhel_4_1_2="$(systemctl enable auditd.service)"
rhel_4_1_2=$?
if [[ "$rhel_4_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditd service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditd service is enabled"
  fail=$((fail + 1))
fi

# Ensure auditing for processes that start prior to auditd is enabled

cp -a /etc/default/grub /etc/default/grub.$TIMESTAMP # Added by RK

echo
echo -e "${RED}4.1.3${NC} Ensure auditing for processes that start prior to auditd is enabled"
rhel_4_1_3_temp_1="$(egrep -q "^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+)?\"(\s*#.*)?\s*$" /etc/default/grub && sed -ri '/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]*)?\"(\s*#.*)?\s*$/ {/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+\s+)?audit=\S+(\s+[^\"]+)?\"(\s*#.*)?\s*$/! s/^(\s*GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+)?)(\"(\s*#.*)?\s*)$/\1 audit=1\3/ }' /etc/default/grub && sed -ri "s/^((\s*)GRUB_CMDLINE_LINUX\s*=\s*\"([^\"]+\s+)?)audit=\S+((\s+[^\"]+)?\"(\s*#.*)?\s*)$/\1audit=1\4/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX=\"audit=1\"" >> /etc/default/grub)"
rhel_4_1_3_temp_1=$?
rhel_4_1_3_temp_2="$(grub2-mkconfig -o /boot/grub2/grub.cfg)"
rhel_4_1_3_temp_2=$?
if [[ "$rhel_4_1_3_temp_1" -eq 0 ]] && [[ "$rhel_4_1_3_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure auditing for processes that start prior to auditd is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure auditing for processes that start prior to auditd is enabled"
  fail=$((fail + 1))
fi

# Ensure events that modify date and time information are collected

cp -a /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.$TIMESTAMP # Added by RK

echo
echo -e "${RED}4.1.4${NC} Ensure events that modify date and time information are collected"
rhel_4_1_4_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_4_temp_1=$?
rhel_4_1_4_temp_2="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_4_temp_2=$?
egrep "^-w\s+/etc/localtime\s+-p\s+wa\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules
rhel_4_1_4_temp_3="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_4_temp_3=$?
if [[ "$rhel_4_1_4_temp_1" -eq 0 ]] && [[ "$rhel_4_1_4_temp_2" -eq 0 ]] && [[ "$rhel_4_1_4_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify date and time information are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify date and time information are collected"
  fail=$((fail + 1))
fi

# Ensure events that modify user/group information are collected

echo
echo -e "${RED}4.1.5${NC} Ensure events that modify user/group information are collected"
rhel_4_1_5_temp_1="$(egrep "^-w\s+/etc/group\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_1=$?
rhel_4_1_5_temp_2="$(egrep "^-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_2=$?
rhel_4_1_5_temp_3="$(egrep "^-w\s+/etc/gshadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_3=$?
rhel_4_1_5_temp_4="$(egrep "^-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_4=$?
rhel_4_1_5_temp_5="$(egrep "^-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_5_temp_5=$?
if [[ "$rhel_4_1_5_temp_1" -eq 0 ]] && [[ "$rhel_4_1_5_temp_2" -eq 0 ]] && [[ "$rhel_4_1_5_temp_3" -eq 0 ]] && [[ "$rhel_4_1_5_temp_4" -eq 0 ]] && [[ "$rhel_4_1_5_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify user/group information are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify user/group information are collected"
  fail=$((fail + 1))
fi

# Ensure events that modify the system's network environment are collected

echo
echo -e "${RED}4.1.6${NC} Ensure events that modify the system's network environment are collected"
rhel_4_1_6_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_1=$?
rhel_4_1_6_temp_2="$(egrep "^-w\s+/etc/issue\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_2=$?
rhel_4_1_6_temp_3="$(egrep "^-w\s+/etc/issue.net\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_3=$?
rhel_4_1_6_temp_4="$(egrep "^-w\s+/etc/hosts\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_4=$?
egrep "^-w\s+/etc/sysconfig/network\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
rhel_4_1_6_temp_5="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_6_temp_5=$?
if [[ "$rhel_4_1_6_temp_1" -eq 0 ]] && [[ "$rhel_4_1_6_temp_2" -eq 0 ]] && [[ "$rhel_4_1_6_temp_3" -eq 0 ]] && [[ "$rhel_4_1_6_temp_4" -eq 0 ]] && [[ "$rhel_4_1_6_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's network environment are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify the system's network environment are collected"
  fail=$((fail + 1))
fi

# Ensure events that modify the system's Mandatory Access Controls are collected

echo
echo -e "${RED}4.1.7${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
rhel_4_1_7="$(egrep "^-w\s+/etc/selinux/\s+-p\s+wa\s+-k\s+MAC-policy\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_7=$?
if [[ "$rhel_4_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
  fail=$((fail + 1))
fi

# Ensure login and logout events are collected

echo
echo -e "${RED}4.1.8${NC} Ensure login and logout events are collected"
rhel_4_1_8_temp_1="$(egrep "^-w\s+/var/run/faillock/\s+-p\s+wa\s+-k\s+logins\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_8_temp_1=$?
rhel_4_1_8_temp_2="$(egrep "^-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_8_temp_2=$?
if [[ "$rhel_4_1_8_temp_1" -eq 0 ]] && [[ "$rhel_4_1_8_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure login and logout events are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure login and logout events are collected"
  fail=$((fail + 1))
fi

# Ensure session initiation information is collected

echo
echo -e "${RED}4.1.9${NC} Ensure session initiation information is collected"
rhel_4_1_9_temp_1="$(egrep "^-w\s+/var/run/utmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_9_temp_1=$?
rhel_4_1_9_temp_2="$(egrep "^-w\s+/var/log/wtmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_9_temp_2=$?
rhel_4_1_9_temp_3="$(egrep "^-w\s+/var/log/btmp\s+-p\s+wa\s+-k\s+session\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_9_temp_3=$?
if [[ "$rhel_4_1_9_temp_1" -eq 0 ]] && [[ "$rhel_4_1_9_temp_2" -eq 0 ]] && [[ "$rhel_4_1_9_temp_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure session initiation information is collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure session initiation information is collected"
  fail=$((fail + 1))
fi

# Ensure discretionary access control permission modification events are collected

echo
echo -e "${RED}4.1.10${NC} Ensure discretionary access control permission modification events are collected"
rhel_4_1_10_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_1=$?
rhel_4_1_10_temp_2="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_2=$?
rhel_4_1_10_temp_3="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_3=$?
rhel_4_1_10_temp_4="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_4=$?
rhel_4_1_10_temp_5="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_5=$?
rhel_4_1_10_temp_6="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_10_temp_6=$?
if [[ "$rhel_4_1_10_temp_1" -eq 0 ]] && [[ "$rhel_4_1_10_temp_2" -eq 0 ]] && [[ "$rhel_4_1_10_temp_3" -eq 0 ]] && [[ "$rhel_4_1_10_temp_4" -eq 0 ]] && [[ "$rhel_4_1_10_temp_5" -eq 0 ]] && [[ "$rhel_4_1_10_temp_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure discretionary access control permission modification events are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure discretionary access control permission modification events are collected"
  fail=$((fail + 1))
fi

# Ensure unsuccessful unauthorized file access attempts are collected

echo
echo -e "${RED}4.1.11${NC} Ensure unsuccessful unauthorized file access attempts are collected"
rhel_4_1_11_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_1=$?
rhel_4_1_11_temp_2="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_2=$?
rhel_4_1_11_temp_3="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_3=$?
rhel_4_1_11_temp_4="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_11_temp_4=$?
if [[ "$rhel_4_1_11_temp_1" -eq 0 ]] && [[ "$rhel_4_1_11_temp_2" -eq 0 ]] && [[ "$rhel_4_1_11_temp_3" -eq 0 ]] && [[ "$rhel_4_1_11_temp_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure unsuccessful unauthorized file access attempts are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure unsuccessful unauthorized file access attempts are collected"
  fail=$((fail + 1))
fi

# Ensure use of privileged commands is collected

echo
echo -e "${RED}4.1.12${NC} Ensure use of privileged commands is collected"
rhel_4_1_12_temp=0
for file in `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f`; do egrep -q "^\s*-a\s+(always,exit|exit,always)\s+-F\s+path=$file\s+-F\s+perm=x\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged\s*(#.*)?$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/audit.rules;  ((rhel_4_1_12_temp=rhel_4_1_12_temp+1)); done
rhel_4_1_12_temp_2="$( ls -1q / | wc -l)"
if [[ "$rhel_4_1_12_temp" -ge "$rhel_4_1_12_temp_2" ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure use of privileged commands is collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure use of privileged commands is collected"
  fail=$((fail + 1))
fi

# Ensure successful file system mounts are collected

echo
echo -e "${RED}4.1.13${NC} Ensure successful file system mounts are collected"
rhel_4_1_13_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_13_temp_1=$?
rhel_4_1_13_temp_2="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_13_temp_2=$?
if [[ "$rhel_4_1_13_temp_1" -eq 0 ]] && [[ "$rhel_4_1_13_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure successful file system mounts are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure successful file system mounts are collected"
  fail=$((fail + 1))
fi

# Ensure file deletion events by users are collected

echo
echo -e "${RED}4.1.14${NC} Ensure file deletion events by users are collected"
rhel_4_1_14_temp_1="$(egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_14_temp_1=$?
rhel_4_1_14_temp_2="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_14_temp_2=$?
if [[ "$rhel_4_1_14_temp_1" -eq 0 ]] && [[ "$rhel_4_1_14_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure file deletion events by users are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure file deletion events by users are collected"
  fail=$((fail + 1))
fi

# Ensure changes to system administration scope (sudoers) is collected

echo
echo -e "${RED}4.1.15${NC} Ensure changes to system administration scope (sudoers) is collected"
rhel_4_1_15_temp_1="$(egrep "^-w\s+/etc/sudoers\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_15_temp_1=$?
rhel_4_1_15_temp_2="$(egrep "^-w\s+/etc/sudoers.d\s+-p\s+wa\s+-k\s+scope\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_15_temp_2=$?
if [[ "$rhel_4_1_15_temp_1" -eq 0 ]] && [[ "$rhel_4_1_15_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure changes to system administration scope (sudoers) is collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure changes to system administration scope (sudoers) is collected"
  fail=$((fail + 1))
fi

# Ensure system administrator actions (sudolog) are collected

echo
echo -e "${RED}4.1.16${NC} Ensure system administrator actions (sudolog) are collected"
rhel_4_1_16="$(egrep "^-w\s+/var/log/sudo.log\s+-p\s+wa\s+-k\s+actions\s*$" /etc/audit/rules.d/audit.rules || echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_16=$?
if [[ "$rhel_4_1_16" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure system administrator actions (sudolog) are collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure system administrator actions (sudolog) are collected"
  fail=$((fail + 1))
fi

# Ensure kernel module loading and unloading is collected


echo
echo -e "${RED}4.1.17${NC} Ensure kernel module loading and unloading is collected"
rhel_4_1_17_temp_1="$(egrep "^-w\s+/sbin/insmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_1=$?
rhel_4_1_17_temp_2="$(egrep "^-w\s+/sbin/rmmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_2=$?
rhel_4_1_17_temp_3="$(egrep "^-w\s+/sbin/modprobe\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_3=$?
rhel_4_1_17_temp_4="$(uname -p | grep -q 'x86_64' || egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_4=$?
rhel_4_1_17_temp_5="$(uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_17_temp_5=$?
if [[ "$rhel_4_1_17_temp_1" -eq 0 ]] && [[ "$rhel_4_1_17_temp_2" -eq 0 ]] && [[ "$rhel_4_1_17_temp_3" -eq 0 ]] && [[ "$rhel_4_1_17_temp_4" -eq 0 ]] && [[ "$rhel_4_1_17_temp_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure kernel module loading and unloading is collected"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure kernel module loading and unloading is collected"
  fail=$((fail + 1))
fi

# Ensure the audit configuration is immutable

echo
echo -e "${RED}4.1.18${NC} Ensure the audit configuration is immutable"
rhel_4_1_18="$(egrep "^-e\s+2\s*$" /etc/audit/rules.d/audit.rules || echo "-e 2" >> /etc/audit/rules.d/audit.rules)"
rhel_4_1_18=$?
augenrules --load
if [[ "$rhel_4_1_18" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure the audit configuration is immutable"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the audit configuration is immutable"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"

# Ensure rsyslog Service is enabled
# 7440 Status of the currently installed 'rsyslog' package on the host
# 9335 Status of the rsyslog services
echo
echo -e "${RED}4.2.1.1${NC} Ensure rsyslog Service is enabled"
rhel_4_2_1_1="$(rpm -q rsyslog && yum install rsyslog -y && systemctl enable rsyslog.service)"
rhel_4_2_1_1=$?
if [[ "$rhel_4_2_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog Service is enabled"
  fail=$((fail + 1))
fi

# Ensure syslog-ng service is enabled
# 7440 Status of the currently installed 'rsyslog' package on the host
# 9335 Status of the rsyslog services
echo
echo -e "${RED}4.2.2.1${NC} Ensure syslog-ng service is enabled"
rhel_4_2_2_1="$(rpm -q syslog-ng && systemctl enable syslog-ng.service)"
rhel_4_2_2_1=$?
if [[ "$rhel_4_2_2_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure syslog-ng service is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure syslog-ng service is enabled"
  fail=$((fail + 1))
fi

# Ensure rsyslog or syslog-ng is installed
# 7440 Status of the currently installed 'rsyslog' package on the host
# 9335 Status of the rsyslog services
echo
echo -e "${RED}4.2.3${NC} Ensure rsyslog or syslog-ng is installed"
rhel_4_2_3="$(rpm -q rsyslog || rpm -q syslog-ng || yum -y install rsyslog)"
rhel_4_2_3=$?
if [[ "$rhel_4_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog or syslog-ng is installed"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog or syslog-ng is installed"
  fail=$((fail + 1))
fi

# Ensure permissions on all logfiles are configured
# Some applicaton like mdatp , oms agents logs will be not worked
# 10673 Status of the 'permission' set for all logfiles in '/var/log' directory
# Changed by RK

echo
echo -e "${RED}4.2.4${NC} Ensure permissions on all logfiles are configured"
rhel_4_2_4="$(find /var/log -type f -exec chmod 640 -- {} +)"
rhel_4_2_4=$?
if [[ "$rhel_4_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on all logfiles are configuredd"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 5.1 Access, Authentication and Authorization - Configure cron
echo
echo -e "${BLUE}5.1 Access, Authentication and Authorization - Configure cron${NC}"

# Ensure cron daemon is enabled
# 9337 Status of the crond service

echo
echo -e "${RED}5.1.1${NC} Ensure cron daemon is enabled"
rhel_5_1_1="$(systemctl enable crond.service)"
rhel_5_1_1=$?
if [[ "$rhel_5_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure cron daemon is enabled"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/crontab are configured
#5154 Status of the 'Permissions' for the '/etc/crontab' file(s)
echo
echo -e "${RED}5.1.2${NC} Ensure permissions on /etc/crontab are configured"
rhel_5_1_2="$(chmod g-r-w-x,o-r-w-x /etc/crontab)"
rhel_5_1_2=$?
if [[ "$rhel_5_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/crontab are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/crontab are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/cron.hourly are configured
# 7343 Status of the 'Permissions' settings for the '/etc/cron.hourly' directory

echo
echo -e "${RED}5.1.3${NC} Ensure permissions on /etc/cron.hourly are configured"
rhel_5_1_3="$(chmod g-r-w-x,o-r-w-x /etc/cron.hourly)"
rhel_5_1_3=$?
if [[ "$rhel_5_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.hourly are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.hourly are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/cron.daily are configured
# 7341 Status of the 'Permissions' settings for the '/etc/cron.daily' directory
echo
echo -e "${RED}5.1.4${NC} Ensure permissions on /etc/cron.daily are configured"
rhel_5_1_4="$(chmod g-r-w-x,o-r-w-x /etc/cron.daily)"
rhel_5_1_4=$?
if [[ "$rhel_5_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.daily are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.daily are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/cron.weekly are configured
# 7345 Status of the 'Permissions' settings for the '/etc/cron.weekly' directory
echo
echo -e "${RED}5.1.5${NC} Ensure permissions on /etc/cron.weekly are configured"
rhel_5_1_5="$(chmod g-r-w-x,o-r-w-x /etc/cron.weekly)"
rhel_5_1_5=$?
if [[ "$rhel_5_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.weekly are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.weekly are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/cron.monthly are configured
# 7347 Status of the 'Permissions' settings for the '/etc/cron.monthly' directory
echo
echo -e "${RED}5.1.6${NC} Ensure permissions on /etc/cron.monthly are configured"
rhel_5_1_6="$(chmod g-r-w-x,o-r-w-x /etc/cron.monthly)"
rhel_5_1_6=$?
if [[ "$rhel_5_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.monthly are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.monthly are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/cron.d are configured
# 7348 Status of the 'Ownership' settings for the '/etc/cron.monthly' directory
echo
echo -e "${RED}5.1.7${NC} Ensure permissions on /etc/cron.d are configured enabled"
rhel_5_1_7="$(chmod g-r-w-x,o-r-w-x /etc/cron.d)"
rhel_5_1_7=$?
if [[ "$rhel_5_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.d are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.d are configured"
  fail=$((fail + 1))
fi

# Ensure at/cron is restricted to authorized users
# 5057 Permissions set for the '/etc/cron.allow' file
echo
echo -e "${RED}5.1.8${NC} Ensure at/cron is restricted to authorized users"
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
rhel_5_1_8_temp_1="$(chmod g-r-w-x,o-r-w-x /etc/cron.allow)"
rhel_5_1_8_temp_1=$?
rhel_5_1_8_temp_2="$(chmod g-r-w-x,o-r-w-x /etc/at.allow)"
rhel_5_1_8_temp_2=$?
if [[ "$rhel_5_1_8_temp_1" -eq 0 ]] && [[ "$rhel_5_1_8_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure at/cron is restricted to authorized users"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure at/cron is restricted to authorized users"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

cp /etc/ssh/sshd_config /etc/ssh/sshd_config_$TIMESTAMP # Added by RK

# Ensure permissions on /etc/ssh/sshd_config are configured
# 4585 Status of the 'Ownership' settings for the '/etc/ssh/sshd_config' file

echo
echo -e "${RED}5.2.1${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
rhel_5_2_1="$(chmod g-r-w-x,o-r-w-x /etc/ssh/sshd_config)"
rhel_5_2_1=$?
if [[ "$rhel_5_2_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
  fail=$((fail + 1))
fi

# Ensure SSH Protocol is set to 2
# Changed by RK
echo
echo -e "${RED}5.2.2${NC} Ensure SSH Protocol is set to 2"
rhel_5_2_2="$(egrep -q "^(\s*)Protocol\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Protocol\s+\S+(\s*#.*)?\s*$/\1Protocol 2\2/" /etc/ssh/sshd_config || sed -ri '18 i Protocol 2' /etc/ssh/sshd_config)"
rhel_5_2_2=$?
if [[ "$rhel_5_2_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Protocol is set to 2"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2" 
  fail=$((fail + 1))
fi

# Ensure SSH LogLevel is set to INFO
# 3598 Status of the 'LogLevel' option in the '/etc/ssh/sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.3${NC} Ensure SSH LogLevel is set to INFO"
rhel_5_2_3="$(egrep -q "^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$/\1LogLevel INFO\2/" /etc/ssh/sshd_config || sed -ri "1,/#LogLevel\s+\S+(\s*#.*)?\s*$/s/^(\s*)#LogLevel\s+\S+(\s*#.*)?\s*$/\1LogLevel INFO\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config ||  echo "LogLevel INFO" >> /etc/ssh/sshd_config)"
rhel_5_2_3=$?
if [[ "$rhel_5_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LogLevel is set to INFO"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LogLevel is set to INFO"
  fail=$((fail + 1))
fi

# Ensure SSH X11 forwarding is disabled
# Changed by RK
# Check with the user wheather they are using x11 forwarding

echo
echo -e "${RED}5.2.4${NC} Ensure SSH X11 forwarding is disabled"
rhel_5_2_4="$(egrep -q "^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$/\1X11Forwarding no\2/" /etc/ssh/sshd_config || sed -ri "1,/#X11Forwarding\s+\S+(\s*#.*)?\s*$/s/^(\s*)#X11Forwarding\s+\S+(\s*#.*)?\s*$/\1X11Forwarding no\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config)"
rhel_5_2_4=$?
if [[ "$rhel_5_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH X11 forwarding is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH X11 forwarding is disabled"
  fail=$((fail + 1))
fi

# Ensure SSH MaxAuthTries is set to 4 or less
# 2234 Status of the 'MaxAuthTries' setting in the 'sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.5${NC} Ensure SSH MaxAuthTries is set to 4 or less"
rhel_5_2_5="$(egrep -q "^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$/\1MaxAuthTries 4\2/" /etc/ssh/sshd_config || sed -ri "1,/#MaxAuthTries\s+\S+(\s*#.*)?\s*$/s/^(\s*)#MaxAuthTries\s+\S+(\s*#.*)?\s*$/\1MaxAuthTries 4\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config)"
rhel_5_2_5=$?
if [[ "$rhel_5_2_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  fail=$((fail + 1))
fi

# Ensure SSH IgnoreRhosts is enabled
# 2236 Status of the 'IgnoreRhosts' setting in the '/etc/ssh/sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.6${NC} Ensure SSH IgnoreRhosts is enabled"
rhel_5_2_6="$(egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || sed -ri "1,/#IgnoreRhosts\s+\S+(\s*#.*)?\s*$/s/^(\s*)#IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config)"
rhel_5_2_6=$?
if [[ "$rhel_5_2_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH IgnoreRhosts is enabled"
  fail=$((fail + 1))
fi

# Ensure SSH HostbasedAuthentication is disabled
# 2278 Status of the 'HostBasedAuthentication' setting in '/etc/ssh/sshd_config'
# Changed by RK
echo
echo -e "${RED}5.2.7${NC} Ensure SSH HostbasedAuthentication is disabled"
rhel_5_2_7="$(egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || sed -ri "1,/#HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/s/^(\s*)#HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config)"
rhel_5_2_7=$?
if [[ "$rhel_5_2_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH HostbasedAuthentication is disabled"
  fail=$((fail + 1))
fi

# Ensure SSH root login is disabled
# 2239 Status of the 'PermitRootLogin' setting in the 'sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.8${NC} Ensure SSH root login is disabled"
rhel_5_2_8="$(egrep -q "^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$/\1PermitRootLogin no\2/" /etc/ssh/sshd_config || sed -ri "1,/#PermitRootLogin\s+\S+(\s*#.*)?\s*$/s/^(\s*)#PermitRootLogin\s+\S+(\s*#.*)?\s*$/\1PermitRootLogin no\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config)"
rhel_5_2_8=$?
if [[ "$rhel_5_2_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH root login is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH root login is disabled"
  fail=$((fail + 1))
fi

# Ensure SSH PermitEmptyPasswords is disabled 
# 2240 Status of the 'PermitEmptyPasswords' setting in the 'sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.9${NC} Ensure SSH PermitEmptyPasswords is disabled"
rhel_5_2_9="$(egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || sed -ri "1,/#PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/s/^(\s*)#PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config)"
rhel_5_2_9=$?
if [[ "$rhel_5_2_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  fail=$((fail + 1))
fi

# Ensure SSH PermitUserEnvironment is disabled
# 5279 Status of the 'PermitUserEnvironment' setting in the '/etc/ssh/sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.10${NC} Ensure SSH PermitUserEnvironment is disable"
rhel_5_2_10="$(egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || sed -ri "1,/#PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/s/^(\s*)#PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config)"
rhel_5_2_10=$?
if [[ "$rhel_5_2_10" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disable"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitUserEnvironment is disable"
  fail=$((fail + 1))
fi

# Ensure only approved MAC algorithms are used
# 17996 Status of the 'MACs' setting in the '/etc/ssh/sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.11${NC} Ensure only approved MAC algorithms are used"
rhel_5_2_11="$(egrep -q "^(\s*)MACs\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MACs\s+\S+(\s*#.*)?\s*$/\1MACs hmac-sha2-512,hmac-sha2-256\2/" /etc/ssh/sshd_config || sed -ri '30 i MACs hmac-sha2-512,hmac-sha2-256' /etc/ssh/sshd_config)"
rhel_5_2_11=$?
if [[ "$rhel_5_2_11" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure only approved MAC algorithms are used"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure only approved MAC algorithms are used"
  fail=$((fail + 1))
fi

# Ensure only approved KexAlgorithms are used
# 14400 Status of the 'kexalgorithms' setting within the /etc/ssh/sshd_config file
# Added by RK
echo
echo -e "${RED}5.2.12${NC} Ensure only approved KexAlgorithms are used"
rhel_5_2_12="$(egrep -q "^(\s*)KexAlgorithms\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)KexAlgorithms\s+\S+(\s*#.*)?\s*$/\1KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256\2/" /etc/ssh/sshd_config || sed -ri '31 i KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256' /etc/ssh/sshd_config)"
rhel_5_2_12=$?
if [[ "$rhel_5_2_12" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure only approved KexAlgorithms are used"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure only approved KexAlgorithms are used"
  fail=$((fail + 1))
fi

# Ensure only approved Ciphers are used
# 5220 Status of the 'Ciphers' setting in the 'sshd_config' file
# Added by RK
echo
echo -e "${RED}5.2.13${NC} Ensure only approved Ciphers are used"
rhel_5_2_13="$(egrep -q "^(\s*)Ciphers\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Ciphers\s+\S+(\s*#.*)?\s*$/\1Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\2/" /etc/ssh/sshd_config || sed -ri '32 i Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com'  /etc/ssh/sshd_config)"
rhel_5_2_13=$?
if [[ "$rhel_5_2_13" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure only approved Ciphers are used"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure only approved Ciphers are used"
  fail=$((fail + 1))
fi


# Ensure SSH Idle Timeout Interval is configured
# 5222 Status of the 'ClientAliveInterval' setting in the 'sshd_config' file
# 5221 Status of the 'ClientAliveCountMax' setting in the 'sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.14${NC} Ensure SSH Idle Timeout Interval is configured"
rhel_5_2_14_temp_1="$(egrep -q "^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\1ClientAliveInterval 300\2/" /etc/ssh/sshd_config || sed -ri "1,/#ClientAliveInterval\s+\S+(\s*#.*)?\s*$/s/^(\s*)#ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\1ClientAliveInterval 300\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config)"
rhel_5_2_14_temp_1=$?
rhel_5_2_14_temp_2="$(egrep -q "^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\1ClientAliveCountMax 3\2/" /etc/ssh/sshd_config || sed -ri "1,/#ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/s/^(\s*)#ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\1ClientAliveCountMax 3\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config)"
rhel_5_2_14_temp_2=$?

if [[ "$rhel_5_2_14_temp_1" -eq 0 ]] && [[ "$rhel_5_2_14_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Idle Timeout Interval is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Idle Timeout Interval is configured"
  fail=$((fail + 1))
fi

# Ensure SSH LoginGraceTime is set to one minute or less
# 5281 Status of the 'LoginGraceTime' setting in the '/etc/ssh/sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.15${NC} Ensure SSH LoginGraceTime is set to one minute or less"
rhel_5_2_15="$(egrep -q "^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$/\1LoginGraceTime 60\2/" /etc/ssh/sshd_config || sed -ri "1,/#LoginGraceTime\s+\S+(\s*#.*)?\s*$/s/^(\s*)#LoginGraceTime\s+\S+(\s*#.*)?\s*$/\1LoginGraceTime 60\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config || echo "LoginGraceTime 60" >> /etc/ssh/sshd_config)"
rhel_5_2_15=$?

if [[ "$rhel_5_2_15" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  fail=$((fail + 1))
fi

# Ensure SSH warning banner is configured
# 2241 Status of the 'Banner' setting in the 'sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.16${NC} Ensure SSH warning banner is configured"
rhel_5_2_16="$(egrep -q "^(\s*)Banner\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Banner\s+\S+(\s*#.*)?\s*$/\1Banner \/etc\/issue.net\2/" /etc/ssh/sshd_config || sed -ri "1,/#Banner\s+\S+(\s*#.*)?\s*$/s/^(\s*)#Banner\s+\S+(\s*#.*)?\s*$/\1Banner \/etc\/issue.net\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)Banner\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config ||  echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config)"
rhel_5_2_16=$?
if [[ "$rhel_5_2_16" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH warning banner is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH warning banner is configured"
  fail=$((fail + 1))
fi

# Ensure SSH MaxStartups is configured
# 5284 Status of the 'MaxStartups' setting in the '/etc/ssh/sshd_config' file
# Changed by RK
echo
echo -e "${RED}5.2.17${NC} Ensure MaxStartups is configured"
rhel_5_2_17="$(egrep -q "^(\s*)MaxStartups\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxStartups\s+\S+(\s*#.*)?\s*$/\1MaxStartups 10:30:60\2/" /etc/ssh/sshd_config || sed -ri "1,/#MaxStartups\s+\S+(\s*#.*)?\s*$/s/^(\s*)#MaxStartups\s+\S+(\s*#.*)?\s*$/\1MaxStartups 10:30:60\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)MaxStartups\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config ||  echo "MaxStartups 10:30:60" >> /etc/ssh/sshd_config)"
rhel_5_2_17=$?
if [[ "$rhel_5_2_17" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure MaxStartups is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure MaxStartups is configured"
  fail=$((fail + 1))
fi

# Ensure SSH MaxSessions is configured
# 5373 Status of the 'MaxSessions' setting in the '/etc/ssh/sshd_config' file
# Added by RK
echo
echo -e "${RED}5.2.18${NC} Ensure MaxSessions  is configured"
rhel_5_2_18="$(egrep -q "^(\s*)MaxSessions\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxSessions\s+\S+(\s*#.*)?\s*$/\1MaxSessions 4\2/" /etc/ssh/sshd_config || sed -ri "1,/#MaxSessions\s+\S+(\s*#.*)?\s*$/s/^(\s*)#MaxSessions\s+\S+(\s*#.*)?\s*$/\1MaxSessions 4\2/" /etc/ssh/sshd_config && egrep -q "^(\s*)MaxSessions\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config ||  echo "MaxSessions 4" >> /etc/ssh/sshd_config)"
rhel_5_2_18=$?
if [[ "$rhel_5_2_18" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure MaxStartups is configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure MaxStartups is configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 5.3 Access, Authentication and Authorization - Configure PAM
echo
echo -e "${BLUE}5.3 Access, Authentication and Authorization - Configure PAM${NC}"
cp /etc/security/pwquality.conf /etc/ssh/pwquality.conf_$TIMESTAMP # Added by RK

# Ensure password creation requirements are configured
# Added by RK
echo
echo -e "${RED}5.3.1${NC} Ensure password creation requirements are configured"
rhel_5_3_1_temp_1="$(egrep -q "^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$/\1minlen = 14\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]minlen\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]minlen\s*=\s*\S+(\s*#.*)?\s*$/\1minlen = 14\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#minlen\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#minlen\s*=\s*\S+(\s*#.*)?\s*$/\minlen = 14\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "minlen = 14" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_1=$?

rhel_5_3_1_temp_2="$(egrep -q "^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$/\1dcredit = -1\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]dcredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]dcredit\s*=\s*\S+(\s*#.*)?\s*$/\1dcredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#dcredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#dcredit\s*=\s*\S+(\s*#.*)?\s*$/\dcredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "dcredit = -1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_2=$?

rhel_5_3_1_temp_3="$(egrep -q "^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$/\1ucredit = -1\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]ucredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]ucredit\s*=\s*\S+(\s*#.*)?\s*$/\1ucredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#ucredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#ucredit\s*=\s*\S+(\s*#.*)?\s*$/\ucredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "ucredit = -1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_3=$?

rhel_5_3_1_temp_4="$(egrep -q "^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$/\1ocredit = -1\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]ocredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]ocredit\s*=\s*\S+(\s*#.*)?\s*$/\1ocredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#ocredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#ocredit\s*=\s*\S+(\s*#.*)?\s*$/\ocredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "ocredit = -1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_4=$?

rhel_5_3_1_temp_5="$(egrep -q "^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$/\1lcredit = -1\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]lcredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]lcredit\s*=\s*\S+(\s*#.*)?\s*$/\1lcredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#lcredit\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#lcredit\s*=\s*\S+(\s*#.*)?\s*$/\lcredit = -1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "lcredit = -1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_5=$?

rhel_5_3_1_temp_6="$(egrep -q "^(\s*)minclass\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)minclass\s*=\s*\S+(\s*#.*)?\s*$/\1minclass = 4\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]minclass\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]minclass\s*=\s*\S+(\s*#.*)?\s*$/\1minclass = 4\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)minclass\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#minclass\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#minclass\s*=\s*\S+(\s*#.*)?\s*$/\minclass = 4\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)minclass\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "minclass = 4" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_6=$?

rhel_5_3_1_temp_7="$(egrep -q "^(\s*)maxrepeat\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)maxrepeat\s*=\s*\S+(\s*#.*)?\s*$/\1maxrepeat = 2\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]maxrepeat\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]maxrepeat\s*=\s*\S+(\s*#.*)?\s*$/\1maxrepeat = 2\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)maxrepeat\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#maxrepeat\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#maxrepeat\s*=\s*\S+(\s*#.*)?\s*$/\maxrepeat = 2\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)maxrepeat\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "maxrepeat = 2" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_7=$?

rhel_5_3_1_temp_8="$(egrep -q "^(\s*)enforcing\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf && sed -ri "s/^(\s*)enforcing\s*=\s*\S+(\s*#.*)?\s*$/\1enforcing = 1\2/" /etc/security/pwquality.conf || sed -ri "1,/#[[:space:]]enforcing\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]enforcing\s*=\s*\S+(\s*#.*)?\s*$/\1enforcing = 1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)enforcing\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf || sed -ri "1,/#enforcing\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#enforcing\s*=\s*\S+(\s*#.*)?\s*$/\enforcing = 1\2/" /etc/security/pwquality.conf && egrep -q "^(\s*)enforcing\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/pwquality.conf||  echo "enforcing = 1" >> /etc/security/pwquality.conf)"
rhel_5_3_1_temp_8=$?

if [[ "$rhel_5_3_1_temp_1" -eq 0 ]] && [[ "$rhel_5_3_1_temp_2" -eq 0 ]] && [[ "$rhel_5_3_1_temp_3" -eq 0 ]] && [[ "$rhel_5_3_1_temp_4" -eq 0 ]] && [[ "$rhel_5_3_1_temp_5" -eq 0 ]] && [[ "$rhel_5_3_1_temp_6" -eq 0 ]] && [[ "$rhel_5_3_1_temp_7" -eq 0 ]] && [[ "$rhel_5_3_1_temp_8" -eq 0 ]] ; then
  echo -e "${GREEN}Remediated:${NC} Ensure password creation requirements are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password creation requirements are configured"
  fail=$((fail + 1))
fi

# Ensure password reuse is limited
cp /etc/pam.d/system-auth /etc/pam.d/system-auth_$TIMESTAMP  # Added by RK
cp /etc/pam.d/password-auth /etc/pam.d/password-auth_$TIMESTAMP # Added by RK

sed -ri '/^\s*auth\s+\[default=die]\s+pam_faillock.so(\s*.*)$/d' /etc/pam.d/password-auth /etc/pam.d/system-auth #Added by RK
sed -ri '/^\s*account\s+required\s+pam_faillock.so(\s*.*)$/d' /etc/pam.d/password-auth /etc/pam.d/system-auth #Added by RK
sed -ri '/^\s*auth\s+required\s+pam_faillock.so\s+/d' /etc/pam.d/password-auth /etc/pam.d/system-auth #Added by RK
sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/d' /etc/pam.d/password-auth /etc/pam.d/system-auth #Added by RK

echo
echo -e "${RED}5.3.3${NC} Ensure password reuse is limited"
rhel_5_3_3_temp_1="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/system-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/system-auth || echo Ensure\ password\ reuse\ is\ limited - /etc/pam.d/system-auth not configured.)"
rhel_5_3_3_temp_1=$?
rhel_5_3_3_temp_2="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/password-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/password-auth || echo Ensure\ password\ reuse\ is\ limited - /etc/pam.d/password-auth not configured.)"
rhel_5_3_3_temp_2=$?
if [[ "$rhel_5_3_3_temp_1" -eq 0 ]] && [[ "$rhel_5_3_3_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password reuse is limited"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password reuse is limited"
  fail=$((fail + 1))
fi

# Ensure password hashing algorithm is SHA-512
echo
echo -e "${RED}5.3.4${NC} Ensure password hashing algorithm is SHA-512"
rhel_5_3_4_temp_1="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/system-auth || echo Ensure\ password\ hashing\ algorithm\ is\ SHA-512 - /etc/pam.d/password-auth not configured.)"
rhel_5_3_4_temp_1=$?
rhel_5_3_4_temp_2="$(egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/password-auth || echo Ensure\ password\ hashing\ algorithm\ is\ SHA-512 - /etc/pam.d/password-auth not configured.)"
rhel_5_3_4_temp_2=$?
if [[ "$rhel_5_3_4_temp_1" -eq 0 ]] && [[ "$rhel_5_3_4_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password hashing algorithm is SHA-512"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password hashing algorithm is SHA-512"
  fail=$((fail + 1))
fi

# Ensure password faillock PAM module configuration is set
# 14797 Status of the 'pam_faillock.so' module in /etc/pam.d/system-auth file
# 14796 Status of the 'pam_faillock.so' module in /etc/pam.d/password-auth file
# Added by RK
echo
echo -e "${RED}5.3.4${NC} Ensure password faillock PAM module configuration is set"
rhel_5_3_4_temp_1="$(egrep -q "^\s*auth\s+required\s+pam_faillock.so\s+" /etc/pam.d/password-auth || sed -ri '/^auth*[[:blank:]]*sufficient*[[:blank:]]*pam_unix.so*/i auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=1200' /etc/pam.d/password-auth)"
rhel_5_3_4_temp_1=$?
rhel_5_3_4_temp_2="$(egrep -q "^\s*account\s+required\s+pam_faillock.so(\s*.*)$" /etc/pam.d/password-auth || sed -ri '/^account*[[:blank:]]*required*[[:blank:]]*pam_unix.so*/a account     required      pam_faillock.so' /etc/pam.d/password-auth)"
rhel_5_3_4_temp_2=$?
rhel_5_3_4_temp_3="$(egrep -q "^\s*auth\s+\[default=die]\s+pam_faillock.so(\s*.*)$" /etc/pam.d/password-auth || sed -ri '/^auth*[[:blank:]]*sufficient*[[:blank:]]*pam_unix.so*/a auth        [default=die]  pam_faillock.so  authfail  audit  deny=5  unlock_time=1200' /etc/pam.d/password-auth)"
rhel_5_3_4_temp_3=$?
rhel_5_3_4_temp_4="$(egrep -q "^\s*auth\s+required\s+pam_faillock.so\s+" /etc/pam.d/system-auth || sed -ri '/^auth*[[:blank:]]*sufficient*[[:blank:]]*pam_unix.so*/i auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=1200' /etc/pam.d/system-auth)"
rhel_5_3_4_temp_4=$?
rhel_5_3_4_temp_5="$(egrep -q "^\s*account\s+required\s+pam_faillock.so(\s*.*)$" /etc/pam.d/system-auth || sed -ri '/^account*[[:blank:]]*required*[[:blank:]]*pam_unix.so*/a account     required      pam_faillock.so' /etc/pam.d/system-auth)"
rhel_5_3_4_temp_5=$?
rhel_5_3_4_temp_6="$(egrep -q "^\s*auth\s+\[default=die]\s+pam_faillock.so(\s*.*)$" /etc/pam.d/system-auth || sed -ri '/^auth*[[:blank:]]*sufficient*[[:blank:]]*pam_unix.so*/a auth        [default=die]  pam_faillock.so  authfail  audit  deny=5  unlock_time=1200' /etc/pam.d/system-auth)"
rhel_5_3_4_temp_6=$?

if [[ "$rhel_5_3_4_temp_1" -eq 0 ]] && [[ "$rhel_5_3_4_temp_2" -eq 0 ]] && [[ "$rhel_5_3_4_temp_3" -eq 0 ]] && [[ "$rhel_5_3_4_temp_4" -eq 0 ]] && [[ "$rhel_5_3_4_temp_5" -eq 0 ]] && [[ "$rhel_5_3_4_temp_6" -eq 0 ]];  then
  echo -e "${GREEN}Remediated:${NC} Ensure password faillock PAM configuration is set"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password faillock PAM configuration is set"
  fail=$((fail + 1))
fi

pam_pwquality.so 
# Ensure password quality PAM module configuration is set
# Added by RK
echo
echo -e "${RED}5.3.4${NC} Ensure password quality PAM module configuration is set"
rhel_5_3_4_temp_1="$(egrep -q "^\s*password\s+requisite\s+pam_pwquality.so\s+" /etc/pam.d/password-auth || sed -ri '/^password*[[:blank:]]*sufficient*[[:blank:]]*pam_unix.so*/i password    requisite     pam_pwquality.so try_first_pass retry=3 authtok_type= reject_username' /etc/pam.d/password-auth)"
rhel_5_3_4_temp_1=$?
rhel_5_3_4_temp_2="$(egrep -q "^\s*password\s+requisite\s+pam_pwquality.so\s+" /etc/pam.d/system-auth   || sed -ri '/^password*[[:blank:]]*sufficient*[[:blank:]]*pam_unix.so*/i password    requisite     pam_pwquality.so try_first_pass retry=3 authtok_type= reject_username' /etc/pam.d/system-auth)"
rhel_5_3_4_temp_2=$?
if [[ "$rhel_5_3_4_temp_1" -eq 0 ]] && [[ "$rhel_5_3_4_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password quality PAM module configuration is set"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password quality PAM module configuration is set"
  fail=$((fail + 1))
fi


############################################################################################################################

##Category 5.4 Access, Authentication and Authorization - User Accounts and Environment
echo
echo -e "${BLUE}5.4 Access, Authentication and Authorization - User Accounts and Environment${NC}"

# Ensure password expiration is 90 days or less
# 1073 Status of the 'Maximum Password Age' setting (expiration) / Accounts having the 'password never expires' flag set
# Changed by RK
echo
echo -e "${RED}5.4.1.1${NC} Ensure password expiration is 90 days or less"
rhel_5_4_1_1="$(egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 90\2/" /etc/login.defs || echo "PASS_MAX_DAYS 90" >> /etc/login.defs)"
rhel_5_4_1_1=$?
cat /etc/passwd | grep -i /bin/bash | awk -F: '{ print $1}' | awk '!/root/' | awk '!/nxautomation/' | awk '!/ssm-user/' | awk '!/omsagent/' | awk '!/azureadmin/'| awk '!/ec2-user/' | awk '!/mdatp/' | xargs -n1 chage --maxdays 90

if [[ "$rhel_5_4_1_1" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 90 days or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password expiration is 90 days or less"
  fail=$((fail + 1))
fi

# Ensure minimum days between password changes is 7 or more
# 1072 Status of the 'Minimum Password Age' setting
# Changed by RK
echo
echo -e "${RED}5.4.1.2${NC} Ensure minimum days between password changes is 1 or more"
rhel_5_4_1_2="$(egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 7\2/" /etc/login.defs || echo "PASS_MIN_DAYS 7" >> /etc/login.defs)"
rhel_5_4_1_2=$?
cat /etc/passwd | grep -i /bin/bash | awk -F: '{ print $1}' | awk '!/root/' | awk '!/nxautomation/' | awk '!/ssm-user/' | awk '!/omsagent/' | awk '!/azureadmin/'| awk '!/ec2-user/' | awk '!/mdatp/' | xargs -n1 chage --mindays 7

if [[ "$rhel_5_4_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure minimum days between password changes is 7 or more"
  fail=$((fail + 1))
fi

# Ensure password expiration warning days is 7 or more
# 7326 Current list of accounts with 'minimum days before password change set to 1 day'
# Changed by RK
echo
echo -e "${RED}5.4.1.3${NC} Ensure password expiration warning days is 7 or more"
rhel_5_4_1_3="$(egrep -q "^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$/\PASS_WARN_AGE 7\2/" /etc/login.defs || echo "PASS_WARN_AGE 7" >> /etc/login.defs)"
rhel_5_4_1_3=$?
cat /etc/passwd | grep -i /bin/bash | awk -F: '{ print $1}' | awk '!/root/' | awk '!/nxautomation/' | awk '!/ssm-user/' | awk '!/omsagent/' |  awk '!/azureadmin/'| awk '!/ec2-user/' | awk '!/mdatp/' | xargs -n1 chage --warndays 7

if [[ "$rhel_5_4_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure password expiration warning days is 7 or more"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure password expiration warning days is 7 or more"
  fail=$((fail + 1))
fi

# Ensure inactive password lock is 30 days or less
# Changed by RK
echo
echo -e "${RED}5.4.1.4${NC} Ensure inactive password lock is 30 days or less"
rhel_5_4_1_4="$(useradd -D -f 30)"
rhel_5_4_1_4=$?
cat /etc/passwd | grep -i /bin/bash | awk -F: '{ print $1}' | awk '!/root/' | awk '!/nxautomation/' | awk '!/ssm-user/' | awk '!/omsagent/' |  awk '!/azureadmin/'| awk '!/ec2-user/' | awk '!/mdatp/' | xargs -n1 chage --inactive 30

if [[ "$rhel_5_4_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure inactive password lock is 30 days or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure inactive password lock is 30 days or less"
  fail=$((fail + 1))
fi


# Ensure default group for the root account is GID 0
echo
echo -e "${RED}5.4.3${NC} Ensure default group for the root account is GID 0"
rhel_5_4_3="$(usermod -g 0 root)"
rhel_5_4_3=$?
if [[ "$rhel_5_4_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default group for the root account is GID 0"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default group for the root account is GID 0"
  fail=$((fail + 1))
fi

# Ensure default user umask is 027 or more restrictive
# 4726 Current 'UMASK' setting for the '/etc/bashrc or /etc/bash.bashrc' file
# Changed by RK
echo
echo -e "${RED}5.4.4${NC} Ensure default user umask is 027 or more restrictive"
rhel_5_4_4_temp_1="$(egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/bashrc && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 027\2/" /etc/bashrc || echo "umask 027" >> /etc/bashrc)"
rhel_5_4_4_temp_1=$?
rhel_5_4_4_temp_2="$(egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 027\2/" /etc/profile || echo "umask 027" >> /etc/profile)"
rhel_5_4_4_temp_2=$?
if [[ "$rhel_5_4_4_temp_1" -eq 0 ]] && [[ "$rhel_5_4_4_temp_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default user umask is 027 or more restrictive"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default user umask is 027 or more restrictive"
  fail=$((fail + 1))
fi

# Ensure access to the su command is restricted
# 6796 Status of the pam module 'pam_wheel.so' setting in PAM configuration file '/etc/pam.d/su'
# Changed by RK
sed -ri '/^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$/d' /etc/pam.d/su #Added by RK
echo
echo -e "${RED}5.4.5${NC} Ensure access to the su command is restricted"
rhel_5_4_5="$(egrep -q "^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$" /etc/pam.d/su && sed -ri '/^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$/ { /^\s*auth\s+required\s+pam_wheel.so(\s+\S+)*(\s+use_uid)(\s+.*)?$/! s/^(\s*auth\s+required\s+pam_wheel.so)(\s+.*)?$/\1 use_uid\2/ }' /etc/pam.d/su || sed -ri "1,/^\s*#auth\s+required\s+pam_wheel.so(\s+.*)?$/s/^(\s*)#auth\s+required\s+pam_wheel.so\s+\S+(\s*#.*)?\s*$/\1auth            required        pam_wheel.so use_uid\2/" /etc/pam.d/su && egrep -q "^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$" /etc/pam.d/su || sed -ri '6 i auth            required        pam_wheel.so use_uid' /etc/pam.d/su)"
rhel_5_4_5=$?
if [[ "$rhel_5_4_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure access to the su command is restricted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure access to the su command is restricted"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"

# Ensure permissions on /etc/passwd are configured
# 2152 Permissions set for the '/etc/passwd' file
# Changed by RK
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
rhel_6_1_2="$(chown root:root /etc/passwd ; chmod u-x,g-wx,o-wx /etc/passwd)"
rhel_6_1_2=$?
if [[ "$rhel_6_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/shadow are configured
# 2188 Permissions set for the '/etc/shadow' file
# Changed by RK
echo
echo -e "${RED}6.1.3${NC} Ensure permissions on /etc/shadow are configured"
rhel_6_1_3="$(chown root:root /etc/shadow ; chmod 0000 /etc/shadow )"

rhel_6_1_3=$?
if [[ "$rhel_6_1_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/group are configured
# 2189 Status of the 'Permissions' settings for the '/etc/group' file
# Changed by RK
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
rhel_6_1_4="$(chown root:root /etc/group ; chmod u-x,g-wx,o-wx /etc/group)"
rhel_6_1_4=$?
if [[ "$rhel_6_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/gshadow are configured
# 2190 'Permissions' settings for the '/etc/gshadow' file
# Changed by RK
echo
echo -e "${RED}6.1.5${NC} Ensure permissions on /etc/gshadow are configured"
rhel_6_1_5="$(chown root:root /etc/gshadow ; chmod 0000 /etc/gshadow)"

rhel_6_1_5=$?
if [[ "$rhel_6_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/passwd- are configured
# 10690 Status of the Permissions set for the '/etc/passwd-' file
# Changed by RK
echo
echo -e "${RED}6.1.6${NC} Ensure permissions on /etc/passwd- are configured"
rhel_6_1_6="$(chown root:root /etc/passwd- ; chmod u-x,go-wx /etc/passwd-)"
rhel_6_1_6=$?
if [[ "$rhel_6_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd- are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/shadow- are configured
# 10692 Status of the Permissions set for the '/etc/shadow-' file
# Changed by RK
echo
echo -e "${RED}6.1.7${NC} Ensure permissions on /etc/shadow- are configured"
rhel_6_1_7="$(chown root:root /etc/shadow- ; chmod 0000 /etc/shadow-)"
rhel_6_1_7=$?
if [[ "$rhel_6_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow- are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/group- are configured
# 10694 Status of the Permissions set for the '/etc/group-' file
# Changed by RK
echo
echo -e "${RED}6.1.8${NC} Ensure permissions on /etc/group- are configured"
rhel_6_1_8="$(chown root:root /etc/group- ; chmod u-x,go-wx /etc/group- )"

rhel_6_1_8=$?
if [[ "$rhel_6_1_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group- are configured"
  fail=$((fail + 1))
fi

# Ensure permissions on /etc/gshadow- are configured
# 10696 Status of the Permissions set for the '/etc/gshadow-' file
# Changed by RK
echo
echo -e "${RED}6.1.9${NC} EEnsure permissions on /etc/gshadow- are configured"
rhel_6_1_9="$(chown root:root /etc/gshadow- ; chmod 0000 /etc/gshadow-)"
rhel_6_1_9=$?
if [[ "$rhel_6_1_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow- are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 6.2 System Maintenance - User and Group Settings
echo
echo -e "${BLUE}6.2 System Maintenance - User and Group Settings${NC}"

# Ensure no legacy &quot;+&quot; entries exist in /etc/passwd
echo
echo -e "${RED}6.2.2${NC} Ensure no legacy + entries exist in /etc/passwd"
rhel_6_2_2="$(sed -ri '/^\+:.*$/ d' /etc/passwd)"
rhel_6_2_2=$?
if [[ "$rhel_6_2_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy + entries exist in /etc/passwd"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy + entries exist in /etc/passwd"
  fail=$((fail + 1))
fi

# Ensure no legacy &quot;+&quot; entries exist in /etc/shadow
echo
echo -e "${RED}6.2.3${NC} Ensure no legacy + entries exist in /etc/shadow"
rhel_6_2_3="$(sed -ri '/^\+:.*$/ d' /etc/shadow)"
rhel_6_2_3=$?
if [[ "$rhel_6_2_3" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy + entries exist in /etc/shadowd"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy + entries exist in /etc/shadowd"
  fail=$((fail + 1))
fi

# Ensure no legacy &quot;+&quot; entries exist in /etc/group
echo
echo -e "${RED}6.2.4${NC} Ensure no legacy + entries exist in /etc/group"
rhel_6_2_4="$(sed -ri '/^\+:.*$/ d' /etc/group)"
rhel_6_2_4=$?
if [[ "$rhel_6_2_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy + entries exist in /etc/group"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy + entries exist in /etc/group"
  fail=$((fail + 1))
fi

# Ensure the setting of journald configuration
# 17131 Status of the 'ForwardToSyslog' attribute in '/etc/systemd/journald.conf' file
# 17132 Status of the 'Compress' attribute in /etc/systemd/journald.conf file
# 17133 Status of the 'Storage' attribute in '/etc/systemd/journald.conf' file
# Added by RK
echo
echo -e "${RED}6.2.5${NC} Ensure the setting of journald configuration"
rhel_6_2_5_1="$(egrep -q "^(\s*)Compress\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/journald.conf && sed -ri "s/^(\s*)Compress\s*=\s*\S+(\s*#.*)?\s*$/\1Compress=yes\2/" /etc/systemd/journald.conf || sed -ri "1,/#Compress\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#Compresss*=\s*\S+(\s*#.*)?\s*$/\1Compress=yes\2/" /etc/systemd/journald.conf && egrep -q "^(\s*)Compress\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/journald.conf ||  echo "Compress=yes" >> /etc/systemd/journald.conf)"
rhel_6_2_5_1=$?
rhel_6_2_5_2="$(egrep -q "^(\s*)ForwardToSyslog\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/journald.conf && sed -ri "s/^(\s*)ForwardToSyslog\s*=\s*\S+(\s*#.*)?\s*$/\1ForwardToSyslog=yes\2/" /etc/systemd/journald.conf || sed -ri "1,/#ForwardToSyslog\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#ForwardToSyslog\s*=\s*\S+(\s*#.*)?\s*$/\1ForwardToSyslog=yes\2/" /etc/systemd/journald.conf && egrep -q "^(\s*)ForwardToSyslog\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/journald.conf ||  echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf)"
rhel_6_2_5_2=$?
rhel_6_2_5_3="$(egrep -q "^(\s*)Storage\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/journald.conf && sed -ri "s/^(\s*)Storage\s*=\s*\S+(\s*#.*)?\s*$/\1Storage=persistent\2/" /etc/systemd/journald.conf || sed -ri "1,/#Storage\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#Storage\s*=\s*\S+(\s*#.*)?\s*$/\1Storage=persistent\2/" /etc/systemd/journald.conf && egrep -q "^(\s*)Storage\s*=\s*\S+(\s*#.*)?\s*$" /etc/systemd/journald.conf ||  echo "Storage=persistent" >> /etc/systemd/journald.conf)"
rhel_6_2_5_3=$?

if [[ "$rhel_6_2_5_1" -eq 0 ]] && [[ "$rhel_6_2_5_2" -eq 0 ]] && [[ "$rhel_6_2_5_3" -eq 0 ]] ; then
  echo -e "${GREEN}Remediated:${NC} Ensure the setting of journald configuration"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the setting of journald configuration"
  fail=$((fail + 1))
fi

############################################################################################################################
## Miscellaneous Configurations

# Status of the 'use_pty' setting in /etc/sudoers and /etc/sudoers.d/ file
# 17145 Status of the sudo log file on the host
# 17126 Status of the 'use_pty' setting in /etc/sudoers and /etc/sudoers.d/ file
# Added by RK
echo
echo -e "${RED}7.1.1${NC} Status of the 'use_pty', sudo log fil setting in /etc/sudoers"
rhel_7_1_1="$(egrep -q "^(\s*)Defaults logfile\s*=\s*\S+(\s*#.*)?\s*$" /etc/sudoers && sed -ri "s/^(\s*)Defaults logfile\s*=\s*\S+(\s*#.*)?\s*$/\1Defaults logfile=\/var\/log\/sudo.log\2/" /etc/sudoers || sed -ri "1,/#Defaults logfile\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#Defaults logfile*=\s*\S+(\s*#.*)?\s*$/\1Defaults logfile=\/var\/log\/sudo.log\2/" /etc/sudoers && egrep -q "^(\s*)Defaults logfile\s*=\s*\S+(\s*#.*)?\s*$" /etc/sudoers||  echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers)"
rhel_7_1_1=$?

rhel_7_1_2="$(egrep -q "^\s*Defaults\s+use_pty(\s+.*)?$" /etc/sudoers || echo "Defaults use_pty" >> /etc/sudoers)"
rhel_7_1_2=$?

if [[ "$rhel_7_1_1" -eq 0 ]] && [[ "$rhel_7_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Status of the 'use_pty', sudo log fil setting in /etc/sudoers"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Status of the 'use_pty', sudo log fil setting in /etc/sudoers"
  fail=$((fail + 1))
fi

# 10666 Status of the '$FileCreateMode' setting within '/etc/rsyslog.conf' file
# Added by RK

echo
echo -e "${RED}7.1.2${NC} Status of the '$FileCreateMode' setting within '/etc/rsyslog.conf' file"
FCM='$FileCreateMode'
rhel_7_1_2="$(cat /etc/rsyslog.conf | grep -q  $FCM  || echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf)"
rhel_7_1_2=$?

if [[ "$rhel_7_1_2" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Status of the '$FileCreateMode' setting within '/etc/rsyslog.conf' file"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Status of the '$FileCreateMode' setting within '/etc/rsyslog.conf' file"
  fail=$((fail + 1))
fi

# 2678 Status of the 'TMOUT' setting in the '/etc/bashrc' file (bash shell)
# 2679 Status of the 'TMOUT' setting in the '/etc/profile' file (ksh shell)
# Added by RK

echo
echo -e "${RED}7.1.3${NC} Status of the 'TMOUT' setting in the '/etc/bashrc and '/etc/profile'"
rhel_7_1_3="$(egrep -q "^(\s*)TMOUT\s*=\s*\S+(\s*#.*)?\s*$" /etc/bashrc && sed -ri "s/^(\s*)TMOUT\s*=\s*\S+(\s*#.*)?\s*$/\1TMOUT=900\2/" /etc/bashrc|| sed -ri "1,/#TMOUT\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#TMOUT\s*=\s*\S+(\s*#.*)?\s*$/\1TMOUT=900\2/" /etc/bashrc && egrep -q "^(\s*)TMOUT\s*=\s*\S+(\s*#.*)?\s*$" /etc/bashrc || echo "TMOUT=900" >> /etc/bashrc)"
rhel_7_1_3=$?

rhel_7_1_4="$(egrep -q "^(\s*)TMOUT\s*=\s*\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)TMOUT\s*=\s*\S+(\s*#.*)?\s*$/\1TMOUT=900\2/"/etc/profile || sed -ri "1,/#TMOUT\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#TMOUT\s*=\s*\S+(\s*#.*)?\s*$/\1TMOUT=900\2/" /etc/profile && egrep -q "^(\s*)TMOUT\s*=\s*\S+(\s*#.*)?\s*$" /etc/profile || echo "TMOUT=900" >> /etc/profile)"
rhel_7_1_4=$?

if [[ "$rhel_7_1_3" -eq 0 ]] && [[ "$rhel_7_1_4" -eq 0 ]] ; then
  echo -e "${GREEN}Remediated:${NC} Status of the 'TMOUT' setting in the '/etc/bashrc and '/etc/profile'"
  success=$((success + 1))
  source /etc/profile /etc/bashrc
else
  echo -e "${RED}UnableToRemediate:${NC} Status of the 'TMOUT' setting in the '/etc/bashrc and '/etc/profile'"
  fail=$((fail + 1))
fi

# log roation /var/log/sudo.log
# Added by RK
echo
echo -e "${RED}7.1.4${NC} log roation /var/log/sudo.log"
rhel_7_1_4="$(
cat > /etc/logrotate.d/sudo << 'EOF'
/var/log/sudo.log {
    weekly
    rotate 5
    size 100M
    compress
    delaycompress
    create 0600 root root
}
EOF
)"
rhel_7_1_4=$?
if [[ "$rhel_7_1_4" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure log roation /var/log/sudo.log"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure log roation /var/log/sudo.log"
  fail=$((fail + 1))
fi


# 9380 Status of the Mail Transfer Agent for Local-Only Mode
# Added by RK

echo
echo -e "${RED}7.1.5${NC} Status of the Mail Transfer Agent for Local-Only Mode'"
rhel_7_1_5="$(egrep -q "^(\s*)inet_interfaces\s*=\s*\S+(\s*#.*)?\s*$" /etc/postfix/main.cf && sed -ri "s/^(\s*)inet_interfaces\s*=\s*\S+(\s*#.*)?\s*$/\1inet_interfaces = loopback-only\2/" /etc/postfix/main.cf || sed -ri "1,/#inet_interfaces\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#inet_interfaces\s*=\s*\S+(\s*#.*)?\s*$/\1inet_interfaces = loopback-only\2/" /etc/postfix/main.cf && egrep -q "^(\s*)inet_interfaces\s*=\s*\S+(\s*#.*)?\s*$" /etc/postfix/main.cf || echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf)"
rhel_7_1_5=$?

if [[ "$rhel_7_1_5" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Status of the Mail Transfer Agent for Local-Only Mode"
  success=$((success + 1))
  systemctl restart postfix
else
  echo -e "${RED}UnableToRemediate:${NC} Status of the Mail Transfer Agent for Local-Only Mode"
  fail=$((fail + 1))
fi


# Ensure mounting of cramfs filesystems is blacklisted
# 20618 Status of 'blacklist' setting for 'cramfs' kernel module specified in '/etc/modprobe.d/*'
# Added by RK
echo
echo -e "${RED}7.1.6${NC} Ensure mounting of cramfs filesystems is disabled"
rhel_7_1_6="$(egrep -q "^\s*blacklist\s+cramfs(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "blacklist cramfs" >> /etc/modprobe.d/CIS.conf)"
rhel_7_1_6=$?
if [[ "$rhel_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is blacklisted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of cramfs filesystems is blacklisted"
  fail=$((fail + 1))
fi

echo
echo -e "${RED}7.1.6${NC} Ensure mounting of usb-storage filesystems is disabled"
rhel_7_1_6="$(egrep -q "^\s*blacklist\s+usb-storage(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "blacklist usb-storage" >> /etc/modprobe.d/CIS.conf)"
rhel_7_1_6=$?
if [[ "$rhel_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of usb-storage filesystems is blacklisted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of usb-storage filesystems is blacklisted"
  fail=$((fail + 1))
fi

echo
echo -e "${RED}7.1.6${NC} Ensure mounting of freevxfs filesystems is disabled"
rhel_7_1_6="$(egrep -q "^\s*blacklist\s+freevxfs(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "blacklist freevxfs" >> /etc/modprobe.d/CIS.conf)"
rhel_7_1_6=$?
if [[ "$rhel_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is blacklisted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of freevxfs filesystems is blacklisted"
  fail=$((fail + 1))
fi

echo
echo -e "${RED}7.1.6${NC} Ensure mounting of hfs filesystems is disabled"
rhel_7_1_6="$(egrep -q "^\s*blacklist\s+hfs(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "blacklist hfs" >> /etc/modprobe.d/CIS.conf)"
rhel_7_1_6=$?
if [[ "$rhel_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is blacklisted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfs filesystems is blacklisted"
  fail=$((fail + 1))
fi

echo
echo -e "${RED}7.1.6${NC} Ensure mounting of hfsplus filesystems is disabled"
rhel_7_1_6="$(egrep -q "^\s*blacklist\s+hfsplus(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "blacklist hfsplus" >> /etc/modprobe.d/CIS.conf)"
rhel_7_1_6=$?
if [[ "$rhel_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is blacklisted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfsplus filesystems is blacklisted"
  fail=$((fail + 1))
fi

echo
echo -e "${RED}7.1.6${NC} Ensure mounting of jffs2 filesystems is disabled"
rhel_7_1_6="$(egrep -q "^\s*blacklist\s+jffs2(\s*.*)$" /etc/modprobe.d/CIS.conf || echo "blacklist jffs2" >> /etc/modprobe.d/CIS.conf)"
rhel_7_1_6=$?
if [[ "$rhel_7_1_6" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is blacklisted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of jffs2 filesystems is blacklisted"
  fail=$((fail + 1))
fi



# Ensure permissions on all SSH private key file
# 11705 Status of permissions on all SSH private key files Failed
# Added by RK
echo
echo -e "${RED}7.1.7${NC} Ensure mounting of cramfs filesystems is disabled"
rhel_7_1_7="$(chmod 0600 /etc/ssh/ssh_host*key)"
rhel_7_1_7=$?
if [[ "$rhel_7_1_7" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on all SSH private key file"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on all SSH private key file"
  fail=$((fail + 1))
fi


# Ensure 'sudo' timeout period is 0
# 8889 Status of the 'sudo' timeout period Failed
# Added by RK
ls /etc/sudoers.d/cis_defaultls || touch /etc/sudoers.d/cis_defaultls && chown root:root /etc/sudoers.d/cis_defaultls && chmod 0440 /etc/sudoers.d/cis_defaultls 

echo
echo -e "${RED}7.1.8${NC} Ensure 'sudo' timeout period is 0"
rhel_7_1_8="$(egrep -q  "^(\s*)Defaults[[:space:]]+timestamp_timeout\s*=\s*\S+(\s*#.*)?\s*$" /etc/sudoers /etc/sudoers.d/* && sed -ri "s/^(\s*)Defaults[[:space:]]+timestamp_timeout\s*=\s*\S+(\s*#.*)?\s*$/\1Defaults   timestamp_timeout = 0\2/" /etc/sudoers /etc/sudoers.d/* || egrep -q  "^(\s*)Defaults[[:space:]]+timestamp_timeout\s*=\s*\S+(\s*#.*)?\s*$" /etc/sudoers /etc/sudoers.d/* || echo "Defaults   timestamp_timeout = 0" >> /etc/sudoers.d/cis_defaultls)"
rhel_7_1_8=$?
if [[ "$rhel_7_1_8" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC}  Ensure 'sudo' timeout period is 0"
  success=$((success + 1))
  
else
  echo -e "${RED}UnableToRemediate:${NC}  Ensure 'sudo' timeout period is 0"
  fail=$((fail + 1))
fi


# Ensure Status of the 'wireless interfaces' using nmcli command 
# 22089 Status of the 'wireless interfaces' using nmcli command (nmcli radio all) Failed
# Added by RK
echo
echo -e "${RED}7.1.9${NC} Ensure Status of the 'wireless interfaces' using nmcli command"
rhel_7_1_9="$(nmcli radio all off)"
rhel_7_1_9=$?
if [[ "$rhel_7_1_9" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure Status of the 'wireless interfaces' using nmcli command"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure Status of the 'wireless interfaces' using nmcli command"
  fail=$((fail + 1))
fi


# Ensure default user umask settings in the /etc/login.defs file is set to 027
# 11401 Default user umask settings in the /etc/login.defs file Failed
# Added by RK
echo
echo -e "${RED}7.1.10${NC} Ensure default user umask settings in the /etc/login.defs file is set to 027"
rhel_7_1_10="$(egrep -q "^(\s*)UMASK\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)UMASK\s+\S+(\s*#.*)?\s*$/\1UMASK 027\2/" /etc/login.defs || echo "PASS_MAX_DAYS 027" >> /etc/login.defs)"
rhel_7_1_10=$?

if [[ "$rhel_7_1_10" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default user umask settings in the /etc/login.defs file is set to 027s"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default user umask settings in the /etc/login.defs file is set to 027"
  fail=$((fail + 1))
fi


# Ensure the 'noexec' option for '/dev/shm' partition using 'mount' command
# 14609 Status of the 'noexec' option for '/dev/shm' partition using 'mount' command
# Added by RK
echo
echo -e "${RED}7.1.11${NC} Ensure the 'noexec' option for '/dev/shm' partition using 'mount' command"
if egrep -q "^(\s*)shmfs[[:space:]]+/dev/shm"  /etc/fstab > /dev/null ; then
rhel_7_1_11="$(egrep -q "^(\s*)shmfs[[:space:]]+/dev/shm" /etc/fstab && sed -ri 's#(/dev/shm\s.*defaults)\s#\1,noexec,nodev,nosuid #' /etc/fstab || echo "tmpfs /dev/shm                                   tmpfs   defaults,noexec,nodev,nosuid    1    2" >> /etc/fstab)"
rhel_7_1_11=$?
else
rhel_7_1_11="$(egrep -q "^(\s*)tmpfs[[:space:]]+/dev/shm"  /etc/fstab && sed -ri 's#(/dev/shm\s.*defaults)\s#\1,noexec,nodev,nosuid #' /etc/fstab || echo "tmpfs /dev/shm                                   tmpfs   defaults,noexec,nodev,nosuid    1    2" >> /etc/fstab)"
rhel_7_1_11=$?
fi

if [[ "$rhel_7_1_11" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure the 'noexec' option for '/dev/shm' partition using 'mount' command"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the 'noexec' option for '/dev/shm' partition using 'mount' command"
  fail=$((fail + 1))
fi


# Ensure the 'deny' setting configured in /etc/security/faillock.conf 
# 20570 Status of 'deny' setting configured in /etc/security/faillock.conf file Failed
# Added by RK
echo
echo -e "${RED}7.1.12${NC} Ensure the 'deny' setting configured in /etc/security/faillock.conf"
if ls /etc/security/faillock.conf > /dev/null; then
rhel_7_1_12_1="$(egrep -q "^(\s*)deny\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/faillock.conf  && sed -ri "s/^(\s*)deny\s*=\s*\S+(\s*#.*)?\s*$/\1deny = 5\2/" /etc/security/faillock.conf  || sed -ri "1,/#[[:space:]]deny\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]deny\s*=\s*\S+(\s*#.*)?\s*$/\1deny = 5\2/" /etc/security/faillock.conf && egrep -q "^(\s*)deny\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/faillock.conf || sed -ri "1,/#deny\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#deny\s*=\s*\S+(\s*#.*)?\s*$/\deny = 5\2/" /etc/security/faillock.conf && egrep -q "^(\s*)deny\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/faillock.conf  ||  echo "deny = 5" >> /etc/security/faillock.conf)"
rhel_7_1_12_1=$?
rhel_7_1_12_2="$(egrep -q "^(\s*)unlock_time\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/faillock.conf  && sed -ri "s/^(\s*)unlock_time\s*=\s*\S+(\s*#.*)?\s*$/\1unlock_time = 1200\2/" /etc/security/faillock.conf  || sed -ri "1,/#[[:space:]]unlock_time\s*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)^(\s*)#[[:space:]]unlock_time\s*=\s*\S+(\s*#.*)?\s*$/\1unlock_time = 1200\2/" /etc/security/faillock.conf && egrep -q "^(\s*)deny\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/faillock.conf || sed -ri "1,/#unlock_times*=\s*\S+(\s*#.*)?\s*$/s/^(\s*)#unlock_time\s*=\s*\S+(\s*#.*)?\s*$/\unlock_time = 1200\2/" /etc/security/faillock.conf && egrep -q "^(\s*)unlock_time\s*=\s*\S+(\s*#.*)?\s*$"  /etc/security/faillock.conf  ||  echo "unlock_time = 1200" >> /etc/security/faillock.conf)"
rhel_7_1_12_2=$?
else
echo "${RED}7.1.12${NC} file /etc/security/faillock.conf is not available"
fi
if [[ "$rhel_7_1_12_1" -eq 0 ]] && [[ "$rhel_7_1_12_2" -eq 0 ]]  ; then
  echo -e "${GREEN}Remediated:${NC} Ensure the 'deny' setting configured in /etc/security/faillock.conf "
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure the 'deny' setting configured in /etc/security/faillock.conf "
  fail=$((fail + 1))
fi

# Chage root and thyadm mindays to 0
chage --mindays 0 root
chage --mindays 0 thyadm
chage --mindays 0 virtusa-it
chage --mindays 0 opc

###########################################################################################################################

echo
echo -e "${GREEN}Remediation script for Red Hat Enterprise Linux 7/8 executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Remediation Passed:${NC} $success" 
echo -e "${YELLOW}Remediation Failed:${NC} $fail"

###########################################################################################################################