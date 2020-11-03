#!/bin/bash

# Script that audits CIS Security benchmarks

# Joe Thetford

function audit() {

	# Arg1: Name of policy
	# Arg2: Output expected for system in compliance
	# Arg3: The command to audit the policy
	# Arg4: Remediation measures

	if [[ $2 != $3 ]]
	then

		echo -e "\e[1;31mThe $1 policy is not in compliance. Current Value: $3\nRemediation:\n$4/e[0m" >> auditresults.txt

	else

		echo -e "\e[;32mThe $1 policy is in Compliance. Current Value: $3\e[0m" >> auditresults.txt

	fi
	echo "" >> auditresults.txt
	}


#audit "${f1}" "${f2}" "$(${f3})" "${f4}"


cmd=$(modprobe -n -v cramfs | awk '{print $1 , $2}')
audit "Ensure mounting of cramfs filesystems is disabled 1" "install /bin/true" "${cmd}" "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf and add the following line:\ninstall cramfs /bin/true"

cmd=$(lsmod | grep cramfs)
audit "Ensure mounting of cramfs filesystems is disabled 2" "" "${cmd}" "Run the following command to unload the cramfs module:\nrmmod cramfs"

cmd=$(modprobe -n -v vfat | awk '{print $1, $2}') 
audit "Ensure mounting of vFAT filesystems is limited 1" "${cmd}" "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf and add the following line:\ninstall vfat /bin/true"

cmd=$(lsmod | grep vfat)
audit "Ensure mounting of vFAT filesystems is limited 2" "" "${cmd}" "Run the following command to unload the vfat module:\nrmmod vfat"

cmd=$(modprobe -n -v squashfs | awk '{print $1, $2}')
audit "Ensure mounting of squashfs filesystems is disabled 1" "install /bin/true" "${cmd}" "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf and add the following line:\ninstall squashfs /bin/true"

cmd=$(lsmod | grep squashfs)
audit "Ensure mounting of squashfs filesystems is disabled 2" "" "${cmd}" "Run the following command to unload the squashfs module:\nrmmod squashfs"

cmd=$(modprobe -n -v udf | awk '{print $1, $2}')
audit "Ensure mounting of udf filesystems is disabled 1" "install /bin/true" "${cmd}" "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf and add the following line:\ninstall udf /bin/true"

cmd=$(lsmod | grep udf)
audit "Ensure mounting of udf filesystems is disabled 2" "" "${cmd}" "Run the following command to unload the udf module:\n# rmmod udf"

cmd=$(systemctl is-enabled tmp.mount)
audit "Ensure /tmp is configured" "enabled" "${cmd}" "Run the following commands to enable systemd /tmp mounting:\nsystemctl unmask tmp.mount\nsystemctl enable tmp.mount"

cmd=$(mount | grep -E '\s/tmp\s' | grep -v nodev)
audit "Ensure nodev option set on /tmp partition" "" "${cmd}" "Run the following command to remount /tmp :\nmount -o remount,nodev /tmp"

cmd=$(mount | grep -E '\s/tmp\s' | grep -v nosuid)
audit "Ensure nosuid option set on /tmp partition" "" "${cmd}" "Run the following command to remount /tmp :\nmount -o remount,nosuid /tmp"

cmd=$(mount | grep -E '\s/tmp\s' | grep -v noexec)
audit "Ensure noexec option set on /tmp partition" "" "${cmd}" "Run the following command to remount /tmp :\nmount -o remount,noexec /tmp"

cmd=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev-type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)
audit "Ensure sticky bit is set on all world-writable directories" "" "${cmd}" "Run the following command to set the sticky bit on all world writable directories:\ndf --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev\n-type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '$"

cmd=$(systemctl is-enabled autofs)
audit "Disable Automounting" "disabled" "${cmd}" "Run the following command to disable autofs:\nsystemctl --now disable autofs"

cmd=$(modprobe -n -v usb-storage | awk '{print $1, $2}')
audit "Disable USB Storage 1" "install /bin/true" "{cmd}" "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf\nand add the following line:\ninstall usb-storage /bin/true"

cmd=$(lsmod | grep usb-storage)
audit "Disable USB Storage 2" "" "${cmd}" "Run the following command to unload the usb-storage module:\nrmmod usb-storage"

cmd=$(grep ^gpgcheck /etc/yum.conf)
audit "Ensure gpgcheck is globally activated 1" "gpgcheck=1" "${cmd}" "Edit /etc/yum.conf and set 'gpgcheck=1' in the [main] section."

cmd=$(rpm -q sudo | cut -c1-4)
audit "Ensure sudo is installed" "sudo" "${cmd}" "Run the following command to install sudo\ndnf install sudo"

cmd=$(grep -Ei '^\s*Defaults\s+(\[^#]+,\s*)?use_pty' /etc/sudoers /etc/sudoers.d/* | awk '{print $1, $2}')
audit "Ensure sudo commands use pty" "Defaults use_pty" "${cmd}" "Edit the file /etc/sudoers or a file in /etc/sudoers.d/ with visudo -f and add the following line:\nDefaults use_pty"

cmd=$(grep -Ei '^\s*Defaults\s+([^#]+,\s*)?logfile=' /etc/sudoers /etc/sudoers.d/* | awk '{print $1, $2}')
audit "Ensure sudo log file exists" 'Defaults logfile="/var/log/sudo.log"' "${cmd}" "Edit the file /etc/sudoers or a file in /etc/sudoers.d/ with visudo -f and add the following line:\nDefaults logfile=""<PATH TO CUSTOM LOG FILE>"""

cmd=$(rpm -q aide | cut -c1-4)
audit "Ensure AIDE is installed" "aide" "${cmd}" "Run the following command to install AIDE:\ndnf install aide"

cmd=$(stat /boot/grub2/grub.cfg | grep -n Access | head -n 1 | awk '{print $2, $5, $9}')
audit "Ensure permissions on bootloader config are configured 1" "(0600/-rw-r--r--) 0/ 0/" "${cmd}" "Run the following commands to set permissions on your grub configuration:\nchown root:root /boot/grub2/grub.cfg\nchmod og-rwx /boot/grub2/grub.cfg"

cmd=$(stat /boot/grub2/grubenv | grep -n Access | head -n 1 | awk '{print $2 "" "" $5 "" "" $9}')
audit "Ensure permissions on bootloader config are configured 2" "(0600/-rw-r--r--) 0/ 0/" "${cmd}" "Run the following commands to set permissions on your grub configuration:\nchown root:root /boot/grub2/grubenv\nchmod og-rwx /boot/grub2/grubenv"

cmd=$(grep /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service | awk '{print $1 "" "" $2}')
audit "Ensure authentication required for single user mode 1" "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue" "${cmd}" "Edit /usr/lib/systemd/system/rescue.service and add/modify the following line:\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue"

cmd=$(grep /systemd-sulogin-shell /usr/lib/systemd/system/emergency.service | awk '{print $1, $2}')
audit "Ensure authentication required for single user mode 2" "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency" "${cmd}" "Edit /usr/lib/systemd/system/emergency.service and add/modify the following line:\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency"

cmd=$(grep -E ""^\s*\*\s+hard\s+core"" /etc/security/limits.conf /etc/security/limits.d/* | awk '{print $1, $2, $3, $4}')
audit "Ensure core dumps are restricted 1" "* hard core 0" "${cmd}" "Add the following line to /etc/security/limits.conf or a /etc/security/limits.d/* file:\n* hard core 0\nRun the command:\nsystemctl daemon-reload"

cmd=$(sysctl fs.suid_dumpable | awk '{print $1, $2, $3}')
audit "Ensure core dumps are restricted 2" "fs.suid_dumpable = 0" "${cmd}" "Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file:\nfs.suid_dumpable = 0\nRun the command:\nsystemctl daemon-reload"

cmd=$(grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/* | awk '{print $1, $2, $3}')
audit "Ensure core dumps are restricted 3" "fs.suid_dumpable = 0" "${cmd}" "Run the following command to set the active kernel parameter:\nsysctl -w fs.suid_dumpable=0\nRun the command:\nsystemctl daemon-reload"

cmd=$(sysctl kernel.randomize_va_space | awk '{print $1, $2, $3}')
audit "Ensure address space layout randomization (ASLR) is enabled 1" "kernel.randomize_va_space = 2" "${cmd}" "Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file:\nkernel.randomize_va_space = 2"

cmd=$(grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* | awk '{print $1 "" "" $2 "" "" $3}')
audit "Ensure address space layout randomization (ASLR) is enabled 2" "kernel.randomize_va_space = 2" "${cmd}" "Run the following command to set the active kernel parameter:\nsysctl -w kernel.randomize_va_space=2"

cmd=$(rpm -q libselinux | cut -c1-10)
audit "Ensure SELinux is installed" "libselinux" "${cmd}" "Run the following command to install SELinux:\ndnf install libselinux"

cmd=$(grep -E 'kernelopts=(\S+\s+)*(selinux=0|enforcing=0)+\b' /boot/grub2/grubenv)
audit "Ensure SELinux is not disabled in bootloader configuration" "" "${cmd}" "Edit /etc/default/grub and remove all instances of selinux=0 and enforcing=0 from all\nCMDLINE_LINUX parameters:\nGRUB_CMDLINE_LINUX_DEFAULT=""quiet""\nGRUB_CMDLINE_LINUX=""""\n\nRun the following command to update the grub2 configuration:\ngrub2-mkconfig -o /boot/grub2/grub.cfg"

cmd=$(grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config)
audit "Ensure SELinux policy is configured 1" "SELINUXTYPE=targeted" "${cmd}" "Edit the /etc/selinux/config file to set the SELINUXTYPE parameter:\nSELINUXTYPE=targeted"

cmd=$(sestatus | grep Loaded | awk '{print $4}')
audit "Ensure SELinux policy is configured 2" "targeted" "${cmd}" "Edit the /etc/selinux/config file to set the SELINUXTYPE parameter:\nSELINUXTYPE=targeted"

cmd=$(grep -E '^\s*SELINUX=enforcing' /etc/selinux/config)
audit "Ensure the SELinux state is enforcing 1" "SELINUX=enforcing" "${cmd}" "Edit the /etc/selinux/config file to set the SELINUX parameter:\nSELINUX=enforcing"

cmd=$(ps -eZ | grep unconfined_service_t)
audit "Ensure no unconfined services exist" "" "${cmd}" "Investigate any unconfined processes found during the audit action. They may need to have an existing security context assigned to them or a policy built for them."

cmd=$(rpm -q setroubleshoot | awk '{print $4, $5}')
audit "Ensure SETroubleshoot is not installed" "not installed" "${cmd}" "Run the following command to uninstall setroubleshoot:\ndnf remove setroubleshoot"

cmd=$(rpm -q mcstrans | awk '{print $4, $5}')
audit "Ensure the MCS Translation Service (mcstrans) is not installed" "not installed" "${cmd}" "Run the following command to uninstall mcstrans:\ndnf remove mcstrans"

cmd=$(stat /etc/motd | grep -n Access | head -n 1 | awk '{print $2, $5, $9}')
audit "Ensure permissions on /etc/motd are configured" "(0644/-rw-r--r--) 0/ 0/" "${cmd}" "Run the following commands to set permissions on /etc/motd :\nchown root:root /etc/motd\nchmod u-x,go-wx /etc/motd"

cmd=$(stat /etc/issue.net | grep -n Access | head -n 1 | awk '{print $2, $5, $9}')
audit "Ensure permissions on /etc/issue are configured" "(0644/-rw-r--r--) 0/ 0/" "${cmd}" "Run the following commands to set permissions on /etc/issue :\nchown root:root /etc/issue\nchmod u-x,go-wx /etc/issue"

cmd=$(stat /etc/issue.net | grep -n Access | head -n 1 | awk '{print $2, $5, $9}')
audit "Ensure permissions on /etc/issue.net are configured" "(0644/-rw-r--r--) 0/ 0/" "${cmd}" "Run the following commands to set permissions on /etc/issue.net :\nchown root:root /etc/issue.net\nchmod u-x,go-wx /etc/issue.net"

cmd=$(grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config)
audit "Ensure system-wide crypto policy is not legacy" "" "${cmd}" "Run the following command to change the system-wide crypto policy\nupdate-crypto-policies --set <CRYPTO POLICY>"


