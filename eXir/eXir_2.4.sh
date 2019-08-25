#!/bin/bash



##############################################################
# Copyrights reserved by Ebryx LLC - www.ebryx.com © 2019
##############################################################

mkdir ~/artifacts


dt=$(date '+%d-%m-%Y_%H-%M-%S_%Z')
echo "$dt"

# mac chrome profile path ~/Library/Application\ Support/Google/Chrome
# linux chrome profile path  ~/.config/google-chrome/

echo "[I] File Created: ~/artifacts/1.1_$dt.txt"
touch ~/artifacts/1.1_$dt.txt



echo "##############################################################"
echo "# Copyrights reserved by Ebryx LLC - www.ebryx.com © 2019"
echo "##############################################################"


echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Script Started"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
date  >> ~/artifacts/1.1_$dt.txt
sudo echo $(date) >> ~/artifacts/1.1_$dt.txt


# Determine OS platform
UNAME=$(uname | tr "[:upper:]" "[:lower:]")
# If Linux, try to determine specific distribution
if [ "$UNAME" == "linux" ]; then
    # If available, use LSB to identify distribution
    if [ -f /etc/lsb-release -o -d /etc/lsb-release.d ]; then
        export DISTRO=$(lsb_release -i | cut -d: -f2 | sed s/'^\t'//)
    # Otherwise, use release info file
    else
        export DISTRO=$(ls -d /etc/[A-Za-z]*[_-][rv]e[lr]* | grep -v "lsb" | cut -d'/' -f3 | cut -d'-' -f1 | cut -d'_' -f1)
    fi
fi
# For everything else (or if above failed), just use generic identifier
[ "$DISTRO" == "" ] && export DISTRO=$UNAME
unset UNAME

shopt -s nocasematch
if [[ "$DISTRO" =~ "redhat" ]]; then
    DISTRO="redhat"
elif [[ "$DISTRO" =~ "centos" ]]; then
    DISTRO="centos"
elif [[ "$DISTRO" =~ "ubuntu" ]]; then
    DISTRO="ubuntu"
elif [[ "$DISTRO" =~ "darwin" ]]; then
    DISTRO="osx"
else
    DISTRO="unknown"
fi




if [ -f /var/log/auth.log ];then
    echo "------------------"   >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
    echo "Details about sudo commands executed by all user"  >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
    echo "------------------"   >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
    sudo grep sudo /var/log/auth.log >> ~/artifacts/17_sudo_commands_by_user_$dt.txt 2>&1
    echo >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
fi


if [ -f /var/log/secure ];then
    echo "------------------"   >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
    echo "Details about sudo commands executed by all user"  >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
    echo "------------------"   >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
    sudo grep sudo /var/log/secure >> ~/artifacts/17_sudo_commands_by_user_$dt.txt 2>&1
    echo >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
fi


echo "------------------"   >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
echo "Details about sudo commands executed by all user"  >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
echo "------------------"   >> ~/artifacts/17_sudo_commands_by_user_$dt.txt
sudo journalctl _COMM=sudo >> ~/artifacts/17_sudo_commands_by_user_$dt.txt 2>&1
echo >> ~/artifacts/17_sudo_commands_by_user_$dt.txt




echo "------------------"   >> ~/artifacts/16_files_changed_$dt.txt
echo "Files changed in close delta (top 25 entries) (Latest edited/created files)"  >> ~/artifacts/16_files_changed_$dt.txt
echo "------------------"   >> ~/artifacts/16_files_changed_$dt.txt
sudo find . -type f -printf '%T@ %p\n' | sort -n | tail -25 | cut -f2- -d" " >> ~/artifacts/16_files_changed_$dt.txt
echo >> ~/artifacts/16_files_changed_$dt.txt




echo "------------------"   >> ~/artifacts/16_files_changed_$dt.txt
echo "Files being written right now"  >> ~/artifacts/16_files_changed_$dt.txt
echo "------------------"   >> ~/artifacts/16_files_changed_$dt.txt
sudo lsof $( find /var/log /var/www/log -type f ) >> ~/artifacts/16_files_changed_$dt.txt
echo >> ~/artifacts/16_files_changed_$dt.txt



echo "------------------"   >> ~/artifacts/16_files_changed_$dt.txt
echo "Files changed during last 24 hours in a dir & sub-dirs"  >> ~/artifacts/16_files_changed_$dt.txt
echo "------------------"   >> ~/artifacts/16_files_changed_$dt.txt
sudo find / -newermt "1 day ago" -ls >> ~/artifacts/16_files_changed_$dt.txt 2>&1
echo >> ~/artifacts/16_files_changed_$dt.txt








echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Host Name" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
	sudo hostname >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt


echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Kernal Verion" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo uname -a >> ~/artifacts/1.1_$dt.txt  2>&1
echo >> ~/artifacts/1.1_$dt.txt


echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "System uptime"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo uptime >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt



if [ "$DISTRO" == "osx" ]; then
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "System Profiler" >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    sudo system_profiler >> ~/artifacts/1.1_$dt.txt 2>&1
    echo >> ~/artifacts/1.1_$dt.txt
else
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "OS Version" >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    sudo cat /etc/*-release >> ~/artifacts/1.1_$dt.txt 2>&1
    echo >> ~/artifacts/1.1_$dt.txt
fi


echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Current Logged In User Name - whoami" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo whoami >> ~/artifacts/1.1_$dt.txt  2>&1
echo >> ~/artifacts/1.1_$dt.txt


echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Current Logged In Users - who -u" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo who -u >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Past Logged in Users" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo lastlog >> ~/artifacts/1.1_$dt.txt  2>&1
sudo last >> ~/artifacts/1.1_$dt.txt   2>&1
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Last System Reboot Time" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo who -b >> ~/artifacts/1.1_$dt.txt  2>&1
echo >> ~/artifacts/1.1_$dt.txt




if [ -f /proc/mounts ];then
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "Mounted Hard Drives Partition"  >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    sudo cat /proc/mounts >> ~/artifacts/1.1_$dt.txt  2>&1
    echo >> ~/artifacts/1.1_$dt.txt
elif [ -f /proc/self/mounts ]; then
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "Mounted Hard Drives Partition"  >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    sudo cat /proc/self/mounts >> ~/artifacts/1.1_$dt.txt  2>&1
    echo >> ~/artifacts/1.1_$dt.txt
fi



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Show file system disk space usage"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo df -aTh >> ~/artifacts/1.1_$dt.txt  2>&1
echo >> ~/artifacts/1.1_$dt.txt




echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Print env"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt

if [ -x "$(command -v printenv)" ]; then
    sudo printenv >> ~/artifacts/1.1_$dt.txt 2>&1
else
    sudo env >> ~/artifacts/1.1_$dt.txt 2>&1
fi

echo >> ~/artifacts/1.1_$dt.txt




echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Currently running screen sessions - screen -ls - empty output means no screen"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo screen -ls >> ~/artifacts/1.1_$dt.txt  2>&1
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Currently running screen sessions - ps auxw|grep -i screen|grep -v grep"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo ps auxw|grep -i screen|grep -v grep >> ~/artifacts/1.1_$dt.txt  2>&1
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Bash Profile" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
if [ -f ~/.bash_profile ];then
    sudo cat ~/.bash_profile >> ~/artifacts/1.1_$dt.txt
else
    sudo echo "~/.bash_profile not exists" >> ~/artifacts/1.1_$dt.txt
fi
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1_passwd_$dt.txt
echo "Users List (Passwd File)" >> ~/artifacts/1_passwd_$dt.txt
echo "------------------"   >> ~/artifacts/1_passwd_$dt.txt
sudo cat /etc/passwd >> ~/artifacts/1_passwd_$dt.txt
echo >> ~/artifacts/1_passwd_$dt.txt





echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Users with high privileges" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo ":::::grep '^sudo:.*$' /etc/group | cut -d: -f4:::::"   >> ~/artifacts/1.1_$dt.txt
tempVar=$(sudo grep '^sudo:.*$' /etc/group | cut -d: -f4)
echo $tempVar >> ~/artifacts/1.1_$dt.txt 2>&1
for i in $(echo $tempVar | sed "s/,/ /g")
do
    id $i >> ~/artifacts/1.1_$dt.txt
done
echo >> ~/artifacts/1.1_$dt.txt
echo ":::::grep '^root:.*$' /etc/group | cut -d: -f4:::::"   >> ~/artifacts/1.1_$dt.txt
tempVar=$(sudo grep '^root:.*$' /etc/group | cut -d: -f4)
echo $tempVar >> ~/artifacts/1.1_$dt.txt 2>&1
for i in $(echo $tempVar | sed "s/,/ /g")
do
    id $i >> ~/artifacts/1.1_$dt.txt
done
echo >> ~/artifacts/1.1_$dt.txt
echo ":::::grep '^admin:.*$' /etc/group | cut -d: -f4:::::"   >> ~/artifacts/1.1_$dt.txt
tempVar=$(sudo grep '^admin:.*$' /etc/group | cut -d: -f4)
echo $tempVar >> ~/artifacts/1.1_$dt.txt 2>&1
for i in $(echo $tempVar | sed "s/,/ /g")
do
    id $i >> ~/artifacts/1.1_$dt.txt
done
echo >> ~/artifacts/1.1_$dt.txt
echo ":::::grep '^wheel:.*$' /etc/group | cut -d: -f4:::::"   >> ~/artifacts/1.1_$dt.txt
tempVar=$(sudo grep '^wheel:.*$' /etc/group | cut -d: -f4)
echo $tempVar >> ~/artifacts/1.1_$dt.txt 2>&1
for i in $(echo $tempVar | sed "s/,/ /g")
do
    id $i >> ~/artifacts/1.1_$dt.txt
done
echo >> ~/artifacts/1.1_$dt.txt





echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Sudoers file" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo cat /etc/sudoers >> ~/artifacts/1.1_$dt.txt
echo >> ~/artifacts/1.1_$dt.txt




echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Group file" >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo cat /etc/group >> ~/artifacts/1.1_$dt.txt
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
echo "Top memory consuming processes"  >> ~/artifacts/18_processes_details_$dt.txt
echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
sudo top -b -n 1 -o +%MEM | head -n 22 >> ~/artifacts/18_processes_details_$dt.txt
echo >> ~/artifacts/18_processes_details_$dt.txt





echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
echo "Non-GUI running processess"  >> ~/artifacts/18_processes_details_$dt.txt
echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
sudo ps -C "$(xlsclients | cut -d' ' -f3 | paste - -s -d ',')" --deselect >> ~/artifacts/18_processes_details_$dt.txt
echo >> ~/artifacts/18_processes_details_$dt.txt



echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
echo "GUI running processess"  >> ~/artifacts/18_processes_details_$dt.txt
echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
sudo xlsclients | cut -d' ' -f3 | paste - -s -d ',' >> ~/artifacts/18_processes_details_$dt.txt
echo >> ~/artifacts/18_processes_details_$dt.txt





echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
echo "Processess with no TTY attached"  >> ~/artifacts/18_processes_details_$dt.txt
echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
sudo ps -C "$(xlsclients | cut -d' ' -f3 | paste - -s -d ',')" --deselect -o tty,args | grep ^? >> ~/artifacts/18_processes_details_$dt.txt
echo >> ~/artifacts/18_processes_details_$dt.txt




echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
echo "All non-GUI processes running without a controlling terminal"  >> ~/artifacts/18_processes_details_$dt.txt
echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
sudo ps -C "$(xlsclients | cut -d' ' -f3 | paste - -s -d ',')" --ppid 2 --pid 2 --deselect -o tty,uid,pid,ppid,args | grep ^? >> ~/artifacts/18_processes_details_$dt.txt
echo >> ~/artifacts/18_processes_details_$dt.txt

    


echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
echo "Top processes by memory and cpu usage"  >> ~/artifacts/18_processes_details_$dt.txt
echo "------------------"   >> ~/artifacts/18_processes_details_$dt.txt
sudo ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head >> ~/artifacts/18_processes_details_$dt.txt
echo >> ~/artifacts/18_processes_details_$dt.txt











if [ "$DISTRO" != "osx" ]; then
    echo "------------------"   >> ~/artifacts/2_shadow_$dt.txt
    echo "Shadow File" >> ~/artifacts/2_shadow_$dt.txt
    echo "------------------"   >> ~/artifacts/2_shadow_$dt.txt
    sudo cat /etc/shadow >> ~/artifacts/2_shadow_$dt.txt
    echo >> ~/artifacts/2_shadow_$dt.txt
fi


echo "------------------"   >> ~/artifacts/3_cmd_history_$dt.txt
echo "Commands History" >> ~/artifacts/3_cmd_history_$dt.txt
echo "------------------"   >> ~/artifacts/3_cmd_history_$dt.txt
sudo cat ~/.bash_history >> ~/artifacts/3_cmd_history_$dt.txt
echo >> ~/artifacts/3_cmd_history_$dt.txt



if [ "$DISTRO" == "osx" ]; then
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "Startup Services"   >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    sudo python find_all_startup_items.py >> ~/artifacts/1.1_$dt.txt
    echo >> ~/artifacts/1.1_$dt.txt
else
    # man bash
    # -x file
    # True if file exists and is executable.
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "Startup Services"   >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
   

    if [ -x "$(command -v systemctl)" ]; then
        sudo systemctl list-unit-files --type=service >> ~/artifacts/1.1_$dt.txt
    elif [ -x "$(command -v service)" ]; then
        sudo service --status-all >> ~/artifacts/1.1_$dt.txt
    elif [ -x "$(command -v initctl)" ]; then
        sudo initctl list >> ~/artifacts/1.1_$dt.txt
    else
        echo "ERROR: Unable To find startup service" >> ~/artifacts/1.1_$dt.txt
    fi
    echo >> ~/artifacts/1.1_$dt.txt
fi



echo "------------------"   >> ~/artifacts/4_md5_bin_$dt.txt
echo "md5 of all binaries"  >> ~/artifacts/4_md5_bin_$dt.txt
echo "------------------"   >> ~/artifacts/4_md5_bin_$dt.txt
OIFS=$IFS
path=$(echo $PATH)
IFS=':'		# : is set as delimiter
read -ra element <<< "$path"	# path is read into an array as tokens separated by IFS
IFS=' '		# reset to default value after usage

for i in "${element[@]}"; do	# access each element of array
    echo "$i" >> ~/artifacts/4_md5_bin_$dt.txt
done

echo >> ~/artifacts/4_md5_bin_$dt.txt
echo >> ~/artifacts/4_md5_bin_$dt.txt

IFS=':'		# : is set as delimiter
read -ra element <<< "$path"	# path is read into an array as tokens separated by IFS
IFS=' '		# reset to default value after usage

for i in "${element[@]}"; do	# access each element of array
    echo "$i" >> ~/artifacts/4_md5_bin_$dt.txt
    if [ "$DISTRO" == "osx" ]; then
        sudo md5 $i/* >> ~/artifacts/4_md5_bin_$dt.txt 2>&1
    else
        sudo md5sum $i/* >> ~/artifacts/4_md5_bin_$dt.txt 2>&1
    fi
    echo >> ~/artifacts/4_md5_bin_$dt.txt
done
IFS=$OIFS
echo >> ~/artifacts/4_md5_bin_$dt.txt







echo "------------------"   >> ~/artifacts/6_processes_$dt.txt
echo "Running Process - ps auxf"  >> ~/artifacts/6_processes_$dt.txt
echo "------------------"   >> ~/artifacts/6_processes_$dt.txt
sudo ps auxf >> ~/artifacts/6_processes_$dt.txt
echo >> ~/artifacts/6_processes_$dt.txt





echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Network connections"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt

if [ "$DISTRO" == "osx" ]; then
    echo "Command netstat -ap tcp:"  >> ~/artifacts/1.1_$dt.txt
    sudo netstat -ap tcp >> ~/artifacts/1.1_$dt.txt
elif [ -x "$(command -v netstat)" ]; then
    echo "Command netstat -plant:"  >> ~/artifacts/1.1_$dt.txt
    sudo netstat -plant >> ~/artifacts/1.1_$dt.txt
    echo "Command netstat -a:"  >> ~/artifacts/1.1_$dt.txt
    sudo netstat -a >> ~/artifacts/1.1_$dt.txt
elif [ -x "$(command -v ss)" ]; then
    echo "Command ss -autp:"  >> ~/artifacts/1.1_$dt.txt
    sudo ss -autp >> ~/artifacts/1.1_$dt.txt
fi




echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Network Adopter Settings"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "::: ifconfig command :::" >> ~/artifacts/1.1_$dt.txt
if [ -x "$(command -v ifconfig)" ]; then
    sudo ifconfig >> ~/artifacts/1.1_$dt.txt
else
    sudo ip addr >> ~/artifacts/1.1_$dt.txt
fi
echo "::: iwconfig command :::" >> ~/artifacts/1.1_$dt.txt
if [ -x "$(command -v iwconfig)" ]; then
    sudo iwconfig >> ~/artifacts/1.1_$dt.txt 2>&1
fi

echo "::: lspci command :::" >> ~/artifacts/1.1_$dt.txt
if [ -x "$(command -v lspci)" ]; then
    sudo lspci >> ~/artifacts/1.1_$dt.txt 2>&1
fi
echo >> ~/artifacts/1.1_$dt.txt




echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Routing Table"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
if [ -x "$(command -v ip)" ]; then
    sudo ip route show >> ~/artifacts/1.1_$dt.txt 2>&1
else
    sudo netstat -nr >> ~/artifacts/1.1_$dt.txt 2>&1
fi
echo >> ~/artifacts/1.1_$dt.txt





echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "ARP Table"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
if [ -x "$(command -v ip)" ]; then
    sudo ip neighbor >> ~/artifacts/1.1_$dt.txt 2>&1
else
    sudo arp -a >> ~/artifacts/1.1_$dt.txt 2>&1
fi
echo >> ~/artifacts/1.1_$dt.txt




echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "List of all active UDP and TCP services"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo lsof -i >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Hosts File"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
cat /etc/hosts >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Resolv.conf File"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo cat  /etc/resolv.conf >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "ip_forward File"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
if [ "$DISTRO" == "osx" ]; then
    sudo sysctl -w net.inet.ip.forwarding >> ~/artifacts/1.1_$dt.txt 2>&1
else
    sudo cat /proc/sys/net/ipv4/ip_forward >> ~/artifacts/1.1_$dt.txt 2>&1
fi

echo >> ~/artifacts/1.1_$dt.txt



if [ -f /etc/sysctl.conf ]; then
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "sysctl.conf File"  >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    cat /etc/sysctl.conf >> ~/artifacts/1.1_$dt.txt 2>&1
    echo >> ~/artifacts/1.1_$dt.txt
fi


if [ -f /etc/sysconfig/network ];then
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    echo "sysconfig/network File (Redhat)"  >> ~/artifacts/1.1_$dt.txt
    echo "------------------"   >> ~/artifacts/1.1_$dt.txt
    cat /etc/sysconfig/network >> ~/artifacts/1.1_$dt.txt 2>&1
    echo >> ~/artifacts/1.1_$dt.txt
fi



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "SSH authorized_keys File"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo cat ~/.ssh/authorized_keys >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt







echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "30 largest files on the disk"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo find / -xdev -type f -size +100M -exec du -sh {} ';' | sort -rh | head -n50 >> ~/artifacts/1.1_$dt.txt
echo >> ~/artifacts/1.1_$dt.txt




echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Files over 100MB on entire filesystem"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo find / -xdev -type f -size +100M -exec ls -lha {} \; | sort -nk 5 >> ~/artifacts/1.1_$dt.txt
echo >> ~/artifacts/1.1_$dt.txt



echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Largest directories from /"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
sudo du -ahx / | sort -rh | head -20 >> ~/artifacts/1.1_$dt.txt 2>&1
echo >> ~/artifacts/1.1_$dt.txt






echo "------------------"   >> ~/artifacts/1.1_$dt.txt
echo "Finding name of devices"  >> ~/artifacts/1.1_$dt.txt
echo "------------------"   >> ~/artifacts/1.1_$dt.txt
disk_name=$(df / | tail -1 | cut -d' ' -f1)
echo $disk_name
echo $disk_name >> ~/artifacts/1.1_$dt.txt
echo "lsdel" > ~/artifacts/cmd.txt
sudo debugfs $disk_name -f ~/artifacts/cmd.txt | cat >> ~/artifacts/1.1_$dt.txt
echo >> ~/artifacts/1.1_$dt.txt






echo "------------------"   >>~/artifacts/7_listing-path_$dt.txt
echo "PATH Environment Variable Listing"  >> ~/artifacts/7_listing-path_$dt.txt
echo "------------------"   >> ~/artifacts/7_listing-path_$dt.txt
OIFS=$IFS
path=$(echo $PATH)
IFS=':'		# : is set as delimiter
read -ra element <<< "$path"	# path is read into an array as tokens separated by IFS
IFS=' '		# reset to default value after usage

for i in "${element[@]}"; do	# access each element of array
    echo "$i" >> ~/artifacts/7_listing-path_$dt.txt
done

echo >> ~/artifacts/7_listing-path_$dt.txt
echo >> ~/artifacts/7_listing-path_$dt.txt

IFS=':'		# : is set as delimiter
read -ra element <<< "$path"	# path is read into an array as tokens separated by IFS
IFS=' '		# reset to default value after usage

for i in "${element[@]}"; do	# access each element of array
    echo "$i" >> ~/artifacts/7_listing-path_$dt.txt
    sudo ls -lah $i >> ~/artifacts/7_listing-path_$dt.txt 2>&1
    echo >> ~/artifacts/7_listing-path_$dt.txt
done
IFS=$OIFS
echo >> ~/artifacts/7_listing-path_$dt.txt




echo "------------------"   >> ~/artifacts/19_ec2_metadata_$dt.txt
echo "EC2 Metadata"  >> ~/artifacts/19_ec2_metadata_$dt.txt
echo "------------------"   >> ~/artifacts/19_ec2_metadata_$dt.txt

if [ -x "$(command -v ec2metadata)" ]; then
    sudo ec2metadata >> ~/artifacts/19_ec2_metadata_$dt.txt 2>&1
else
    echo "ec2metadata command not found" >> ~/artifacts/19_ec2_metadata_$dt.txt 2>&1
fi

echo >> ~/artifacts/19_ec2_metadata_$dt.txt




echo "------------------"   >> ~/artifacts/20_packages_list_$dt.txt
echo "Packages List"  >> ~/artifacts/20_packages_list_$dt.txt
echo "------------------"   >> ~/artifacts/20_packages_list_$dt.txt
sudo dpkg -l >> ~/artifacts/20_packages_list_$dt.txt 2>&1
echo >> ~/artifacts/20_packages_list_$dt.txt




mkdir ~/artifacts/8_interesting-files_$dt
echo "------------------"   >> ~/artifacts/8_interesting-files_$dt.txt
echo "Interesting Files (.conf .config .yaml user password .err .deb .rpm boot.log .exe, .ps, .py and .sh)"  >> ~/artifacts/8_interesting-files_$dt.txt
echo "------------------"   >> ~/artifacts/8_interesting-files_$dt.txt
sudo find / -type f \( -iname "*.conf" -o -iname "*.config" -o -iname "*.yaml" -o -iname "*user*"\
 -o -iname "*password*" -o -iname "*passwd*" -o -iname "*.err" -o -iname "*.deb" -o -iname "*.rpm" -o -iname "boot.log" -o -iname "*.exe" -o -iname "*.ps" -o -iname "*.py" -o -iname "*.sh" \) \
| while read -r file; do
    echo "$file" >> ~/artifacts/8_interesting-files_$dt.txt
    sudo cp "$file"  ~/artifacts/8_interesting-files_$dt    # double quotes inside filename is necessary to handle whitespaces
done
echo "Zipping Interesting Files"

mkdir ~/artifacts/8_interesting-files_$dt/conf_$dt
mkdir ~/artifacts/8_interesting-files_$dt/config_$dt
mkdir ~/artifacts/8_interesting-files_$dt/yaml_$dt
mkdir ~/artifacts/8_interesting-files_$dt/user_$dt
mkdir ~/artifacts/8_interesting-files_$dt/password_$dt
mkdir ~/artifacts/8_interesting-files_$dt/error_$dt
mkdir ~/artifacts/8_interesting-files_$dt/deb_$dt
mkdir ~/artifacts/8_interesting-files_$dt/rpm_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*.conf ~/artifacts/8_interesting-files_$dt/conf_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*.config ~/artifacts/8_interesting-files_$dt/config_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*.yaml ~/artifacts/8_interesting-files_$dt/yaml_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*.err ~/artifacts/8_interesting-files_$dt/error_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*.deb ~/artifacts/8_interesting-files_$dt/deb_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*.rpm ~/artifacts/8_interesting-files_$dt/rpm_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*[uU][sS][eE][rR]* ~/artifacts/8_interesting-files_$dt/user_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*[pP][aA][sS][sS][wW][oO][rR][dD]* ~/artifacts/8_interesting-files_$dt/password_$dt
sudo mv ~/artifacts/8_interesting-files_$dt/*[pP][aA][sS][sS][wW][dD]* ~/artifacts/8_interesting-files_$dt/password_$dt

sudo tar cvf ~/artifacts/8_interesting-files_$dt.tar --absolute-names ~/artifacts/8_interesting-files_$dt
sudo rm -rf ~/artifacts/8_interesting-files_$dt
echo >> ~/artifacts/8_interesting-files_$dt.txt







# mkdir ~/artifacts/9_interesting-directories_$dt
echo "------------------"   >> ~/artifacts/9_interesting-directories_$dt.txt
echo "Interesting Directories"  >> ~/artifacts/9_interesting-directories_$dt.txt
echo "------------------"   >> ~/artifacts/9_interesting-directories_$dt.txt
sudo find / -type d \( -name "www" -o  -name "htdocs" \) \
| while read -r file; do
    echo "$file" >> ~/artifacts/9_interesting-directories_$dt.txt
#    sudo cp -R "$file"  ~/artifacts/9_interesting-directories_$dt
done
# echo "Zipping Interesting Directories"
# sudo tar cvf ~/artifacts/9_interesting-directories_$dt.tar ~/artifacts/9_interesting-directories_$dt
# sudo rm -rf ~/artifacts/9_interesting-directories_$dt
echo >> ~/artifacts/9_interesting-directories_$dt.txt









echo "------------------"   >> ~/artifacts/10_tree_$dt.txt
echo "Tree /home/"  >> ~/artifacts/10_tree_$dt.txt
echo "------------------"   >> ~/artifacts/10_tree_$dt.txt
#if [ -n "$(command -v yum)" ]; then
#	sudo yum install -y tree
#else
#	sudo apt install -y tree
#fi

sudo ls -laR /home/ >> ~/artifacts/10_tree_$dt.txt

echo >> ~/artifacts/10_tree_$dt.txt






mkdir ~/artifacts/11_mail_$dt
echo "------------------"
echo "Mail Directories"
echo "------------------"
if [ -d "/var/mail/" ]; then
    sudo cp -R /var/mail/ ~/artifacts/11_mail_$dt
fi
if [ -d "/var/spool/mail/" ]; then
    sudo cp -R /var/spool/mail/ ~/artifacts/11_mail_$dt
fi
if [ -d "/var/vmail/" ]; then
    sudo cp -R /var/vmail/ ~/artifacts/11_mail_$dt
fi

cat /etc/passwd | cut -d: -f6 | grep /home/ | while read -r directory; do
	if [ -d "$directory/Maildir" ]; then
    	sudo cp -R $directory/Maildir ~/artifacts/11_mail_$dt
	fi
	if [ -d "$directory/mail/sent-mail" ]; then
    	sudo cp -R $directory/mail/sent-mail ~/artifacts/11_mail_$dt
	fi
done
echo





echo "------------------" >> ~/artifacts/12_mysql_history_$dt.txt
echo "MySQL History" >> ~/artifacts/12_mysql_history_$dt.txt
echo "------------------" >> ~/artifacts/12_mysql_history_$dt.txt
cat /etc/passwd | cut -d: -f6 | grep /home/ | while read -r directory; do
	if [ -f "$directory/.mysql_history" ]; then
    	sudo cat $directory/.mysql_history >> ~/artifacts/12_mysql_history_$dt.txt
	fi
done
echo >> ~/artifacts/12_mysql_history_$dt.txt





mkdir ~/artifacts/13_cron_$dt
echo "------------------"   >> ~/artifacts/13_cron_$dt.txt
echo "Cron Jobs of Every User"   >> ~/artifacts/13_cron_$dt.txt
echo "------------------"   >> ~/artifacts/13_cron_$dt.txt
for user in $(cut -f1 -d: /etc/passwd); do 
	echo $user >> ~/artifacts/13_cron_$dt.txt
	tmp_var=$(sudo crontab -u $user -l 2>&1)
	echo $tmp_var >> ~/artifacts/13_cron_$dt.txt
done
sudo cp -R /etc/cron* ~/artifacts/13_cron_$dt/
echo >> ~/artifacts/13_cron_$dt.txt



mkdir ~/artifacts/14_tmp_$dt
echo "------------------"   >> ~/artifacts/14_tmp_$dt.txt
echo "zipping /tmp/"   >> ~/artifacts/14_tmp_$dt.txt
echo "------------------"   >> ~/artifacts/14_tmp_$dt.txt
tar cvf ~/artifacts/14_tmp_$dt.tar  --absolute-names /tmp/ 
echo >> ~/artifacts/14_tmp_$dt.txt



mkdir ~/artifacts/15_home_hidden_file_dir_$dt
echo "------------------"   >> ~/artifacts/15_home_hidden_file_dir_$dt.txt
echo "zipping /home/ hidden dir & files"   >> ~/artifacts/15_home_hidden_file_dir_$dt.txt
echo "------------------"   >> ~/artifacts/15_home_hidden_file_dir_$dt.txt

usersHavingHomeDir=$(cat /etc/passwd | grep /bin/bash | cut -d: -f6)


for userHavingHomeDir in $usersHavingHomeDir
do
    tempVar=$(cd $userHavingHomeDir ; tmp=$(ls -d .?*); echo $tmp )
    listOfFileToZip=""
    
    userName=$(echo ${userHavingHomeDir##*/}  | tr -d '\040\011\012\015')

    for f in $tempVar
    do
        if [ $f == ".." ]; then
            continue
        fi
        listOfFileToZip=$listOfFileToZip" $userHavingHomeDir/$f"
    done
    
    echo $listOfFileToZip >> ~/artifacts/15_home_hidden_file_dir_$dt.txt
    echo -e "\n" >> ~/artifacts/15_home_hidden_file_dir_$dt.txt
    tarName=(~/artifacts/15_home_hidden_file_dir_"$userName"_$dt.tar)
    tar cvf $tarName --absolute-names $listOfFileToZip
done
echo >> ~/artifacts/15_home_hidden_file_dir_$dt.txt


if [ "$DISTRO" == "osx" ]; then
    echo "------------------"
    echo "Please Wait - This step will take some time"
    echo "------------------"
    sudo python osxcollector.py
fi

echo "------------------"
echo "Zipping Artifacts Folder"
echo "------------------"
rm ~/artifacts/cmd.txt
sudo tar cvf ~/artifacts/output_$dt.tar --absolute-names ~/artifacts/


echo "------------------"
echo "Removing Temporary Artifacts"
echo "------------------"
sudo rm -rf ~/artifacts/*.txt ~/artifacts/11_mail* ~/artifacts/13_cron* ~/artifacts/8_interesting-files*.tar  ~/artifacts/14_tmp* ~/artifacts/15_home_hidden* 


echo "------------------"
echo "Zipping Log File /var/log/"
echo "------------------"
sudo tar cvf ~/artifacts/logs.tar --absolute-names /var/log/




echo "------------------"
echo "TCP Dump for 20 minutes"
echo "------------------"
if [ "$DISTRO" == "osx" ]; then
    activeInterface=$(sudo route get example.com | grep interface | cut -d: -f2)
fi
activeInterface=$(sudo route | grep '^default' | grep -o '[^ ]*$')
sudo tcpdump -i $activeInterface -w  tcpdump.pcap & 
pid=$!
sleep 1200  # sleep for 20 minutes
sudo kill $pid



sudo mv tcpdump.pcap ~/artifacts/


echo "script execute successfully!"

