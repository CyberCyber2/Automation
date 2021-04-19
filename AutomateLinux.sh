
#!/bin/bash
#pam,ssh,sudoers,login.defs,sysctl,pam,users,malware,media,firewall,update,bashrc,cron,#netstat,download files from github, packages, LAMP
#to add: verbos>call function to dev null, user to set user
#==============================================================#
clear
apt install pv -y &> /dev/null
apt install figlet -y &> /dev/null
apt install toilet -y &> /dev/null
apt install net-tools -y &> /dev/null
for x in {1..100} ; do
    sleep .01    # do some work here
    printf .
done | pv -pt -i0.2 -s100 -w 80 > /dev/null
clear
sleep 0.5

echo "$(date '+%D %T' | toilet -f term -F border)"
echo "========================================================================="
toilet -f ivrit 'TEAM SAFFRON'
echo "========================================================================="
#==============================================================#
verbosity=false
outputfile=/home/cyber/Desktop/output.txt
userfile=/home/cyber/Desktop/usr.txt
RESET="\033[0m"
BOLD="\033[1m"
COLOR="\033[38;5;11m"
#==============================================================#
function all_vulns () {
basic_vulns #call basic function
advServ
}
#==============================================================#
function basic_vulns () {
#basic stuff
ufw enable &> /dev/null #& echo "ufw enabled" >> $outputfile
ufw enable
ufw logging HIGH
ufw default deny
echo "ENABLING FIREWALL..."

#generate user list
usrFile=""
user=""
echo -e -n "${COLOR}Enter username (ie johnny): ${RESET}"
read user

#Backup files
mkdir /home/$user/Desktop/.BackupFiles
cp /etc/sudoers /home/$user/Desktop/.BackupFiles
cp /etc/passwd /home/$user/Desktop/.BackupFiles
cp /etc/login.defs /home/$user/Desktop/.BackupFiles
cp /etc/ssh/sshd_config /home/$user/Desktop/.BackupFiles



#Delete bad users
delusr=""
cut -d: -f1,3 /etc/passwd > /home/$user/Desktop/.tusr.txt
echo -e -n "${COLOR}Do you wish to delete bad users [y/n]? ${RESET}"
read delusr
if [ $delusr = 'y' ]
then
	while IFS=':' read line
		do
		((linenum++))
		[[ -z $line ]] && continue
		tmpusr=$(echo $line | cut -d\: -f1)	
		read -p "Do you wish to delete $line? "  choice <&3

		    case "$choice" in
			y|Y ) echo "deleting $tmpusr" ; sudo userdel $tmpusr ;;
			n|N ) echo "keeping $tmpusr";;
			* )   echo "invalid, keeping $tmpusr";;
		    esac
		update-passwd
		done 3<&0 < "/home/$user/Desktop/.tusr.txt"
	rm -rf /home/$user/Desktop/.tusr.txt
fi
#Fix user pemissions
prmusr=""
echo -e -n "${COLOR}Do you want to change permissions of all users[y/n]? ${RESET}"
read pasusr
if [ $pasusr = 'y' ]
then
	cut -d: -f1,3 /etc/passwd > /home/$user/Desktop/.tusr2.txt
		while IFS=':' read line
		do
		[[ -z $line ]] && continue
		tmpusr=$(echo $line | cut -d\: -f1)	
		tmpuid=$(echo $line | cut -d\: -f2)
		if [ "$tmpuid" -gt 999 -a "$tmpuid" -lt 60000 ] 
		then
			read -p "Enters permissions for $line  [a for admin, s for standard]? " choice <&3
			    case "$choice" in
				a|A ) echo "$tmpusr is now an admin"; adduser $tmpusr "sudo";;
				s|S ) echo "$tmpusr is now a standard user"; deluser $tmpusr "sudo";;
				* )   echo "invalid, keeping perms the same for $tmpusr";;
			    esac
			update-passwd
		fi
		done 3<&0 < "/home/$user/Desktop/.tusr2.txt"
	rm -rf /home/$user/Desktop/.tusr2.txt
fi
#Change user passwords
pasusr=""
echo -e -n "${COLOR}Do you want to change the passwords of every user[y/n]? ${RESET}"
read pasusr
if [ $pasusr = 'y' ]
then
	cut -d: -f1,3 /etc/passwd > /home/$user/Desktop/.tusr3.txt
	npasswd=""
	read -p "Enter secure password: "  npasswd
		while IFS=':' read line
		do
		[[ -z $line ]] && continue
		tmpusr=$(echo $line | cut -d\: -f1)	
		echo "$tmpusr:$npasswd" | chpasswd
		update-passwd
		done 3<&0 < "/home/$user/Desktop/.tusr3.txt"
	rm -rf /home/$user/Desktop/.tusr3.txt
fi

#delete malware
malware=('openssh-server' 'openssh-client' vsftpd 'pureftpd' john kismet nc netcat wireshark tshark telnet hydra mimikatz ophcrack)
delmal=""
echo -e -n "${COLOR}Do you want to delete unauthorized programs[y/n]? ${RESET}"
read delmal
if [ $delmal = 'y' ]
then
	for i in "${malware[@]}" 
	do 
		read -p "Do you want to delete $i [y/n]? " choice #<&3
			    case "$choice" in
				y|Y ) echo "removing malware: $i"; apt-get remove --purge $i;;
				n|N ) echo "keeping program: $i";;
				* )   echo "invalid, keeping program: $i";;
			    esac 
	done
fi

#delete cupsd
delcups=""
echo -e -n "${COLOR}Do you want to delete cupsd[y/n]? ${RESET}"
read delcups
if [ $delcups = 'y' ]
then
  apt-get remove -y --purge --auto-remove cups* &> /dev/null
  rm -rf * /var/spool/cups &> /dev/null
  rm -rf * /usr/share/cups &> /dev/null
  rm -rf * /usr/share/doc/*cups &> /dev/null
  rm -rf * /usr/share/doc-base/*cups &> /dev/null
  rm -rf * /etc/init.d/*cups &> /dev/null
  rm -rf * /run/cups &> /dev/null
  rm -rf * /usr/share/bug/*cups* &> /dev/null
  rm -rf * /usr/lib/cups &> /dev/null
  rm -rf * /etc/cups &> /dev/null
  rm -rf * /etc/pam.d/cups &> /dev/null
  rm -rf * /etc/rc1.d/*cups &> /dev/null
  rm -rf * /etc/rc2.d/*cups &> /dev/null
  rm -rf * /etc/rc3.d/*cups &> /dev/null
  rm -rf * /etc/rc4.d/*cups &> /dev/null
  rm -rf * /etc/rc5.d/*cups &> /dev/null
  rm -rf * /usr/share/lintian/overrides/cups &> /dev/null
  rm -rf * /etc/ufw/applications.d/cups &> /dev/null
  rm -rf * /var/cache/cups &> /dev/null
  rm -rf * /var/log/cups &> /dev/null

fi

#deep malware scan
deepmal=""
echo -e -n "${COLOR}Perform indepth malware scan[y/n]?  ${RESET}"
read deepmal
if [ $deepmal = 'y' ]
then
  dpkg --list | cut -d ' ' -f3 | tail -n +6  > /home/$user/Desktop/.crnt.txt #currently installed
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/Ubuntu18.04defaultpackages -q -O - > /home/$user/Desktop/.dflt.txt #default installed
	diff --new-line-format="" --unchanged-line-format="" <(sort /home/$user/Desktop/.crnt.txt) <(sort /home/$user/Desktop/.dflt.txt) >> /home/$user/Desktop/nondefaultservices.txt
fi

#delete media files
media=(txt mp3 mp4)
delmed=""
echo -e -n "${COLOR}Do you want to delete media files[y/n]?  ${RESET}"
read delmed
if [ $delmed = 'y' ]
then
	for i in "${media[@]}"  
	do
		tmpext=( $(find "/home" -type f -name "*.$i" | sed '/firefox/,+1 d' | sed '/Trash/,+1 d' ) ) #find all media files ending in every extension and put them in that array. sed "/$user/Desktop/,+1 d"
		for j in "${tmpext[@]}"
		do
			read -p "Do you want to delete $j [y/n]? " choice #<&3
				    case "$choice" in
					y|Y ) echo "removing media file: $j"; rm -rf $j;;
					n|N ) echo "keeping file: $j";;
					* )   echo "invalid, keeping file: $j";;
				    esac 
		done
	done
fi

#File Configurations
confiles=""
echo -e -n "${COLOR}Do you want to configure PAM, SYSCTL, LOGIN.DEFS, and SUDOERS [y/n]? ${RESET}"
read confiles
if [ $confiles = 'y' ]
then
  apt-get install -y libpam-cracklib &> /dev/null
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/sysctl.conf -q -O - > /etc/sysctl.conf
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/sshd_config -q -O - > "/etc/ssh/sshd_config"
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/login.defs -q -O - > /etc/login.defs
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/sudoers.d -q -O - > /etc/sudoers
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/PAMCommon -q -O - > /etc/pam.d/common-password
  echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth
  echo "allow-guest=false" >> /etc/lightdm/lightdm.conf.d/50-enable-guest.conf 
  #echo "Ubuntu 18.04.5 LTS" > /etc/issue.net
  #echo "order hosts,bind" > /etc/host.conf
  #echo "multi on" >> /etc/host.conf
fi

#File permissions
perms=""
echo -e -n "${COLOR}Do you want to configure file permissions [y/n]? ${RESET}"
read perms
if [ $perms = 'y' ]
then
  files=('/etc/shadow' '/etc/passwd' '/root/bash.rc' '/root/.profile' '/etc/profile' '/etc/syctl.conf' '/tmp' '/var/tmp')
  permsArr=(400 644 644 644 644 700 1777 877)
  for i in ${files[@]}; do
  chmod ${permsArr[i]} ${files[i]}
  done
fi
#get list of all default file perms; for every file that exists; compare file perms
#List all files with sticky, SUID, GUID bit ---->Put values into an array and list them out, ask if want to delete
#find / -perm +4000 -type f #SUID
#find / -perm +1000 #Sticky
#find / -perm +2000 #GUID

#LAMP--->Do this manually

#Rootkit hunter

#List running services with netstat, ask if want to kill them
servnamesVAR=$(netstat -tulpn | tr -d 'LISTEN' | tail -n +3 | tr -s ' ' | cut -d ' ' -f6 | cut -d/ -f2 | sed 's/:$//' ) #string form of services separated with space
pidsVAR=$(netstat -tulpn | tr -d 'LISTEN' | tail -n +3 | tr -s ' ' | cut -d ' ' -f6 | cut -d/ -f1)
portVAR=$(netstat -tulpn | tr -d 'LISTEN' | tail -n +3 | tr -s ' ' | cut -d ' ' -f4 | sed 's|.*:||')
srv=""
echo -e -n "${COLOR}Do you want to stop services [y/n]? ${RESET}"
read srv
if [ $srv = 'y' ]
then
    servnamesARR=(`echo $servnamesVAR | cut -d " "  --output-delimiter=" " -f 1-`) #convert string into array
    pidsARR=(`echo $pidsVAR | cut -d " "  --output-delimiter=" " -f 1-`)
    portARR=(`echo $portVAR | cut -d " "  --output-delimiter=" " -f 1-`)

    #TEST#
    echo ${pidsARR[*]}
    echo ${portARR[*]}
    echo ${servnamesARR[*]}
    ######
    for index in ${!servnamesARR[*]}; do 
      read -p "Delete ${servnamesARR[$index]} with PID ${pidsARR[$index]} and port ${portARR[$index]}  [y/n]? " choice #<&3
				    case "$choice" in
					y|Y ) echo "stopping service: ${servnamesARR[$index]} " ; kill -9 ${pidsARR[$index]};;
					n|N ) echo "keeping service: ${servnamesARR[$index]} " ;;
					* )   echo "invalid, keeping service: ${servnamesARR[$index]} " ;;
				    esac 
    done
fi

#Update Settings
updates=""
echo -e -n "${COLOR}Do you want to configure update settings and update the system [y/n]? ${RESET}"
read updates
if [ $updates = 'y' ]
then
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/sources.list -q -O - > /etc/apt/sources.list
  wget https://raw.githubusercontent.com/CyberCyber2/CyberPatriot/master/10periodic -q -O - > /etc/apt/apt.conf.d/10periodic 
  apt-get update
  apt-get dist-upgrade
fi

#fix apt(not vulnerability)
aptfix=""
echo -e -n "${COLOR}fix apt lock issue(not vulnerability)[y/n]? ${RESET}"
read aptfix
if [ $aptfix = 'y' ]
then
  sudo rm /var/lib/apt/lists/lock
  sudo rm /var/cache/apt/archives/lock
  sudo rm /var/lib/dpkg/lock
  
  #--new-line-format="" --unchanged-line-format="" <(sort /home/$user/Desktop/.crnt.txt) <(sort /home/$user/Desktop/.dflt.txt) >> /home/$user/Desktop/nondefaultservices.txt
fi

#backup admin creation
user BackupAdmin
echo BackupAdmin:password | chpasswd
usermod -U -e "" cyber
}
#==============================================================#
function advServices () {
#APACHE2

#PHP

#MYSQL

#pure=ftpd

#vsftpd

#samba

#crontab & rc.local & profile

#
}
#==============================================================#
function print_usage () {
echo "SYNTAX: .script.sh [-h(help) -a(all) -b(basic) -v(verbose) -u(user)] [-o(output file) outputfile]"
}
#==============================================================#
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -o|--output) outputfile="$2"; shift ;;
	-a|--all) all_vulns ; shift ;;
	-b|--basic) basic_vulns ; shift ;;
	-h|--help) print_usage ; shift ;;
  -l|--advanced-services) advServices ; shift ;;
  #-v|--verbose) verbosity=true ;;
  *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done
###############
echo -e "\e[1;33;4;44mFinished Executing Script\e[0m"
exit
