#!/bin/bash

# Nom : postinstall.sh 
# Auteur : Mathieu NOYELLE
# contact : mathieu@noyelle.pro

create_ssh_key(){
	##########################################################
	#							 #
	#	Création des clés ssh pour un utilisateur	 #
	#							 #
	##########################################################

	# Param1 = nom d'utilisateur

	user=$1 
	
	if [ $user = "root" ]; then 
		ssh_path=/root/.ssh
	else
		ssh_path=/home/$user/.ssh
	fi 

	if [[ ! -e $ssh_path ]]; then	
		mkdir -v $ssh_path
	fi
	chmod -v 700 $ssh_path
	ssh-keygen -t ed25519 -f $ssh_path/id_ed25519 -q -N ""
	chown -R $user:$user $ssh_path

}

packager(){
	##########################################################
	#							 #
	#	Gestion des paquets (Clean & Install)		 #
	#							 #
	##########################################################

	# Mise à jour des paquets 
	apt update -y 
	apt upgrade -y 
	
	# Suppression des paquets non nécessaires 
	apt remove task-laptop telnet -y
	
	# installation des paquets essentiels 
	apt install -y mlocate rsync htop net-tools vim tmux screen zip pigz pixz \
		       dstat iotop git psmisc tree lynx at lshw inxi figlet \
		       gdisk mc cifs-utils ntfs-3g sudo curl sshfs apt-file openssl \
		       gnupg2 dnsutils fish gpm grc ncdu p7zip-full parted
	
	updatedb
	# Netoyage après installation 
	apt autoremove -y
	apt clean -y 
}


create_user(){
	##########################################################
	#							 #
	#		Création d'un utilisateur 		 #
	#							 #
	##########################################################
	
	# Param1 = nom d'utilisateur 
	# Param2 = GID 
	# Param3 = UID 
	# Param4 = Mot de passe 
	# Param5 = sudo / nosudo

	username=$1
	gid=$2
	uid=$3
	password=$4
	admin=$5
	shell=/bin/bash

	groupadd -g $gid $username
	useradd -u $uid -g $gid -m $username -s $shell
	echo -e "$password\n$password" | passwd $username 

	if [ $admin = sudo ]; then 
		usermod -aG sudo $username
	fi 
	chmod 700 /home/$username/
}


config_ssh(){
	##########################################################
	#							 #
	#		Création d'un utilisateur 		 #
	#							 #
	##########################################################

	echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
	echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
	chmod -v 640 /etc/ssh/ssh_config
	chmod -v 640 /etc/ssh/sshd_config
}

set_default_applications(){
	##########################################################
	#							 #
	# 	Définitions des applications par défaut	 	 #
	#							 #
	##########################################################

	ln -sfn /usr/bin/vim.basic /etc/alternatives/editor

}

set_default_ip(){
	##########################################################
	#							 #
	# 	Définitions des applications par défaut	 	 #
	#							 #
	##########################################################

	# Param1 = adresse IP 
	# Param2 = netmask 
	# Param3 = gateway 
	# Param4 = dns serveurs 

	address=$1
	mask=$2
	gateway=$3
	dns=$4

	interface=`ip -o link show | awk -F': ' '{print $2}' | grep -v lo`
	#sed -i 's/dhcp/static/' /etc/network/interfaces
	mv /etc/network/interfaces /etc/network/interfaces.old
	sed "/$interface/d" /etc/network/interfaces.old >> /etc/network/interfaces

	cat >> /etc/network/interfaces.d/ifcfg-$interface << EOF
# Ajout de l'interface $interface
allow-hotplug $interface
auto $interface
iface $interface inet static
	address $address
	netmask $mask 
	gateway $gateway
	dns-nameservers $dns 
EOF

	ifdown $interface
	ifup $interface

	sysctl -w net.ipv6.conf.$interface.disable_ipv6=1
	
}


set_banner(){
	##########################################################
	#							 #
	# 	Mise en place d'une banière connexion		 #
	#							 #
	##########################################################
	
	cat >> /etc/issue.net << EOF
Toute utilisation non autorisée sera sévèrement punie 
EOF
	cp /etc/issue.net /etc/issue
	figlet WIKI-COFFRE > /etc/motd
}

set_ntp_on(){
	##########################################################
	#							 #
	#	Activer le service NTP 				 #
	#							 #
	##########################################################
	timedatectl set-timezone Europe/Paris
	timedatectl set-ntp on 
	#systemctl status systemd-timesyncd
	systemctl restart systemd-timesyncd
}

secure_grub(){
	##########################################################
	#							 #
	#		Sécurisation de GRUB 			 #
	#		EN COURS DE CONSTRUCTION		 #
	#							 #
	##########################################################

	path_grub=/boot/grub/grub.cfg
	path_etc_grub=/etc/default/grub

	echo "GRUB_DISABLE_RECOVERY=\"true\"" >> $path_etc_grub
	echo "GRUB_DISABLE_SUBMENU=y" >> $path_etc_grub 


	sed -i '$a set superusers="grub"' /etc/grub.d/40_custom
	grub_mdp_hash=`echo -e "grub\ngrub" | grub-mkpasswd-pbkdf2 | grep grub | awk -F " " '{ print $7}'`

	sed -i '$a password_pbkdf2 grub HASH' /etc/grub.d/40_custom
	sed -i "/HASH/s/HASH/$grub_mdp_hash/" /etc/grub.d/40_custom

	sed -i 's/--class os/--class os --unrestricted/g' /etc/grub.d/10_linux

	##resolution
	sed -i 's/quiet/vga=791/' /etc/default/grub
	sed -i "/GRUB_GFXMODE/s/^#//" /etc/default/grub
	sed -i "/GRUB_GFXMODE/s/640x480/1920x1080/" /etc/default/grub

	##timeout
	sed -i 's/=5/=20/' /etc/default/grub

	update-grub
}

define_bashrc(){
	##########################################################
	#							 #
	#		Fonction compteur Prof 			 #
	#							 #
	##########################################################
	
	# Param1 = user 
	user=$1
	
	if [ $user = 'root' ]; then 
	       	path=/root/.bashrc
		ps1="\[\e[31;40m\]\u\[\e[m\]@\[\e[34m\]\h\[\e[m\][\[\e[33m\]\w\[\e[m\]] \d -\A \[\e[33;41m\]\\$\[\e[m\]  "
	else
		path=/home/$user/.bashrc
		if [[ "`groups $user`" == *"sudo"* ]]; then 
			ps1="\[\e[32m\][\[\e[m\]\[\e[31m\]\u\[\e[m\]\[\e[33m\]@\[\e[m\]\[\e[32m\]\h\[\e[m\]:\[\e[36m\]\w\[\e[m\]\[\e[32m\]]\[\e[m\]\[\e[32;47m\]\\$\[\e[m\] "

		else
			ps1="\[\e[32;40m\]\u\[\e[m\] at \[\e[34m\]\h\[\e[m\] in \[\e[33m\]\w\[\e[m\] \d -\A \[\e[44m\]\\$\[\e[m\]  "
		fi	
	fi
	
	if [ -f $path ]; then
		rm $path
	fi


cat >> $path << EOF
HISTOCONTROL=ignoreboth
HISTSIZE=100000
HISTFILESIZE=100000
export PROMT_COMMAND='history -a; history -n ; history -w'
export PS1="$ps1"
export CHEAT_CONFIG_PATH="/etc/cheat/conf.yml"

alias ll="ls -las"
alias ip="ip -c"
alias cp="cp -iv"
alias mv="mv -iv"
alias mkdir="mkdir -vp"
alias rmdir="rmdir -vp"

EOF
	chown $user:$user $path	
	chmod 770 $path
}

customize_debian(){
	set_banner
}

define_hostname(){
	##########################################################
	#							 #
	#		Definis le hostname 			 #
	#							 #
	##########################################################
	
	ip=$1

	old_hostname=`hostname`
	hostnamectl set-hostname wiki.esgi.local
	sed -i "s/$old_hostname/wiki.esgi.local		wiki/g" /etc/hosts
	sed -i "s/127.0.1.1/$ip/" /etc/hosts

} 


compteur(){
	##########################################################
	#							 #
	#		Fonction compteur Prof 			 #
	#							 #
	##########################################################

	for i in $(seq 20);do
		echo -n "$i"
		sleep 1 
	done 

}

install_cheat(){
	##########################################################
	#							 #
	#		Installation de cheat			 #
	#							 #
	##########################################################
	
	cheat_version="4.2.0"
	cheat_type="cheat-linux-amd64"
	apt install wget
	wget https://github.com/cheat/cheat/releases/download/$cheat_version/$cheat_type.gz
	gzip -d $cheat_type.gz 
	mv $cheat_type /usr/bin/cheat
	chmod +x /usr/bin/cheat

	mkdir -pv /etc/cheat

	chmod -R 731 /etc/cheat
	
}

postinstall_ESGI_work(){
	# Quitter si Erreur 
	set -e 
	# Activer le mode debogage
	# set -x 

	first_user=`cat /etc/passwd | grep 1000 | awk -F":" '{ print $1 }'`
	ip=192.168.1.190
	mask=255.255.255.0
	gateway=192.168.1.254
	dns="1.1.1.1 9.9.9.9"

	# Mise en place machine ESGI 
	hwclock --hctosys # met à l'heure du bios 
	timedatectl set-timezone Europe/Paris
	packager 

	create_ssh_key root
	create_user esgi 10000 10000 P@ssword sudo
	create_ssh_key esgi 
	create_ssh_key $first_user

	set_default_applications

	config_ssh 
	set_ntp_on
	secure_grub

	set_default_ip $ip $mask $gateway $dns

	set_banner
	customize_debian

	define_bashrc root
	define_bashrc esgi
	define_bashrc $first_user
	
	define_hostname $ip
	install_cheat	
	reboot 	
}

postinstall_ESGI_work
#customize_debian
#install_cheat
#define_hostname 192.168.1.190

#secure_grub
