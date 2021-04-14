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
	
	mkdir -v $ssh_path
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
		       dstat iotop git psmisc tree lynx at postfix lshfw inxi figlet \ 
	       		gdisk mc cifs-utils ntfs-3g sudo curl sshfs apt-file openssl \ 
	       		gnupg2 dnsutils fish gpm grc ncdu p7zip-full parted

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

	groupadd -g $gid $username
	useradd -u $uid -g $gid -m $username
	echo -e "$password\n$password" | passwd $username 

	if [ $admin = sudo ]; then 
		usermod -aG sudo $username
	fi 
}


config_ssh(){
	##########################################################
	#							 #
	#		Création d'un utilisateur 		 #
	#							 #
	##########################################################

	echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
	echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
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
	sed -i 's/dhcp/static/' /etc/network/interfaces

	cat >> /etc/network/interfaces.d/$interface << EOF
# Ajout de l'interface $interface
allow-hotplug $interface
iface $interface inet static
	address $address
	netmask $mask 
	gateway $gateway
	dns-nameservers $dns 
EOF

	ifdown $interface
	ifup $interface

	systemctl -w net.ipv6.conf.$interface.disable_ipv6=1
	
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

	timedatectl set-ntp on 
	systemctl status systemd-timesyncd
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
	
	cp $path_grub $path_grub.cfg

	# Set User and Password 
	#echo "set superusers = \"mathieu\"" >> $path_grub
	#echo "password.pbkdf2 mathieu">> $path_grub
	#echo "`echo -e "P@ssword\nP@ssword" | grub-mkpasswd-pbkdf2 2> /dev/null | awk -F" " '{ print $7 }'`" >> $path_grub


	echo "GRUB_DISABLE_RECOVERY=\"true\"" >> $path_etc_grub
	echo "GRUB_DISABLE_SUBMENU=y" >> $path_etc_grub 

	update-grub
}

define_bashrc(){
	
	##########################################################
	#							 #
	#		Fonction compteur Prof 			 #
	#							 #
	##########################################################

cat >> /tmp/.bashrc << EOF
HISTOCONTROL=ignoreboth
HISTSIZE=100000
HISTFILESIZE=100000
export PROMT_COMMAND='history -a; history -n ; history -w'
export PS1="\[\e[32m\][\[\e[m\]\[\e[31m\]\u\[\e[m\]\[\e[33m\]@\[\e[m\]\[\e[32m\]\h\[\e[m\]:\[\e[36m\]\w\[\e[m\]\[\e[32m\]]\[\e[m\]\[\e[32;47m\]\\$\[\e[m\] "


EOF
	source /tmp/.bashrc
}

customize_debian(){
	define_bashrc
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

postinstall_ESGI_work(){
	# Quitter si Erreur 
	set -e 
	# Activer le mode debogage
	# set -x 


	# Mise en place machine ESGI 
	packager 
	create_ssh_key root
	create_user esgi 10000 10000 P@ssword sudo
	create_ssh_key esgi 
	create_ssh_key $USER
	set_default_applications
	config_ssh 
	set_default_ip 192.168.1.190 255.255.255.0 192.168.1.254 "1.1.1.1 9.9.9.9"
	set_banner
	set_ntp_on
	secure_grub
}

#postinstall_ESGI_work
customize_debian
