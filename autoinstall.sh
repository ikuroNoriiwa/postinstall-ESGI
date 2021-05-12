#!/bin/bash

# Nom : postinstall.sh 
# Auteur : Mathieu NOYELLE
# contact : mathieu@noyelle.pro

print_header(){
echo "             _                _ _    _   _ "
echo "  __ _ _   _| |_ _____      _(_) | _(_) | |"
echo " / _\` | | | | __/ _ \\ \\ /\\ / / | |/ / | | |"
echo "| (_| | |_| | || (_) \ V  V /| |   <| | |_|"
echo " \__,_|\__,_|\__\___/ \_/\_/ |_|_|\_\_| (_)"

}

create_ssh_key(){
	##########################################################
	#							 #
	#	Création des clés ssh pour un utilisateur	 #
	#							 #
	##########################################################

	# Param1 = nom d'utilisateur

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#		Create SSH key for user $1			    #"
	echo "#							    	    #"	
	echo "###############################################################"

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


	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#				Setup Packages			    #"
	echo "#							    	    #"	
	echo "###############################################################"

	hwclock --hctosys # met à l'heure du bios 
	timedatectl set-timezone Europe/Paris

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

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#			Create User $1				    #"
	echo "#							    	    #"	
	echo "###############################################################"

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

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#				Config SSH			    #"
	echo "#							    	    #"	
	echo "###############################################################"

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

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#			Setup Default Applications		    #"
	echo "#							    	    #"	
	echo "###############################################################"

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

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     		Setup Static IP : $1			    #"
	echo "#							    	    #"	
	echo "###############################################################"

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
	
	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Setup Banner			    #"
	echo "#							    	    #"	
	echo "###############################################################"

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

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Setup NTP			    #"
	echo "#							    	    #"	
	echo "###############################################################"

	timedatectl set-timezone Europe/Paris
	timedatectl set-ntp on 
	systemctl restart systemd-timesyncd
}

secure_grub(){
	##########################################################
	#							 #
	#		Sécurisation de GRUB 			 #
	#		EN COURS DE CONSTRUCTION		 #
	#							 #
	##########################################################

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Secure GRUB			    #"
	echo "#							    	    #"	
	echo "###############################################################"

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
	#			Set Bashrc 			 #
	#							 #
	##########################################################
	
	# Param1 = user 
	# Param2 = user créé à l'installation
	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Setup Bashrc			    #"
	echo "#							    	    #"	
	echo "###############################################################"

	user=$1
	first_user=$2
	
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

		if [ ! -f /home/$user/.bash_profile ]; then
			echo -e "if [ -f ~/.bashrc ]; then\n	. ~/.bashrc\nfi" >> /home/$user/.bash_profile
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
export CHEAT_CONFIG_PATH="/home/$first_user/COFFRE/MEMENTO/conf.yml"

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
	
	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Set Hostname Wiki		    #"
	echo "#							    	    #"	
	echo "###############################################################"
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

install_dropbear(){
	##########################################################
	#							 #
	#		installation de Dropbear		 #
	#							 #
	##########################################################

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Setup Dropbear			    #"
	echo "#							    	    #"	
	echo "###############################################################"
	cle_publique=`pwd`/$1
	ip=$2
	gateway=$3
	mask=$4

	apt install dropbear busybox -y 

	sed -i "s/BUSYBOX=auto/BUSYBOX=y/g" /etc/initramfs-tools/initramfs.conf
	echo "DROPBEAR=y" >> /etc/initramfs-tools/initramfs.conf
	echo "IP=$ip::$gateway:$mask:`hostname`" >> /etc/initramfs-tools/initramfs.conf
	
	cd /etc/dropbear-initramfs/
	/usr/lib/dropbear/dropbearconvert dropbear openssh dropbear_rsa_host_key id_rsa
	dropbearkey -y -f dropbear_rsa_host_key | grep "^ssh-rsa " > id_rsa.pub

	
	cat $cle_publique >> /etc/dropbear-initramfs/authorized_keys	

	cd 
	sed -i "s/NO_START=1/NO_START=0/g" /etc/default/dropbear
	echo "DROPBEAR_OPTIONS=\"-p 21\"" >> /etc/dropbear-initramfs/config
       	update-initramfs -u 
	systemctl disable dropbear
}


setup_coffre(){
	##########################################################
	#							 #
	#		Setup Coffre :)				 #
	#							 #
	##########################################################

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Setup COFFRE 			    #"
	echo "#							    	    #"	
	echo "###############################################################"
	user=$1
	
	umount -v /home/$user/COFFRE
	#echo -e "YES\nP@ssword\nP@ssword" | cryptsetup luksFormat /dev/VGCRYPT/lv_coffre
	echo "YES" | echo "P@ssword" | echo "P@ssword" | cryptsetup luksFormat /dev/VGCRYPT/lv_coffre 
	
	mv /etc/fstab /etc/fstab.old
	sed "/COFFRE/d" /etc/fstab.old > /etc/fstab
	echo "P@ssword" | cryptsetup luksOpen /dev/VGCRYPT/lv_coffre lv_coffrecrypt
	mkfs.btrfs /dev/mapper/lv_coffrecrypt

	mount /dev/mapper/lv_coffrecrypt /home/$user/COFFRE
	mkdir -vp /home/$user/COFFRE/CERTIFICAT
	mkdir -vp /home/$user/COFFRE/ENVIRONNEMENT/{bash,ksh,zsh}
	mkdir -vp /home/$user/COFFRE/MEMENTO/cheat/cheatsheets/{community,personal} 
	mkdir -vp /home/$user/COFFRE/SECURITE/{fail2ban,firewall,supervision}
	mkdir -vp /home/$user/COFFRE/SERVEUR/DEBIAN10/APPLIS/{BookStack,mysql}
	mkdir -vp /home/$user/COFFRE/SERVEUR/DEBIAN10/TEMPLATES/{php,php-fpm,apache,bind,nginx,rsyslog,ssh}

}

install_cheat(){
	##########################################################
	#							 #
	#		Installation de cheat			 #
	#							 #
	##########################################################
	# Param1 : user propriétaire des cheats 

	echo "\n\n###############################################################"
	echo "#								    #"
	echo "#	     			Install Cheat 			    #"
	echo "#							    	    #"	
	echo "###############################################################"

	user=$1

	cheat_version="4.2.0"
	cheat_type="cheat-linux-amd64"
	apt install wget
	wget https://github.com/cheat/cheat/releases/download/$cheat_version/$cheat_type.gz
	gzip -d $cheat_type.gz 

	mv $cheat_type /usr/bin/cheat
	cp /usr/bin/cheat /home/$user/COFFRE/MEMENTO/cheat/cheat

	chmod +x /home/$user/COFFRE/MEMENTO/cheat/cheat
	chmod +x /usr/bin/cheat

	mkdir -pv /etc/cheat

	chmod -R 755 /etc/cheat


	cat >>  /etc/cheat/conf.yml << EOF
editor: vim
colorize: true
style: monokai
formatter: terminal16m

cheatpaths:
 - name: community
   path: /home/$user/COFFRE/MEMENTO/cheat/cheatsheets/community
   tags: [ community ] 
   readonly: true

 - name: personal
   path: /home/$user/COFFRE/MEMENTO/cheat/cheatsheets/personal
   tags: [ personal ] 
   readonly: false 
EOF
	cd /tmp/
	git clone https://github.com/cheat/cheatsheets
	mv /tmp/cheatsheets/* /home/$user/COFFRE/MEMENTO/cheat/cheatsheets/community

	
}


chroot_default_user(){
	##########################################################
	#							 #
	#		Chroot user 				 #
	#							 #
	##########################################################
	# Param1 : user créé à l'installation 
	user=$1
	mkdir /home/CHROOT
	cd /home/CHROOT
	rsync -Ra /usr/{bin,lib64,lib}/ /home/CHROOT

	ln -s usr/bin/ bin
	ln -s usr/lib lib
	ln -s usr/lib64 lib64

	rsync -Ra /home/$user/ /home/CHROOT/
	rsync -Ra /dev/{null,zero,tty*} /home/CHROOT/
	rsync -Ra /etc/{passwd,shadow} /home/CHROOT/


	cd dev/
	ln -s /dev/stdin 
	ln -s /dev/stdout
	ln -s /dev/sterr


	touch /home/CHROOT/home/mathieu/.profile
cat >> /home/CHROOT/home/mathieu/.profile << EOF
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f /home/yonix/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true


EOF


cat >> /etc/ssh/sshd_config << EOF
Match User $user
        ChrootDirectory /home/CHROOT
  

EOF
	systemctl restart ssh


}
install_nginx(){
	apt install nginx -y

	systemctl stop nginx.service
	systemctl start nginx.service
	systemctl enable nginx.service
}

install_mariadb(){
	apt install -y mariadb-server mariadb-client
	DB_PASS="password"

	systemctl stop mariadb.service
	systemctl start mariadb.service
	systemctl enable mariadb.service

	echo -e "Y\n$DB_PASS\n$DB_PASS\nY\nY\nY\nY" | mysql_secure_installation
	mysql -u root --execute="CREATE DATABASE bookstack;"
	mysql -u root --execute="CREATE USER 'bookstack'@'localhost' IDENTIFIED BY '$DB_PASS';"
	mysql -u root --execute="GRANT ALL ON bookstack.* TO 'bookstack'@'localhost';FLUSH PRIVILEGES;"
}

install_php(){
	version=7.3

	apt install php$version-fpm php$version-mbstring php$version-curl php$version-mysql php$version-gd php$version-xml php-tokenizer -y
}

install_bookstack(){
	install_nginx
	install_mariadb
	install_php

	apt install composer -y

	cd /var/www

	git clone https://github.com/BookStackApp/BookStack.git --branch release --single-branch
	cd BookStack
	composer install --no-dev
	cp .env.example .env
	sed -i.bak "s@APP_URL=.*\$@APP_URL=http://$DOMAIN@" .env
	sed -i.bak 's/DB_DATABASE=.*$/DB_DATABASE=bookstack/' .env
	sed -i.bak 's/DB_USERNAME=.*$/DB_USERNAME=bookstack/' .env
	sed -i.bak "s/DB_PASSWORD=.*\$/DB_PASSWORD=$DB_PASS/" .env
	php artisan key:generate --no-interaction --force
	echo -e "Y\n" | php artisan migrate 

	
cat >> /etc/nginx/sites-available/bookstack.conf << EOF
server { 
	listen 80;
	listen [::]:80;

	server_name wiki.esgi.local;

	root /var/www/BookStack/public;

	index index.php index.html;

	location / {
		try_files \$uri \$uri/ /index.php?\$query_string;
	}

	location ~ \.php$ { 
		fastcgi_index index.php;
		try_files \$uri =404;
		include fastcgi_params; 
		fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
		fastcgi_pass unix:/run/php/php7.3-fpm.sock;
	}
}

EOF
	#mkdir -vp /etc/nginx/sites-available/bookstack
	ln -s /etc/nginx/sites-available/bookstack.conf /etc/nginx/sites-enabled/

	chown -R www-data:www-data /var/www/BookStack
	systemctl stop nginx.service
	systemctl start nginx.service
	systemctl enable nginx.service

}

postinstall_ESGI_work(){
	# Quitter si Erreur 
	set -e 
	# Activer le mode debogage
	# set -x 
	print_header

	first_user=`cat /etc/passwd | grep 1000 | awk -F":" '{ print $1 }'`
	#ip=192.168.1.190
	#mask=255.255.255.0
	#gateway=192.168.1.254
	#dns="1.1.1.1 9.9.9.9"

	ip=192.168.1.200
	mask=255.255.255.0
	gateway=192.168.1.1
	dns="192.168.1.1 1.1.1.1"

	# Mise en place machine ESGI

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

	define_bashrc root $first_user
	define_bashrc esgi $first_user
	define_bashrc $first_user $first_user
	
	define_hostname $ip

	install_dropbear intel_nuc_debian.pub $ip $gateway $netmask

	setup_coffre $first_user
	install_cheat $first_user 
	
	chroot_default_user $first_user

	install_bookstack

	reboot 	
}

postinstall_ESGI_work
#print_header
#chroot_default_user mathieu

#install_bookstack
