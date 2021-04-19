#!/bin/bash 
#
# description 		: Permet d' ouvrir et de fermer le conteneur chiffre
# param1		: "open" ou " close" en fonction de l'action voulue
# param2		: utilisateur propriétaire du coffre 
# author 		: Mathieu Noyelle
# contact 		: mathieu@noyelle.pro
#

clear
NAME_CRYPT="lv_coffrecrypt"
PATH_SETUPCRYPT="/usr/sbin/cryptsetup" 
PATH_MOUNT="/usr/bin/mount" 
PATH_MKDIR="/usr/bin/mkdir"
#OUVERTURE="/home/$SUDO_USER/COFFRE"
ROOT=`id -g`

# On verifie le nombre de parametre
if [ $# -ne 2 ]; then 
	echo " Erreur de syntaxe" 
	echo " utilisation : sudo $0 <open/close> user" 
	echo " exemple pour ouvrir le conteneur : sudo $0 open $USER"
	exit
fi

OUVERTURE="/home/$2/COFFRE"

# On verifie que l'utilisateur dispose des droits root
echo "$ROOT" 
if [ $ROOT -ne 0 ]; then 
	echo "Il faut disposer des droits root pour lancer le script" 
	echo "utilisez la commande sudo" 
	exit
fi

# on verifie que le parametre est soit "open" soit "close" 
if [ $1  = "open"  ]; then
	echo "Ouverture du coffre, saisissez votre cle"
        $PATH_SETUPCRYPT luksOpen /dev/VGCRYPT/lv_coffre $NAME_CRYPT
	if [ ! -d $OUVERTURE ]; then
		$PATH_MKDIR -p $OUVERTURE
	fi
	$PATH_MOUNT /dev/mapper/$NAME_CRYPT $OUVERTURE
elif [ $1 = "close"  ]; then
	echo "Fermeture du coffre"
        umount $OUVERTURE
	$PATH_SETUPCRYPT luksClose $NAME_CRYPT	
else
	echo "Mauvais parametre" 
	echo " utilisation : sudo $0 <open/close> user" 
	echo " exemple pour ouvrir le conteneur : sudo $0 open $USER"
fi
