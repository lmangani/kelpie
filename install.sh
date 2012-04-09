#!/bin/bash
set -e

KELPIE_VERSION=0.1
KELPIE_CONF=/usr/lib/kelpie-$KELPIE_VERSION/conf/server.properties

# Identify Linux Flavour
if [ -f /etc/debian_version ] ; then
    PGROUP="nobody:nogroup"
elif [ -f /etc/redhat-release ] ; then
    PGROUP="nobody:nobody"
else
    PGROUP="nobody:nogroup"
fi


if [ -f $KELPIE_CONF ]
then
    cp $KELPIE_CONF $KELPIE_CONF.bak
fi

mvn -fpom.xml clean assembly::assembly

INSTALL_ROOT=$(pwd)/target
echo 'Installing Kelpie Server ...' 
cd /usr/lib && tar -xvzf $INSTALL_ROOT/kelpie-$KELPIE_VERSION.tar.gz 
mkdir -p /var/run/kelpie/ 
touch /var/run/kelpie/kelpied.pid 
chown $PGROUP /var/run/kelpie/ 
chown $PGROUP /var/run/kelpie/kelpied.pid 
mkdir -p /var/spool/kelpie/ 
chmod 777 /var/spool/kelpie/ 
mkdir -p /var/spool/kelpie/subscriptions/ 
chmod 777 /var/spool/kelpie/subscriptions/ 
mkdir -p /var/spool/kelpie/watchers/ 
chmod 777 /var/spool/kelpie/watchers/ 
chown -R $PGROUP /var/spool/kelpie
mkdir -p /var/log/kelpie/ 
chmod 777 /var/log/kelpie/ 
chown -R $PGROUP /usr/lib/kelpie-$KELPIE_VERSION/ 
ln -sf /usr/lib/kelpie-$KELPIE_VERSION/kelpied /etc/init.d/kelpied 

if [ -f $KELPIE_CONF.bak ]
then
    echo "Kelpie installed, retained settings in /usr/lib/kelpie-$KELPIE_VERSION/conf/server.properties"
    cp $KELPIE_CONF $KELPIE_CONF.clean
    mv $KELPIE_CONF.bak $KELPIE_CONF
else
    echo "Kelpie installed, don't forget to update /usr/lib/kelpie-$KELPIE_VERSION/conf/server.properties"
fi
