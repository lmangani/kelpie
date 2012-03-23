#!/bin/bash
set -e

KELPIE_VERSION=0.1


mvn -fpom.xml clean assembly::assembly

INSTALL_ROOT=$(pwd)/target
echo 'installing Kelpie Server ...' 
cd /usr/lib && tar -xvzf $INSTALL_ROOT/kelpie-$KELPIE_VERSION.tar.gz 
mkdir -p /var/run/kelpie/ 
touch /var/run/kelpie/kelpied.pid 
chown nobody:root /var/run/kelpie/ 
chown nobody:nogroup /var/run/kelpie/kelpied.pid 
mkdir -p /var/spool/kelpie/ 
chmod 777 /var/spool/kelpie/ 
mkdir -p /var/spool/kelpie/subscriptions/ 
chmod 777 /var/spool/kelpie/subscriptions/ 
mkdir -p /var/spool/kelpie/watchers/ 
chmod 777 /var/spool/kelpie/watchers/ 
chown -R nobody:nogroup /var/spool/kelpie
mkdir -p /var/log/kelpie/ 
chmod 777 /var/log/kelpie/ 
chown -R nobody:nogroup /usr/lib/kelpie-$KELPIE_VERSION/ 
ln -sf /usr/lib/kelpie-$KELPIE_VERSION/kelpied /etc/init.d/kelpied 


echo "Kelpie installed, don't forget to update /usr/lib/kelpie-$KELPIE_VERSION/conf/server.properties"

