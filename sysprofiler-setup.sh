#!/bin/bash

sudo apt update

#installing packages required
sudo apt-get -y install cpanminus make unzip wget sleuthkit libwin-hivex-perl bc python python-crypto john

#installing Parse::Win32Registry library
mkdir /usr/local/lib/rip-lib
cpanm -l /usr/local/lib/rip-lib Parse::Win32Registry
cpan look Parse::Win32Registry

#downloading and installing regripper
#modifying to work on Linux - instructions courtesy of https://linuxconfig.org/how-to-install-regripper-registry-data-extraction-tool-on-linux
wget -q https://github.com/keydet89/RegRipper2.8/archive/master.zip
unzip -q master.zip
tail -n +2 RegRipper2.8-master/rip.pl > rip
perl -pi -e 'tr[\r][]d' rip
sed -i "1i #!`which perl`" rip
sed -i '2i use lib qw(/usr/local/lib/rip-lib/lib/perl5/);' rip
cp rip /usr/local/bin
chmod +x /usr/local/bin/rip
mkdir /usr/local/bin/plugins
cp RegRipper2.8-master/plugins/* /usr/local/bin/plugins/

#modifying regripper to point to created plugins directory (otherwise, will error)
sed -ie '/^my $plugindir = File::Spec->catfile("plugins");/a my \$plugindir = \"/usr/local/bin/plugins\";' /usr/local/bin/rip
sed -i 's/^my $plugindir = File::Spec->catfile("plugins");/#&/' /usr/local/bin/rip

#cleaning up
rm -r RegRipper2.8-master
rm master.zip

#downloading and installing pwdump
wget -q https://github.com/Neohapsis/creddump7/archive/master.zip
unzip -q master.zip
cp creddump7-master/pwdump.py pwdump
sed -i "1i #!`which python`" pwdump
cp pwdump /usr/local/bin
chmod +x /usr/local/bin/pwdump
cp -r creddump7-master/framework /usr/local/bin/framework

#cleaning up
rm -r creddump-master
rm master.zip

#downloading and installing pylnker
wget -q https://github.com/HarmJ0y/pylnker/archive/master.zip
unzip -q master.zip
cp pylnker-master/pylnker.py /usr/local/bin

#cleaning up
rm -r pylnker-master
rm master.zip