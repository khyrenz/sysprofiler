#!/bin/bash

#installing packages required
sudo apt-get -y install cpanminus make unzip wget sleuthkit libwin-hivex-perl bc python python-crypto john

#asking user to copy files to local drive
echo "Please copy the Parse::Win32Registry library (Parse-Win32Registry-1.0.tar.gz), RegRipper (RegRipper2.8-master.zip) and Creddump (creddump-master.zip) to the same drive your bash shell is running from"

#asking user for location of Parse::Win32Registry library
echo "Please give full path (inc. filename) for Parse::Win32Registry library - MUST be a write-enabled location:"
read parsewin32libfile
basedir=$(dirname "${parsewin32libfile}")
parsewin32filename=$(basename "${parsewin32libfile}")
parsewin32unzipdirname=$(echo $parsewin32filename | sed 's/.tar.gz//')

#installing Parse::Win32Registry library
mkdir /usr/local/lib/rip-lib
cd /home
tar -xzf $parsewin32libfile
build_folder=/home/$parsewin32unzipdirname
cd $build_folder
perl Makefile.PL
make
make test
make install
cd $basedir

#cleaning up
rm $parsewin32libfile
rm -r $build_folder

#asking user for location of RegRipper zip
echo "Please give full path (inc. filename) for RegRipper zip - MUST be a write-enabled location:"
read regripperfile
regripfilename=$(basename "${regripperfile}")
regripunzipdirname="${regripfilename%.*}"

#installing RegRipper
unzip -q $regripperfile
build_folder=$basedir/$regripunzipdirname
tail -n +2 $build_folder/rip.pl > rip
perl -pi -e 'tr[\r][]d' rip
sed -i "1i #!`which perl`" rip
sed -i '2i use lib qw(/usr/local/lib/rip-lib/lib/perl5/);' rip
cp rip /usr/local/bin
chmod +x /usr/local/bin/rip
mkdir /usr/local/bin/plugins
cp $build_folder/plugins/* /usr/local/bin/plugins/

#modifying regripper to point to created plugins directory (otherwise, will error)
sed -ie '/^my $plugindir = File::Spec->catfile("plugins");/a my \$plugindir = \"/usr/local/bin/plugins\";' /usr/local/bin/rip
sed -i 's/^my $plugindir = File::Spec->catfile("plugins");/#&/' /usr/local/bin/rip

#cleaning up
rm -r $build_folder
rm $regripperfile
rm rip

#asking user for location of creddump zip
echo "Please give full path (inc. filename) for creddump zip - MUST be a write-enabled location:"
read creddumpfile
creddumpfilename=$(basename "${creddumpfile}")
creddumpunzipdirname="${creddumpfilename%.*}"

#installing Creddump
unzip -q $creddumpfile
build_folder=$basedir/$creddumpunzipdirname
cp $build_folder/pwdump.py pwdump
sed -i "1i #!`which python`" pwdump
cp pwdump /usr/local/bin
chmod +x /usr/local/bin/pwdump
cp -r $build_folder/framework /usr/local/bin/framework

#cleaning up
rm -r creddump-master
rm $creddumpfile
rm pwdump