### Install Kernel 3.2 on Ubuntu 14.04
1. Download the header and source .deb packages 
`wget http://launchpadlibrarian.net/205137262/linux-headers-3.2.0-83_3.2.0-83.120_all.deb`
`wget http://security.ubuntu.com/ubuntu/pool/main/l/linux/linux-headers-3.2.0-83-generic_3.2.0-83.120_i386.deb`
`wget http://mirrors.kernel.org/ubuntu/pool/main/l/linux/linux-image-3.2.0-83-generic_3.2.0-83.120_i386.deb`

2. Extract and install these packages:
`sudo dpkg -i linux-headers-3.2.0-83_3.2.0-83.120_all.deb
sudo dpkg -i linux-headers-3.2.0-83-generic_3.2.0-83.120_i386.deb
sudo dpkg -i linux-image-3.2.0-83-generic_3.2.0-83.120_i386.deb`

3. Add the new kernel boot images to the /boot/grub/menu.lst
