#!/usr/bin/env bash
base_dir=$pwd

echo "[+] Installing common libraries for enhanced fuzzing support"
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get install -y build-essential nmap build-essential llvm libcairo2-dev \
libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev nmap afl-clang git curl wireshark clang gdb bison \
libbison-dev zita-rev1 python-parsley btyacc bnfc racc libreadline-dev libssl-dev libpq5 libpq-dev \
libreadline5 libsqlite3-dev libpcap-dev autoconf postgresql pgadmin3 curl zlib1g-dev libxml2-dev libxslt1-dev \
libyaml-dev curl zlib1g-dev gawk bison libffi-dev libgdbm-dev libncurses5-dev libtool sqlite3 libgmp-dev \
gnupg2 dirmngr screen re2c pkg-config lib32asan2 valgrind qt4-qmake libqt4-dev tcpdump cmake python3 flex \
make openssl libgbm1 gdbserver net-tools fontconfig libpango1.0-dev libxft2 libxft-dev libcups2-dev libcork-dev \
libqt5core5a libqtcore4 libqt5gui5 libqt5network5 libqt4-network libreadline-dev libconfig-dev libssl-dev \
lua5.2 liblua5.2-dev libevent-dev libjansson-dev libpython-dev fossil libavis-dev harvid libavahi-glib-dev \
libswscale-dev liba52-0.7.4-dev libxcb-xkb-dev libxcb-composite0-dev libdssialsacompat-dev alsa-utils \
libao-dev apt-file python-pip dput librivet-dev libcue-dev libbellesip-dev libbctoolbox-dev libantlr3c-dev \
nvptx-tools texi2html libgnutls-dane0 gnuastro auctex a2ps ; sudo apt-get install -y --reinstall texinfo ; sudo apt-get install -y libgd-dev \
libsynctex-dev unrar php7.1 postgresql-client-10 libqt4-sql-psql pspg libsipwitch-dev sipwitch p7zip-full zlib1g libzzip-dev \
libsdl2-dev openssh-server libelf-dev zstd libboost-all-dev g++ automake autoconf autoconf-archive libtool liblz4-dev liblzma-dev \
zlib1g-dev make libjsoncpp-dev libiberty-dev qemu-kvm qemu virt-manager libavcodec-dev libavutil-dev virt-viewer libvirt-bin \
libdlna-dev winff mencoder libdlna-dev libchromaprint-dev libchromaprint-tools libchromaprint1 libsoxr-dev libcap-dev libsoxr0 checkinstall \

echo "[+] Installing AFLplusplus"
git clone https://github.com/vanhauser-thc/AFLplusplus.git
cd AFLplusplus/
make
cd qemu_mode/
./build_qemu_support.sh
cd ..
cd llvm_mode/
make all
cd ..
sudo make install

# Tested on 4.15.0-72-generic Ubuntu 18.04
