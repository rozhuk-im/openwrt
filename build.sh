#!/bin/sh
### Rozhuk Ivan 2022-2024
### build.sh
### 


# Exit on error.
set -e

# Init constans.
THIS_SCRIPT_NAME=`readlink -nf "${0}"`
THIS_SCRIPT_DIR=`dirname "${THIS_SCRIPT_NAME}"`
case $(uname) in
('Darwin'|*'BSD')
	NPROCESSORS_ONLN_NAME='NPROCESSORS_ONLN'
	;;
*)
	NPROCESSORS_ONLN_NAME='_NPROCESSORS_ONLN'
	;;
esac
AUTO_THREADS=`getconf ${NPROCESSORS_ONLN_NAME} | tr -cd '[:print:]'`
: ${SRC_DIR=${THIS_SCRIPT_DIR}}
export FORCE_UNSAFE_CONFIGURE=1


# FreeBSD portability check.
# grep -rsp '\-\-date' /home/rim/docs/Progs-pub/owrt/
# grep -rsp 'touch \-hcd' /home/rim/docs/Progs-pub/owrt/


# Build.
case $(uname) in
('Darwin'|*'BSD')
	/usr/bin/nice -n 15 /usr/bin/time -h make -j"${AUTO_THREADS}" -C "${SRC_DIR}"
	;;
*)
	make -j"${AUTO_THREADS}" -C "${SRC_DIR}"
	;;
esac


#cp -f '/home/rim/docs/Progs-pub/owrt/bin/targets/ath79/nand/openwrt-ath79-nand-perenio_peacg01-initramfs-kernel.bin' '/home/rim/mnt/172.16.0.254/usr/local/tftproot/0201A8C0.img'

