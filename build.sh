#!/bin/sh
### Rozhuk Ivan 2022-2024
### build.sh
### https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem


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
	/usr/bin/nice -n 20 /usr/bin/time -h make -j"${AUTO_THREADS}" -C "${SRC_DIR}"
	;;
*)
	make -j"${AUTO_THREADS}" -C "${SRC_DIR}"
	;;
esac

rm -rf "${SRC_DIR}/build_dir/target-"*

