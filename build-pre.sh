#!/bin/sh
### Rozhuk Ivan 2022-2024
### build-pre.sh
### https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem


# Exit on error.
set -e

# Init constans.
THIS_SCRIPT_NAME=`readlink -nf "${0}"`
THIS_SCRIPT_DIR=`dirname "${THIS_SCRIPT_NAME}"`
: ${SRC_DIR=${THIS_SCRIPT_DIR}}
DIRS_LIST='.ccache dl feeds staging_dir'
DIRS_TMP_LIST='build_dir logs tmp'


# May also try "make distclean" to full clean.
make -C "${SRC_DIR}" dirclean


# Force move crap dirs to fast drive.
for __DIR in ${DIRS_LIST}; do
	rm -rf "${SRC_DIR}/${__DIR}"
	mkdir -p "/home/${USER}_tmp/build_cache/owrt/${__DIR}"
	ln -sf "/home/${USER}_tmp/build_cache/owrt/${__DIR}" "${SRC_DIR}/${__DIR}"
done
# Force move crap dirs to /tmp drive.
for __DIR in ${DIRS_TMP_LIST}; do
	rm -rf "${SRC_DIR}/${__DIR}"
	mkdir -p "/tmp/owrt_${__DIR}"
	ln -sf "/tmp/owrt_${__DIR}" "${SRC_DIR}/${__DIR}"
done


cp -af "${SRC_DIR}/ccache.conf" "/home/${USER}_tmp/build_cache/owrt/.ccache/"


# Update and install deps.
"${SRC_DIR}/scripts/feeds" update -a
"${SRC_DIR}/scripts/feeds" install -a

