#!/bin/sh
### Rozhuk Ivan 2022-2024
### build-devices.sh
### 


# Exit on error.
set -e

# Init constans.
THIS_SCRIPT_NAME=`readlink -nf "${0}"`
THIS_SCRIPT_DIR=`dirname "${THIS_SCRIPT_NAME}"`
: ${SRC_DIR=${THIS_SCRIPT_DIR}}


# Prepare.
mv -n "${SRC_DIR}/.config" "${SRC_DIR}/.config_build_save" || true
"${THIS_SCRIPT_DIR}/build-pre.sh"

# Build.
for __FILE_CONF in ${SRC_DIR}/devices/*.config; do
	[ ! -f "${__FILE_CONF}" ] && continue
	echo ''
	echo '================================================================'
	echo "Building: ${__FILE_CONF}"
	cp -f "${__FILE_CONF}" "${SRC_DIR}/.config"
	make -C "${SRC_DIR}" defconfig
	"${THIS_SCRIPT_DIR}/build.sh"
done

# Post.
mv -f "${SRC_DIR}/.config_build_save" "${SRC_DIR}/.config" || true
rsync -rlHpEXogtWz --inplace --del --ignore-errors --force --numeric-ids -hiv --stats --ipv4 --exclude=packages "${SRC_DIR}/bin/targets/" 'rsync://wupd.dhis.org:873/openwrt/'

