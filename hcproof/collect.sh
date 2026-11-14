#!/bin/sh
# HostCrust Patch Proof collector, v1. Apache-2.0. https://hostcrust.com
#
# Read-only. Needs no root and no network. Installs nothing, writes nothing.
# Prints package and OS metadata only: no hostname, no IP address, no users,
# and no file contents other than /etc/os-release.
#
# Usage:  sh collect.sh > inventory.txt
#         ssh host 'sh -s' < collect.sh > inventory.txt

LC_ALL=C
export LC_ALL

echo "# hcproof-collector 1"

echo "## os-release"
cat /etc/os-release 2>/dev/null

echo "## kernel"
echo "release=$(uname -r)"
echo "build=$(uname -v)"
echo "arch=$(uname -m)"
# Ubuntu only: the exact package version of the running kernel.
[ -r /proc/version_signature ] && echo "signature=$(cat /proc/version_signature)"
# Installed kernel images (file names only).
for f in /boot/vmlinuz-*; do [ -e "$f" ] && echo "image=${f#/boot/vmlinuz-}"; done

echo "## reboot-required"
if [ -e /var/run/reboot-required ]; then
    echo "flag=yes"
    [ -r /var/run/reboot-required.pkgs ] && sed 's/^/pkg=/' /var/run/reboot-required.pkgs
else
    echo "flag=no"
fi

echo "## packages"
if command -v dpkg-query >/dev/null 2>&1; then
    echo "format=dpkg"
    # status, binary name, version, architecture, source ("name" or "name (version)")
    dpkg-query -W -f='${Status}\t${Package}\t${Version}\t${Architecture}\t${Source}\n'
elif command -v rpm >/dev/null 2>&1; then
    echo "format=rpm"
    # name, epoch, version, release, architecture, source rpm, vendor
    rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\n'
else
    echo "format=none"
fi

echo "## end"
