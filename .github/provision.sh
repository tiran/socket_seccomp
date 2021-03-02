#!/bin/sh
set -ex

. /etc/os-release

if [ -e /usr/bin/dnf ]; then
    dnf update -y
    dnf install -y python3
    if [ "$PLATFORM_ID" = "platform:f34" ]; then
        dnf install -y libseccomp
    fi
    dnf clean all
elif [ -e /usr/bin/yum ]; then
    yum update -y
    yum install -y python3 libseccomp
    yum clean all
elif [ -e /usr/bin/apt ]; then
    apt update
    apt upgrade -y
    apt install -y python3
    apt clean
elif [ -e /sbin/apk ]; then
    apk add python3 libseccomp
else
    echo "Distro not supported"
    exit 1
fi
