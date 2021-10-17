#!/bin/bash

# Quick setup script to config a Hugo
# blog on a new computer.
# 2016 - Leon Jacobs

set -e

DESTINATION="leonjza.github.io"
GIT="git@github.com:leonjza/leonjza.github.io.git"

echo -e "\033[0;32mCloning blog source..\033[0m"
git clone -b source $GIT $DESTINATION
cd $DESTINATION

echo -e "\033[0;32m updating submodules..\033[0m"
git submodule update --init --recursive

echo -e "\033[0;32mCloning blog build directory (public)..\033[0m"
git clone -b master $GIT public

if ! command -v hugo
then
	echo -e "\033[0;32mHugo might not be installed. Double check it..\033[0m"
fi
