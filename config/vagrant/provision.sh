#!/bin/sh
pacman --noconfirm -Sy
pacman --noconfirm -S archlinux-keyring
pacman --noconfirm -Su
pacman --noconfirm -S base-devel libnetfilter_queue vim git tcpdump strace ltrace gdb

cat >> ~vagrant/.bashrc <<EOF
alias ls='ls --color=auto -F -b -T 0'
alias vi='vim'
EOF

cat >> ~vagrant/.vimrc <<EOF
set background=dark
set ruler
set hlsearch
set mouse=""
syn on
EOF
