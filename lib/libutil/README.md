# Common utility for Linux system software programming

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![libutils ci](https://github.com/w180112/libutil/actions/workflows/ci.yml/badge.svg)](https://github.com/w180112/libutil/actions/workflows/ci.yml)

This is a Linux userspace system software programmimg utility. Programmers can easily compile them into a static library and use provided APIs in their project.

## How to use:

Git clone this repository

	# git clone https://github.com/w180112/libutil.git

Type

	# cd libutil

Use GNU build system to generate configure file and makefile

	# autoreconf --install
	# ./configure

Type make to compile

	# make

Then you can find there is a static library in the same directory.

To remove the binary files

	# make clean
