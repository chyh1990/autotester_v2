#!/bin/bash

OUT="env.txt"

function getversion
{
	printf "%-24s" "$1" >> $OUT
	"$1" --version 2>&1 |head -1 >> $OUT
}

function getversion1
{
	printf "%-24s" "$1" >> $OUT
	"$1" -version 2>&1 |head -1 >> $OUT
}


uname -s -o -m > $OUT
TOOLCHAIN=/tmp/my-android-toolchain/bin/arm-linux-androideabi
for i in $TOOLCHAIN-g++ cmake clang g++
do
	getversion "$i"
done

for i in java emulator-arm
do
	getversion1 "$i"
done

cat $OUT
