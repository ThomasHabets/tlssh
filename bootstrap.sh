#!/bin/sh

git submodule update --init
exec autoreconf -i
