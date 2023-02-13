#! /bin/bash

LD_LIBRARY_PATH=../preload:../lib  LD_PRELOAD=libtracker.so ./trktest
