#!/usr/bin/expect -f

set timeout 6
spawn scp opcodeTester.c disassembler.c disassembler.h cu_check.c Makefile lab15:~/tester/code/


expect "*assword:*" {send "$::env(SSHPASS)\n"}
expect "*assword:*" {send "$::env(SSHPASS)\n"}
expect eof



