
#ifndef ARMTESTER_DISASSEMBLER_H
#define ARMTESTER_DISASSEMBLER_H
#define _GNU_SOURCE /* asprintf, vasprintf */

/* Note: code adapted from https://blog.yossarian.net/2019/05/18/Basic-disassembly-with-libopcodes */
/* Note: need to install binutils-dev for dis-asm.h header */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//hack to get bfd.h error to shut up, bfd developers claim it's an internal-only lib and shouldn't be used like this
#define PACKAGE
#define PACKAGE_VERSION

#include <dis-asm.h>

#define ARMV6M 0	//mbed NXP LPC11U24 board
#define ARMV8A 1	//Nvidia Tegra TX2
//TODO: is Thumb included in the above?

//see https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=bfd/cpu-arm.c for mappings from Arm machines + arches to CPUs
//see /usr/include/bfd.h for definitions
#define DISASM_ARCH bfd_arch_aarch64
#if ARMV6M
#define DISASM_MACHINE bfd_mach_arm_6SM
#elif ARMV8A
#define DISASM_MACHINE bfd_mach_aarch64
#else
#define DISASM_MACHINE bfd_mach_arm_unknown
#endif



static int dis_fprintf(void *stream, const char *fmt, ...);

int is_constrained_unpredictable(uint32_t instruction);

int is_valid_instruction(uint8_t *input_buffer, size_t input_buffer_size);

char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size);

#endif //ARMTESTER_DISASSEMBLER_H
