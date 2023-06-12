
#ifndef ARMTESTER_CU_CHECK_H
#define ARMTESTER_CU_CHECK_H


#include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define INS_LEN 4

#define B8PAT "%c%c%c%c %c%c%c%c"
#define B32PAT B8PAT" "B8PAT" "B8PAT" "B8PAT
#define BYTOBIN(byte)  \
  (byte & 0x80u ? '1' : '0'), \
  (byte & 0x40u ? '1' : '0'), \
  (byte & 0x20u ? '1' : '0'), \
  (byte & 0x10u ? '1' : '0'), \
  (byte & 0x08u ? '1' : '0'), \
  (byte & 0x04u ? '1' : '0'), \
  (byte & 0x02u ? '1' : '0'), \
  (byte & 0x01u ? '1' : '0')

//opcode masks
#define LDST_EX_MASK 0xffe08000u
#define LDPSW_MASK   0xffc00000u

// opcode encodings
#define LDARB        0x08c08000u
#define LDAXRH       0x48408000u
#define LDARH        0x48c08000u
#define LDAR_W       0x88c08000u
#define LDAR_X       0xc8c08000u
#define LDPSW_POST   0x68c00000u //post index
#define LDPSW_PRE    0x69c00000u //pre index
#define LDPSW_SIGN   0x69400000u //sign index

#define IS_INSTRUCTION(instr, opc_mask, opc_encoding) ((~(instr ^ opc_encoding) & opc_mask) == opc_mask)
#define REGISTER(inst, mask, offset) (((mask << offset) & inst) >> offset)


int is_constrained_unpredictable(uint32_t instruction);
int main();



#endif //ARMTESTER_CU_CHECK_H
