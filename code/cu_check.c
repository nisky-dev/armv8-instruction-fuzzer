
#include "cu_check.h"


/*
* Returns 0 if constrained unpredictable, 1 otherwise
*/


int is_constrained_unpredictable(uint32_t instruction)
{
    // reference https://static.docs.arm.com/ddi0487/fb/DDI0487F_b_armv8_arm.pdf?_ga=2.132578958.1898446815.1590764666-27691479.1590764666
    //this is not a complete implementation check for constrained
    //unpredictable behaviour and only serves as an additional check
    uint32_t Rt;
    uint32_t Rn;
    uint32_t Rt2;
    uint32_t Rs;
    uint32_t Imm7;
    uint32_t Rt_off;
    uint32_t Rn_off;
    uint32_t Rt2_off;
    uint32_t Rs_off;
    uint32_t Imm7_off;
    
    //LOAD / STORES EXCLUSIVE
    Rt        = 0x0000001fu;
    Rn        = 0x0000001fu;
    Rt2       = 0x0000001fu;
    Rs        = 0x0000001fu;
    Rt_off    = 0x0u;
    Rn_off    = 0x5u;
    Rt2_off   = 0xau;
    Rs_off    = 0x10u;
    
    //SBO bits. registers Rs and Rt2 should be one (SBO)
    if (IS_INSTRUCTION(instruction, LDST_EX_MASK, LDARB) ||
        IS_INSTRUCTION(instruction, LDST_EX_MASK, LDAXRH) ||
        IS_INSTRUCTION(instruction, LDST_EX_MASK, LDARH) ||
        IS_INSTRUCTION(instruction, LDST_EX_MASK, LDAR_W) ||
        IS_INSTRUCTION(instruction, LDST_EX_MASK, LDAR_X))
    {
        uint16_t rs = REGISTER(instruction, Rs, Rs_off);
        uint16_t rt2 = REGISTER(instruction, Rt2, Rt2_off);
        if (rs != 0x1f || rt2 != 0x1f) {return 0;}
    }
    
    //LOAD / STORE PAIRS
    Rt         = 0x0000001fu;
    Rn         = 0x0000001fu;
    Rt2        = 0x0000001fu;
    Imm7       = 0x0000007fu;
    Rt_off     = 0x0u;
    Rn_off     = 0x5u;
    Rt2_off    = 0xau;
    Imm7_off   = 0xfu;
    
    
    //K1-7864
    if (IS_INSTRUCTION(instruction, LDPSW_MASK, LDPSW_PRE) ||
        IS_INSTRUCTION(instruction, LDPSW_MASK, LDPSW_POST))
    {
        uint16_t t = REGISTER(instruction, Rt, Rt_off);
        uint16_t n = REGISTER(instruction, Rn, Rn_off);
        uint16_t t2 = REGISTER(instruction, Rt2, Rt2_off);
        if ((t == n || t2 == n) && n != 31) { return 0;}
    }
    if (IS_INSTRUCTION(instruction, LDPSW_MASK, LDPSW_PRE) ||
        IS_INSTRUCTION(instruction, LDPSW_MASK, LDPSW_POST) ||
        IS_INSTRUCTION(instruction, LDPSW_MASK, LDPSW_SIGN))
    {
        uint16_t t = REGISTER(instruction, Rt, Rt_off);
        uint16_t t2 = REGISTER(instruction, Rt2, Rt2_off);
        if (t == t2) {return 0;}
    }
    
    return 1;
}

int main()
{
    // how i f***** hate c
    // it takes forever to write the simplest things
    
    char * line = NULL;
    char * next_byte = NULL;
    size_t len = 0;
    ssize_t read;
    uint64_t total_count = 0;
    uint64_t cu_count = 0;
    
    while ((read = getline(&line, &len, stdin)) != -1) {
        total_count++;
        uint32_t a = strtol(&line[0], &next_byte, 16);
        next_byte++;
        uint32_t b = strtol(next_byte, &next_byte, 16);
        next_byte++;
        uint32_t c = strtol(next_byte, &next_byte, 16);
        next_byte++;
        uint32_t d = strtol(next_byte, &next_byte, 16);
        uint32_t instruction = (a << 24u) | (b << 16u) | (c << 8u) | d;
        if (is_constrained_unpredictable(instruction) == 0){
            cu_count++;
            line[read-1] = '\0';
            printf("%s CONSTRAINED UNPREDICTABLE\n", line);
        }else{
            //it is not constrained unpredictable
            cu_count++;
            line[read-1] = '\0';
            printf("%s "B32PAT"\n", line, BYTOBIN(a), BYTOBIN(b), BYTOBIN(c), BYTOBIN(d));
            fflush(stdout);
        }
    }
    printf("%ld/%ld can be attributed to constrained unpredictable behaviour.\n", cu_count, total_count);
}
