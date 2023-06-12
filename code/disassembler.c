#define _GNU_SOURCE /* asprintf, vasprintf */

/* Note: code adapted from https://blog.yossarian.net/2019/05/18/Basic-disassembly-with-libopcodes */
/* Note: need to install binutils-dev for dis-asm.h header */

#include "disassembler.h"



typedef struct {
  char *insn_buffer;
  bool reenter;
} stream_state;


//TODO: improve mem efficiency if necessary

int dis_fprintf(void *stream, const char *fmt, ...)
{
    stream_state *ss = (stream_state *)stream;
    
    va_list arg;
    va_start(arg, fmt);
    if (!ss->reenter) {
        vasprintf(&ss->insn_buffer, fmt, arg);
        ss->reenter = true;
    } else {
        char *tmp;
        vasprintf(&tmp, fmt, arg);
        
        char *tmp2;
        asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
        free(ss->insn_buffer);
        free(tmp);
        ss->insn_buffer = tmp2;
    }
    va_end(arg);
    
    return 0;
}

/*
 * Returns 0 if valid, 1 otherwise
 */
int is_valid_instruction(uint8_t *input_buffer, size_t input_buffer_size)
{
    //TODO: refactor this into a setup method. I suspect some overhead here,
    // since we basically set up the disassembler newly on every instruction check
    stream_state ss = {};
    disassemble_info disasm_info = {};
    init_disassemble_info(&disasm_info, &ss, dis_fprintf);
    disasm_info.arch = DISASM_ARCH;
    disasm_info.mach = DISASM_MACHINE;
    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = input_buffer;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = input_buffer_size;
    disassemble_init_for_target(&disasm_info);
    
    disassembler_ftype disasm;
    disasm = disassembler(DISASM_ARCH, false, DISASM_MACHINE, NULL);
    disasm(0, &disasm_info);
    //hacky solution, but libopcodes apparently deems it a luxury to tell us more than a disassembly string
    bool valid = strstr(ss.insn_buffer, "UNDEFINED") != NULL || strstr(ss.insn_buffer, "undefined") != NULL;
    free(ss.insn_buffer);
    return valid;
}



char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size)
{
    char *disassembled = NULL;
    stream_state ss = {};
    
    disassemble_info disasm_info = {};
    init_disassemble_info(&disasm_info, &ss, dis_fprintf);
    disasm_info.arch = DISASM_ARCH;
    disasm_info.mach = DISASM_MACHINE;
    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = input_buffer;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = input_buffer_size;
    disassemble_init_for_target(&disasm_info);
    
    disassembler_ftype disasm;
    disasm = disassembler(DISASM_ARCH, false, DISASM_MACHINE, NULL);
    
    size_t pc = 0;
    while (pc < input_buffer_size) {
        size_t insn_size = disasm(pc, &disasm_info);
        pc += insn_size;
        
        if (disassembled == NULL) {
            asprintf(&disassembled, "%s", ss.insn_buffer);
        } else {
            char *tmp;
            asprintf(&tmp, "%s\n%s", disassembled, ss.insn_buffer);
            free(disassembled);
            disassembled = tmp;
        }
        
        /* Reset the stream state after each instruction decode.
         */
        free(ss.insn_buffer);
        ss.reenter = false;
    }
    
    return disassembled;
}



//int main(int argc, char *argv[]) {
//    size_t input_buffer_size = 1 * INS_LEN;
//    uint8_t* input_buffer = malloc(sizeof(uint8_t)*input_buffer_size);
//    int opt;
//    uint32_t bitPattern = 0;
//    while ((opt = getopt(argc, argv, ":c:")) != -1)
//    {
//        switch (opt)
//        {
//            case 'c':
//                bitPattern = (uint32_t) strtol(optarg, NULL, 0);
//                printf("Using opcode 0x%08x\n", bitPattern);
//                break;
//            case ':':
//                printf("option needs a value\n");
//                return -1;
//            case '?':
//                printf("unknown option: %c\n", optopt);
//                break;
//            default:
//                break;
//        }
//    }
//    input_buffer[0] = (bitPattern & 0xffu);            //lowermost 8 bits, mask 0000 0000 0000 0000 0000 0000 1111 1111 */
//    input_buffer[1] = ((bitPattern >> 8u) & 0xffu);    //next 8 bits, mask      0000 0000 0000 0000 1111 1111 0000 0000
//    input_buffer[2] = ((bitPattern >> 16u) & 0xffu);   //next 8 bits, mask      0000 0000 1111 1111 0000 0000 0000 0000
//    input_buffer[3] = ((bitPattern >> 24u) & 0xffu);   //uppermost 8 bits, mask 1111 1111 0000 0000 0000 0000 0000 0000
//
//    printf("is valid: %d\n", !is_valid_instruction(input_buffer, INS_LEN));
//    printf("is constrained unpredictable: %d\n", !is_constrained_unpredictable(bitPattern));
//
//  char *disassembled = disassemble_raw(input_buffer, input_buffer_size);
//  puts(disassembled);
//  free(disassembled);
//  free(input_buffer);
//
//    return 0;
//}