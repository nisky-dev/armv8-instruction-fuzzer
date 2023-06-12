#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <capstone/capstone.h>
#include <sys/ucontext.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <time.h>

#include "disassembler.h"

#define INSTR_LEN 4

#define ARMV6M 0
#define ARMV7M 0
#define ARMV8A 1

#if ARMV8A
    #define RESET_REGISTERS() do {\
    __asm__ __volatile__ (\
        "mov x0, #0;"\
        "mov x1, #0;"\
        "mov x2, #0;" \
        "mov x3, #0;" \
        "mov x4, #0;" \
        "mov x5, #0;" \
        "mov x6, #0;" \
        "mov x7, #0;" \
        "mov x8, #0;" \
        "mov x9, #0;" \
        "mov x10, #0;" \
        "mov x11, #0;" \
        "mov x12, #0;" \
        "mov x13, #0;" \
        "mov x14, #0;" \
        "mov x15, #0;" \
        "mov x16, #0;" \
        "mov x17, #0;" \
        "mov x18, #0;" \
        "mov x19, #0;" \
        "mov x20, #0;" \
        "mov x21, #0;" \
        "mov x22, #0;" \
        "mov x23, #0;" \
        "mov x24, #0;" \
        "mov x25, #0;" \
        "mov x26, #0;" \
        "mov x27, #0;" \
        "mov x28, #0;" \
        "mov x29, #0;" \
        "mov x30, #0;" \
    :::\
    ); \
    } while(0)
#endif

//keep everything on the heap so it's less likely we corrupt it - may be overkill
char * executingInstruction = NULL;
stack_t sig_stack;
struct sigaction handler;
volatile sig_atomic_t executingNow = 0;
volatile sig_atomic_t handlerHasAlreadyRun = 0;
volatile sig_atomic_t lastSig = 0;
sigjmp_buf buf;
uint32_t bitPattern = 0;
uint8_t a, b, c, d = 0;
int instr_count = 0;
FILE *f;
bool rnd = false;
bool verbose = false;
bool run_valid = false;
uint32_t n = 0xFFFFFFFF;
uint32_t branch_max_offset = 0x10000000; // branch_max_offset % pagesize must be 0!
uint32_t fill_instruction = 0x000020d4; // BRK but remember to use little endian
uint32_t log_sigill_every = 0x10000; // sigill log frequency
bool log_valid_instructions = false;
uint32_t log_counter = 1; //used for sigill log frequency, do not change
int opt;
int core = 0; //default to 0
bool testing = false;
unsigned char disasm_temp[INSTR_LEN];

/*TODO:
    rewrite logging to use one function and csv.
    regular logging should be just big endian opcode and result, skipping illegal instr.
    verbose including little endian opcode and not skipping illegals

 */
struct RegisterState
{
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    //uint64_t cpsr;;
    //uint64_t fpsr;
    //uint64_t fpcr;
    uint64_t fault_addr;
    
};

//struct RegisterState before = {0};
//struct RegisterState after = {0};
struct RegisterState fault = {0};


void fprintRegisters(struct RegisterState *r){
    int k = 8;
    for (int i = 0; i < k; i++)
    {
        fprintf(f, "x%02u: %016"PRIx64" x%02u: %016"PRIx64" x%02u: %016"PRIx64" x%02u: %016"PRIx64" \n",
                i, r->x[i],
                i + k, r->x[i + k],
                i + 2*k, r->x[i + 2*k],
                i + 3*k, r->x[i + 3*k]);
    }
    fprintf(f, "sp        : %016"PRIx64"\n", r->sp);
    fprintf(f, "pc        : %016"PRIx64"\n", r->pc);
    fprintf(f, "fault addr: %016"PRIx64"\n\n", r->fault_addr);
    fflush(f);
}

void printRegisters(struct RegisterState *r)
{
    int k = 8;
    for (int i = 0; i < k; i++)
    {
        printf("x%02u: %016"PRIx64" x%02u: %016"PRIx64" x%02u: %016"PRIx64" x%02u: %016"PRIx64" \n",
                i, r->x[i],
                i + k, r->x[i + k],
                i + 2*k, r->x[i + 2*k],
                i + 3*k, r->x[i + 3*k]);
    }
    printf("sp        : %016"PRIx64"\n", r->sp);
    printf("pc        : %016"PRIx64"\n", r->pc);
    printf("fault addr: %016"PRIx64"\n\n", r->fault_addr);
    fflush(stdout);
    
}

void signalHandler(int sig, siginfo_t *siginfo, void *context)
{
    if (verbose){
        //DUMP_REGISTERS(after);
        ucontext_t *con = (ucontext_t*)context;
        #if ARMV8A
            //specifications from https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/aarch64/sys/ucontext.h.html
            fault.sp = con->uc_mcontext.sp;
            fault.pc = con->uc_mcontext.pc;
            fault.fault_addr = con->uc_mcontext.fault_address;
    
            //add gp registers
            // c->uc_mcontext.r[0-31]
            for (int i = 0; i < 31; i++){
                fault.x[i] = con->uc_mcontext.regs[i];
            }
        #endif //ARMV8
        #if ARMV7M
            fault.sp = con->uc_mcontext.arm_sp;
            fault.pc = con->uc_mcontext.arm_pc;
    
            //add gp registers
            fault.x[0] = con->uc_mcontext.arm_r0;
            fault.x[1] = con->uc_mcontext.arm_r1;
            fault.x[2] = con->uc_mcontext.arm_r2;
            fault.x[3] = con->uc_mcontext.arm_r3;
            fault.x[4] = con->uc_mcontext.arm_r4;
            fault.x[5] = con->uc_mcontext.arm_r5;
            fault.x[6] = con->uc_mcontext.arm_r6;
            fault.x[7] = con->uc_mcontext.arm_r7;
            fault.x[8] = con->uc_mcontext.arm_r8;
            fault.x[9] = con->uc_mcontext.arm_r9;
            fault.x[11] = con->uc_mcontext.arm_fp;
            fault.x[12] = con->uc_mcontext.arm_ip;
            fault.x[13] = con->uc_mcontext.arm_sp;
            fault.x[14] = con->uc_mcontext.arm_lr;
            fault.x[15] = con->uc_mcontext.arm_pc;
            fault.x[16] = con->uc_mcontext.arm_cpsr;
            fault.fault_addr = con->uc_mcontext.fault_address;
    
            /* From /usr/include/arm-linux-gnueabihf/asm/sigcontext.h
             * 	unsigned long trap_no;
                unsigned long error_code;
                unsigned long oldmask;
                unsigned long arm_r0;
                unsigned long arm_r1;
                unsigned long arm_r2;
                unsigned long arm_r3;
                unsigned long arm_r4;
                unsigned long arm_r5;
                unsigned long arm_r6;
                unsigned long arm_r7;
                unsigned long arm_r8;
                unsigned long arm_r9;
                unsigned long arm_r10;
                unsigned long arm_fp;
                unsigned long arm_ip;
                unsigned long arm_sp;
                unsigned long arm_lr;
                unsigned long arm_pc;
                unsigned long arm_cpsr;
                unsigned long fault_address;
             * */
        #endif //ARMV7M
    }
    if(handlerHasAlreadyRun){
        // need to fix, not signal handler safe
        fprintf(f, "double exception\n");
        printf("double exception\n");
        fflush(f);
        fflush(stdout);
    
        signal(SIGILL, SIG_DFL);
        signal(SIGFPE, SIG_DFL);
        signal(SIGSEGV, SIG_DFL);
        signal(SIGBUS, SIG_DFL);
        signal(SIGTRAP, SIG_DFL);
    }
    else{
        handlerHasAlreadyRun = 1;
        if (!executingNow){
            // need to fix, not signal handler safe
            fprintf(f, "Exception outside of execution context\n");
            printf("Exception outside of execution context\n");
            fflush(f);
            fflush(stdout);
    
            signal(SIGILL, SIG_DFL);
            signal(SIGFPE, SIG_DFL);
            signal(SIGSEGV, SIG_DFL);
            signal(SIGBUS, SIG_DFL);
            signal(SIGTRAP, SIG_DFL);
        }
    }
    lastSig = sig;
    siglongjmp(buf, 1);
}
int setCpu(int core){
    //lock to CPU core to prevent cross-modifying code
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core, &mask);
    return sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

int setSignalHandler(){
    //giving handler its own stack allows it to continue handling even in case stack pointer has ended up wildly out
    sig_stack.ss_sp = malloc(SIGSTKSZ);
    if (sig_stack.ss_sp == NULL)
    {
        printf("Couldn't allocate memory for alt handler stack, exiting.\n");
        return 1;
    }
    sig_stack.ss_size = SIGSTKSZ;
    sig_stack.ss_flags = 0;
    if (sigaltstack(&sig_stack, NULL) == -1)
    {
        printf("Couldn't set alt handler stack, exiting.\n");
        //TODO exitCleanup();
        return 1;
    }
    
    memset(&handler, 0, sizeof(handler));
    handler.sa_flags = SA_SIGINFO | SA_ONSTACK;
    handler.sa_sigaction = signalHandler;
    if (sigaction(SIGILL, &handler, NULL) < 0 || \
      sigaction(SIGFPE, &handler, NULL) < 0 || \
      sigaction(SIGSEGV, &handler, NULL) < 0 || \
      sigaction(SIGBUS, &handler, NULL) < 0 || \
      sigaction(SIGTRAP, &handler, NULL) < 0)
    {
        //TODO exit cleanup
        printf("Couldn't set signal handler, exiting.\n");
        return 1;
    }
    return 0;
}

void printPageContents(void * start, uint32_t size){
    for(uint64_t i = 0; i < size; i+=4){
        uint32_t * addr = (uint32_t *)&((char*)start)[i];
        printf("%016"PRIx64": %08"PRIx32"\n", (uint64_t)addr, (uint32_t)*addr);
    }
    fflush(stdout);
}

int memset32(void* dest, uint32_t value, uint64_t size){
    //make sure dest and size are aligned to 32 bit
    if (((uint64_t)dest & 0x1fu) != 0 ||
        (size & 0x1fu) != 0){
        printf("Destination or size are not 32 bit aligned!\n");
        return -1;
    }
    //I trust my compiler to optimize this
    //... actually I don't, but i made sure gcc unrolls that loop
    for(uint64_t i = 0; i < size; i+=4)
    {
        uint32_t * addr = (uint32_t *)&((char*)dest)[i];
        *addr = value;
    }
    return 0;
}

void * reserveProtectedMemory(uint64_t maxJumpOffset){
    uint64_t length = 2 * maxJumpOffset;
    return mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

void * createExecutionPage(void * addr, uint64_t pageSize){
    if (mprotect((void *) addr, pageSize,
        PROT_READ | PROT_WRITE | PROT_EXEC))
    {
        printf("Failed to change permissions on the executable page\n");
        return NULL;
    }
    return addr;
}

FILE * createLogFile(){
    char * logfolder = "./log";
    struct stat st = {0};
    if (stat(logfolder, &st) == -1) {
        mkdir(logfolder, 0700);
    }
    
    time_t t = time(NULL);
    struct tm time = *localtime(&t);
    char filename[100];
    snprintf(filename, 100, "log/%d-%02d-%02d_%02d:%02d:%02d.txt", time.tm_year + 1900,
             time.tm_mon + 1, time.tm_mday, time.tm_hour, time.tm_min, time.tm_sec);
    
    return fopen(filename, "w");
}

void printInstruction(FILE* file, uint8_t b3, uint8_t b2, uint8_t b1, uint8_t b0){
    if (verbose){
        printf("%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,", b3, b2, b1, b0, b0, b1, b2, b3);
        fprintf(file,"%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,",b3, b2, b1, b0, b0, b1, b2, b3);
    }else{
        printf("%02x,%02x,%02x,%02x,", b0, b1, b2, b3);
        fprintf(file,"%02x,%02x,%02x,%02x,", b0, b1, b2, b3);
    }
}


int main(int argc, char *argv[])
{
    f = createLogFile();
    if (f == NULL)
    {
        printf("Failed to create logfile.");
        return -1;
    }
    for (int i = 0; i < argc; i++){
        fprintf(f, "%s ", argv[i]);
    }
    fprintf(f,"\n");
    
    
    while ((opt = getopt(argc, argv, ":c:hk:n:rvx")) != -1)
    {
        switch (opt)
        {
            case 'c':
                bitPattern = (uint32_t) strtol(optarg, NULL, 0);
                printf("Using opcode 0x%08x\n", bitPattern);
                fprintf(f, "Using opcode 0x%08x\n", bitPattern);
                break;
            case 'h':
                printf("./opcodetester [options]\n");
                printf(" -c [opcode]  Start from opcode (big endian), e.g. 0x01234567 Defaults to 0.\n");
                printf(" -h           Display help.\n");
                printf(" -k [core]    CPU core to lock on. Defaults to 0.\n");
                printf(" -n [count]   Number of instructions to execute. Defaults to all.\n");
                printf(" -r           Enable random instruction fuzzing.\n");
                printf(" -v           Enable verbose logging.\n");
                printf(" -x           Enable execution of valid instructions.\n");
                return 0;
            case 'n':
                n = (int) strtol(optarg, NULL, 0);
                printf("Executing %d instructions.\n", n);
                fprintf(f, "Executing %d instructions.\n", n);
                break;
            case 'k':
                core = strtol(optarg, NULL, 0);
                printf("Using core %d\n", core);
                fprintf(f, "Using core %d\n", core);
                break;
            case 'r':
                rnd = true;
                printf("Using random mode\n");
                fprintf(f, "Using random mode\n");
                break;
            case 'v':
                printf("Using verbose mode\n");
                fprintf(f, "using verbose mode\n");
                verbose = true;
                log_sigill_every = 1;
                log_valid_instructions = true;
                break;
            case 'x':
                run_valid = true;
                break;
            case ':':
                printf("option needs a value\n");
                return -1;
            case '?':
            default:
                printf("unknown option: %c\n", optopt);
                return -1;
        }
    }
    
    if (verbose){
        printf( "LSB, byte 1, byte 2, MSB, MSB, byte 2, byte 1, LSB, Result\n");
        fprintf(f, "\nLSB, byte 1, byte 2, MSB, MSB, byte 2, byte 1, LSB, Result\n");
    }else{
        printf("MSB, byte 2, byte 1, LSB, Result\n");
        fprintf(f, "\nMSB, byte 2, byte 1, LSB, Result\n");
    }
    
    if (setCpu(core) != 0){
        printf("Couldn't lock to CPU core %d.\nContinuing, but can't guarantee there will be no code cross-modification between cores.\n", core);
    }
    
    if(setSignalHandler() != 0){
        return -1;
    }
    
    void * mem_start_addr = reserveProtectedMemory(branch_max_offset);
    if (mem_start_addr == NULL){
        printf("Failed to allocate protected memory\n");
        return -1;
    }
    uint64_t pagesize = sysconf(_SC_PAGESIZE);
    void * execPageStart = mem_start_addr + branch_max_offset - pagesize;
    execPageStart = createExecutionPage(execPageStart, 2*pagesize);
    if (execPageStart == NULL){
        return -1;
    }
    if ((ARMV8A && memset32(execPageStart, fill_instruction, pagesize) != 0)) {
        return -1;
    }
    executingInstruction = mem_start_addr + branch_max_offset - 2*INSTR_LEN;
    
    testing = true;
    while (testing)
    {
        if (!rnd)
        {
            if (instr_count != 0) bitPattern++;
            if (bitPattern == UINT32_MAX) testing = false;
        }
        else
        {
            bitPattern = rand();
        }
        
        if (n == 0){
            printf("Finished after executing %d instructions.\n", instr_count);
            fprintf(f, "Finished after executing %d instructions.\n", instr_count);
            fflush(stdout);
            fflush(f);
            break;
        }
        n--;
        instr_count++;
        
        a = (bitPattern & 0xffu);            // lowermost 8 bits, mask 0000 0000 0000 0000 0000 0000 1111 1111
        b = ((bitPattern >> 8u) & 0xffu);    // next 8 bits, mask      0000 0000 0000 0000 1111 1111 0000 0000
        c = ((bitPattern >> 16u) & 0xffu);   // next 8 bits, mask      0000 0000 1111 1111 0000 0000 0000 0000
        d = ((bitPattern >> 24u) & 0xffu);   // uppermost 8 bits, mask 1111 1111 0000 0000 0000 0000 0000 0000
        
        disasm_temp[0] = a;
        disasm_temp[1] = b;
        disasm_temp[2] = c;
        disasm_temp[3] = d;
        
        if (!run_valid && is_valid_instruction(disasm_temp, INSTR_LEN) == 0){
            if (log_valid_instructions){
                printInstruction(f, a, b, c, d);
                printf("VALID\n");
                fprintf(f, "VALID\n");
            }
        }else {
            executingInstruction[0] = a;
            executingInstruction[1] = b;
            executingInstruction[2] = c;
            executingInstruction[3] = d;
            executingInstruction[4] = fill_instruction;
            __clear_cache(executingInstruction, &executingInstruction[2*INSTR_LEN -1]);
            if (!sigsetjmp (buf, 1))
            {
    
                lastSig = 0;
                handlerHasAlreadyRun = 0;
                executingNow = 1;
                RESET_REGISTERS();
                ((void (*)()) executingInstruction)();
            }
            executingNow = 0;
            if (lastSig == 0)
            {
                printInstruction(f, a, b, c, d);
                printf("NO EXCPT\n");
                fprintf(f, "NO EXCPT\n");
            }
            else if (lastSig == SIGTRAP)
            {
                printInstruction(f, a, b, c, d);
                printf("RAN (TRAP)\n");
                fprintf(f, "RAN (TRAP)\n");
            }
            else
            {
                if (lastSig != 4 || --log_counter == 0 || verbose){
                    if (log_counter == 0)
                    {
                        log_counter = log_sigill_every;
                    }
                    printInstruction(f, a, b, c, d);
                    printf("EXCPT %d\n", lastSig);
                    fprintf(f, "EXCPT %d\n", lastSig);
                }
                
            }
        }
        fflush(stdout);
        fflush(f);
    }
    fclose(f);
    return 0;
}
