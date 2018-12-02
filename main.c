#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "terminal.h"
#define ProgramStart 0x0600
#define RAMSize      64;
#define Stackpos     0x0100
#define Stacksize    0xFF
#define IPS          0xD59F8
#define CPU_Pause() (flagset(fBreak, 1));
#define CPU_Resume() (flagset(fBreak, 0));
#define mWORD(M,L) (mem_t)(M*256)+L
#define wMSB(W) (byte_t)((mem_t)W>>8)
#define wLSB(W) (byte_t)((mem_t)W&0xFF)

typedef enum {false, true} bool;
typedef unsigned char  byte_t;
typedef signed char sbyte_t;
typedef unsigned short mem_t;
typedef signed short smem_t;
typedef enum
{
    fCarry    =  1,   // Result is less than 0x00 or greater than 0xFF
    fZero     =  2,   // Result is 0
    fInterupt =  4,   // IO interrupt
    fDecimal  =  8,   // Count in base 10
    fBreak    = 16,   // Interrupt in-process
    fUnknown  = 32,   // ???
    fOverflow = 64,   // Result is invalid 2s complement 8bit arithmetic. ( + add + equals - )
    fNegative = 128,  // Result is a negative number.
    bSign     = 0x80, // Value is a negative number.
    rA = 0,
    rX,
    rY,
    mINX = 0,
    mINY,

} CPUEnums;

struct CPU
{
    byte_t A, X, Y, Flags, SP;
    mem_t PC;
    bool STEP;
};

// Globals

static byte_t* pRAM;
static struct CPU* pCPU;
static double uTimer;
static bool inTerminal;

// Routine prototypes
inline void wait_timer();
inline void SetPC(mem_t);
inline void SetReg(byte_t, byte_t);
inline bool check_reserved(mem_t);
inline byte_t GetReg(byte_t);

byte_t peek(mem_t);
byte_t stack_pop();
byte_t getflags();
mem_t RelAdd(smem_t, sbyte_t);

void poke(mem_t, byte_t);
void stack_push(byte_t);
void flagset(byte_t, bool);
void setflags(byte_t);
void load_program(const char* , long);
int run_instr(byte_t,bool);

typedef struct AssemblerLabel
{
    const char* name;
    sbyte_t relative;
    mem_t absolute;
} ASM_Label;
typedef struct AssemblerVar
{
    const char* name;
    const char* data;
    int datasize;
} ASM_Var;

void RunTerminal();
bool initalize();

// Main

int main()
{
    uTimer = clock();
    if(initalize())
    {
        wait_timer();
        //char program[] = {0x20,0x06,0x09,0x20,0x06,0x0C,0x20,0x06,0x12,0xA2,0x00,0x60,0xE8,0xE0,0x05,0xD0,0xFB,0x60,0x00};//{0xa2,0x00,0xe8,0xe0,0x50,0xd0,0xfb,0xea}; //{0xA2,0x00,0xE8,0x20,0x06,0x02}; //{0x08,0xA9,0x60,0x48,0x69,0x45,0x68,0x28,0x00};
        //load_program(program, 19);
        //pCPU->STEP = true;
        //CPU_Start();
        RunTerminal();
    }
    else
    {
        printf("Failed to initialize.");
    }
    free(pRAM);
    free(pCPU);
    return 0;
}

// Timing
void wait_timer()
{
    while( (clock()-uTimer) < 1000./IPS ) { };
    uTimer = clock();
}

// Debug
void printf_cpuinfo()
{
    printf("\nA=$%x, X=$%x, Y=$%x\nSP=$%x, PC=$%x\n\nNV-BDIZC\n", pCPU->A, pCPU->X, pCPU->Y, pCPU->SP, pCPU->PC);
    char flags[9] = "00000000\0";
    register int i;
    for(i = 0; i <= 7; i++)
    {
        int bit = pow(2,i);
        flags[7-i] = (pCPU->Flags & bit) ? '1' : '0';
    }
    printf("%s\n",flags);
}

// Memory
bool check_reserved(mem_t location)
{
    return (location >= Stackpos && location <= Stackpos+Stacksize);
}
byte_t peek(mem_t location)
{
    if( location > 0xFFFF ) return '\0';
    return (byte_t) *(pRAM + location);
}
void poke(mem_t location, byte_t data)
{
    if( location > 0xFFFF ) return;
    *(pRAM + location) = data;
}
byte_t stack_pop()
{
    byte_t data = peek(Stackpos + pCPU->SP +1);
    pCPU->SP++;
    return data;
}
void stack_push(byte_t data)
{
    poke(Stackpos + pCPU->SP, data);
    pCPU->SP--;
}
void load_program(const char* program, long bytes)
{
    printf("\nLoading %i bytes...\n", bytes);
    for (int i = 0; i < bytes; i++)
    {
        poke(ProgramStart+i,program[i]);
        printf("$%X: %X\n",(byte_t)ProgramStart+i, (byte_t)program[i]);
    }
    pCPU->PC = ProgramStart;
    printf(" Loaded.\n");
}

// CPU routines
void SetPC(mem_t addr){ pCPU->PC = addr; }
void SetReg(byte_t r, byte_t data)
{
    byte_t* robj = (!r) ? &pCPU->A : ( (r&1) ? &pCPU->X  : &pCPU->Y );
    *robj = data;
    flagset(fZero, data==0);
    flagset(fNegative, (data&bSign)!=0);
}
byte_t GetReg(byte_t r)
{
    return (!r) ? pCPU->A : ( (r&1) ? pCPU->X  : pCPU->Y );
}

// Flags
void flagset(byte_t flag, bool val)
{
    if(!val) pCPU->Flags &= ~flag;
    if( val) pCPU->Flags |=  flag;
}
void setflags(byte_t flags) { pCPU->Flags = flags; };
byte_t getflags() { return pCPU->Flags; }

int run_instr(byte_t c, bool demo)
{
    smem_t pc = pCPU->PC;
    byte_t flags = pCPU->Flags;
    bool switchf = false; // Flag load switch.
    bool C = flags&fCarry;
    bool Z = flags&fZero;
    bool I = flags&fInterupt;
    bool D = flags&fDecimal;
    bool B = flags&fBreak;
    bool V = flags&fOverflow;
    bool N = flags&fNegative;
    byte_t H = peek(pCPU->PC+1);
    byte_t L = peek(pCPU->PC+2);
    mem_t HL = (mem_t)(L*0x100)+H; // Reverse endian.
    byte_t A = pCPU->A;
    byte_t X = pCPU->X;
    byte_t Y = pCPU->Y;
    byte_t ticks = 1;

    switch(c)
    {
        // Indirect helpers
        #define dINX(M) peek((mem_t)(peek(M+X+1)*256)+peek(M+X))
        #define dINY(M) peek((mem_t)((peek(M+1)*256)+peek(M+Y))+Y)
        #define dIND(M) peek((mem_t)(peek(M+1)*256)+peek(M))
        // Flag helpers
        #define CMP(R,M) C=(R>=M);Z=(R==M);N=(R-M)&bSign
        // If H has the same sign as L and the result has a different sign, overflow.
        #define OVR(Q,W,E) !((Q&bSign)-(W&bSign))&&((Q&bSign)-(E&bSign))
        #define ADC(M) C=(A+M<A);V=OVR(A,M,A+M)
        #define SBC(M) C=(A-M>A);V=OVR(A,M,A-M)
        // Math helpers
        #define ROL(M) (M << 1) | (M >> 7)
        #define ROR(M) (M >> 1) | (M << 7)

        // -- 00
        /* BRK IMP */ case 0x00: B=1; break;
        /* BPL REL */ case 0x10: N?0:(pc+=(sbyte_t)H); ticks++; break;
        /* JSR ABS */ case 0x20: stack_push(wLSB(pc)+1);stack_push(wMSB(pc));pc=HL; ticks=0; break;
        /* BMI REL */ case 0x30: N?(pc+=(sbyte_t)H):0; ticks++; break;
        /* RTI IMP */ case 0x40: switchf=1;flags=stack_pop();pc=stack_pop(); ticks++; break;
        /* BVC REL */ case 0x50: V?0:(pc+=(sbyte_t)H); ticks++; break;
        /* RTS IMP */ case 0x60: pc=mWORD(stack_pop(),stack_pop()+1); break;
        /* BVS REL */ case 0x70: V?(pc+=(sbyte_t)H):0; ticks++; break;
        /* BCC REL */ case 0x90: C?0:(pc+=(sbyte_t)H); ticks++; break;
        /* LDY IMM */ case 0xA0: Y=H; ticks++; break;
        /* BCS REL */ case 0xB0: C?(pc+=(sbyte_t)H):0; ticks++; break;
        /* CPY IMM */ case 0xC0: CMP(Y,H); ticks++; break;
        /* BNE REL */ case 0xD0: C?0:(pc+=(sbyte_t)H); ticks++; break;
        /* CPX IMM */ case 0xE0: CMP(X,H); ticks++; break;
        /* BEQ REL */ case 0xF0: C?(pc+=(sbyte_t)H):0; ticks++; break;
        // -- 01
        /* ORA INX */ case 0x01: A|=dINX(H); ticks++; break;
        /* ORA INY */ case 0x11: A|=dINY(H); ticks++; break;
        /* AND INX */ case 0x21: A&=dINX(H); ticks++; break;
        /* AND INY */ case 0x31: A&=dINY(H); ticks++; break;
        /* EOR INX */ case 0x41: A^=dINX(H); ticks++; break;
        /* EOR INY */ case 0x51: A^=dINY(H); ticks++; break;
        /* ADC INX */ case 0x61: H=dINX(H)+C;ADC(H);A+=H; ticks++; break;
        /* ADC INY */ case 0x71: H=dINY(H)+C;ADC(H);A+=H; ticks++; break;
        /* STA INX */ case 0x81: poke(dINX(H),A); ticks++; break;
        /* STA INY */ case 0x91: poke(dINY(H),A); ticks++; break;
        /* LDA INX */ case 0xA1: A=dINX(H); ticks++; break;
        /* LDA INY */ case 0xB1: A=dINY(H); ticks++; break;
        /* CMP INX */ case 0xC1: H=dINX(H);CMP(A,H); ticks++; break;
        /* CMP INY */ case 0xD1: H=dINY(H);CMP(A,H); ticks++; break;
        /* SBC INX */ case 0xE1: H=dINX(H)-~C;SBC(H);A-=H; ticks++; break;
        /* SBC INY */ case 0xF1: H=dINY(H)-~C;SBC(H);A-=H; ticks++; break;
        // -- 02
        /* LDX IMM */ case 0xA2: X=H; ticks++; break;
        // -- 04
        /* BIT ZP  */ case 0x24: H=peek(H);Z=!(A&H);V=(H&0x20);N=(H&0x40); ticks++; break;
        /* STY ZP  */ case 0x84: poke(H,Y); ticks++; break;
        /* STY ZPX */ case 0x94: poke(H+X,Y); ticks++; break;
        /* LDY ZP  */ case 0xA4: Y=peek(H); ticks++; break;
        /* LDY ZPX */ case 0xB4: Y=peek(H+X); ticks++; break;
        /* CPY ZP  */ case 0xC4: H=peek(H); CMP(Y,H); ticks++; break;
        /* CPX ZP  */ case 0xE4: H=peek(H); CMP(X,H); ticks++; break;
        // -- 05
        /* ORA ZP  */ case 0x05: A|=peek(H); ticks++; break;
        /* ORA ZPX */ case 0x15: A|=peek(H+X); ticks++; break;
        /* AND ZP  */ case 0x25: A&=peek(H); ticks++; break;
        /* AND ZPX */ case 0x35: A&=peek(H+X); ticks++; break;
        /* EOR ZP  */ case 0x45: A^=peek(H); ticks++; break;
        /* EOR ZPX */ case 0x55: A^=peek(H+X); ticks++; break;
        /* ADC ZP  */ case 0x65: H=peek(H);ADC(H);A+=H+C; ticks++; break;
        /* ADC ZPX */ case 0x75: H=peek(H+X);ADC(H);A+=H+C; ticks++; break;
        /* STA ZP  */ case 0x85: poke(H,A); ticks++; break;
        /* STA ZPX */ case 0x95: poke(H+X,A); ticks++; break;
        /* LDA ZP  */ case 0xA5: A=peek(H); ticks++; break;
        /* LDA ZPX */ case 0xB5: A=peek(H+X); ticks++; break;
        /* CMP ZP  */ case 0xC5: H=peek(H);CMP(A,H); ticks++; break;
        /* CMP ZPX */ case 0xD5: H=peek(H+X);CMP(A,H); ticks++; break;
        /* SBC ZP  */ case 0xE5: H=peek(H);SBC(H);A-=H-~C; ticks++; break;
        /* SBC ZPX */ case 0xF5: H=peek(H+X);SBC(H);A-=H-~C; ticks++; break;
        // -- 06
        /* ASL ZP  */ case 0x06: L=peek(H);poke(H,L<<1);H=L<<1;C=(L&bSign);N=(H&bSign); ticks++; break;
        /* ASL ZPX */ case 0x16: L=peek(H+X);poke(H+X,L<<1);H=L<<1;C=(L&bSign);N=(H&bSign); ticks++; break;
        /* ROL ZP  */ case 0x26: L=peek(H);poke(H,ROL(L));H=ROL(L);C=(L&bSign);N=(H&bSign); ticks++; break;
        /* ROL ZPX */ case 0x36: L=peek(H+X);poke(H+X,ROL(L));H=ROL(L);C=(L&bSign);N=(H&bSign); ticks++; break;
        /* LSR ZP  */ case 0x46: L=peek(H);poke(H,(sbyte_t)L>>1);H=(sbyte_t)L>>1;C=(L&1);N=(H&bSign);Z=!H; ticks++; break;
        /* LSR ZPX */ case 0x56: L=peek(H+X);poke(H+X,(sbyte_t)L>>1);H=(sbyte_t)L>>1;C=(L&1);N=(H&bSign);Z=!H; ticks++; break;
        /* ROR ZP  */ case 0x66: L=peek(H);poke(H,ROR(L));H=ROR(L);C=(L&1);N=(H&bSign); ticks++; break;
        /* ROR ZPX */ case 0x76: L=peek(H+X);poke(H+X,ROR(L));H=ROR(L);C=(L&1);N=(H&bSign); ticks++; break;
        /* STX ZP  */ case 0x86: poke(H,X); ticks++; break;
        /* STX ZPY */ case 0x96: poke(H+Y,X); ticks++; break;
        /* LDX ZP  */ case 0xA6: X=peek(H); ticks++; break;
        /* LDX ZPY */ case 0xB6: X=peek(H+Y); ticks++; break;
        /* DEC ZP  */ case 0xC6: L=peek(H)-1;poke(H,L);Z=!L;N=L&bSign; ticks++; break;
        /* DEC ZPX */ case 0xD6: L=peek(H+X)-1;poke(H,L);Z=!L;N=L&bSign; ticks++; break;
        /* INC ZP  */ case 0xE6: L=peek(H)+1;poke(H,L);Z=!L;N=L&bSign; ticks++; break;
        /* INC ZPX */ case 0xF6: L=peek(H+X)+1;poke(H,L);Z=!L;N=L&bSign; ticks++; break;
        // -- 08
        /* PHP IMP */ case 0x08: stack_push(flags); break;
        /* CLC IMP */ case 0x18: C=0; break;
        /* PLP IMP */ case 0x28: switchf=1;flags=stack_pop(); break;
        /* SEC IMP */ case 0x38: C=1; break;
        /* PHA IMP */ case 0x48: stack_push(A); break;
        /* CLI IMP */ case 0x58: I=0; break;
        /* PLA IMP */ case 0x68: A=stack_pop(A); break;
        /* SEI IMP */ case 0x78: I=1; break;
        /* DEY IMP */ case 0x88: Y--; break;
        /* TYA IMP */ case 0x98: A=Y; break;
        /* TAY IMP */ case 0xA8: Y=A; break;
        /* CLV IMP */ case 0xB8: V=0; break;
        /* INY IMP */ case 0xC8: Y++; break;
        /* CLD IMP */ case 0xD8: D=0; break;
        /* INX IMP */ case 0xE8: X++; break;
        /* SED IMP */ case 0xF8: D=1; break;
        // -- 09
        /* ORA IMM */ case 0x09: A|=H; ticks++; break;
        /* ORA ABY */ case 0x19: A|=peek(H+Y); ticks+=2; break;
        /* AND IMM */ case 0x29: A&=H; ticks++; break;
        /* AND ABY */ case 0x39: A&=peek(HL+Y); ticks+=2; break;
        /* EOR IMM */ case 0x49: A^=peek(H); ticks++; break;
        /* EOR ABY */ case 0x59: A^=peek(HL+Y); ticks+=2; break;
        /* ADC IMM */ case 0x69: ADC(H);A+=H+C; ticks++; break;
        /* ADC ABY */ case 0x79: H=peek(HL+Y);ADC(H);A+=H+C; ticks+=2; break;
        /* STA ABY */ case 0x99: poke(HL+Y,A); ticks+=2; break;
        /* LDA IMM */ case 0xA9: A=H; ticks++; break;
        /* LDA ABY */ case 0xB9: A=peek(HL+Y); ticks+=2; break;
        /* CMP IMM */ case 0xC9: CMP(A,H); ticks++; break;
        /* CMP ABY */ case 0xD9: H=peek(HL+Y);CMP(A,H); ticks+=2; break;
        /* SBC IMM */ case 0xE9: SBC(H);A-=H-~C; ticks++; break;
        /* SBC ABY */ case 0xF9: H=peek(HL+Y);SBC(H);A-=H-~C; ticks+=2; break;
        // -- 0A
        /* ASL ACC */ case 0x0A: H=A<<1;C=(A&bSign);N=(H&bSign);A=H; break;
        /* ROL ACC */ case 0x2A: H=ROL(A);C=(A&bSign);N=(H&bSign);A=H; ticks++; break;
        /* LSR ACC */ case 0x4A: H=(sbyte_t)A>>1;C=(A&1);N=(H&bSign);A=H; ticks++; break;
        /* ROR ACC */ case 0x6A: H=ROR(A);C=(A&1);N=(H&bSign);A=H; ticks++; break;
        /* TXA IMP */ case 0x8A: A=X; break;
        /* TXS IMP */ case 0x9A: stack_push(X); break;
        /* TAX IMP */ case 0xAA: X=A; break;
        /* TSX IMP */ case 0xBA: X=stack_pop(); break;
        /* DEX IMP */ case 0xCA: X--; break;
        /* NOP IMP */ case 0xEA: break;
        // -- 0C
        /* BIT ABS */ case 0x2C: H=peek(HL);Z=!(A&H);V=(H&0x20);N=(H&0x40); ticks+=2; break;
        /* JMP ABS */ case 0x4C: pc=HL; ticks=0; break;
        /* JMP IND */ case 0x6C: pc=dIND(HL); ticks=0; break;
        /* STY ABS */ case 0x8C: poke(HL,Y); ticks+=2; break;
        /* LDY ABS */ case 0xAC: Y=peek(HL); ticks+=2; break;
        /* LDY ABX */ case 0xBC: Y=peek(HL+X); ticks+=2; break;
        /* CPY ABS */ case 0xCC: H=peek(HL);CMP(Y,H); ticks+=2; break;
        /* CPX ABS */ case 0xEC: H=peek(HL);CMP(X,H); ticks+=2; break;
        // -- 0D
        /* ORA ABS */ case 0x0D: A|=peek(HL); ticks+=2; break;
        /* ORA ABX */ case 0x1D: A|=peek(HL+X); ticks+=2; break;
        /* AND ABS */ case 0x2D: A&=peek(HL); ticks+=2; break;
        /* AND ABX */ case 0x3D: A&=peek(HL+X); ticks+=2; break;
        /* EOR ABS */ case 0x4D: A^=peek(HL); ticks+=2; break;
        /* EOR ABX */ case 0x5D: A^=peek(HL+X); ticks+=2; break;
        /* ADC ABS */ case 0x6D: H=peek(HL);ADC(H);A+=H+C; ticks+=2; break;
        /* ADC ABX */ case 0x7D: H=peek(HL+X);ADC(H);A+=H+C; ticks+=2; break;
        /* STA ABS */ case 0x8D: poke(HL,A); ticks+=2; break;
        /* STA ABX */ case 0x9D: poke(HL+X,A); ticks+=2; break;
        /* LDA ABS */ case 0xAD: A=peek(HL); ticks+=2; break;
        /* LDA ABX */ case 0xBD: A=peek(HL+X); ticks+=2; break;
        /* CMP ABS */ case 0xCD: H=peek(HL);CMP(A,H); ticks+=2; break;
        /* CMP ABX */ case 0xDD: H=peek(HL+X);CMP(A,H); ticks+=2; break;
        /* SBC ABS */ case 0xED: H=peek(HL);SBC(H);A-=H-~C; ticks+=2; break;
        /* SBC ABX */ case 0xFD: H=peek(HL+X);SBC(H);A-=H-~C; ticks+=2; break;
        // -- 0E
        /* ASL ABS */ case 0x0E: H=peek(HL);C=(H&bSign);N=(H<<1)&bSign;poke(HL,H<<1); ticks+=2; break;
        /* ASL ABX */ case 0x1E: H=peek(HL+X);C=(H&bSign);N=(H<<1)&bSign;poke(HL+X,H<<1); ticks+=2; break;
        /* ROL ABS */ case 0x2E: H=peek(HL);C=(H&bSign);N=(ROL(H)&bSign);poke(HL,ROL(H)); ticks+=2; break;
        /* ROL ABX */ case 0x3E: H=peek(HL+X);C=(H&bSign);N=(ROL(H)&bSign);poke(HL+X,ROL(H)); ticks+=2; break;
        /* LSR ABS */ case 0x4E: L=peek(HL);H=(sbyte_t)L>>1;poke(HL,H);C=(L&1);N=(H&bSign);Z=!H; ticks+=2; break;
        /* LSR ABX */ case 0x5E: L=peek(HL);H=(sbyte_t)L>>1;poke(HL,H);C=(L&1);N=(H&bSign);Z=!H; ticks+=2; break;
        /* ROR ABS */ case 0x6E: H=peek(HL);C=(H&bSign);N=(ROR(H)&bSign);poke(HL,ROR(H)); ticks+=2; break;
        /* ROR ABX */ case 0x7E: H=peek(HL+X);C=(H&bSign);N=(ROR(H)&bSign);poke(HL+X,ROR(H)); ticks+=2; break;
        /* STX ABS */ case 0x8E: poke(HL,X); ticks+=2; break;
        /* LDX ABS */ case 0x9E: X=peek(HL); ticks+=2; break;
        /* LDX ABY */ case 0xBE: X=peek(HL+Y); ticks+=2; break;
        /* DEC ABS */ case 0xCE: H=peek(HL)-1;poke(HL,H);Z=!H;N=H&bSign; ticks+=2; break;
        /* DEC ABX */ case 0xDE: H=peek(HL+X)-1;poke(HL,H);Z=!H;N=H&bSign; ticks+=2; break;
        /* INC ABS */ case 0xEE: H=peek(HL)+1;poke(HL,H);Z=!H;N=H&bSign; ticks+=2; break;
        /* INC ABX */ case 0xFE: H=peek(HL+X)+1;poke(HL,H);Z=!H;N=H&bSign; ticks+=2; break;

        // ERR
        default:
            printf("\nEncountered Invalid instruction, halting...");
            CPU_Pause();
            return NULL;
        break;
    }

    // Very useful for running just to get how many bytes an instruction takes.
    if(demo) return ticks;

    if(!switchf)
    {
        flagset(fCarry,C);
        flagset(fZero,Z);
        flagset(fInterupt,I);
        flagset(fDecimal,D);
        flagset(fBreak,B);
        flagset(fOverflow,V);
        flagset(fNegative,N);
    }
    else
    {
        pCPU->Flags = flags;
    }

    // SetReg is used here to trigger flags.
    if(pCPU->A!=A)SetReg(rA,A);
    if(pCPU->X!=X)SetReg(rX,X);
    if(pCPU->Y!=Y)SetReg(rY,Y);

    if(pCPU->STEP)
    {
        printf("\n-------------------------");
        printf("\nRunning: %X", c);
        printf_cpuinfo();
        printf("-------------------------\n");
    }
    pCPU->PC = pc+ticks;
    // Wait next icycle.
    wait_timer();
    return ticks;
}

// Routine definitions

bool initalize()
{
    pRAM = calloc(64, 1024); // 64k of RAM.
    pCPU = malloc( sizeof(struct CPU) );

    if(!pRAM || !pCPU) return false;

    // Reset CPU
    pCPU->Flags = fUnknown;
    pCPU->A     = 0x00;
    pCPU->X     = 0x00;
    pCPU->Y     = 0x00;
    pCPU->PC    = ProgramStart;
    pCPU->SP    = 0xFF;
    pCPU->STEP  = false;

    // Switch to terminal
    inTerminal = true;

    return true;
}

void CPU_Start()
{
    while( !(pCPU->Flags & fBreak) )
    {
        run_instr(peek(pCPU->PC),false);
        if(pCPU->STEP)getch();
    }
    printf("\nStopped at: PC=$%x\n",pCPU->PC);
    printf("System time: %.0f usec.\n",uTimer);
    printf("-------------------------\n");
    printf_cpuinfo();
}

// Assembler
void RunTerminal()
{
   #define safecontinue if(finp.inp)free(finp.inp);if(tdata)free(tdata);continue

   // Label support.
   int buffsize = 0xFF;
   char* buffer = calloc(1,buffsize);
   TermData* tdata;
   int label_c=0;
   int macro_c=0;
   ASM_Label** labels = calloc(0xFF,sizeof(ASM_Label));
   ASM_Var**   macros = calloc(0xFF,sizeof(ASM_Var));

   while(inTerminal)
   {
        if(!(pCPU->Flags&fBreak))
        {
            //label_c = 0;
            CPU_Start();
            pCPU->PC--;
        }
        #define nextcmd term_finished = true
        bool term_finished = false;
        char pbytes[7];
        char* found; // Used for labels.
        sbyte_t addr_rel = ((sbyte_t)(ProgramStart-pCPU->PC));
        printf("%04X[%02X]: ",pCPU->PC,(byte_t)addr_rel);
        fgets(buffer,buffsize,stdin);
        FilteredInput* finp = FilterInput(buffer,buffsize);
        char* fbuffer = finp->inp;
        if(!fbuffer)
        {
            printf("[ERROR] Failed to process input.");
            continue;
        }

        // Decode assembler-side objects.
        bool parsed = false;
        for(int i = 0; i < macro_c; i++)
        {
            if(!strncmp(fbuffer,"def",3)) break;
            found = strstr(buffer,macros[i]->name);
            char* mname = macros[i]->name;
            if( found != NULL )
            {
                 char rbuffer[macros[i]->datasize];
                 rbuffer[macros[i]->datasize] = '\0';
                 strncpy(rbuffer,macros[i]->data,macros[i]->datasize);
                 //printf("[DEBUG] rbuffer %s\n",rbuffer);
                 //strstr_replace(buffer,found,mname,rbuffer);
                 char cbuffer[0xFF];
                 int fsize = found-buffer;
                 strncpy(cbuffer, buffer, fsize);
                 cbuffer[fsize] = '\0';
                 sprintf(cbuffer+fsize, "%s%s", rbuffer, found+strlen(macros[i]->name));
                 strncpy(buffer,cbuffer,0xFF);
                 parsed = true;
                 printf("[MACRO]:> %s\n",buffer);
            }
        }
        for(int i = 0; i < label_c; i++)
        {
            if(!strncmp(fbuffer,"::",2)) break;
            if(!strncmp(fbuffer,"def",3)) break;
            found = strstr(buffer,labels[i]->name);
            char* lname = labels[i]->name;
            if( found != NULL )
            {
                 // Setup replacement buffer, convert label to ABS value.
                 char rbuffer[6];
                 sprintf(rbuffer,"$%04X",labels[i]->absolute);
                 // Replace label name with the replace buffer.
                 strstr_replace(buffer,found,lname,rbuffer);
                 parsed = true;
                 printf("[LABEL]>: %s\n",buffer);
            }
        }

        // Re-filter input if it was parsed.
        if(parsed)
        {
            delete_finp(finp);
            finp = FilterInput(buffer,buffsize);
            char* fbuffer = finp->inp;
            //printf("[DEBUG] New filtered: %s\n",fbuffer);
        }
        // Assembler preprocessor
        if(!strncmp(fbuffer,"::",2))
        {
           bool duplicate = false;
           ASM_Label* label = malloc(sizeof(ASM_Label));
           char* name = malloc(strlen(fbuffer)-1);
           strncpy(name,fbuffer+2,strlen(fbuffer)-1);
           for(int i = 0; i < label_c; i++)
           {
               if(!strncmp(labels[i]->name,name,strlen(name)))
               {
                   duplicate = true;
                   free(name);
                   printf("[WARN] Label \"%s\" redefined: $%04X -> $%04X. \n",name,labels[i]->absolute,pCPU->PC);
                   labels[i]->absolute = pCPU->PC;
                   labels[i]->relative = addr_rel;
               }
           }
           if(!duplicate)
           {
                label->name = name;
                label->relative = addr_rel;
                label->absolute = pCPU->PC;
                *(labels+label_c) = label;
                //printf("[INFO] Label %d,%s defined at :> $%04X\n",label_c,name,pCPU->PC);
                label_c++;
           }
           nextcmd;
        }
        else if(!strncmp(fbuffer,"def",3))
        {
           ASM_Var* duplicate = NULL;
           ASM_Var* avar = malloc(sizeof(ASM_Var));
           char* name_begin;
           char* name_end;
           char* name_copy;
           char* data_copy;
           // Find name
           name_begin = fbuffer+3;
           name_end = strstr(fbuffer,":");
           if(!name_end)
           {
               printf("[USRERR] Cannot resolve name as it wasn't colon terminated.\n");
               nextcmd;
           }
           int namesize = (name_end-name_begin);
           name_copy = malloc(namesize);
           name_copy[namesize] = '\0';
           strncpy(name_copy,name_begin,namesize);
           // Check if duplicate
           for(int i = 0; i < macro_c; i++)
           {
               if(!strncmp(macros[i]->name,name_copy,strlen(name_copy)))
               {
                   duplicate = macros[i];
               }
           }
           // Find macro data.
           int datasize = strlen(fbuffer)-((name_end+1)-fbuffer);
          // printf("[INFO] Macro datasize: %d\n",datasize);
           data_copy = malloc(datasize);
           data_copy[datasize] = '\0';
           strncpy(data_copy,name_end+1,datasize);
           if(duplicate)
           {
               free(duplicate->data);
               //free(name_copy);
               duplicate->data = data_copy;
               duplicate->datasize = datasize;
               printf("[WARN] Macro redefined: %s\n",data_copy);
               nextcmd;
           }
           //printf("[INFO] Macro defined: %s -> %s\n",name_copy,data_copy);
           avar->data = data_copy;
           avar->name = name_copy;
           avar->datasize = datasize;
           *(macros + macro_c) = avar;
           macro_c ++;

           nextcmd;
        }
        else if(!strncasecmp(fbuffer,"BCD",3))
        {
           char cbytes[strlen(fbuffer)-3];
           strncpy(cbytes,fbuffer+3,strlen(fbuffer)-3);
           char* token = strtok(cbytes,",");
           int tcount=0;
           while(token)
           {
               // Convert to byte_t and add to PC.
               if( (*token != '$' && *token != '#')  || strlen(token) > 3)
               {
                   printf("[ERROR] Syntax error on token #%d\n",tcount);
                   break;
               }
               int base = 16;
               if(*token == '#') base = 10;
               byte_t data = strtol(token+1,NULL,base);
               poke(pCPU->PC,data);
               printf("%04X=$%02X\n",pCPU->PC,data);
               pCPU->PC++;
               tcount++;
               token = strtok(0,",");
           }
           nextcmd;
        }

        // Terminal commands
        else if(!strncasecmp(fbuffer,"RUNP",4))
        {
           pCPU->PC = ProgramStart;
           flagset(fBreak,false);
           nextcmd;
        }
        else if(!strncasecmp(fbuffer,"RUN",3))
        {
            flagset(fBreak,false);
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"EXIT",4))
        {
            inTerminal = false;
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"=P",2))
        {
            pCPU->PC = ProgramStart;
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"=",1))
        {
            char pc[4];
            int offs = (*(fbuffer+1)=='$')?2:1;
            strncpy(pc,fbuffer+offs,4);
            mem_t addr = strtol(pc,NULL,16);
            pCPU->PC = addr;
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"PC=",3))
        {
            char pc[4];
            int offs = (*(fbuffer+3)=='$')?4:3;
            strncpy(pc,fbuffer+offs,4);
            mem_t addr = strtol(pc,NULL,16);
            pCPU->PC = addr;
            nextcmd;
        }
        else if(!strncmp(fbuffer,"++",2))
        {
            pCPU->PC++;
            nextcmd;
        }
        else if(!strncmp(fbuffer,"--",2))
        {
            pCPU->PC--;
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"STEP",4))
        {
            pCPU->STEP = !pCPU->STEP;
            if(pCPU->STEP)
                printf("[INFO] Stepping mode ON.\n");
            else
                printf("[INFO] Stepping mode OFF.\n");
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"RESET",5))
        {
            label_c = 0;
            uTimer = clock();
            free(pCPU);
            free(pRAM);
            initalize();
            wait_timer();
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"READ",4)|!strncasecmp(fbuffer,"R",1))
        {
            printf("%X -> %X\n",pCPU->PC,peek(pCPU->PC));
            nextcmd;
        }
        else if(!strncasecmp(fbuffer,"HELP",4))
        {
            printf("\n        .: LIST OF COMMANDS :.\n\n");
            printf("RUNP   : Runs program starting at 0x0600\n");
            printf("RUN    : Runs program at current addr\n");
            printf("PC=,=  : Sets PC to numeric argument\n");
            printf("=P     : Set PC to 0x0600\n");
            printf("++,--  : PC++,PC--\n");
            printf("READ,R : Exports data at PC");
            printf("STEP   : Toggles program stepping\n");
            printf("RESET  : Resets CPU and Assembler\n");
            printf("EXIT   : Exits program\n\n");
            printf("\n                    .: Assembler Quirks :.\n\n");
            printf("::NAME         | Declares NAME as Label at current addr\n");
            printf("def NAME: DATA | Creates an alias for DATA under NAME (A macro)\n");
            printf("bcd $00,...    | Writes bytes to memory at PC\n\n");
            nextcmd;
        }
        // Assemble code.
        if(!term_finished)
        {
            tdata = AssembleCMD(finp,pCPU->PC);
            if(tdata != NULL)
            {
                if(tdata->bytecode == 0xFF)
                {
                    printf("[ERROR] Incompatible operation: %s, %s\n",tdata->CMD,tdata->modestr);
                    continue;
                }
                // Insert instruction/bytes into RAM.
                poke(pCPU->PC,tdata->bytecode);
                if(tdata->bytes > 1) poke(pCPU->PC+1,tdata->H);
                if(tdata->bytes > 2) poke(pCPU->PC+2,tdata->L);
                pCPU->PC += tdata->bytes;
            }
            else if(inTerminal)
            {
                printf("[ERROR] Syntax error\n");
            }
        }
        delete_finp(finp);
   }
   for(int i = 0; i < label_c; i++)
   {
        free(labels[i]->name);
        free(labels[i]);
   }
   for(int i = 0; i < macro_c; i++)
   {
        free(macros[i]->name);
        free(macros[i]->data);
        free(macros[i]);
   }
   free(buffer);
}
