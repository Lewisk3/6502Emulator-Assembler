#pragma once
#ifndef TERMINAL_H
#define TERMINAL_H

typedef struct FilteredInput
{
	char* inp;
	int nbytes;
} FilteredInput;

typedef struct TerminalData
{
	const char CMD[4];
	const char* modestr;
	int mode;
	unsigned char bytecode;
	int bytes;
	long H, L;
} TermData;

TermData* TerminalCMD(char*);
unsigned char AssembleI(const char*, int);
FilteredInput* FilterInput(char*, long);
void strstr_replace(char*, char*, const char*, const char*, int);
void delete_finp(FilteredInput*);

typedef enum
{
	md_IMP = 0,
	md_IMM,
	md_ZP,
	md_ZPX,
	md_ZPY,
	md_ABS,
	md_ABX,
	md_ABY,
	md_INX,
	md_INY,
	md_REL,
	md_ACC,
	md_IND,
	ad_IMMH,
	ad_IMMD

} TerminalEnums;

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#endif

unsigned char AssembleI(const char* i, int m)
{
#define DECODE(IMP,IMM,ZP,ZPX,ZPY,ABS,ABX,ABY,INX,INY,REL,ACC,IND) (m==md_IMP)?IMP:(m==md_IMM)?IMM:(m==md_ZP)?ZP:(m==md_ZPX)?ZPX:(m==md_ZPY)?ZPY:(m==md_ABS)?ABS:(m==md_ABX)?ABX:(m==md_ABY)?ABY:(m==md_INX)?INX:(m==md_INY)?INY:(m==md_REL)?REL:(m==md_ACC)?ACC:(m==md_IND)?IND:0xFF;

	if (!strncasecmp(i, "ADC", 3)) return DECODE(0xFF, 0x69, 0x65, 0x75, 0xFF, 0x6D, 0x7D, 0x79, 0x61, 0x71, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "AND", 3)) return DECODE(0xFF, 0x29, 0x25, 0x35, 0xFF, 0x2D, 0x3D, 0x39, 0x21, 0x31, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "ASL", 3)) return DECODE(0xFF, 0xFF, 0x06, 0x16, 0xFF, 0x0E, 0x1E, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "BCC", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x90, 0xFF, 0xFF);
	if (!strncasecmp(i, "BEQ", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0xFF, 0xFF);
	if (!strncasecmp(i, "BIT", 3)) return DECODE(0xFF, 0x24, 0xFF, 0xFF, 0xFF, 0x2C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "BMI", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x30, 0xFF, 0xFF);
	if (!strncasecmp(i, "BNE", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0xFF, 0xFF);
	if (!strncasecmp(i, "BPL", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x10, 0xFF, 0xFF);
	if (!strncasecmp(i, "BRK", 3)) return DECODE(0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "BVC", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xB0, 0xFF, 0xFF);
	if (!strncasecmp(i, "BVS", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0xFF, 0xFF);
	if (!strncasecmp(i, "CLC", 3)) return DECODE(0x18, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "CLD", 3)) return DECODE(0xD8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "CLI", 3)) return DECODE(0x58, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "CLV", 3)) return DECODE(0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "CMP", 3)) return DECODE(0xFF, 0xC9, 0xC5, 0xD5, 0xFF, 0xCD, 0xDD, 0xD9, 0xC1, 0xD1, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "CPX", 3)) return DECODE(0xFF, 0xE0, 0xE4, 0xFF, 0xFF, 0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "CPY", 3)) return DECODE(0xFF, 0xC0, 0xC4, 0xFF, 0xFF, 0xCC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "DEC", 3)) return DECODE(0xFF, 0xFF, 0xC6, 0xD6, 0xFF, 0xCE, 0xDE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "DEX", 3)) return DECODE(0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "DEY", 3)) return DECODE(0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "EOR", 3)) return DECODE(0xFF, 0x49, 0x45, 0x55, 0xFF, 0x4D, 0x5D, 0x59, 0x41, 0x51, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "INC", 3)) return DECODE(0xFF, 0xFF, 0xE6, 0xF6, 0xFF, 0xEE, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "INX", 3)) return DECODE(0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "INY", 3)) return DECODE(0xC8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "JMP", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6C);
	if (!strncasecmp(i, "JSR", 3)) return DECODE(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "LDA", 3)) return DECODE(0xFF, 0xA9, 0xA5, 0xB5, 0xFF, 0xAD, 0xBD, 0xB9, 0xA1, 0xB1, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "LDX", 3)) return DECODE(0xFF, 0xA2, 0xA6, 0xFF, 0xB6, 0xAE, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "LDY", 3)) return DECODE(0xFF, 0xA0, 0xA4, 0xB4, 0xFF, 0xAC, 0xBC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "LSR", 3)) return DECODE(0xFF, 0xFF, 0x46, 0x56, 0xFF, 0x4E, 0x5E, 0xFF, 0xFF, 0xFF, 0xFF, 0x4A, 0xFF);
	if (!strncasecmp(i, "NOP", 3)) return DECODE(0xEA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "ORA", 3)) return DECODE(0xFF, 0x09, 0x05, 0x15, 0xFF, 0x0D, 0x1D, 0x19, 0x01, 0x11, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "PHA", 3)) return DECODE(0x48, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "PHP", 3)) return DECODE(0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "PLA", 3)) return DECODE(0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "PLP", 3)) return DECODE(0x28, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "ROL", 3)) return DECODE(0xFF, 0xFF, 0x26, 0x36, 0xFF, 0x2E, 0x3E, 0xFF, 0xFF, 0xFF, 0xFF, 0x2A, 0xFF);
	if (!strncasecmp(i, "ROR", 3)) return DECODE(0xFF, 0xFF, 0x66, 0x76, 0xFF, 0x6E, 0x7E, 0xFF, 0xFF, 0xFF, 0xFF, 0x6A, 0xFF);
	if (!strncasecmp(i, "RTI", 3)) return DECODE(0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "RTS", 3)) return DECODE(0x60, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "SBC", 3)) return DECODE(0xFF, 0xE9, 0xE5, 0xF5, 0xFF, 0xED, 0xFD, 0xF9, 0xE1, 0xF1, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "SEC", 3)) return DECODE(0x38, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "SED", 3)) return DECODE(0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "SEI", 3)) return DECODE(0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "STA", 3)) return DECODE(0xFF, 0x85, 0x95, 0x8D, 0xFF, 0x8D, 0x9D, 0x99, 0x81, 0x91, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "STX", 3)) return DECODE(0xFF, 0xFF, 0x86, 0xFF, 0x96, 0x8E, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "STY", 3)) return DECODE(0xFF, 0xFF, 0x84, 0x94, 0xFF, 0x8C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "TAX", 3)) return DECODE(0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "TAY", 3)) return DECODE(0xA8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "TSX", 3)) return DECODE(0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "TXA", 3)) return DECODE(0x8A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "TXS", 3)) return DECODE(0x9A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	if (!strncasecmp(i, "TYA", 3)) return DECODE(0x98, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);


	return 0xFF; // Return invalid instruction
}

void strstr_replace(char* buffer, char* buffer_index, const char* replacestr, const char* replacewith, int msize)
{
	// Get size of string before index token
	// Load prefix_buffer with prefix of string before replacestr occurs
	// Insert suffix of string behind prefix_buffer, include replacestr.
	// Load buffer with prefix_buffer. fin.
	char* prefix_buffer = calloc(1, msize + 1);
	int fsize = buffer_index - buffer;
	strncpy(prefix_buffer, buffer, msize);
	// Make sure the data occurring before replacestr is properly null terminated.
	prefix_buffer[fsize] = '\0';
	// Process string.
	sprintf(prefix_buffer + fsize, "%s%s", replacewith, buffer_index + strlen(replacestr));
	memcpy(buffer, prefix_buffer, msize);
	buffer[msize] = '\0';
	free(prefix_buffer);
}

void delete_finp(FilteredInput* inp)
{
	if(inp->inp)free(inp->inp);
	inp->inp = NULL;
	if(inp)free(inp);
	inp = NULL;
}

FilteredInput* FilterInput(char* CMD, long bytes)
{
	// Used for running terminal commands.
	#define filter(C) C!='\t'&&C!=' '&&C!='\n'
	char* buffer = calloc(1, bytes+1);
	buffer[bytes] = '\0';
	if (buffer == NULL)
	{
		printf("[FATAL] Failed to allocate buffer space! \n");
	}
	char* src = CMD;
	char* aux = buffer;
	int nbytes = 0;
	while (*src) {
		if (filter(*src))
		{
			*(buffer++) = *src;
			nbytes++;
		}
		src++;
	}
	*buffer = 0x0;

	FilteredInput* finput = malloc(sizeof(FilteredInput));
	finput->inp = aux;
	finput->nbytes = nbytes;
	return finput;
}

// Terminal
TermData* AssembleCMD(FilteredInput* fCMD, unsigned short PC)
{
	char* buffer = fCMD->inp;
	int nbytes = fCMD->nbytes;
	if (nbytes < 3) return NULL;
	long opH = 0;
	long opL = 0;
	int modeactual;
	char instruction[4];
	instruction[3] = '\0';
	char modechk[6];
	modechk[5] = '\0';
	strncpy(instruction, buffer, 3);
	strncpy(modechk, buffer + 3, 2);
	strncpy(modechk + 2, buffer + (nbytes - 3), 3);
	int isize = 1;
	// Check next set to determine mode
	// #Special Branch mode#
	if (!strncasecmp(instruction, "B", 1) && strncasecmp(instruction, "BIT", 3) && !strncasecmp(modechk, "$", 1))
		modeactual = md_REL;
	// #IMM modes#
	else if (!strncasecmp(modechk, "#$", 2))
		modeactual = ad_IMMH;
	else if (!strncasecmp(modechk, "#", 1))
		modeactual = ad_IMMD;
	// #IND modes#
	else if (!strncasecmp(modechk, "($", 2) && !strncasecmp(modechk + 2, ",X)", 3))
		modeactual = md_INX;
	else if (!strncasecmp(modechk, "($", 2) && !strncasecmp(modechk + 2, "),Y", 3))
		modeactual = md_INY;
	// #ZP modes#
	else if (!strncasecmp(modechk, "$", 1) && !strncasecmp(modechk + 3, ",X", 2) && nbytes < 9)
		modeactual = md_ZPX;
	else if (!strncasecmp(modechk, "$", 1) && !strncasecmp(modechk + 3, ",Y", 2) && nbytes < 9)
		modeactual = md_ZPY;
	else if (!strncasecmp(modechk, "$", 1) && nbytes < 7)
		modeactual = md_ZP;
	// #ABS modes#
	else if (!strncasecmp(modechk, "$", 1) && !strncasecmp(modechk + 3, ",X", 2))
		modeactual = md_ABX;
	else if (!strncasecmp(modechk, "$", 1) && !strncasecmp(modechk + 3, ",Y", 2))
		modeactual = md_ABY;
	else if (!strncasecmp(modechk, "$", 1))
		modeactual = md_ABS;
	else if (!strncasecmp(modechk, "A", 1))
		modeactual = md_ACC;
	else if (nbytes == 3)
		modeactual = md_IMP;
	else // Oof, you done messed up, kid.
		return NULL;

	// Operand loading.
	char op[2];
	switch (modeactual)
	{
	case md_IMP: break;
	case ad_IMMH:
		strncpy(op, buffer + 5, 2);
		opH = strtol(op, NULL, 16);
		isize++;
		modeactual = md_IMM;
		break;
	case ad_IMMD:
		strncpy(op, buffer + 4, 2);
		opH = strtol(op, NULL, 10);
		isize++;
		modeactual = md_IMM;
		break;
	case md_ZPY:
	case md_ZPX:
	case md_ZP:
		strncpy(op, buffer + 4, 2);
		opH = strtol(op, NULL, 16);
		isize++;
		break;
	case md_ABY:
	case md_ABX:
	case md_ABS:
		strncpy(op, buffer + 4, 2);
		opL = strtol(op, NULL, 16);
		strncpy(op, buffer + 6, 2);
		opH = strtol(op, NULL, 16);
		isize += 2;
		break;
	case md_INY:
	case md_INX:
		strncpy(op, buffer + 5, 2);
		opH = strtol(op, NULL, 16);
		isize++;
		break;
	case md_REL:
		if (nbytes > 6)
		{
			// Convert from ABS to REL
			char op[2];
			strncpy(op, buffer + 4, 2);
			opH = strtol(op, NULL, 16);
			strncpy(op, buffer + 6, 2);
			opL = strtol(op, NULL, 16);
			unsigned short abs = (unsigned short)(opH * 256) + opL;
			signed char rel = (signed char)(abs - PC) - 2; // -2 for BNE bytes.
			opH = (unsigned char)rel;
			printf("[ABSREL]: %04X -> %02X\n", abs, (unsigned char)rel);
		}
		else
		{
			strncpy(op, buffer + 4, 2);
			opH = strtol(op, NULL, 16);
		}
		isize++;
		break;
	}
	const char* strmodes[12] =
	{
		"IMP",
		"IMM",
		"ZP",
		"ZPX",
		"ZPY",
		"ABS",
		"ABX",
		"ABY",
		"INX",
		"INY",
		"REL",
		"ACC"
	};
	//free(buffer);
	TermData* data = malloc(sizeof(TermData));
	if (data)
	{
		strncpy(data->CMD, instruction, 4);
		data->bytes = isize;
		data->mode = modeactual;
		data->modestr = strmodes[modeactual];
		data->H = opH;
		data->L = opL;
		data->bytecode = AssembleI(instruction, modeactual);
	}
	return data;
}

#endif // TERMINAL_H

