#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define Nb 4
#define Nk 8
#define Nr 10
typedef unsigned char byte;
typedef unsigned int word;
byte S[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // 后面省略
};
byte InvS[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    // 后面省略
};
word Rcon[Nr] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000
};
word Key[Nb*(Nr+1)] = {0};
word State[Nb*Nb] = {0};
void SubBytes()
{
    int i;
    for (i = 0; i < Nb*Nb; i++)
        State[i] = S[State[i]];
}
void ShiftRows()
{
    byte temp;
    // Row 1
    temp = State[1];
    State[1] = State[5];
    State[5] = State[9];
    State[9] = State[13];
    State[13] = temp;
    // Row 2
    temp = State[2];
    State[2] = State[10];
    State[10] = temp;
    temp = State[6];
    State[6] = State[14];
    State[14] = temp;
    // Row 3
    temp = State[3];
    State[3] = State[15];
    State[15] = State[11];
    State[11] = State[7];
    State[7] = temp;
}
void MixColumns()
{
    int i;
    byte a, b, c, d;
    word temp;
    for (i = 0; i < Nb; i++) {
        a = State[4*i];
        b = State[4*i+1];
        c = State[4*i+2];
        d = State[4*i+3];
        temp = (word)a << 24 | (word)b << 16 | (word)c << 8 | (word)d;
        temp = (0x02 * ((temp >> 24) & 0xff) + 0x03 * ((temp >> 16) & 0xff) + ((temp >> 8) & 0xff) + (temp & 0xff)) % 0x100;
        State[4*i]   = (byte)(temp >> 24);
        State[4*i+1] = (byte)(temp >> 16);
        State[4*i+2] = (byte)(temp >> 8);
        State[4*i+3] = (byte)temp;
    }
}
void AddRoundKey(int round)
{
    int i;
    for (i = 0; i < Nb*Nb; i++)
        State[i] ^= Key[round*Nb*Nb+i];
}
void KeyExpansion(byte* key, int keysize)
{
    int i, j;
    word temp;
    for (i = 0; i < Nk; i++)
        Key[i] = (key[4*i]<<24) | (key[4*i+1]<<16) | (key[4*i+2]<<8) | key[4*i+3];
    for (i = Nk; i < Nb*(Nr+1); i++) {
        temp = Key[i-1];
        if (i % Nk == 0) {
            temp = ((S[(temp>>16)&0xff]<<24) | (S[(temp>>8)&0xff]<<16) | (S[(temp>>0)&0xff]<<8) | (S[(temp>>24)&0xff]<<0)) ^ Rcon[i/Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = (S[(temp>>24)&0xff]<<24) | (S[(temp>>16)&0xff]<<16) | (S[(temp>>8)&0xff]<<8) | S[temp&0xff];
        }
        Key[i] = Key[i-Nk] ^ temp;
    }
}
void Encrypt(byte* in, byte* out)
{
    int i, j, round;
    for (i = 0; i < Nb*Nb; i++)
        State[i] = (in[4*i]<<24) | (in[4*i+1]<<16) | (in[4*i+2]<<8) | in[4*i+3];
    AddRoundKey(0);
    for (round = 1; round < Nr; round++) {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
    for (i = 0; i < Nb*Nb; i++) {
        out[4*i]   = (byte)(State[i]>>24);
        out[4*i+1] = (byte)(State[i]>>16);
        out[4*i+2] = (byte)(State[i]>>8);
        out[4*i+3] = (byte)State[i];
    }
}

void print_hex(unsigned char *str, int len) {
    int i;
    for(i = 0; i < len; i++) {
        printf("%02x", str[i]);
    }
    printf("\n");
}


int main()
{
    int i, keysize;
    char keystr[33]; 
    printf("Enter plaintext (16 bytes): ");
    scanf("%32s", plainstr);
    for (i = 0; i < 32; i++) {
        if (!isxdigit(plainstr[i])) {
            printf("Error: plaintext must be a valid hex string\n");
            return 1;
        }
    }

    byte plain[16];
    for (i = 0; i < 16; i++) {
        sscanf(plainstr + 2*i, "%2hhx", &plain[i]);
    }
 
    printf("Enter key size (128, 192, or 256 bits): ");
    scanf("%d", &keysize);
    printf("Enter key (in hex): ");
    scanf("%32s", keystr);

    for (i = 0; i < 32; i++) {
        if (!isxdigit(keystr[i])) {
            printf("Error: key must be a valid hex string\n");
            return 1;
        }
    }

    byte key[32];
    for (i = 0; i < 16; i++) {
        sscanf(keystr + 2*i, "%2hhx", &key[i]);
    }
    AES_Init(key, keysize);
    AES_Encrypt(plain);

    printf("Ciphertext: ");
    for (i = 0; i < 16; i++) {
        printf("%02x", plain[i]);
    }
    printf("\n");
    return 0;
}
