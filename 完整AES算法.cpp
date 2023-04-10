#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define Nb 4
#define Nk 8
#define Nr 14
typedef unsigned char byte;
typedef unsigned int word;
byte S[256] = {
    // S-box
};
byte InvS[256] = {
    // 逆S-box
};
word Rcon[Nr] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000,
    0xab000000, 0x4d000000
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
    for (i = 0; i < Nb; i++) {
        a = State[4*i];
        b = State[4*i+1];
        c = State[4*i+2];
        d = State[4*i+3];
        State[4*i]   = (byte)(0x02*a + 0x03*b + c      + d      ) % 0x100;
        State[4*i+1] = (byte)(a      + 0x02*b + 0x03*c + d      ) % 0x100;
        State[4*i+2] = (byte)(a      + b      + 0x02*c + 0x03*d) % 0x100;
        State[4*i+3] = (byte)(0x03*a + c      + d      + 0x02*d) % 0x100;
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
            temp = (S[(temp>>16)&0xff]<<24) | (S[(temp>>8)&0xff]<<16) | (S[temp&0xff]<<8) | S[(temp>>24)&0xff];
            temp ^= Rcon[(i/Nk)-1]<<24;
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
    char keystr[33]; // 32 hex digits + null terminator
    // Read plaintext from user input
    printf("Enter plaintext (16 bytes): ");
    scanf("%32s", plainstr);
    // Verify that plaintext string is a valid hex string
    for (i = 0; i < 32; i++) {
        if (!isxdigit(plainstr[i])) {
            printf("Error: plaintext must be a valid hex string\n");
            return 1;
        }
    }
    // Convert plaintext string to byte array
    byte plain[16];
    for (i = 0; i < 16; i++) {
        sscanf(plainstr + 2*i, "%2hhx", &plain[i]);
    }
    // Read key size and key string from user input
    printf("Enter key size (128, 192, or 256 bits): ");
    scanf("%d", &keysize);
    printf("Enter key (in hex): ");
    scanf("%32s", keystr);
    // Verify that key string is a valid hex string
    for (i = 0; i < 32; i++) {
        if (!isxdigit(keystr[i])) {
            printf("Error: key must be a valid hex string\n");
            return 1;
        }
    }
    // Convert key string to byte array
    byte key[32];
    for (i = 0; i < 16; i++) {
        sscanf(keystr + 2*i, "%2hhx", &key[i]);
    }
    // Perform AES encryption
    AES_Init(key, keysize);
    AES_Encrypt(plain);
    // Print ciphertext
    printf("Ciphertext: ");
    for (i = 0; i < 16; i++) {
        printf("%02x", plain[i]);
    }
    printf("\n");
    return 0;
}
