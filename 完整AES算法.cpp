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
    // Inverse S-box
};
word Rcon[Nr] = {
    // Rcon
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
    byte key[32];
    byte in[16];
    byte out[16];
    int keysize, i;
    printf("Enter plaintext (16 bytes): ");
    for (i = 0; i < 16; i++)
        scanf("%c", &in[i]);
    printf("Enter key size (128, 192, or 256 bits): ");
    scanf("%d", &keysize);
    printf("Enter key (in hex): ");
    for (i = 0; i < keysize/8; i++)
        scanf("%2hhx", &key[i]);
    KeyExpansion(key, keysize/8);
    Encrypt(in, out);
    printf("Cipher text: ");
    for (i = 0; i < 16; i++)
        printf("%02x", out[i]);
    printf("\n");
    return 0;
}
