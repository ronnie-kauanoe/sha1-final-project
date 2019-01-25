/*
 * Final Project: Secure Hash Algorith (SHA-1)
 * @author Ronnie Kauanoe
 * @since 4/10/18
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "printbits.h"

#define MAX_SIZE 1048576
#define WORDS 16

void readFile(unsigned char[], FILE *, int);
unsigned int calculateBlocks(unsigned int);
void establishBlockData(unsigned int blocks, unsigned char[], unsigned int, unsigned int[blocks][WORDS]);
void fillBlock(unsigned char[], unsigned int[]);
unsigned int makeWord(unsigned char[]);
unsigned int S(unsigned int, int);
unsigned int f_0(unsigned int, unsigned int, unsigned int);
unsigned int f_1(unsigned int, unsigned int, unsigned int);
unsigned int f_2(unsigned int, unsigned int, unsigned int);
unsigned int f_3(unsigned int, unsigned int, unsigned int);
void computeMessageDigest(int blockCount, unsigned int[blockCount][WORDS]);

int main(void) {
    FILE *filePointer = NULL;
    char *fileName = "abc.txt";
    unsigned int charCount = 0;
    int readError = 0;
    int i = 0;
    unsigned int blockCount = 0;
    
    puts("BEGINNING ENCRYPTION...");
    int k = 0;
    for (k = 0; k < 3; k++) {
        if (k == 0) {
            fileName = "abc.txt";
        } else if (k == 1) {
            fileName = "alpha.txt";
        } else {
            fileName = "a.txt";
        }
        filePointer = fopen(fileName, "r");
        fseek(filePointer, 0, SEEK_END);
        charCount = ftell(filePointer);
        if (charCount > MAX_SIZE) {
            printf("ERROR: File input too large\n");
            exit(1);
        } else {
            rewind(filePointer);
            unsigned char input[charCount + 1];
            readFile(input, filePointer, charCount);
            printf("Character count = %d\n", charCount);
            blockCount = calculateBlocks(charCount);
            input[charCount] = (unsigned int) 128;
            unsigned int blocks[blockCount][16];
            establishBlockData(blockCount, input, charCount, blocks);
            computeMessageDigest(blockCount, blocks);
        }
    }
    return 0;
}

/** Reads data from file and populates the input array. */
void readFile(unsigned char buffer[], FILE *fp, int inputLength) {
    char temp;
    int i = 0;
    while (((temp = fgetc(fp)) != EOF)) {
        buffer[i] = (unsigned char) temp;
        i++;
    }
}

/** Calculates the amount of blocks needed to contain file data. */
unsigned int calculateBlocks(unsigned int dataCount) {
    unsigned int blocks = floor((dataCount + 1) / 64) + 1;
    int temp = (int) blocks;
    if ((dataCount + 1) - ((temp - 1) * 64) > 8) {
        blocks++;
    }
    printf("Blocks needed for input = %d\n", blocks);
    return blocks;
}

/** Cycles through each block to be populated by the fillBlock function. */
void establishBlockData(unsigned int blocks, unsigned char message[], unsigned int mLength,  unsigned int blockArr[blocks][WORDS]) {
    /** Counter for blocks loop. */
    unsigned int i = 0;
    /** Counter for characters loop. */
    unsigned int k = 0;
    /** Counter for characters from message loop. */
    unsigned int x = 0;
    unsigned int pad = 0;
    int charactersLeft = mLength;
    unsigned int tempNum = 0;
    char tempArr[64] = {'\0'};
    for (i = 0; i < blocks; i++) {
        for (k = 0; k < 64; k++) {
            if (message[x] == 0x80) {
                tempArr[k] = message[x];
                /** The end of the input has been reached and padding will
                 *  now begin. */
                pad++;
            } else if (pad > 0) {
                /** The remaining words of the last block will be zeroes. */
                tempArr[k] = 0;
            } else {
                tempArr[k] = message[x];
            }
            x++;
        }
        fillBlock(tempArr, blockArr[i]);
    }
    blockArr[blocks - 1][15] = mLength * 8;
}

/** Fills block with 16 words. */
void fillBlock(unsigned char message[], unsigned int tempBlockArr[]) {
    unsigned int i = 0;
    unsigned int k = 0;
    unsigned char sub[4] = {'\0'};
    for (i = 0; i < 16; i++) {
        /** Puts four characters into a temp array that
         *  will be used to make an unsigned int. */
        sub[0] = message[k];
        sub[1] = message[k + 1];
        sub[2] = message[k + 2];
        sub[3] = message[k + 3];
        /** The word is put into the array. */
        tempBlockArr[i] = makeWord(sub);
        k += 4;
    }
}

/** Creates an unsigned into using four unsigned chars. */
unsigned int makeWord(unsigned char message[]) {
    unsigned int word =0;
    int i = 0;
    unsigned int temp = 0;
    for (i = 0; i < 4; i++) {
        temp = message[i];
        word += temp;
        if ((i + 1) != 4) {
            word = word << 8;
        }
    }
    return word;
}

/** Bit rotation fuction. */
unsigned int S(unsigned int data, int shift) {
    return ((data << shift) | (data >> (32 - shift)));
}

/** f helper functions used for A value calculation. */
/** Used when 0 <= k <= 19. */
unsigned int f_0(unsigned int B, unsigned int C, unsigned int D) {
    return ((B & C) | ((~B) & D));
}
/** Used when 20 <= k <= 39. */
unsigned int f_1(unsigned int B, unsigned int C, unsigned int D) {
    return (B ^ C ^ D);
}
/** Used when 40 <= k <= 59. */
unsigned int f_2(unsigned int B, unsigned int C, unsigned int D) {
    return ((B & C) | (B & D) | (C & D));
}
/** Used when 60 <= k <= 79. */
unsigned int f_3(unsigned int B, unsigned int C, unsigned int D) {
    return (B ^ C ^ D);
}

/** Computes and prints the message digest. */
void computeMessageDigest(int blockCount, unsigned int unpadded[blockCount][16]) {
    int x = 0;
    /** Initial H values. */
    unsigned int H[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    /** Initial A, B, C, D, and E values. */
    unsigned int A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];
    int i = 0;
    int k = 0;
    /** K constant declarations. */
    unsigned int K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}; 
    unsigned int temp = 0;
    /** 80 word 2D array. */
    unsigned int blocks[blockCount][80];
    /** Transfers information from the 16 word 2D array and fills
     *  the indices 16 to 79 with words using the original 16 words.*/
    for (i = 0; i < blockCount; i++) {
        for (k = 0; k < 80; k++) {
            if (k < 16) {
                blocks[i][k] = unpadded[i][k];
            } else {
                blocks[i][k] = S((blocks[i][k - 3] ^ blocks[i][k - 8] ^ blocks[i][k - 14] ^ blocks[i][k - 16]), 1);
            }
        }
    }
    /** This is where the hasing (magic) happens. */
    for (i = 0; i < blockCount; i++) {
        A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];
        for (k = 0; k < 80; k++) {
                  if ((0 <= k) && (k <= 19)) {
                temp = S(A, 5) + f_0(B, C, D) + E + blocks[i][k] + K[0];
            } else if ((20 <= k) && (k <= 39)) {
                temp = S(A, 5) + f_1(B, C, D) + E + blocks[i][k] + K[1];
            } else if ((40 <= k) && (k <= 59)) {
                temp = S(A, 5) + f_2(B, C, D) + E + blocks[i][k] + K[2];
            } else if ((60 <= k) && (k <= 79)) {
                temp = S(A, 5) + f_3(B, C, D) + E + blocks[i][k] + K[3];
            }
            E = D; 
            D = C;
            C = S(B, 30);
            B = A;
            A = temp;
            if (blockCount <= 2) {
                printf("k = %02d: %08x %08x %08x %08x %08x\n", k, A, B, C, D, E);
            }
        }
        H[0] += A;
        H[1] += B;
        H[2] += C;
        H[3] += D;
        H[4] += E;
    }
    /** Ta da! Prints the final hashed message. */
    printf("message digest: %08x %08x %08x %08x %08x\n", H[0], H[1], H[2], H[3], H[4]);
}
