#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <Windows.h>

#define MD5_SIZE 64 //a universal size that is used all over in MD5
#define MAX_PASSWORD_LENGTH 32 //our maximum supported password length

void pad_digest(char *, uint32_t);
void init();
void clipboard_copy(char *);
uint8_t* get_password();
void hashify_digest(uint8_t *, uint8_t *);
void hash_512(uint32_t *);

uint32_t mod_db[MD5_SIZE];
uint32_t shift_amts[MD5_SIZE];

int main(int argc, char *argv[])
{
    init();
    uint8_t *password = get_password();
    uint8_t *password_padded = malloc(MD5_SIZE);
    uint32_t password_length = strlen(password); //guaranteed less than 512bit, so we dont have to mod512
    uint8_t *password_hashed = malloc(16); //16bytes == 128bits == md5 standard length

    memset(password_padded, 0x00, MD5_SIZE);
    strcpy(password_padded, password);

    pad_digest(password_padded, password_length);
    hashify_digest(password_padded, password_hashed);
    
    free(password_padded);
    free(password);
    
    getchar();
    return 0;
}
//Pad the password message to comply with MD5.
//password_padded is the message that will be padded (out)
//password_length is the length of the message, in bytes.
void pad_digest(char *password_padded, uint32_t password_length)
{
     //pad the hashable string to 448 bits
    password_padded[password_length] = 0x80;
    for(int i = password_length + 1; i < MD5_SIZE - 8; i++)
    {
        password_padded[i] = 0x00;
    }

    password_padded[MD5_SIZE - 8] = password_length & 0xff000000;
    password_padded[MD5_SIZE - 7] = password_length & 0x00ff0000;
    password_padded[MD5_SIZE - 6] = password_length & 0x0000ff00;
    password_padded[MD5_SIZE - 5] = password_length & 0x000000ff;
    
}
//Initializes our data structures that will be used in the hashification of a password.
void init()
{
    //init k
    mod_db[ 0] = 0xd76aa478; mod_db[ 1] = 0xe8c7b756; mod_db[ 2] = 0x242070db; mod_db[ 3] = 0xc1bdceee;
    mod_db[ 4] = 0xf57c0faf; mod_db[ 5] = 0x4787c62a; mod_db[ 6] = 0xa8304613; mod_db[ 7] = 0xfd469501;
    mod_db[ 8] = 0x698098d8; mod_db[ 9] = 0x8b44f7af; mod_db[10] = 0xffff5bb1; mod_db[11] = 0x895cd7be;
    mod_db[12] = 0x6b901122; mod_db[13] = 0xfd987193; mod_db[14] = 0xa679438e; mod_db[15] = 0x49b40821;

    mod_db[16] = 0xf61e2562; mod_db[17] = 0xc040b340; mod_db[18] = 0x265e5a51; mod_db[19] = 0xe9b6c7aa;
    mod_db[20] = 0xd62f105d; mod_db[21] = 0x02441453; mod_db[22] = 0xd8a1e681; mod_db[23] = 0xe7d3fbc8;
    mod_db[24] = 0x21e1cde6; mod_db[25] = 0xc33707d6; mod_db[26] = 0xf4d50d87; mod_db[27] = 0x455a14ed;
    mod_db[28] = 0xa9e3e905; mod_db[29] = 0xfcefa3f8; mod_db[30] = 0x676f02d9; mod_db[31] = 0x8d2a4c8a;
    
    mod_db[32] = 0xfffa3942; mod_db[33] = 0x8771f681; mod_db[34] = 0x6d9d6122; mod_db[35] = 0xfde5380c;
    mod_db[36] = 0xa4beea44; mod_db[37] = 0x4bdecfa9; mod_db[38] = 0xf6bb4b60; mod_db[39] = 0xbebfbc70;
    mod_db[40] = 0x289b7ec6; mod_db[41] = 0xeaa127fa; mod_db[42] = 0xd4ef3085; mod_db[43] = 0x04881d05;
    mod_db[44] = 0xd9d4d039; mod_db[45] = 0xe6db99e5; mod_db[46] = 0x1fa27cf8; mod_db[47] = 0xc4ac5665;
    
    mod_db[48] = 0xf4292244; mod_db[49] = 0x432aff97; mod_db[50] = 0xab9423a7; mod_db[51] = 0xfc93a039;
    mod_db[52] = 0x655b59c3; mod_db[53] = 0x8f0ccc92; mod_db[54] = 0xffeff47d; mod_db[55] = 0x85845dd1;
    mod_db[56] = 0x6fa87e4f; mod_db[57] = 0xfe2ce6e0; mod_db[58] = 0xa3014314; mod_db[59] = 0x4e0811a1;
    mod_db[60] = 0xf7537e82; mod_db[61] = 0xbd3af235; mod_db[62] = 0x2ad7d2bb; mod_db[63] = 0xeb86d391;

    //init s
    shift_amts[ 0] =  7; shift_amts[ 1] = 12; shift_amts[ 2] = 17; shift_amts[ 3] = 22;
    shift_amts[ 4] =  7; shift_amts[ 5] = 12; shift_amts[ 6] = 17; shift_amts[ 7] = 22;
    shift_amts[ 8] =  7; shift_amts[ 9] = 12; shift_amts[10] = 17; shift_amts[11] = 22;
    shift_amts[12] =  7; shift_amts[13] = 12; shift_amts[14] = 17; shift_amts[15] = 22;

    shift_amts[16] =  5; shift_amts[17] =  9; shift_amts[18] = 14; shift_amts[19] = 20;
    shift_amts[20] =  5; shift_amts[21] =  9; shift_amts[22] = 14; shift_amts[23] = 20;
    shift_amts[24] =  5; shift_amts[25] =  9; shift_amts[26] = 14; shift_amts[27] = 20;
    shift_amts[28] =  5; shift_amts[29] =  9; shift_amts[30] = 14; shift_amts[31] = 20;

    shift_amts[32] =  4; shift_amts[33] = 11; shift_amts[34] = 16; shift_amts[35] = 23;
    shift_amts[36] =  4; shift_amts[37] = 11; shift_amts[38] = 16; shift_amts[39] = 23;
    shift_amts[40] =  4; shift_amts[41] = 11; shift_amts[42] = 16; shift_amts[43] = 23;
    shift_amts[44] =  4; shift_amts[45] = 11; shift_amts[46] = 16; shift_amts[47] = 23;

    shift_amts[48] =  6; shift_amts[49] = 10; shift_amts[50] = 15; shift_amts[51] = 21;
    shift_amts[52] =  6; shift_amts[53] = 10; shift_amts[54] = 15; shift_amts[55] = 21;
    shift_amts[56] =  6; shift_amts[57] = 10; shift_amts[58] = 15; shift_amts[59] = 21;
    shift_amts[60] =  6; shift_amts[61] = 10; shift_amts[62] = 15; shift_amts[63] = 21;

}
//Copies the parameter data to the system clipboard.
//data is a string that will be copied to the clipboard.
void clipboard_copy(char *data)
{
    const size_t len = strlen(data) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    memcpy(GlobalLock(hMem), data, len);
    GlobalUnlock(hMem);
    OpenClipboard(0);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
}

//Gets user input for a valid password. 
//Returns a malloc pointer to the password, or string that the user typed in. Will not exceed 32 characters.
uint8_t* get_password()
{
    int finished = 0;
    uint8_t input[MAX_PASSWORD_LENGTH + 2]; //32 characters for password, an error character (if > 32, then password is invalid), and a null character
    uint8_t *password;
    while(!finished)
    {
        memset(input, '\0', sizeof(input));
        int inlen = 0;

        printf("Enter a password (max 32 characters): \n");
        fgets(input, sizeof(input), stdin);

        int newline_index = strcspn(input, "\n");
        input[newline_index] = '\0'; //set the newline char to null, so we can treat it like null

        inlen = strlen(input) + 1;
        password = malloc(inlen);

        strcpy(password, input);

        fflush(stdin); //flush the input buffer

        if(inlen > MAX_PASSWORD_LENGTH + 1) 
        {
            system("CLEAR");
            printf("The password you entered was too long. Please try again. \n");
        }
        else
        {
            return password;
        }
        
    }
}

//Turns a message into a 128-bit hash. Assumes big-endian order. Converted in-function.
//digest is the message to hashify using md5
//md5_hash is a new digest that is hashified, and ready for use.
void hashify_digest(uint8_t *digest, uint8_t *md5_hash)
{
    uint32_t *digest_32 = malloc(MD5_SIZE);
    memset(digest_32, 0x00, MD5_SIZE);

    for(int i = 0; i < MD5_SIZE - 8; i+=4)
    {
        digest_32[i] = 0x00000000;

        //here, we reverse the ordering to little endian...
        digest_32[i] = digest_32[i] | digest[i];
        digest_32[i] = digest_32[i] | digest[i+1] << 8;
        digest_32[i] = digest_32[i] | digest[i+2] << 16;
        digest_32[i] = digest_32[i] | digest[i+3] << 24;
        printf("%02d :::: %08x \n", i, digest_32[i]);
    }
    //todo: should this be little endian? specification says "lower-order word in front", not byte... 
    digest_32[14] = 0x00000000;
    digest_32[15] = 0x00000000;
    digest_32[14] = (digest[MD5_SIZE - 8] << 24) | 
        (digest[MD5_SIZE - 7] << 16) | 
        (digest[MD5_SIZE - 6] << 8)  |
        (digest[MD5_SIZE - 5]);
        printf("%02d :::: %08x \n", 14, digest_32[14]);
        printf("%02d :::: %08x \n", 15, digest_32[15]);
    //digest_32[15] is guaranteed to be 0 due to password length restrictions

    hash_512(digest_32);
}

//Instead of bit shifting, we instead "rotate" bits.
//This avoids overflow, and instead wraps the bits around to the other end.
//value is the number to be shifted
//shift is the amount of bits to shift by
//returns the value, shifted by shift
unsigned int left_rotate(const unsigned int value, int shift) 
{
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

//Takes a 512-bit message and applies a hashing algorithm.
//processed_digest is a digest, processed for hashing (see hashify_digest()).
//processed_digest will be changed to a hashed string. (out parameter)
//this is the main md5 algorithm
void hash_512(uint32_t *processed_digest)
{
    unsigned int a_initial = 0x67452301; unsigned int A = a_initial;
    unsigned int b_initial = 0xefcdab89; unsigned int B = b_initial;
    unsigned int c_initial = 0x98badcfe; unsigned int C = c_initial;
    unsigned int d_initial = 0x10325476; unsigned int D = d_initial;
    
    //Main loop:
    for(int i = 0; i < MD5_SIZE; i++)
    {
        uint32_t F, G;
        if(i <= 15)
        {
            F = (B & C) | ((~B) & D);
            G = i;
        }
        else if(i >= 16 && i <= 31)
        {
            F = (D & B) | ((~D) & C);
            G = (5*i + 1) % 16;
        }
        else if(i >= 32 && i <= 47)
        {
            F = B ^ C ^ D;
            G = (3*i + 5) % 16;
        }
        else if(i >= 48 && i <= 63)
        {
            F = C ^ (B | (~D));
            G = (7*i) % 16;
        }

        F = F + A + mod_db[i] + processed_digest[G];
        A = D;
        D = C;
        C = B;
        B = B + left_rotate(F, shift_amts[i]);
    }

    a_initial += A;
    b_initial += B;
    c_initial += C;
    d_initial += D;

    free(processed_digest);
    processed_digest = malloc(MD5_SIZE/4); //the final, processed string...

    processed_digest[0] = a_initial;
    processed_digest[1] = b_initial;
    processed_digest[2] = c_initial;
    processed_digest[3] = d_initial;
    printf("%x", a_initial);
    printf("%x", b_initial);
    printf("%x", c_initial);
    printf("%x", d_initial);
    
}