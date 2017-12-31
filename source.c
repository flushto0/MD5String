#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <Windows.h>

#define MAX_PASSWORD_LENGTH 32  //password length restriction
#define MD5_SIZE 64             //aka 512 bits

uint32_t const_lookups[] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
	0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,
	0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
    0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
	0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
	0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
    0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
	0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

uint32_t chunks[16]; //our password message, converted into 32-bit little-endian words (defined in a special way)


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

/////////////////////////////HELP FUNCTIONS///////////////////////////////

//Gets user input for a valid password using standard c input techniques.
//Returns a malloc pointer to the password, i.e. string that the user typed in. Will not exceed 32 characters.
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
            printf("The password you entered was too long. Please try again. \n\n");
        }
        else
        {
            return password;
        }
        
    }
}
//Gets the amount of hash passes from the user.
//returns the amount of times we should rehash our message.
uint8_t get_passes()
{
    int num, nitems = 0;

    while(nitems == 0 || num > 255)
    {
        printf("How many times would you like to re-hash the value? (max 255): ");
        nitems = scanf("%d", &num);
        if (nitems <= 0 || num > 255)
        {   
            printf("The number you picked is not applicable. Try again.");
        } 
        else break;
    }
    return num;
}

//This "rotates" bits. This avoids bit-shift overflow, and instead wraps the bits around to the other end of the byte(s).
//value is the number to be shifted
//shift is the amount of bits to rotate by
//returns the value, bit-rotated by shift
unsigned int left_rotate(const uint32_t value, int shift) 
{
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

//The main MD5 transformation algorithm.
// A, B, C, D are all 32-bit ints defined by the MD5 specification, and 
// represent the final 128-bit digest. Upon return of function, they will
// be the final digest.
void transform_digest(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D)
{
	uint32_t AA,BB,CC,DD,f,g,temp;
	AA=*A;	
	BB=*B;
	CC=*C;
	DD=*D;
    ;
	// break chunk into sixteen 32-bit words w[j], from 0 to 15
    // Main loop:
    for(int i = 0; i<64; i++) {

        if (i < 16) {
            f = (BB & CC) | ((~BB) & DD);
            g = i;
        } else if (i < 32) {
            f = (DD & BB) | ((~DD) & CC);
            g = (5*i + 1) % 16;
        } else if (i < 48) {
            f =BB ^ CC ^ DD;
            g = (3*i + 5) % 16;          
        } else {
            f = CC ^ (BB | (~DD));
            g = (7*i) % 16;
        }

        temp = DD;
        DD = CC;
        CC = BB;
        BB = BB + left_rotate((AA + f + const_lookups[i] + chunks[g]), r[i]);
        AA = temp;

    }

	*A=*A+AA;
	*B=*B+BB;
	*C=*C+CC;
	*D=*D+DD;
}

uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}

void convert_to32(uint8_t *message, uint32_t length)
{
    for (int i = 0; i < 14; ++i)
            chunks[i] = to_int32(message + i*4); 
    chunks[14] = length;
}
void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}



uint8_t* MD5(uint8_t *message, uint8_t final_digest[16])
{
    uint32_t message_length = strlen(message);
    uint32_t padded_length;
    
    for (padded_length = message_length + 1; padded_length % (512/8) != 448/8; ++padded_length);

    uint8_t padded_message[MD5_SIZE];       //this is a 512-bit array. 
                        //there is no need to create anymore than 1 chunk because our message will never be over 32*8 bits wide
    memset(padded_message, 0, MD5_SIZE * sizeof(padded_message[0])); 
    strcpy(padded_message, message);

    padded_message[message_length] = 0x80; //set the first non-message bit to 1 as the specification states
    message_length *= 8;                   //turn this into the bit count of the message size for further processing

    int a0 = 0x67452301;   //A
    int b0 = 0xefcdab89;   //B
    int c0 = 0x98badcfe;   //C
    int d0 = 0x10325476;   //D

    convert_to32(padded_message, message_length);
    transform_digest(&a0, &b0, &c0, &d0);
    
    uint8_t digest[16];
    memset(digest, 0, MD5_SIZE/4);

    to_bytes(a0, digest);
    to_bytes(b0, digest + 4);
    to_bytes(c0, digest + 8);
    to_bytes(d0, digest + 12);

    memcpy(final_digest, digest, 16);
}
//////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{  
    uint8_t str_digest[33]; 
    uint8_t *message = get_password();
    uint8_t passes = get_passes();
    uint8_t final_digest[16];
        
    memset(str_digest, '\0', 33);

    // //////////////////////////////////// TODO: remove this when we get multihashing to work
    // MD5(message, final_digest);
    // for(int i = 0; i < MD5_SIZE/4; i++) //now we can convert to a string
    // {
    //     char temp[2];
    //     sprintf(temp, "%2.2x", final_digest[i]);
    //     str_digest[i*2] = temp[0];
    //     str_digest[(i*2)+1] = temp[1];
    // }
    // ///////////////////////////////////

    for(int j = 1; j <= passes; j++)
    {
        MD5(message, final_digest);

        for(int i = 0; i < MD5_SIZE/4; i++) //now we can convert to a string
        {
            char temp[2];
            sprintf(temp, "%2.2x", final_digest[i]);
            str_digest[i*2] = temp[0];
            str_digest[(i*2)+1] = temp[1];
        }
        free(message);
        if(j < passes) //if this is the "last" loop, then let's keep our info so we can give it to the user
        {
            message = malloc(33);
            memset(message, '\0', 33);
            memcpy(message, str_digest, 33);
            memset(final_digest, 0, 16);

            memset(str_digest, '\0', 33); 
        }
        
        
    }

    printf("%s \n", str_digest);
    getchar(); 
    getchar();     
    return 0;
}