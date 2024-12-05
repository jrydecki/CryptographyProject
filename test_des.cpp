#include <iostream>
#include <cstring>
#include <fstream>
#include <chrono>

#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <cryptopp/modes.h>
#include <cryptopp/des.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

# define IV_LEN 8
# define BLOCK_LEN 8
# define KEY_LEN 8

using namespace std;

enum MODE {
    CBC = 1,
    OFB = 2,
    CTR = 3
};

/////////////////////////////
//// Debugging Functions ////
/////////////////////////////
void handle_error(string message){
    cout << message << "\n";
    exit(1);
}

// Prints a single character as its hex representation.
void printc(unsigned char c){
    cout << "0x" << std::hex << (int)c << "\n";
}

// Prints each char of an array as hex.
void printa(unsigned char* arr, int len){
    for (int i = 0; i < len; i++){
        cout << std::hex << (int)arr[i] << " ";
    }
    cout << "\n";
}

///////////////////////////
//// Utility Functions ////
///////////////////////////
void Copy_Array(unsigned char* out, unsigned char* in, int len){
    for (int i = 0; i < len; i++)
        out[i] = in[i];
} // end Copy_Array

void XOR(unsigned char* block1, unsigned char* block2, int len){
    for (int i = 0; i < len; i++)
        block1[i] = block1[i] ^ block2[i];
} // end XOR

///////////////////////////
//// Key/IV Functions ////
///////////////////////////
void Set_Key(unsigned char* key, int len){
    for (int i = 0; i < len; i++)
        key[i] = 'A';

} // end Set_Key

void Set_IV(unsigned char* iv, int len){
    for (int i = 0; i < len; i++)
        iv[i] = i;
} // end Set_IV

void Increment(unsigned char* ctr){
    // Assuming Little-Endian (Increment Right-Most Element)
    for (int i = IV_LEN-1; i >= 0; i--){
        ctr[i] += 1;
        if (ctr[i] != 0) // No overflow, we're good.
            return;
    }
} // end Increment

int Get_Needed_Padding(int plaintext_len, int block_size){
    int remainder = plaintext_len % block_size;
    if (remainder == 0)
        return 0;
    return block_size - remainder;
} // end Get_Needed_Padding

////////////////////////////////
//// Cryptography Functions ////
////////////////////////////////

void Encrypt_Block(unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* key){
    int out_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_des_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, BLOCK_LEN);
    EVP_CIPHER_CTX_free(ctx);
} // end Encrypt_Block

void Decrypt_Block(unsigned char* ciphertext, unsigned char* plaintext, unsigned char* key){
    int out_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handle_error("ctx Failed to Initialize.");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), nullptr, key, nullptr)){
        ERR_print_errors_fp(stderr);
        handle_error("DecryptInit Failed.");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, BLOCK_LEN))
        handle_error("DecryptUpdate Failed.");

    EVP_CIPHER_CTX_free(ctx);
} // end Decrypt_Block


void Custom_CBC_Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key, unsigned char* iv){

    int block_size = BLOCK_LEN; // Bytes
    int ciphertext_len = plaintext_len + Get_Needed_Padding(plaintext_len, block_size);
    int blocks = ciphertext_len / block_size;
    int n = 1;

    // First Block with IV: C_1 = E(P_1 XOR IV)
    XOR(plaintext, iv, block_size);
    Encrypt_Block(plaintext, ciphertext, key);
    
    // Subsequent Blocks: C_n = E(P_n XOR C_{n-1})
    for (n = 2; n <= blocks; n++){
        int start = (n-1) * block_size;
        XOR(&plaintext[start], &ciphertext[start-block_size], block_size);
        Encrypt_Block(&plaintext[start], &ciphertext[start], key);
    }

} // end Custom_CBC_Encrypt

void Custom_CBC_Decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key, unsigned char* iv){

    int block_size = BLOCK_LEN; // Bytes
    int blocks = ciphertext_len / block_size;
    int n = 1;

    // First Block with IV: P_1 = D(C_1) XOR IV
    Decrypt_Block(ciphertext, plaintext, key);
    XOR(plaintext, iv, block_size);

    // Subsequent Blocks: P_n = D(C_n) XOR C_{n-1}
    for (n = 2; n <= blocks; n++){
        int start = (n-1) * block_size;
        Decrypt_Block(&ciphertext[start], &plaintext[start], key);
        XOR(&plaintext[start], &ciphertext[start-block_size], block_size);
    }

} // end Custom_CBC_Decrypt

void Custom_OFB_Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key, unsigned char* iv){

    int block_size = BLOCK_LEN; // Bytes
    int ciphertext_len = plaintext_len + Get_Needed_Padding(plaintext_len, block_size);
    int blocks = ciphertext_len / block_size;
    int n = 1;
    unsigned char nonce[IV_LEN];
    Copy_Array(nonce, iv, IV_LEN);

    // C_n = E^n(IV) XOR P_n 
    for (n = 1; n <= blocks; n++){
        int start = (n-1) * block_size;
        Encrypt_Block(nonce, nonce, key);
        Copy_Array(&ciphertext[start], nonce, block_size);
        XOR(&ciphertext[start], &plaintext[start], block_size);
    }

} // end Custom_OFB_Encrypt

void Custom_OFB_Decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key, unsigned char* iv){

    int block_size = BLOCK_LEN; // Bytes
    int blocks = ciphertext_len / block_size;
    int n = 1;
    unsigned char nonce[IV_LEN];
    Copy_Array(nonce, iv, IV_LEN);

    // P_n = C_n XOR E^n(IV)
    for (n = 1; n <= blocks; n++){
        int start = (n-1) * block_size;
        Encrypt_Block(nonce, nonce, key);
        Copy_Array(&plaintext[start], nonce, block_size);
        XOR(&plaintext[start], &ciphertext[start], block_size);
    }

} // end Custom_OFB_Decrypt

void Custom_CTR_Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key, unsigned char* iv){

    int block_size = BLOCK_LEN; // Bytes
    int ciphertext_len = plaintext_len + Get_Needed_Padding(plaintext_len, block_size);
    int blocks = ciphertext_len / block_size;
    int n = 1;
    unsigned char ctr[IV_LEN];
    Copy_Array(ctr, iv, IV_LEN);

    // C_n = E(IV+n) XOR P_n  
    for (n = 1; n <= blocks; n++){
        int start = (n-1) * block_size;
        Increment(ctr);
        Encrypt_Block(ctr, &ciphertext[start], key);
        XOR(&ciphertext[start], &plaintext[start], block_size);
    }

} // end Custom_CTR_Encrypt

void Custom_CTR_Decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key, unsigned char* iv){

    int block_size = BLOCK_LEN; // Bytes
    int blocks = ciphertext_len / block_size;
    int n = 1;
    unsigned char ctr[IV_LEN];
    Copy_Array(ctr, iv, IV_LEN);

    // P_n = E(IV+n) XOR C_n 
    for (n = 1; n <= blocks; n++){
        int start = (n-1) * block_size;
        Increment(ctr);
        Encrypt_Block(ctr, &plaintext[start], key);
        XOR(&plaintext[start], &ciphertext[start], block_size);
    }

} // end Custom_CTR_Decrypt


void Custom_Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key, unsigned char* iv, int mode){
    if (mode == CBC)
        Custom_CBC_Encrypt(plaintext, plaintext_len, ciphertext, key, iv);

    else if (mode == OFB)
        Custom_OFB_Encrypt(plaintext, plaintext_len, ciphertext, key, iv);

    else if (mode == CTR)
        Custom_CTR_Encrypt(plaintext, plaintext_len, ciphertext, key, iv);

    else
        handle_error("Unknown Encryption Mode.");

} // end Custom_Encrypt

void Custom_Decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key, unsigned char* iv, int mode){
    if (mode == CBC)
        Custom_CBC_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);

    else if (mode == OFB)
        Custom_OFB_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);

    else if (mode == CTR)
        Custom_CTR_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);

    else
        handle_error("Unknown Decryption Mode.");

} // end Custom_Decrypt

void OpenSSL_Encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* key, unsigned char* iv, int mode){
    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
} // end OpenSSL_Encrypt

void OpenSSL_Decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* plaintext, unsigned char* key, unsigned char* iv, int mode){
    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
} // end OpenSSL_Decrypt



int main() {

    // Clock Usage -- https://stackoverflow.com/a/22387757
    using std::chrono::high_resolution_clock;
    using std::chrono::duration_cast;
    using std::chrono::duration;
    using std::chrono::milliseconds;
    auto t1 = high_resolution_clock::now();
    auto t2 = high_resolution_clock::now();
    duration<double, std::milli> ms_double;

    // Open Data/Message File
    ifstream iFile("test.txt", std::ios::binary | std::ios::ate);
    if (!iFile) {
        handle_error("Could not open file.");
    }
    streamsize plaintext_len = iFile.tellg();
    iFile.seekg(0, std::ios::beg);

    // Define Variables
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    int ciphertext_len = plaintext_len + Get_Needed_Padding(plaintext_len, block_size);
    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    unsigned char ciphertext[ciphertext_len];
    unsigned char plaintext[plaintext_len];
    Set_Key(key, KEY_LEN);
    Set_IV(iv, IV_LEN);
    

    // Read & Store Data/Message Length
    iFile.read(reinterpret_cast<char*>(plaintext), plaintext_len);
    iFile.close();
    
    cout << "*** DES ***\n";

    /////////////////// OpenSSL ///////////////////
    cout << "OpenSSL\n";
    cout << "CBC:\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, CBC);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv, CBC);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "OFB:\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, OFB);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv, OFB);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "CTR:\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, CTR);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv, CTR);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";
    cout << "\n";

    /////////////////// Custom ///////////////////
    cout << "Custom Modes\n";
    cout << "CBC:\n";
    t1 = high_resolution_clock::now();
    Custom_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, CBC);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    Custom_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv, CBC);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "OFB:\n";
    t1 = high_resolution_clock::now();
    Custom_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, OFB);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    Custom_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv, OFB);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "CTR:\n";
    t1 = high_resolution_clock::now();
    Custom_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, CTR);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    Custom_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv, CTR);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "********************\n";



} // end main
