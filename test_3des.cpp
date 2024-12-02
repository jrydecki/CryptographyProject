#include <iostream>
#include <cstring>
#include <fstream>
#include <chrono>

#include <openssl/des.h>
#include <openssl/rand.h>

using namespace std;



enum MODE {
    CBC = 1,
    OFB = 2,
    CTR = 3
};

void handle_error(){

}

void Custom_CBC_Encrypt(char* plaintext, int plaintext_len, char* ciphertext, unsigned char* key, unsigned char* iv){

} // end Custom_CBC_Encrypt

void Custom_CBC_Decrypt(char* ciphertext, int ciphertext_len, char* plaintext, unsigned char* key, unsigned char* iv){

} // end Custom_CBC_Decrypt

void Custom_OFB_Encrypt(char* plaintext, int plaintext_len, char* ciphertext, unsigned char* key, unsigned char* iv){

} // end Custom_OFB_Encrypt

void Custom_OFB_Decrypt(char* ciphertext, int ciphertext_len, char* plaintext, unsigned char* key, unsigned char* iv){

} // end Custom_OFB_Decrypt

void Custom_CTR_Encrypt(char* plaintext, int plaintext_len, char* ciphertext, unsigned char* key, unsigned char* iv){

} // end Custom_CTR_Encrypt

void Custom_CTR_Decrypt(char* ciphertext, int ciphertext_len, char* plaintext, unsigned char* key, unsigned char* iv){

} // end Custom_CTR_Decrypt


void Custom_Encrypt(char* plaintext, int plaintext_len, char* ciphertext, unsigned char* key, unsigned char* iv, int mode){
    if (mode == CBC)
        Custom_CBC_Encrypt(plaintext, plaintext_len, ciphertext, key, iv);

    else if (mode == OFB)
        Custom_OFB_Encrypt(plaintext, plaintext_len, ciphertext, key, iv);

    else if (mode == CTR)
        Custom_CTR_Encrypt(plaintext, plaintext_len, ciphertext, key, iv);

    else
        handle_error();

} // end Custom_Encrypt

void Custom_Decrypt(char* ciphertext, int ciphertext_len, char* plaintext, unsigned char* key, unsigned char* iv, int mode){
    if (mode == CBC)
        Custom_CBC_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);

    else if (mode == OFB)
        Custom_OFB_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);

    else if (mode == CTR)
        Custom_CTR_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);

    else
        handle_error();

} // end Custom_Decrypt

void OpenSSL_Encrypt(char* plaintext, int plaintext_len, char* ciphertext, unsigned char* key, unsigned char* iv, int mode){
    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
} // end OpenSSL_Encrypt

void OpenSSL_Decrypt(char* ciphertext, int ciphertext_len, char* plaintext, unsigned char* key, unsigned char* iv, int mode){
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
    ifstream iFile("data-1mb.bin", std::ios::binary | std::ios::ate);
    streamsize plaintext_len = iFile.tellg();
    int ciphertext_len = plaintext_len + EVP_CIPHER_block_size(EVP_des_ede3_cbc()); // This is the Max Length
    iFile.seekg(0, std::ios::beg);

    // Define Variables
    unsigned char key[24];
    unsigned char iv[8];
    char ciphertext[ciphertext_len];
    char plaintext[plaintext_len];

    // Read & Store Data/Message Length
    iFile.read(plaintext, plaintext_len);
    iFile.close();
    
    cout << "*** 3DES ***\n";

    /////////////////// OpenSSL ///////////////////
    cout << "OpenSSL\n";
    cout << "CBC:\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, CBC);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    OpenSSL_Decrypt(plaintext, plaintext_len, ciphertext, key, iv, CBC);
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
    OpenSSL_Decrypt(plaintext, plaintext_len, ciphertext, key, iv, OFB);
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
    OpenSSL_Decrypt(plaintext, plaintext_len, ciphertext, key, iv, CTR);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";
    cout << "\n";

    /////////////////// Custom ///////////////////
    cout << "Custom Modes\n";
    cout << "CBC\n";
    t1 = high_resolution_clock::now();
    Custom_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, CBC);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    Custom_Decrypt(plaintext, plaintext_len, ciphertext, key, iv, CBC);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "OFB\n";
    t1 = high_resolution_clock::now();
    Custom_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, OFB);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    Custom_Decrypt(plaintext, plaintext_len, ciphertext, key, iv, OFB);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "CTR\n";
    t1 = high_resolution_clock::now();
    Custom_Encrypt(plaintext, plaintext_len, ciphertext, key, iv, CTR);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tEncrypt: " << ms_double.count() << " ms\n";
    t1 = high_resolution_clock::now();
    Custom_Decrypt(plaintext, plaintext_len, ciphertext, key, iv, CTR);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "\tDecrypt: " << ms_double.count() << " ms\n";

    cout << "********************\n";



} // end main