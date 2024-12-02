#include <iostream>
#include <cstring>
#include <fstream>
#include <chrono>

#include <openssl/aes.h>
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

void Custom_Encrypt(char* plaintext, int plaintext_len, char* ciphertext, unsigned char* key, unsigned char* iv){

} // end Custom_Encrypt

void Custom_Decrypt(char* ciphertext, int ciphertext_len, char* plaintext, unsigned char* key, unsigned char* iv){

} // end Custom_Decrypt

void OpenSSL_Encrypt(char* plaintext, int plaintext_len, char* ciphertext, unsigned char* key, unsigned char* iv){
    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
} // end OpenSSL_Encrypt

void OpenSSL_Decrypt(char* ciphertext, int ciphertext_len, char* plaintext, unsigned char* key, unsigned char* iv){
    // https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
} // end OpenSSL_Decrypt



int main() {

    // Clock Usage -- https://stackoverflow.com/a/22387757
    using std::chrono::high_resolution_clock;
    using std::chrono::duration_cast;
    using std::chrono::duration;
    using std::chrono::milliseconds;

    // Open Data/Message File
    ifstream iFile("data-1mb.bin", std::ios::binary | std::ios::ate);
    streamsize plaintext_len = iFile.tellg();
    int ciphertext_len = plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()); // This is the Max Length
    iFile.seekg(0, std::ios::beg);

    // Define Variables
    unsigned char key[32];
    unsigned char iv[16];
    char ciphertext[ciphertext_len];
    char plaintext[plaintext_len];

    // Get Data/Message Length
    iFile.read(plaintext, plaintext_len);
    iFile.close();


    // OpenSSL Encryption
    auto t1 = high_resolution_clock::now();
    OpenSSL_Encrypt(plaintext, plaintext_len, ciphertext, key, iv);
    auto t2 = high_resolution_clock::now();
    duration<double, std::milli> ms_double = t2 - t1;
    cout << "OpenSSL Encryption: " << ms_double.count() << " ms\n";

    // OpenSSL Decryption
    t1 = high_resolution_clock::now();
    OpenSSL_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "OpenSSL Decryption: " << ms_double.count() << " ms\n";

    // Custom Encryption
    t1 = high_resolution_clock::now();
    Custom_Encrypt(ciphertext, ciphertext_len, plaintext, key, iv);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "Custom Encryption: " << ms_double.count() << " ms\n";


    // Custom Decryption
    t1 = high_resolution_clock::now();
    Custom_Decrypt(ciphertext, ciphertext_len, plaintext, key, iv);
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    cout << "Custom Decryption: " << ms_double.count() << " ms\n";



} // end main