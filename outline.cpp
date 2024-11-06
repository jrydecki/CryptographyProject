
#include <iostream>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <cstring>

using namespace std;

enum MODE {
  CBC = 1,
  OFB = 2,
  CTR = 3
};

void handle_error(){

} // end handle_error

int get_length(unsigned char *char_arr){
    // Get length of character array
} // end length

void GenerateAESKey(unsigned char* byte_length){
	// generate key for AES Modes
} // end GenerateKey

void GenerateAESIV(unsigned char* byte_length){
	// generate IV for AES Modes
} // end GenerateIV

void GenerateDESKey(unsigned char* byte_length){
	// generate key for DES Modes
} // end GenerateKey

void GenerateDESIV(unsigned char* byte_length){
	// generate IV for DES Modes
} // end GenerateIV

void AES_Encrypt(unsigned char* iv, unsigned char* key, unsigned char* plaintext, int mode){

    // AES key structure
    AES_KEY encryptKey, decryptKey;
    AES_set_encrypt_key(key, 256, &encryptKey);

    if (mode == CBC){
        for (int i = 0; i < get_length(plaintext); i++){

            // Calculate CBC Block To Encrypt
            unsigned char block[16];
            unsigned char ciphertext_block[16];
            AES_encrypt(block, ciphertext_block, &encryptKey);
        }
    }

    else if (mode == OFB){
        for (int i = 0; i < get_length(plaintext); i++){

            // Calculate OFB Block To Encrypt
            unsigned char block[16];
            unsigned char ciphertext_block[16];

            AES_encrypt(block, ciphertext_block, &encryptKey);
        }
    }


    else if (mode == CTR){
        for (int i = 0; i < get_length(plaintext); i++){

            // Calculate CTR Block To Encrypt
            unsigned char block[16];
            unsigned char ciphertext_block[16];

            AES_encrypt(block, ciphertext_block, &encryptKey);
        }
    }

    else{
        handle_error();
    }
	
	// for encrypting single block

} // end AES_Encrypt

void AES_Decrypt(unsigned char* iv, unsigned char* key, unsigned char* ciphertext, int mode){
    AES_KEY decryptKey;
    AES_set_decrypt_key(key, 256, &decryptKey);

	if (mode == CBC){
        for (int i = 0; i < get_length(ciphertext); i++){

            // Calculate CBC Block To Encrypt
            unsigned char block[16];
            unsigned char plaintext_block[16];
            AES_decrypt(block, plaintext_block, &decryptKey);
        }
    }

    else if (mode == OFB){
        for (int i = 0; i < get_length(ciphertext); i++){

            // Calculate OFB Block To Encrypt
            unsigned char block[16];
            unsigned char plaintext_block[16];

            AES_decrypt(block, plaintext_block, &decryptKey);
        }
    }


    else if (mode == CTR){
        for (int i = 0; i < get_length(ciphertext); i++){

            // Calculate CTR Block To Encrypt
            unsigned char block[16];
            unsigned char plaintext_block[16];

            AES_decrypt(block, plaintext_block, &decryptKey);
        }
    }

    else{
        handle_error();
    }

} // end AES_Decrypt

void DES_CBC_Encrypt(unsigned char* plaintext, unsigned char* ciphertext, int length, DES_cblock& key, DES_cblock& iv, int mode) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

	if (mode == CBC){
        for (int i = 0; i < get_length(ciphertext); i++){

            // Calculate CBC Block To Encrypt
            DES_LONG block[16];
            unsigned char plaintext_block[16];
            DES_encrypt1(block, &schedule, 1);
        }
    }

    else {
        handle_error();
    }

} // end of DES_Encrypt

void DES_CBC_Decrypt(unsigned char* ciphertext, unsigned char* plaintext, int length, DES_cblock& key, DES_cblock& iv, int mode) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);


    if (mode == CBC){
        for (int i = 0; i < get_length(ciphertext); i++){

            // Calculate CBC Block To Encrypt
            DES_LONG block[16];
            unsigned char plaintext_block[16];
            DES_encrypt1(block, &schedule, 0);
        }
    }

    else {
        handle_error();
    }
} // end of DES_Decrypt

// CTR and OFB modes for both AES and DES would similarly involve 
// setting up counter increments for CTR or feedback chaining for OFB, 
// but with the adjusted block size for DES (64-bit blocks).




int main() {
	// Test data
    unsigned char plaintext[64] = "Example plaintext for AES and DES in CBC, CTR, and OFB modes.";
    unsigned char ciphertext[64];
    unsigned char decryptedtext[64];

    // AES Key and IV
    unsigned char aes_key[32];  // AES-256 key (32 bytes)
    unsigned char aes_iv[16];   // AES IV (16 bytes)
    GenerateAESKey(aes_key);
    GenerateAESIV(aes_iv);

    // DES Key and IV
    DES_cblock des_key;
    DES_cblock des_iv;
    GenerateDESKey(des_key);
    GenerateDESIV(des_iv);

} // end main
