
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <chrono>

using namespace std;
using namespace std::chrono;

void GenerateKey(int byte_length){

} // end GenerateKey

void GenerateIV(int byte_length){

} // end GenerateIV

void AES_Encrypt(char* iv, char* key, char* plaintext, int mode){

} // end AES_Encrypt

void AES_Decrypt(char* iv, char* key, char* ciphertext, int mode){

} // end DES_Decrypt




int main() {

	// How to Time
	auto start = high_resolution_clock::now();
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start);
	cout << duration.count() << endl;

} // end main
