#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

void handleErrors() {
    std::cerr << "An error occurred" << std::endl;
    exit(1);
}

int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    int len;
    int plaintext_len;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main() {
    // 256-bit key and a 128-bit IV
    unsigned char key[32];
    unsigned char iv[16];

    // Generate random key and IV (for demonstration purposes)
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        handleErrors();
    }

    const char *plaintext = "This is a secret message!";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    int decryptedtext_len, ciphertext_len;

    std::cout << "Plaintext: " << plaintext << std::endl;

    // Encrypt the plaintext
    ciphertext_len = aes_encrypt(reinterpret_cast<const unsigned char *>(plaintext), strlen(plaintext), key, iv, ciphertext);

    std::cout << "Ciphertext (in hex): ";
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    std::cout << std::endl;

    // Decrypt the ciphertext
    decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted string

    std::cout << "Decrypted text: " << decryptedtext << std::endl;

    return 0;
}

