#pragma once
#include <iostream> //cout
#include <string> //strings
#include <fstream> //file io
#include <vector> //Vector arrays
#include <stdlib.h>	//openssl b64 decoding function
#include <openssl/evp.h> //high level evp handler
#include <openssl/err.h> //openssl error outputs
#include <map> //for entropy
#include <thread> //multi-threading
#include <future> //multi-threading
#include <tuple> //for results to gather data together

using namespace std; //I'm sorry future me

//Return how long the wordlist is
unsigned int wordlist_length(string wordlist_name);

//Decode base64 to unsigned char with openssl functions
unsigned char* decode64(const char* input);

//Actual AES decrypt, mode defines key size and sets the plaintext input variable to the result
int AES_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext, int& mode);

//For entropy
double log2a(double number);

//Actual entropy function
double entropy_calc(string& data);

//AES Decrypt list with given bounds for multithreading
void AESdecodeList(promise<tuple<string, string, double>> p, unsigned char* enc_data, int enc_data_length, int mode, string wordlist_name, unsigned int index_start, unsigned int index_span);
