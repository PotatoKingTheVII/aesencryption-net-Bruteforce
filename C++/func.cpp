#include "func.h"

//Get number of wordlist lines
unsigned int wordlist_length(string wordlist_name)
{
    ifstream wordlist_file;
    wordlist_file.open(wordlist_name);
    //File sanity check
    if (!wordlist_file.is_open())
    {
        perror("Error opening wordlist file");
        exit(EXIT_FAILURE);
    }

    //Load line by line
    unsigned int line_count = 0;
    string line;
    while (getline(wordlist_file, line))
    {
        line_count++;
    }

    wordlist_file.close();

    return line_count;
}

//Decode base64 to unsigned char with openssl functions
unsigned char* decode64(const char* input) {
    unsigned int length = strlen(input);
    const auto pl = 3 * length / 4; //may allocate a few extra unused bytes depending on padding
    auto output = reinterpret_cast<unsigned char*>(calloc(pl + 1, 1));
    const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char*>(input), length);
    if (pl != ol) { std::cerr << "Whoops, decode predicted " << pl << " but we got " << ol << "\n"; }
    return output;
}

//OpenSSL error handler - debug only
void handleErrors(void)
{
    //ERR_print_errors_fp(stderr);
    //std::cout << "Error encountered\n";
    //abort();
}

//Decrypt AES into provided plaintext. mode 1,2,3 == 128, 192, 256
//Return plaintext length
int AES_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext, int& mode)
{
    int len;
    int plaintext_len;

    //Make cipher context
    EVP_CIPHER_CTX* ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    //Initialise relevant decryption mode
    if (mode == 1)
    {
        unsigned char keyn[16] = { 0 };
        memcpy(keyn, key, 16);

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyn, iv))
            handleErrors();
    }

    if (mode == 2)
    {
        unsigned char keyn[24] = { 0 };
        memcpy(keyn, key, 24);

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, keyn, iv))
            handleErrors();
    }

    if (mode == 3)
    {
        unsigned char keyn[32] = { 0 };
        memcpy(keyn, key, 32);

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyn, iv))
            handleErrors();
    }

    //Input ciphertext and do inital decryption round, writing to plaintext
    //Note that OpenSSL by default checks for the correct padding so we don't need to
    //EVP_CIPHER_CTX_set_padding(ctx, 0); //If we wanted to disable PKCS7 padding do it here
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);   //Error if we're here so free the context and return 0 length
        return 0;
    }
    plaintext_len = len;

    //Do final round for the end plaintext
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);   //Error if we're here so free the context and return 0 length
        return 0;
    }
    plaintext_len += len;

    //Clear the context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

//For entropy
double log2a(double number)
{
    return log(number) / log(2);
}

//Return entropy of string input
double entropy_calc(string& data)
{
    map<char, int> frequencies;
    for (char c : data)
    {
        frequencies[c] ++;
    }

    int numlen = data.length();
    double entropy = 0;
    for (pair<char, int> p : frequencies)
    {
        double freq = static_cast<double>(p.second) / numlen;
        entropy -= freq * log2a(freq);
    }

    return entropy;
}

//Decode given section of wordlist as a worker thread. Returns a tuple of best key and corresponding plaintext with entropy
void AESdecodeList(promise<tuple<string, string, double>> p, unsigned char* enc_data, int enc_data_length, int mode, string wordlist_name, unsigned int index_start, unsigned int index_span)
{
    unsigned char* iv = (unsigned char*)"12345678b0z2345n";

    //Set up framework to hold best results and then loop through the wordlist and record them
    double best_entropy = 1e10;
    tuple<string, string, double> results_list = make_tuple("N/A", "N/A", 1e10); // Will hold the final results. Plaintext, entropy and key used

    //Load file
    ifstream wordlist_file;
    wordlist_file.open(wordlist_name);
    //File sanity check
    if (!wordlist_file.is_open())
    {
        perror("Error opening wordlist file");
        exit(EXIT_FAILURE);
    }

    string line;
    unsigned int wordlist_index = 0;
    while (getline(wordlist_file, line))    //Read wordlist one line at a time instead of all at once to save memory
    {
        //Before we start get to the correct starting position for the thread
        if (wordlist_index < index_start)
        {
            wordlist_index++;
            continue;
        }

        //Also check if we're at the end of our span
        if (wordlist_index == index_start + index_span)
        {
            wordlist_file.close();
            break;
        }

        //Otherwise we're within the wordlist limit so decrypt normally:
        string current_key = line;
        unsigned char key[32] = { 0, 0, 0, 0, 0, 0, 0 ,0 ,0 ,0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0 ,0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0, 0, 0 };
        //Longest key mode will be 32, padded with 0 bytes if not long enough

        //Check for buffer overflow and copy c_str version of our word into the key. This pads it and converts to unsigned char *
        if (current_key.length() > 32)
        {
            memcpy(key, current_key.c_str(), 32);
        }
        else
        {
            memcpy(key, current_key.c_str(), current_key.length());
        }

        //Do the actual decryption
        int decryptedtext_len;
        unsigned char* plaintext = new unsigned char[enc_data_length](); //() initalises to 0
        decryptedtext_len = AES_decrypt(enc_data, enc_data_length, key, iv, plaintext, mode);  //Sets plaintext variable with result

        //Check if the result was valid
        if (decryptedtext_len != 0) //If the decrypt was sucessful
        {
            //Convert back to C++ strings for ease and calculate entropy
            string plaintext_string(plaintext, plaintext + enc_data_length); //We'll cout it later so easier instead of unsigned char to avoid a copy
            double current_entropy = entropy_calc(plaintext_string);

            //If this is the best result yet then keep track of it and se it as the new goal
            if (current_entropy < best_entropy)
            {
                best_entropy = current_entropy;
                results_list = make_tuple(current_key, plaintext_string, current_entropy);
            }
        }

        delete[] plaintext;    //Clean up allocated plaintext
        wordlist_index++;
    }

    p.set_value(results_list);   //What we actually return via the promise
}
