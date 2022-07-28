#include "func.h" //All functions

int main(int argc, char* argv[])
{
    //First parse the arguments:
    //Set placeholder user inputs to see if they're actually changed later
    string ciphertext = "PLACEHOLDER_CT";
    string wordlist_name = "PLACEHOLDER_WORDLIST";
    int thread_count = 1337;
    int mode = 1337;

    //Parse the arguments for actual inputs
    if (argc == 1)  //If no flags were given
    {
        cout << "\nERROR, correct usage:\n\n"
            "aesbrute.exe -w string -t integer -m integer -c string\n\n"
            "-w : wordlist filename\n"
            "-t : threadcount to use\n"
            "-m : AES mode (1 = 128, 2 = 192, 3 = 256)\n"
            "-c : ciphertext with correct padding\n";
    }

    //For each argument given
    for (int i = 1; i < argc; ++i)
    {
        string currentArg(argv[i]);
        string tmp_perm_int;

        //If the current argument is actually a flag
        if (currentArg[0] == '-')
        {
            string currentNextArg(argv[i + 1]);
            switch (currentArg[1])  //Check which flag
            {
            case 't':   //Set threads
                thread_count = (int)*(argv[i + 1]) - 48;  //(Ascii so -48 to get correct range)
                break;
            case 'c':   //Set ciphertext
                ciphertext = string(argv[i + 1]);
                break;

            case 'm':   //Set AES mode
                mode = (int)*(argv[i + 1]) - 48;
                break;

            case 'w':   //Set wordlist
                wordlist_name = string(argv[i + 1]);
                break;

            default:    //Input error
                cout << "\nERROR, correct usage:\n\n"
                    "aesbrute.exe -w string -t integer -m integer -c string\n\n"
                    "-w : wordlist filename\n"
                    "-t : threadcount to use\n"
                    "-m : AES mode (1 = 128, 2 = 192, 3 = 256)\n"
                    "-c : ciphertext with correct padding\n";

            }
        }
    }

    //Sanity check to make sure the user actually input all the needed values:
    if (ciphertext == "PLACEHOLDER_CT" || mode == 1337 || thread_count == 1337 || wordlist_name == "PLACEHOLDER_WORDLIST")
    {
        cout << "\n*Missing arguments*\n";
        return 1;
    }

    //Decode ciphertext - note the carried data will always be 16 byte aligned so we can assume length
    unsigned char* enc_data = decode64(ciphertext.c_str());
    int tmp_length = (ciphertext.length() / 4) * 3;
    int enc_data_length = ((tmp_length + 16 / 2) / 16) * 16;    //Rounds to nearest 16 which will always be rounding up

    //Multi-threading boilerplate
    vector<future<tuple<string, string, double>>> future_results;
    vector<thread> threadPool;

    //Calculate the starting index and span that each thread will have based on how many there are
    unsigned int wordlist_size = wordlist_length(wordlist_name);
    unsigned int chunk_size = wordlist_size / thread_count;
    unsigned int chunk_remainder = wordlist_size % thread_count;

    //For each thread we're going to use pass it the correct bounds to use
    for (int i = 0; i < thread_count; i++)
    {
        unsigned int index_start = i * chunk_size;
        unsigned int index_span = chunk_size;
    
        //But if this is the last thread then add the remainder to it
        if (i == thread_count - 1)
        {
            index_span = chunk_size + chunk_remainder;
        }

        //Keep track of the return promises
        promise<tuple<string, string, double>> promise;
        future_results.push_back(promise.get_future());

        //Create the thread, pass it its promise and keep track in the thread pool.
        threadPool.push_back(thread(AESdecodeList, move(promise), enc_data, enc_data_length, mode, wordlist_name, index_start, index_span));
    }

    //Actually join all threads
    for (int i = 0; i < thread_count; i++)
    {
        threadPool[i].join();
    }

    //Get results from all threads
    vector<tuple<string, string, double>> ordered_list;
    for (int i = 0; i < thread_count; i++)
    {
        tuple<string, string, double> b = future_results[i].get();
        ordered_list.push_back(b);
    }

    //Sort results list for best entropy to first entry
    sort(ordered_list.begin(), ordered_list.end(),
        [](const auto& i, const auto& j) { return get<2>(i) < get<2>(j); });

    //Output best result
    cout << "\nThe best key was: || " << get<0>(ordered_list[0]) << " || for a plaintext of:\n" << get<1>(ordered_list[0]) << "\n";

    return 0;
}
