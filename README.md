## Summary
Scripts to bruteforce https://aesencryption.net/ encrypted data with multithreading support primarily using wordlists.

## File usage
User inputs can be found at the top of each file. Once supplied with a dictionary file and ciphertext it will run through all passwords writing the valid decryptions to a file sorted by their entropy with lowest first.


## Technical overview
The website uses AES-CBC with PKCS(5?) padding of a block size of 16 bytes on the plaintext. The password entered is directly the key with no key derivation used and is padded to the right with 00 bytes to the selected key length. If it's longer than the key length then the excess bytes are ignored. The current IV is "31 32 33 34 35 36 37 38 62 30 7a 32 33 34 35 6e" credit to [tryone144](https://gist.github.com/tryone144/db389557bc2ad45bba3522cd0f01cebb) who found the correct IV

**Finding the IV:**
Again, tryone144 originally found the IV I'm just detailing the method here for completeness.
AES uses 16 byte blocks with an IV of the same length so figuring out just one block will get the IV. Using ECB which can be used as a substitute of CBC but without the IV XOR function the IV can be found from the known plaintext, unknown IV and output of the initial AES keyround block.

![Overview of IV recovery](https://i.imgur.com/kWFOGiW.png)

At (1) we use the same ciphertexts, an output from the website ex. encoding "test" with the key "test" in 128 bit gives "66 87 bb 94 69 9b 37 05 4f 81 e2 57 34 67 a1 2e". The first "block cipher decryption" for each ECB/CBC method is identical so we decrypt this with ECB which uses no IV. Then at (2) this output is identical to the output of the CBC just after the decryption but before the IV XOR. At (3) we have the output of the decryption "45 57 40 40 39 3a 3b 34 6e 3c 76 3e 3f 38 39 62" and the plaintext "74 65 73 74 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C", XORing these gives the IV of "31 32 33 34 35 36 37 38 62 30 7a 32 33 34 35 6e".

**Verifying the possible plaintexts:**
As it's just normal CBC with no proper verification there will be many valid keys that decrypt the data. However, the PKCS5 padding can help cut down on these. Immediately just by checking the last byte of the decrypted text anything equal to 0 or >16 isn't valid padding and can be ruled out. Anything left can be further cut down by checking the rest of the padding makes sense i.e. if the last byte is 03 then check that all last 3 bytes are also 03. To be safe this is all the script does and it reduces false positives by about 9x. Technically only printable characters (and a few others) should be encoded by a user on the website allowing further checks but this only gives about a further 2x improvement and might miss some obscure non-printable data that has been encrypted.

**Sorting the results:**
Even after verifying the results there's usually about 10% of the initial wordlist that's still valid. To try and rank these and make possible plaintexts easier to identify they're sorted by their Shannon entropy. The actual valid plaintext will usually have the lowest entropy compared to all other possibilities. Otherwise the user will have to make educated guesses on the format and search through the results.


## Dependancies
 - numpy
 - pycryptodome
