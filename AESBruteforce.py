from multiprocessing import Pool
from Crypto.Cipher import AES
import base64 as b64
import numpy as np
import math

####USER INPUT####
threads = 6 #Set to about 2/3 of your actual threads
WordlistName = "dict.txt"
KeyLength = 128 #128, 192 or 256
Ciphertext = "SQ9BWMgqWBwXejGp7hfJ8xRUF7KFHmZbklNaI4ocojjxef89ePwlFAXUFl75Hsdi"
INiv = bytes.fromhex("31 32 33 34 35 36 37 38 62 30 7a 32 33 34 35 6e") #If IV has changed
##################


Ciphertext = b64.b64decode(Ciphertext)
####Entropy function
def range_bytes(): return range(256)
def ShannonEntropy(data, iterator=range_bytes):
    if not data:
        return 0
    entropy = 0
    for x in iterator():
        p_x = float(data.count(int(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


####Validate padding of decrypted data
def Validate(data):
    lastByte = int(data[-1])
    if(lastByte>16 or lastByte==0): #Not valid padding options
        return False

    #If last byte is N check N last bytes are also N
    for i in range(0,lastByte):
        if(int(data[-1-i])!=lastByte):
            return False
    return True


####For use with multiprocess, decrypts text with the given list of keys
def decryptComboList(keyList):
    fullList = []
    for keyPerm in keyList:
        password = str(keyPerm)[0:int(KeyLength/8)]
        INkey = (password.encode("utf-8").ljust(int(KeyLength/8),b"\x00"))[0:int(KeyLength/8)]
        cipher = AES.new(INkey, AES.MODE_CBC, iv=INiv)
        result = cipher.decrypt(Ciphertext)
        if(Validate(result)):
            fullList.append([result,password])

    return fullList


####For use with multiprocess, calculates entropy of given list of data
def CalculateEntropyList(dataList):
    entropySubArray = []
    for data in dataList:
        result = data[0]
        entropyCalc = ShannonEntropy(result, range_bytes)
        temp = [entropyCalc, result,data[1]]
        entropySubArray.append(temp)
    return entropySubArray

    

####Split a list up into chunkNum number of lists, seems to use far less memory than np.split
def splitChunks(arrayIn, chunkNum):
    fullArray = []
    chunkNum = (len(arrayIn)//threads)
    chunkSize = len(arrayIn)//chunkNum

    for i in range(0,chunkNum-1):
        start = i*chunkSize
        fullArray.append(arrayIn[start:start+chunkSize])

    fullArray.append(arrayIn[(chunkNum-1)*chunkSize::])
    return fullArray




#Only run this section if it's the main script running, not a sub-process from multiprocessing
if __name__ == '__main__':
    
    ###Key list start, replace with any kind of key_list to try other methods
    #Get the dictionary, format it and add it to a list of keys to try
    fin = open(WordlistName,"r")
    words = fin.readlines()
    key_list = []
    for word in words:
        key_list.append(word.strip())
    print("Wordlist length: ", len(key_list))
    ###Key list end


    #We split the list of combinations up into chunks for the number of processes we're using
    comboChunks = splitChunks(key_list,threads)
    with Pool(threads) as p:
        results = (p.map(decryptComboList, comboChunks))

    #Combine each thread's sublist results once they're finished
    allcombos = [item for sublist in results for item in sublist]
    print("Possible plaintexts: ",len(allcombos))
    print("Calculating entropy...")

    #Split results up again to calculate entropy with multiple threads
    comboChunks = splitChunks(allcombos,threads)
    with Pool(threads) as p:
        results = (p.map(CalculateEntropyList, comboChunks))

    #Combine each thread's sublist results once they're finished
    entropyArray = [item for sublist in results for item in sublist]
    entropyArray = sorted(entropyArray) #Sort so smallest is first, most likely to be valid


    #Write results to file in order of entropy
    with open("OrderedOutput.txt", "wb") as fout:
        for i in range(0,len(entropyArray)):
            entropyFormat = ((str(entropyArray[i][0])).ljust(4,"0"))[0:4]
            passFormat = entropyArray[i][2]
            fout.write(entropyFormat.encode("ascii"))
            fout.write(b"   ")
            fout.write(passFormat.encode("ascii"))
            fout.write(b"   ")
            fout.write(entropyArray[i][1])
            fout.write(b"\n")
    print("Dumped to file")


