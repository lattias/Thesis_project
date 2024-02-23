    
#include "openfhe.h"

#include <cstring>
#include <iostream>
#include <vector>
#include "openfhe.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"
#include "utils/debug.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

#include <filesystem>

#include "binfhe/binfhecontext.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"


using namespace lbcrypto;
using namespace std;
using namespace cereal;

using CT = lbcrypto::LWECiphertext;

using PT = lbcrypto::Plaintext ; //plaintext
using vecCT = vector<CT>; //vector of ciphertexts
using vecPT = vector<PT>; //vector of plaintexts
using vecInt = vector<int64_t>; // vector of ints
using vecChar = vector<char>; // vector of characters

int main(){

    int plaintextModulus = 65537;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetScalingModSize(60);
    CryptoContext<DCRTPoly> ccPoly = GenCryptoContext(parameters);
    
    ccPoly->Enable(PKE);
    ccPoly->Enable(KEYSWITCH);
    ccPoly->Enable(LEVELEDSHE);
    ccPoly->Enable(PRE);

    

    std::string reenc_homolog = "../reencrypted_homolog";
    std::string reenc_percentmatch_result = "../reenc_percentmatch_result";
    std::string reenc_pattern_index_result = "../reenc_pattern_index_result";
    std::string DATAFOLDER = "../bob_keys";
     
    
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> bob_private_key;

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", bob_private_key, SerType::BINARY)) {
        std::cerr << "Could not deserialize the public key" << std::endl;
        return 1;
    }

    //std::string reenc_pattern = "../reencrypted_pattern";

    Ciphertext<DCRTPoly> homolog_for_bob;
    if (!Serial::DeserializeFromFile(reenc_homolog + "ciphertxt.txt", homolog_for_bob, SerType::BINARY)) {
        std::cerr << "Error deserialization of reencrypted pattern" << std::endl;
        //return 1; 
    }

    PT dec;
    ccPoly->Decrypt(bob_private_key, homolog_for_bob, &dec);
    
    cout << "Homolog result is: \n";

    for (auto item : dec->GetPackedValue()){
        cout << (char)item;
        if (item == 0){
            break;
        }
    }

    // percentmatch result

    //std::string reenc_pattern = "../reencrypted_percentmatch_result";

    Ciphertext<DCRTPoly> percentmatch_result_for_bob;
    if (!Serial::DeserializeFromFile(reenc_percentmatch_result + "ciphertxt.txt", percentmatch_result_for_bob, SerType::BINARY)) {
        std::cerr << "Error deserialization of reencrypted percent match result" << std::endl;
        //return 1; 
    }

    PT dec2;
    ccPoly->Decrypt(bob_private_key, percentmatch_result_for_bob, &dec2);
    
    cout << "\nPercent match result is: \n";

    for (auto item : dec2->GetPackedValue()){
        if (item == 0){
            break;
        }
        cout << item;
        cout << "%\n";
    }

    // pattern index result
    Ciphertext<DCRTPoly> pattern_index_result_for_bob;
    if (!Serial::DeserializeFromFile(reenc_pattern_index_result + "ciphertxt.txt", pattern_index_result_for_bob, SerType::BINARY)) {
        std::cerr << "Error deserialization of pattern index result" << std::endl;
        //return 1; 
    }


    PT dec3;
    ccPoly->Decrypt(bob_private_key, pattern_index_result_for_bob, &dec3);
    
    cout << "\n Pattern is found at the following indexes: \n";

    for (auto item : dec3->GetPackedValue()){
        if (item == 0){
            break;
        }

        cout << "index: ";
        cout << (int) item - 1;
        cout << "\n";


    }
    return 1;
}