
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

//forward declarations
void pattern_match_enc_try2(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, BinFHEContext cc, CT **populate_me);

int deserialize_ciphertexts(vector<vecCT>& ct_genome, vector<vecCT>& ct_pattern, vector<vecCT>& ct_homo, vector<vecCT>& ct_percentmatch);

int populate_arrays_from_vector(vector<vecCT> ct_vector, CT **ct_array);

void true_false_found(vector<vecCT> enc_result, vector<vecCT> ct_pattern, CT &any_found_result, BinFHEContext cc, CT* array_to_return);

void true_false_helper(CT* input_array, CT &output_boolean, BinFHEContext cc, vector<vecCT> enc_result);

void true_false_index(CT* input_array, CT &output_boolean, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> enc_result);

void raw_match(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, BinFHEContext cc, int offset, CT** populate_me);

void precent_match(vector<vecCT> raw_match_enc_result, BinFHEContext cc, vecCT &result, CT* array);

void pattern_match_enc_homolog(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, BinFHEContext cc, CT **populate_me);

void precent_match_homolog(vector<vecCT> pattern_match_result, BinFHEContext cc, vecCT &result, vector<vecCT> ct_pattern, CT *array);

void any_found_result_function(CT &popluate_me, CT* input_array, vector<vecCT> enc_result, BinFHEContext cc);

//should be removed!
void percent_match_decrypt(vecCT percent_match_result, double &percent_match_value, LWEPrivateKey sk, BinFHEContext cc);
void get_the_homolog(vecCT percent_match_result_for_homolog, vector<char*> &get_the_homolog_result, vecChar pattern, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> ct_genome, vector<vecCT> ct_pattern);

mutex mv;

namespace fs = std::filesystem;
int main(){

    ////////////////////////////////////////////////////////////
    // Re-encryption Key Generation protocol 
    ////////////////////////////////////////////////////////////
    int plaintextModulus = 65537;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetScalingModSize(60);

    CryptoContext<DCRTPoly> ccPoly = GenCryptoContext(parameters);
    // Turn on features
    ccPoly->Enable(PKE);
    ccPoly->Enable(KEYSWITCH);
    ccPoly->Enable(LEVELEDSHE);
    ccPoly->Enable(PRE);


    // deserialize Bob's public key
    std::string DATAFOLDER = "../bob_keys";

    lbcrypto::PublicKey<lbcrypto::DCRTPoly> bob_public_key;

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", bob_public_key, SerType::BINARY)) {
        std::cerr << "Could not deserialize the public key" << std::endl;
        return 1;
    }

    //generate temporary key pair for alice
    KeyPair<DCRTPoly> alicePair;

    alicePair = ccPoly->KeyGen();
    if (!alicePair.good()) {
        std::cout << "Alice temporary Key generation failed!" << std::endl;
        return (false);
    }

    //generate a proxy re-encryption key using the temporary secret key and Bob's public key
    EvalKey<DCRTPoly> re_encryption_key;
    re_encryption_key = ccPoly->ReKeyGen(alicePair.secretKey, bob_public_key);

    ////////////////////////////////////////////////////////////
    // temporary decryption step
    ////////////////////////////////////////////////////////////


    //cross platform time reporting:
    TimeVar t;
    struct timeval start, end;
    long mtime, secs, usecs;

    std::string small_folder = "../serialized_genome_pattern_and_keys";
    BinFHEContext cc;
    if (Serial::DeserializeFromFile(small_folder + "/cryptoContext.txt", cc, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

// deserializing the refreshing and switching keys (for bootstrapping)

    RingGSWACCKey refreshKey;
    if (Serial::DeserializeFromFile(small_folder + "/refreshKey.txt", refreshKey, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the refresh key" << std::endl;
        return 1;
    }
    std::cout << "The refresh key has been deserialized." << std::endl;
    
    LWESwitchingKey ksKey;
    if (Serial::DeserializeFromFile(small_folder + "/ksKey.txt", ksKey, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the switching key" << std::endl;
        return 1;
    }
    cc.BTKeyLoad({refreshKey, ksKey});
    LWEPrivateKey sk;
    if (Serial::DeserializeFromFile(small_folder + "/sk1.txt", sk, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the secret key" << std::endl;
        return 1;
    }

   const std::string any_found_folder = "../ciphertext_result_true_false_found/tf_any_found_result.txt";
   LWECiphertext any_found_result;
   if (Serial::DeserializeFromFile(any_found_folder, any_found_result, SerType::BINARY) == false){
      std::cerr << "Could not derserialize ciphertext result for any found result" << std::endl;
      return 1;
   }
   std::cout << "Deserialzed the encrypted result of true false found" <<std::endl;
 

gettimeofday(&start, NULL);
TIC(t);
    LWEPlaintext the_decr; 
    cc.Decrypt(sk, any_found_result, &the_decr);
    std::cout << "\ndecrypt time one bit: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

    std::cout << "\nWas the pattern found (1 yes 0 no): " << the_decr << std::endl;
 
    //get the index of the pattern
    std::string pm_folder0 = "../ciphertext_result_true_false_index_array";

    vecCT row_0_pm;

    int length_of_sequence_pm = 0;
   std::string  path = pm_folder0;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence_pm--;
        }
        length_of_sequence_pm++;
    }

    for (int i = 0; i < length_of_sequence_pm; i++){
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder0 + "/tf_index_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext result" << std::endl;
            std::cerr << "true false found index " << i << std::endl;
            return 1;
        }
        row_0_pm.push_back(ct);
    }

   for (int i = 0; i < (int) row_0_pm.size(); i++){
      	LWEPlaintext pt;
	    cc.Decrypt(sk, row_0_pm[i], &pt);
        std::cout << pt <<std::endl;
        if(pt){
            std::cout << "pattern found at index " << i << std::endl;
        }
   }


	//get the percent match result (for large genome)
    //pattern: row zero
    std::string datafolder =  "../ciphertext_result_percent_match_large";

    int length_of_sequence = 0;
    path = datafolder;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence--;
        }
        length_of_sequence++;
    }

    vecCT row_0;

    for (int i = 0; i < length_of_sequence; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder + "/pm_result_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext result" << std::endl;
            std::cerr << "percent match result index " << i << std::endl;
            return 1;
        }
        row_0.push_back(ct);
    }



TIC(t);
     double percent_match_valuePM;
//     percent_match_decrypt(percent_match_resultPM, percent_match_valuePM, sk, cc);
     percent_match_decrypt(row_0, percent_match_valuePM, sk, cc);
     std::cout << "\npercent match PERCENT MATCHdecrypt time: "
                  << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
        std::cout << "\npercent match value result  = " << percent_match_valuePM << std::endl;
    

	//get the result of homolog search
    //pattern: row zero
    printf("hie");
    datafolder = "../ciphertext_result_wildcard_search";

    length_of_sequence = 0;
    path = datafolder;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence--;
        }
        length_of_sequence++;
    }

    vecCT row_1;
    // printf("size is here %d \n", length_of_sequence);
    // vecCT percent_match_result_for_homolog;
    // char* homo_array = new char[homo.size()];

    for (int i = 0; i < length_of_sequence; i++){
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder + "/wildcard_result_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "wildcard search result index " << i << std::endl;
            return 1;
        }
        row_1.push_back(ct);
    }


    vector<char*> get_the_homolog_result;
    vector<vecCT> ct_genome(0);
    vector<vecCT> ct_pattern;
    vector<vecCT> ct_percentmatch;
    vector<vecCT> ct_homo; //DONT USE THIS
    deserialize_ciphertexts(ct_genome, ct_pattern, ct_homo, ct_percentmatch);

    gettimeofday(&start, NULL);
TIC(t);
    vecChar thehomo = {'t','x','x'};

//    get_the_homolog(percent_match_result_for_homolog, get_the_homolog_result, thehomo, cc, sk, ct_genome, ct_homo, homo_array);

    
    get_the_homolog(row_1, get_the_homolog_result, thehomo, cc, sk, ct_genome, ct_homo);
    std::cout << "\nget the homolog time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
    //vector<vecChar> get_the_homolog_result;
    //get_the_homolog(percent_match_result_for_homolog, get_the_homolog_result, homo, cc, sk, ct_genome, ct_pattern);

    //printf("oy4\n");

    for(char* item : get_the_homolog_result){
        for (int i = 0; i < (int) thehomo.size(); i++){
            std::cout << item[i];
        }
        printf("\n");
    }
    
    ////////////////////////////////////////////////////////////
    // Re-encrypt using the temporary public key
    ////////////////////////////////////////////////////////////

    //homolog result
    vecInt vShorts;
    for (char* item: get_the_homolog_result){
        for (int i = 0; i < (int) thehomo.size(); i++){
            vShorts.push_back((int)(item[i]));
        }
    }

    PT packedplaintext = ccPoly->MakePackedPlaintext(vShorts);

    //temporary encryption with public key
    auto temp = ccPoly->Encrypt(alicePair.publicKey, packedplaintext);

    //re encrypt with re-enc key
    auto temp2 = ccPoly->ReEncrypt(temp, re_encryption_key);

    // serialize the result so Bob can decrypt it with his private key
    std::string reenc_homolog = "../reencrypted_homolog";

    if (!Serial::SerializeToFile(reenc_homolog + "/ciphertxt.txt", temp2, SerType::BINARY)) {
        std::cerr << "Error writing serialization of reencrypted homolog" << std::endl;
        //return 1; 
    }

    //precent match result
    vecInt vShorts2;
    vShorts2.push_back(percent_match_valuePM);
    

    PT packedplaintext2 = ccPoly->MakePackedPlaintext(vShorts2);

    //temporary encryption with public key
    // auto temp = ccPoly->Encrypt(alicePair.publicKey, packedplaintext2);

    //re encrypt with re-enc key
    auto temp_percentmatch_result = ccPoly->ReEncrypt(ccPoly->Encrypt(alicePair.publicKey, packedplaintext2), re_encryption_key);

    // serialize the result so Bob can decrypt it with his private key
    std::string reenc_percentmatch_result = "../reenc_percentmatch_result";

    if (!Serial::SerializeToFile(reenc_percentmatch_result + "/ciphertxt.txt", temp_percentmatch_result, SerType::BINARY)) {
        std::cerr << "Error writing serialization of reencrypted pattern result" << std::endl;
        //return 1; 
    }

    // pattern found result

    vecInt vShorts3;

    for (int i = 0; i < (int) row_0_pm.size(); i++){
      	LWEPlaintext pt;
	    cc.Decrypt(sk, row_0_pm[i], &pt);
        std::cout << pt <<std::endl;
        
        if(pt){
            // this allows us to identify if the pattern is at index 0 when we pack plantext for reenc
            vShorts3.push_back(i + 1);
            // std::cout << "pattern found at index " << i << std::endl;
        }
    }

    PT packedplaintext3 = ccPoly->MakePackedPlaintext(vShorts3);
    auto temp_patternfound_result = ccPoly->ReEncrypt(ccPoly->Encrypt(alicePair.publicKey, packedplaintext3), re_encryption_key);
    
    std::string reenc_pattern_index_result = "../reenc_pattern_index_result";
        if (!Serial::SerializeToFile(reenc_pattern_index_result + "/ciphertxt.txt", temp_patternfound_result, SerType::BINARY)) {
        std::cerr << "Error writing serialization of reencrypted pattern index result" << std::endl;
        //return 1; 
    }



    

    



    
    
    

    // //homolog re-encrypt
    // for (char* item: get_the_homolog_result){


    //     packedplaintext = ccPoly->MakePackedPlaintext(vShorts);

    //     //temporary encryption with public key
    //     auto temp = ccPoly->Encrypt(alicePair.publicKey, item);

    //     //re encrypt with re-enc key
    //      auto temp2 = ccPoly->ReEncrypt(temp, re_encryption_key);

    //      //check if decrypt works
    //     //bob's private key

    //      PT dec; 
    //      ccPoly->Decrypt(bob_private_key, temp2, &dec);
    //      cout << the_decr;


    // }


    return 0;

}

int populate_arrays_from_vector(vector<vecCT> ct_vector, CT **ct_array){
    int len = (int) ct_vector[0].size();
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < len; j++){
            ct_array[i][j] = ct_vector[i][j];
        }
    }
    return 1;
}
    
int deserialize_ciphertexts(vector<vecCT>& ct_genome, vector<vecCT>& ct_pattern, vector<vecCT>& ct_homo, vector<vecCT>& ct_percentmatch){
    
    const std::string small_folder = "../serialized_genome_pattern_and_keys";
    const std::string homo_folder = "../serialized_wildcard_data";
    const std::string pm_folder = "../serialized_percent_match_data";
    //DESERIALIZE THE ENCRYPTED PATTERN
    
    //pattern: row zero
    std::string datafolder = small_folder + "/pattern/zero";

    int length_of_sequence = 0;
    std::string path = datafolder;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence--;
        }
        length_of_sequence++;
    }

    //construct matrix for the sequence

    // vector<vecCT> ct_genome(0);
    // vector<vecCT> ct_pattern;
    // vector<vecCT> ct_homo;
    // vector<vecCT> ct_percentmatch;

    vecCT row_0;
    vecCT row_1;
    vecCT row_2;
    vecCT row_3;

    for (int i = 0; i < length_of_sequence; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern zero index " << i << std::endl;
            return 1;
        }
        row_0.push_back(ct);
    }

    std::string datafolder1 = small_folder + "/pattern/one";
        for (int i = 0; i < length_of_sequence; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder1 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern one index " << i << std::endl;
            return 1;
        }
        row_1.push_back(ct);
    }

    std::string datafolder2 = small_folder + "/pattern/two";
    for (int i = 0; i < length_of_sequence; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder2 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern two index " << i << std::endl;
            return 1;
        }
        row_2.push_back(ct);
    }

    std::string datafolder3 = small_folder + "/pattern/three";
    for (int i = 0; i < length_of_sequence; i++){
        //deserialize three
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder3 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern three index " << i << std::endl;
            return 1;
        }
        row_3.push_back(ct);
    }

    ct_pattern.push_back(row_0);
    ct_pattern.push_back(row_1);
    ct_pattern.push_back(row_2);
    ct_pattern.push_back(row_3);


    //DESERIALIZE THE ENCRYPTED GENOME
    vecCT row_0_genome;
    vecCT row_1_genome;
    vecCT row_2_genome;
    vecCT row_3_genome;

    std::string genome_folder0 = small_folder + "/text/zero";

    int length_of_sequence_genome = 0;
    path = genome_folder0;
    for (const auto & entry : fs::directory_iterator(path)){
        //std::cout << entry.path() << std::endl;
        //std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence_genome--;
        }
        length_of_sequence_genome++;
    }

    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder0 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome zero index " << i << std::endl;
            return 1;
        }
        row_0_genome.push_back(ct);
    }

    std::string genome_folder1 = small_folder + "/text/one";
    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder1 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome one index " << i << std::endl;
            return 1;
        }
        row_1_genome.push_back(ct);
    }

    std::string genome_folder2 = small_folder + "/text/two";
    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder2 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome two index " << i << std::endl;
            return 1;
        }
        row_2_genome.push_back(ct);
    }

    std::string genome_folder3 = small_folder + "/text/three";
    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize three
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder3 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome three index " << i << std::endl;
            return 1;
        }
        row_3_genome.push_back(ct);
    }

    ct_genome.push_back(row_0_genome);
    ct_genome.push_back(row_1_genome);
    ct_genome.push_back(row_2_genome);
    ct_genome.push_back(row_3_genome);

    //DESERIALIZE THE ENCRYPTED WILDCARD
    vecCT row_0_homo;
    vecCT row_1_homo;
    vecCT row_2_homo;
    vecCT row_3_homo;

    std::string homo_folder0 = homo_folder + "/pattern/zero";

    int length_of_sequence_homo = 0;
    path = homo_folder0;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence_homo--;
        }
        length_of_sequence_homo++;
    }

    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder0 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo zero index " << i << std::endl;
            return 1;
        }
        row_0_homo.push_back(ct);
    }

    std::string homo_folder1 = homo_folder + "/pattern/one";
    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder1 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo one index " << i << std::endl;
            return 1;
        }
        row_1_homo.push_back(ct);
    }

    std::string homo_folder2 = homo_folder + "/pattern/two";
    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder2 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo two index " << i << std::endl;
            return 1;
        }
        row_2_homo.push_back(ct);
    }

    std::string homo_folder3 = homo_folder + "/pattern/three";
    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder3 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo three index " << i << std::endl;
            return 1;
        }
        row_3_homo.push_back(ct);
    }

    ct_homo.push_back(row_0_homo);
    ct_homo.push_back(row_1_homo);
    ct_homo.push_back(row_2_homo);
    ct_homo.push_back(row_3_homo);

    //DESERIALIZE THE ENCRYPTED PERCENT MATCH PATTERN
    vecCT row_0_pm;
    vecCT row_1_pm;
    vecCT row_2_pm;
    vecCT row_3_pm;

    std::string pm_folder0 = pm_folder + "/pattern/zero";

    int length_of_sequence_pm = 0;
    path = pm_folder0;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence_pm--;
        }
        length_of_sequence_pm++;
    }

    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder0 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match zero index " << i << std::endl;
            return 1;
        }
        row_0_pm.push_back(ct);
    }

    std::string pm_folder1 = pm_folder + "/pattern/one";
    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder1 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match one index " << i << std::endl;
            return 1;
        }
        row_1_pm.push_back(ct);
    }

    std::string pm_folder2 = pm_folder + "/pattern/two";
    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder2 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match two index " << i << std::endl;
            return 1;
        }
        row_2_pm.push_back(ct);
    }

    std::string pm_folder3 = pm_folder + "/pattern/three";
    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize three
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder3 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match three index " << i << std::endl;
            return 1;
        }
        row_3_pm.push_back(ct);
    }

    ct_percentmatch.push_back(row_0_pm);
    ct_percentmatch.push_back(row_1_pm);
    ct_percentmatch.push_back(row_2_pm);
    ct_percentmatch.push_back(row_3_pm);

    return 1;

}

void pattern_match_enc_try2(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, BinFHEContext cc, CT **populate_me){

    //try rotation
    CT **tempg = new CT*[ct_genome[0].size()];
    for (int i = 0; i < (int) ct_genome[0].size(); i++){
        tempg[i] = new CT[4];
    }
    for(int i = 0; i < 4; i ++){
        for (int j = 0; j < (int) ct_genome[0].size(); j++){
            tempg[j][i] = ct_genome[i][j];
        }
    }

    CT **tempp = new CT*[ct_pattern[0].size()];
    for (int i = 0; i < (int) ct_pattern[0].size(); i++){
        tempp[i] = new CT[4];
    }

    for(int i = 0; i < 4; i ++){
        for (int j = 0; j < (int) ct_pattern[0].size(); j++){
            tempp[j][i] = ct_pattern[i][j];
        }
    }

#pragma omp parallel for collapse (2) 
    for (int i_genome = 0; i_genome < (int) (ct_genome[0].size() - ct_pattern[0].size() + 1); i_genome++){
        for (int row = 0; row < (int) ct_genome.size(); row++){ 

            CT aggregate = cc.EvalBinGate(XNOR, 
                                        tempp[0][row], 
                                        tempg[i_genome + 0][row]);  

            for (int i_pattern = 1; i_pattern < (int) ct_pattern[0].size(); i_pattern++){ 

                 aggregate = cc.EvalBinGate(AND, 
                                           aggregate,
                                           cc.EvalBinGate(XNOR, 
                                                          tempp[i_pattern][row], 
                                                          tempg[i_genome + i_pattern][row]));     
            }

            populate_me[i_genome][row] = aggregate;
            //aggregate = temp;
        }
    }

printf("success");
    return;
}   

void true_false_found(vector<vecCT> enc_result, vector<vecCT> ct_pattern, CT &any_found_result, BinFHEContext cc, CT* array_to_return){

    //CT *temp_array = new CT[enc_result[0].size()];
    //any_found_result = enc_result[0][0];

#pragma omp parallel for
    for (int i = 0; i < (int) enc_result[0].size(); i++){
        
        CT temp = enc_result[0][i];
        for (int j = 1; j < 4; j++){      
            temp = cc.EvalBinGate(AND, temp, enc_result[j][i]);
        }
        //any_found_result = cc.EvalBinGate(OR, any_found_result, temp);
        // LWEPlaintext t;
        // cc.Decrypt(sk, temp, &t);
        // std::cout <<t << std::endl;
        array_to_return[i] = temp;
    }

    return;
}

void true_false_helper(CT* input_array, CT &output_boolean, BinFHEContext cc, vector<vecCT> enc_result){

    output_boolean = input_array[0];
#pragma omp parallel for
    for (int i = 1; i < (int) enc_result[0].size(); i++){
        // LWEPlaintext t;
        // cc.Decrypt(sk, input_array[i], &t);
        // std::cout << t << std::endl;
        #pragma omp critical
        {
        output_boolean = cc.EvalBinGate(AND, output_boolean, input_array[i]);
        }
    }
    return;
}

void true_false_index(CT* input_array, CT &output_boolean, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> enc_result){
     for (int i = 0; i < (int) enc_result[0].size(); i++){
        LWEPlaintext t;
        cc.Decrypt(sk, input_array[i], &t);
        if (t){
            printf("INDEX is %d\n", i);
        }

        //lior remove
        std::cout << t << std::endl;
    }
    return;
}

void raw_match(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, BinFHEContext cc, int offset, CT** populate_me){
    //printf("entering raw match\n");
int len_genome = ct_genome[0].size();
int len_pattern = ct_pattern[0].size();
int rows = ct_genome.size();
int shorter_len;

if (len_genome + offset >= len_pattern){
    shorter_len = len_pattern;
    printf("first\n");
} else{
    shorter_len = len_genome;
    printf("second\n");
}

#pragma omp parallel for collapse (2)
    for (int i = offset; i < shorter_len + offset; i++){ //4 rows
        for (int row = 0; row < rows; row++){

            populate_me[row][i] = cc.EvalBinGate(XNOR, 
                                            ct_pattern[row][i - offset], 
                                            ct_genome[row][i]);
        }
    }
    return;
}

void precent_match(vector<vecCT> raw_match_enc_result, BinFHEContext cc, vecCT &result, CT* array){
    
    //printf("entering percent match\n");
    //printf("raw_match_enc_result[0].size() %lu\n", raw_match_enc_result[0].size() );

#pragma omp parallel for
    for (int i = 0; i < (int) raw_match_enc_result[0].size(); i++){

        array[i] = cc.EvalBinGate(AND, 
                                    raw_match_enc_result[0][i], 
                                    cc.EvalBinGate(AND, 
                                        raw_match_enc_result[1][i],
                                        cc.EvalBinGate(AND,
                                             raw_match_enc_result[2][i],
                                             raw_match_enc_result[3][i])));
                                             
        //rLIOR: it looks like saving off temp vars takes a lot of time
    }

    return;
}

void percent_match_decrypt(vecCT percent_match_result, double &percent_match_value, LWEPrivateKey sk, BinFHEContext cc){
    int total = 0;
    for (CT item : percent_match_result ){
        LWEPlaintext result;
        cc.Decrypt(sk, item, &result);
        total += result;
    }

    printf("total is %d", total);



    percent_match_value = ((double)total / (double) percent_match_result.size()) * 100;

    return;
}

void pattern_match_enc_homolog(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, BinFHEContext cc, CT **populate_me){

//lior fix this, should take in array of where wildcards are
std::string pattern = "txx";

    CT **tempg = new CT*[ct_genome[0].size()];
    for (int i = 0; i < (int) ct_genome[0].size(); i++){
        tempg[i] = new CT[4];
    }

    for(int i = 0; i < 4; i ++){
        for (int j = 0; j < (int) ct_genome[0].size(); j++){
            tempg[j][i] = ct_genome[i][j];
        }
    }

    CT **tempp = new CT*[ct_pattern[0].size()];
    for (int i = 0; i < (int) ct_pattern[0].size(); i++){
        tempp[i] = new CT[4];
    }

    for(int i = 0; i < 4; i ++){
        for (int j = 0; j < (int) ct_pattern[0].size(); j++){
            tempp[j][i] = ct_pattern[i][j];
        }
    }
    // end try rotation

    int num_wildcards = 0;
    for(int x = 0; x < (int) pattern.size(); x++){
        if (tolower(pattern[x]) == 'x'){
            num_wildcards++;
        }
    }

// CT temp_ct = cc.Encrypt(sk, 1);
// CT aggregate = temp_ct;
int found_wildcard = 0;

#pragma omp parallel for collapse(2) //this works
    for (int i_genome = 0; i_genome < (int) (ct_genome[0].size() - ct_pattern[0].size() + 1 - num_wildcards); i_genome++){ 

        for (int row = 0; row < 4; row++){

            CT aggregate = cc.EvalBinGate(XNOR, 
                                          tempp[0][row], 
                                          tempg[i_genome + 0][row]);

            for (int i_pattern = 0; i_pattern < (int) ct_pattern[0].size(); i_pattern++){ 

                if (tolower(pattern[i_pattern]) == 'x'){
                    found_wildcard += 1;
                }

                aggregate = cc.EvalBinGate(AND, 
                                           aggregate,
                                           cc.EvalBinGate(XNOR, 
                                                          tempp[i_pattern][row], 
                                                          tempg[i_genome + i_pattern + found_wildcard][row]));

            }

            populate_me[i_genome][row] = aggregate;
            // aggregate = temp_ct;
            found_wildcard = 0;
        }
    }

    return;
}

//LIOR SHOULD BE IN trusted
void get_the_homolog(vecCT percent_match_result_for_homolog, vector<char*> &get_the_homolog_result, vecChar pattern, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> ct_genome, vector<vecCT> ct_pattern){

    //printf("get the homolog\n");
    //printf("%lu\n", percent_match_result_for_homolog.size() );

// #pragma omp parallel for
    for (int i = 0; i < (int) percent_match_result_for_homolog.size(); i++){
        LWEPlaintext res;
        cc.Decrypt(sk, percent_match_result_for_homolog[i], &res);
        // printf("hello1\n");
        // printf("%lu", percent_match_result_for_homolog.size());

        if (res){ //i contains the start index of the match
            //vecChar homolog;
            char *homo = new char[pattern.size()];
            //char homo[pattern.size()];
            printf("ffhello!\n");
            for (int j = 0; j < (int) pattern.size(); j++){
                printf("hello!\n");

                LWEPlaintext res0;
                LWEPlaintext res1;
                LWEPlaintext res2;
                LWEPlaintext res3;
                cc.Decrypt(sk, ct_genome[0][i+j], &res0);
                cc.Decrypt(sk, ct_genome[1][i+j], &res1);
                cc.Decrypt(sk, ct_genome[2][i+j], &res2);
                cc.Decrypt(sk, ct_genome[3][i+j], &res3);  

                // cc.Decrypt(sk, ct_genome[0][i + j], &res0);
                // cc.Decrypt(sk, ct_genome[1][i + j], &res1);
                // cc.Decrypt(sk, ct_genome[2][i + j], &res2);
                // cc.Decrypt(sk, ct_genome[3][i + j], &res3);  

                if(res0){
                    homo[j] = 'a';
                }
                else if(res1){
                    homo[j] = 'c';
                }
                else if(res2){
                    homo[j] = 'g';
                }
                else{ //res3
                    homo[j] = 't';
                }
            }
            get_the_homolog_result.push_back(homo);
        }
    }
    return;
}

void precent_match_homolog(vector<vecCT> pattern_match_result, BinFHEContext cc, vecCT &result, vector<vecCT> ct_pattern, CT *array){
    
    //printf("entering percent match HOMOLOG\n");
    //printf("pattern_match_result[0].size() %lu\n", pattern_match_result[0].size() );

#pragma omp parallel for
    for (int i = 0; i < (int) pattern_match_result[0].size(); i++){

        // CT temp = cc.EvalBinGate(AND, pattern_match_result[0][i], pattern_match_result[1][i]);
        // temp = cc.EvalBinGate(AND, temp, pattern_match_result[1][i]);
        // temp = cc.EvalBinGate(AND, temp, pattern_match_result[2][i]);
        // temp = cc.EvalBinGate(AND, temp, pattern_match_result[3][i]);
        array[i] = cc.EvalBinGate(AND, 
                            pattern_match_result[0][i], 
                            cc.EvalBinGate(AND, 
                                pattern_match_result[1][i],
                                cc.EvalBinGate(AND,
                                        pattern_match_result[2][i],
                                        pattern_match_result[3][i])));

        //result.push_back(temp);
        // array[i] = temp;
    }

    return;
}

void any_found_result_function(CT &any_found_result, CT* input_array, vector<vecCT> enc_result, BinFHEContext cc){
    any_found_result = input_array[0];

#pragma omp parallel for
    for (int i = 1; i < (int) enc_result[0].size(); i++){
        
        #pragma omp critical
         any_found_result = cc.EvalBinGate(OR,any_found_result, input_array[i]);
    }
}
int deserialize_ciphertext_query_result(vector<vecCT>& ct_genome, vector<vecCT>& ct_pattern, vector<vecCT>& ct_homo, vector<vecCT>& ct_percentmatch){
    
    const std::string small_folder = "../ciphertext_result_percent_match_small";
    const std::string homo_folder = "../ciphertext_result_wildcard_search";
    const std::string pm_folder = "../ciphertext_result_percent_match+larger";

const std::string true_false_found = "../ciphertext_result_true_false_found";

const std::string true_false_index= "../ciphertext_result_true_false_index_array";
    //DESERIALIZE THE true false found
    
    //pattern: row zero
    std::string datafolder = small_folder + "/pattern/zero";

    int length_of_sequence = 0;
    std::string path = datafolder;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence--;
        }
        length_of_sequence++;
    }

    //construct matrix for the sequence

    // vector<vecCT> ct_genome(0);
    // vector<vecCT> ct_pattern;
    // vector<vecCT> ct_homo;
    // vector<vecCT> ct_percentmatch;

    vecCT row_0;
    vecCT row_1;
    vecCT row_2;
    vecCT row_3;

    for (int i = 0; i < length_of_sequence; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern zero index " << i << std::endl;
            return 1;
        }
        row_0.push_back(ct);
    }

    std::string datafolder1 = small_folder + "/pattern/one";
        for (int i = 0; i < length_of_sequence; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder1 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern one index " << i << std::endl;
            return 1;
        }
        row_1.push_back(ct);
    }

    std::string datafolder2 = small_folder + "/pattern/two";
    for (int i = 0; i < length_of_sequence; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder2 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern two index " << i << std::endl;
            return 1;
        }
        row_2.push_back(ct);
    }

    std::string datafolder3 = small_folder + "/pattern/three";
    for (int i = 0; i < length_of_sequence; i++){
        //deserialize three
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(datafolder3 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "pattern three index " << i << std::endl;
            return 1;
        }
        row_3.push_back(ct);
    }

    ct_pattern.push_back(row_0);
    ct_pattern.push_back(row_1);
    ct_pattern.push_back(row_2);
    ct_pattern.push_back(row_3);


    //DESERIALIZE THE ENCRYPTED GENOME
    vecCT row_0_genome;
    vecCT row_1_genome;
    vecCT row_2_genome;
    vecCT row_3_genome;

    std::string genome_folder0 = small_folder + "/text/zero";

    int length_of_sequence_genome = 0;
    path = genome_folder0;
    for (const auto & entry : fs::directory_iterator(path)){
        //std::cout << entry.path() << std::endl;
        //std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence_genome--;
        }
        length_of_sequence_genome++;
    }

    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder0 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome zero index " << i << std::endl;
            return 1;
        }
        row_0_genome.push_back(ct);
    }

    std::string genome_folder1 = small_folder + "/text/one";
    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder1 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome one index " << i << std::endl;
            return 1;
        }
        row_1_genome.push_back(ct);
    }

    std::string genome_folder2 = small_folder + "/text/two";
    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder2 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome two index " << i << std::endl;
            return 1;
        }
        row_2_genome.push_back(ct);
    }

    std::string genome_folder3 = small_folder + "/text/three";
    for (int i = 0; i < length_of_sequence_genome; i++){
        //deserialize three
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(genome_folder3 + "/text_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "genome three index " << i << std::endl;
            return 1;
        }
        row_3_genome.push_back(ct);
    }

    ct_genome.push_back(row_0_genome);
    ct_genome.push_back(row_1_genome);
    ct_genome.push_back(row_2_genome);
    ct_genome.push_back(row_3_genome);

    //DESERIALIZE THE ENCRYPTED WILDCARD
    vecCT row_0_homo;
    vecCT row_1_homo;
    vecCT row_2_homo;
    vecCT row_3_homo;

    std::string homo_folder0 = homo_folder + "/pattern/zero";

    int length_of_sequence_homo = 0;
    path = homo_folder0;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence_homo--;
        }
        length_of_sequence_homo++;
    }

    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder0 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo zero index " << i << std::endl;
            return 1;
        }
        row_0_homo.push_back(ct);
    }

    std::string homo_folder1 = homo_folder + "/pattern/one";
    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder1 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo one index " << i << std::endl;
            return 1;
        }
        row_1_homo.push_back(ct);
    }

    std::string homo_folder2 = homo_folder + "/pattern/two";
    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder2 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo two index " << i << std::endl;
            return 1;
        }
        row_2_homo.push_back(ct);
    }

    std::string homo_folder3 = homo_folder + "/pattern/three";
    for (int i = 0; i < length_of_sequence_homo; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(homo_folder3 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "homo three index " << i << std::endl;
            return 1;
        }
        row_3_homo.push_back(ct);
    }

    ct_homo.push_back(row_0_homo);
    ct_homo.push_back(row_1_homo);
    ct_homo.push_back(row_2_homo);
    ct_homo.push_back(row_3_homo);

    //DESERIALIZE THE ENCRYPTED PERCENT MATCH PATTERN
    vecCT row_0_pm;
    vecCT row_1_pm;
    vecCT row_2_pm;
    vecCT row_3_pm;

    std::string pm_folder0 = pm_folder + "/pattern/zero";

    int length_of_sequence_pm = 0;
    path = pm_folder0;
    for (const auto & entry : fs::directory_iterator(path)){
        // std::cout << entry.path() << std::endl;
        // std::cout << entry.path().filename() << std::endl;
        if (entry.path().filename() == ".DS_Store"){
            length_of_sequence_pm--;
        }
        length_of_sequence_pm++;
    }

    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize zero
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder0 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match zero index " << i << std::endl;
            return 1;
        }
        row_0_pm.push_back(ct);
    }

    std::string pm_folder1 = pm_folder + "/pattern/one";
    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize one
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder1 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match one index " << i << std::endl;
            return 1;
        }
        row_1_pm.push_back(ct);
    }

    std::string pm_folder2 = pm_folder + "/pattern/two";
    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize two
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder2 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match two index " << i << std::endl;
            return 1;
        }
        row_2_pm.push_back(ct);
    }

    std::string pm_folder3 = pm_folder + "/pattern/three";
    for (int i = 0; i < length_of_sequence_pm; i++){
        //deserialize three
        LWECiphertext ct;
        if (Serial::DeserializeFromFile(pm_folder3 + "/pat_enc_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the ciphertext" << std::endl;
            std::cerr << "percent_match three index " << i << std::endl;
            return 1;
        }
        row_3_pm.push_back(ct);
    }

    ct_percentmatch.push_back(row_0_pm);
    ct_percentmatch.push_back(row_1_pm);
    ct_percentmatch.push_back(row_2_pm);
    ct_percentmatch.push_back(row_3_pm);

    return 1;

}
