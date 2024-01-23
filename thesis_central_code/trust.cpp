//0. includes and namespaces THIS IST HE ONE THAT WOKS

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

#include "binfhe/binfhecontext.h"


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
void get_input_from_term(vecChar& a);
uint32_t get_input_from_file(vecChar& a, string fname);
uint32_t read_from_file(vecChar& a, string fname);
void one_hot_encode(vecChar input, vector<vecInt>& output);
int find_pattern(vector<vecInt> larger_matrix, vector<vecInt> submatrix);
int find_pattern_four_rows(vector<vecInt> Ma, vector<vecInt> Su);
vecInt KMPSearch(vecInt pattern, vecInt txt);
void LPSArray(vecInt pattern, int M, int* lps);
vecInt KMPSearch_possible_locations(vecInt pattern, vecInt txt, vecInt possible_locations);
void serialize_keys_and_context(BinFHEContext cc, LWEPrivateKey sk, string DATAFOLDER, bool serialize);

void pattern_match_enc(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, CT **populate_me);

void true_false_found(vector<vecCT> enc_result, vector<vecCT> ct_pattern, CT &any_found_result, BinFHEContext cc, CT* array_to_return, LWEPrivateKey sk);

void raw_match(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, int offset, CT** populate_me, LWEPrivateKey sk);

void precent_match_homolog(vector<vecCT> raw_match_enc_result, BinFHEContext cc, vecCT &result, vecChar pattern, vector<vecCT> ct_pattern, CT* array);

void percent_match_decrypt(vecCT percent_match_result, double &percent_match_value, LWEPrivateKey sk, BinFHEContext cc);

void get_the_homolog(vecCT percent_match_result_for_homolog, vector<char*> &get_the_homolog_result, vecChar pattern, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> ct_genome, vector<vecCT> ct_patter, char *homo_char_array);

void precent_match(vector<vecCT> raw_match_enc_result, BinFHEContext cc, vecCT &result,CT* array);

void pattern_match_enc_homolog(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, vecChar pattern, CT **populate_me, LWEPrivateKey sk);

void encrypt_me_threaded_genome(vector<vecInt> one_hot_genome,  vector<vecInt> one_hot_pattern, BinFHEContext cc, vector<vecCT> &ct_genome, vector<vecCT> &ct_pattern, LWEPrivateKey sk, string DATAFOLDER, bool serialize, CT **cipher);

void encrypt_me_threaded_pattern(vector<vecInt> one_hot_genome,  vector<vecInt> one_hot_pattern, BinFHEContext cc, vector<vecCT> &ct_genome, vector<vecCT> &ct_pattern, LWEPrivateKey sk, string DATAFOLDER, bool serialize, CT **cipher);

void true_false_helper(CT* input_array, CT &output_boolean, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> enc_result);

void pattern_match_enc_try2(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, vecChar pattern, CT **populate_me, LWEPrivateKey sk);

void true_false_index(CT* input_array, CT &output_boolean, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> enc_result);

mutex mv;

int main(){

    vecChar genome;
    vecChar percentmatch;
    string infilename;
    vector<vecInt> one_hot_genome;
    vecChar pattern;
    vector<vecInt> one_hot_pattern;
    vector<vecInt> one_hot_homo;
    vector<vecInt> one_hot_percentmatch;

    vector<vecCT> ct_genome(0);
    vector<vecCT> ct_pattern;
    vector<vecCT> ct_homo;
    vector<vecCT> ct_percentmatch;
    TimeVar t;
    printf("lior");

    string percent_file_name = "/home/lra2135/openfhe-development/build/test_pattern_mid.txt";
    infilename = "/home/lra2135/openfhe-development/build/test_mid.txt";

    percent_file_name = "/Users/lior/Documents/research-bellovin/data/test_pattern_mid.txt";

    percent_file_name = "tiny_pattern.txt";
    infilename = "tiny_test.txt"; 

struct timeval start, end;
long mtime, secs, usecs;
gettimeofday(&start, NULL);
    bool serialize = true;

    read_from_file(genome, infilename);
    read_from_file(percentmatch, percent_file_name);

    one_hot_encode(genome, one_hot_genome);
    one_hot_encode(percentmatch, one_hot_percentmatch);

    //pattern = {'a','g','t'};
    pattern = {'a', 'a','a'};
    //pattern = {'a','g','c','g'};
    //vecChar homo = {'a','g','X','c','g', 'X'};
    vecChar homo = {'t','X','X'};


    //pattern = {'a','a','t','t'};
    //pattern = {'t','t','t','t','t','t','t','t','t','t','t','t'};
    printf("Transforming genome into a matrix via one-hot encoding\n");
    one_hot_encode(pattern, one_hot_pattern);
    one_hot_encode(homo, one_hot_homo);

    printf("print the one-hot encoding of the Percent Match pattern\n");
for(int i = 0; i < 4; i++){
    for (int j = 0; j < (int) one_hot_percentmatch[0].size(); j++){
        printf("%lld ", one_hot_percentmatch[i][j]);
    }
    printf("\n");
}

  /*  
    printf("I'm printing my genome:\n");

    for (vecInt item : one_hot_genome){
      for(int aa : item){
        printf("%d", aa);
      }
      printf("\n");
    }
    
    printf("\n\n");
    for (vecInt item : one_hot_pattern){
      for(int aa : item){
        printf("%d", aa);
      }
      printf("\n");
    }
*/ 
    printf("Using KMP Search to quickly search for the pattern within the genome in plaintext. The result will indicate if the pattern was or was not found to aid in debugging:\n");
    int result = find_pattern_four_rows(one_hot_genome, one_hot_pattern);
    if (result){
      printf("\n\nfound!\n");
    } else{
      printf("\n\nnot found\n");
    }

    printf("Creating binary context\n");

    //auto cc = BinFHEContext();
    BinFHEContext cc = BinFHEContext();



    cc.GenerateBinFHEContext(STD128); //default is GINX = cggi i think
    LWEPrivateKey sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto switchy_key = cc.GetSwitchKey();
    //const std::string small_folder = "/Users/lior/Documents/research-bellovin/code2/liors_project/serialized_data_small";
    const std::string small_folder = "../serialized_genome_pattern_and_keys";
    const std::string homo_folder = "../serialized_wildcard_data";
    const std::string pm_folder = "../serialized_percent_match_data";
    
    serialize_keys_and_context(cc, sk, small_folder, serialize);

    printf("Starting fully homomorphic encryption of the genome and the pattern (encoded in a one-hot matrix form) \n");

    //encrypt_me_threaded(one_hot_genome, one_hot_pattern, cc, ct_genome, ct_pattern, sk, small_folder, serialize);
    // CT (*)[4]temp_pattern = new CT[one_hot_pattern[0].size()][4];
    int pattern_len = one_hot_pattern[0].size();
    int genome_len = one_hot_genome[0].size();
    int homo_len = one_hot_homo[0].size();
    int percentmatch_len = one_hot_percentmatch[0].size();

    CT** temp_pattern = new CT*[4];
    for (int i = 0; i < 4; i++){
        temp_pattern[i] = new CT[pattern_len];
    }

    CT** temp_genome = new CT*[4];
    for (int i = 0; i < 4; i++){
        temp_genome[i] = new CT[genome_len];
    }

    CT** temp_homo = new CT*[4];
    for (int i = 0; i < 4; i++){
        temp_homo[i] = new CT[homo_len];
    }
    CT** temp_percentmatch = new CT*[4];
    for (int i = 0; i < 4; i++){
        temp_percentmatch[i] = new CT[percentmatch_len];
    }
    TIC(t);
    std::cout << "\ndoes work>>>>n time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
gettimeofday(&start, NULL);
TIC(t);
    encrypt_me_threaded_pattern(one_hot_genome, one_hot_pattern, cc, ct_genome, ct_pattern, sk, small_folder, serialize, temp_pattern);
    std::cout << "\nencrypt pattern time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

gettimeofday(&start, NULL);
TIC(t);
    encrypt_me_threaded_genome(one_hot_genome, one_hot_pattern, cc, ct_genome, ct_pattern, sk, small_folder, serialize, temp_genome);
    std::cout << "\nencrypt genome time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);


gettimeofday(&start, NULL);
TIC(t);
     encrypt_me_threaded_pattern(one_hot_genome, one_hot_homo, cc, ct_genome, ct_homo, sk, homo_folder, serialize, temp_homo);
    std::cout << "\nencrypt homolog time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

gettimeofday(&start, NULL);
TIC(t);
        encrypt_me_threaded_pattern(one_hot_genome, one_hot_percentmatch, cc, ct_genome, ct_percentmatch, sk, pm_folder, serialize, temp_percentmatch);
        std::cout << "\nencrypt percent match time: "
                  << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
    //populate the vectors
    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j< genome_len; j++ ){
            temp.push_back(temp_genome[i][j]);
        }
        ct_genome.push_back(temp);
    }

    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j< pattern_len; j++ ){
            temp.push_back(temp_pattern[i][j]);
        }
        ct_pattern.push_back(temp);
    }

    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j< homo_len; j++ ){
            temp.push_back(temp_homo[i][j]);
        }
        ct_homo.push_back(temp);
    }
    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j< percentmatch_len; j++ ){
            temp.push_back(temp_percentmatch[i][j]);
        }
        ct_percentmatch.push_back(temp);
    }


    vector<vecCT> enc_result;
    //printf("start pattern match\n");

    CT **populate_me = new CT*[genome_len-pattern_len+1];
    for (int i = 0; i < genome_len-pattern_len+1; i++){
        populate_me[i] = new CT[4];
    }

    std::cout << "Encryption is complete. The encrypted genome and encrypted pattern have been serizalized to:\n" 
    << small_folder 
    << "\nPlease pass only the encrypted substring pattern, encrypted homolog (wildcard) pattern, the encrypted percent match pattern, and the encrypted genome to the Untrusted Environment. Do not pass your symmetric secret key to anyone!\n" << std::endl;

    std::cout << "\nYou may now exit the Trusted Environment. To continue assesing the FlexFHE system, run the file \"pattern_search.exe\" in the Untrusted Environment\n." << std::endl;

    return 1;

   // LIOR DELETE BELOW
gettimeofday(&start, NULL);
TIC(t);
    //pattern_match_enc(ct_genome, ct_pattern, enc_result, one_hot_pattern, cc, populate_me); //this works
    pattern_match_enc_try2(ct_genome, ct_pattern, enc_result, one_hot_pattern, cc, pattern, populate_me,sk); //this works LIOR
    std::cout << "PATTERN MATCH match enc try2time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

   //printf("KRRRRRR\n");
   //printf("PRINTlior\n");
//  /*  
//    for (int i = 0; i < genome_len-pattern_len+1; i++){
//     for (int j = 0; j < 4; j++){
//         // std::cout << rot[i][j];
//         printf(" ");
//         LWEPlaintext t;
//         cc.Decrypt(sk, populate_me[i][j], &t);
//         std::cout << t << " ";
//     }
//     printf("\n");
//    }
// */ 
   //rotate
    CT **rot = new CT*[4];
    for (int i = 0; i < 4; i++){
        rot[i] = new CT[genome_len-pattern_len+1];
    }

   for (int i = 0; i < genome_len-pattern_len+1; i++){
    for (int j = 0; j < 4; j++){
        //printf("%d %i\n", j, i);
        
        rot[j][i] = populate_me[i][j];
    }
   }

// /*
// printf("PRINTliorsadddd\n");
//    for (int i = 0; i < 4; i++){
//     for (int j = 0; j < genome_len-pattern_len+1; j++){
//         // std::cout << rot[i][j];
//         printf(" ");
//         LWEPlaintext t;
//         cc.Decrypt(sk, rot[i][j], &t);
//         std::cout << t << " ";
//     }
//     printf("\n");
//    }
// */ 

    //populate vector
    
    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j < genome_len - pattern_len + 1; j++){
            temp.push_back(rot[i][j]);
        }
        enc_result.push_back(temp);
    }

   //printf("\ni'm here\n");
///* LIOR start
    CT any_found_result;
    CT *true_false_found_array = new CT[enc_result[0].size()];
gettimeofday(&start, NULL);
TIC(t);
    true_false_found(enc_result, ct_pattern, any_found_result, cc, true_false_found_array, sk); //this works, unthread currently
    std::cout << "\ntrue false found time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
	
gettimeofday(&start, NULL);	
TIC(t);
    true_false_helper(true_false_found_array,any_found_result,cc,sk, enc_result );
    std::cout << "\ntrue false helper time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

gettimeofday(&start, NULL);	
TIC(t);
    true_false_index(true_false_found_array,any_found_result,cc,sk, enc_result );
    std::cout << "\ntrue false index time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

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

    std::cout << "\n result of decrypt= " << the_decr << std::endl;

//*/ //LIOR END     
    //test raw match

    vector<vecCT> raw_match_enc_result;
    int offset = 0;
    CT ** raw_match_array = new CT*[4];
    for (int i = 0; i < 4; i++){
        //raw_match_array[i] = new CT[genome_len - pattern_len + 1 - offset];
        raw_match_array[i] = new CT[genome_len - offset];
    }
    vector<vecCT> raw_match_enc_resultPM;
    CT ** raw_match_arrayPM = new CT*[4];
    for (int i = 0; i < 4; i++){
        //raw_match_arrayPM[i] = new CT[genome_len - percentmatch_len + 1 - offset];
        raw_match_arrayPM[i] = new CT[genome_len - offset];
    }

//* lior remove small pattern match
gettimeofday(&start, NULL);
TIC(t);
    raw_match(ct_genome, ct_pattern, raw_match_enc_result, one_hot_pattern, cc, offset, raw_match_array,sk);
    std::cout << "\nraw match time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j < genome_len -offset; j++){
            if(raw_match_array[i][j] != nullptr){
                temp.push_back(raw_match_array[i][j]);
            }
        }
        raw_match_enc_result.push_back(temp);
    }
//*/ //lior end remove small pattern match

    gettimeofday(&start, NULL);
TIC(t);
        raw_match(ct_genome, ct_percentmatch, raw_match_enc_resultPM, one_hot_percentmatch, cc, offset, raw_match_arrayPM, sk);
        std::cout << "\nraw match PERCENT MATCH time: "
                  << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j < genome_len - offset; j++){
            if(raw_match_arrayPM[i][j] != nullptr){
                temp.push_back(raw_match_arrayPM[i][j]);
                LWEPlaintext t;
                cc.Decrypt(sk, raw_match_arrayPM[i][j], &t);
                std::cout << t << ' ';
            } else{
                printf("bad %d %d", i, j);
            }
        }
        printf("\n");
        raw_match_enc_resultPM.push_back(temp);
    }

    gettimeofday(&start, NULL);
    CT *percent_match_output_normal = new CT[raw_match_enc_result[0].size()];
TIC(t);
    vecCT percent_match_result;
    precent_match(raw_match_enc_result, cc, percent_match_result,percent_match_output_normal);
    std::cout << "\npercent match time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

    for (int i = 0; i < (int) raw_match_enc_result[0].size(); i++){
        percent_match_result.push_back(percent_match_output_normal[i]);
    }
    double percent_match_value_double;
    percent_match_decrypt(percent_match_result, percent_match_value_double, sk, cc);
    std::cout << "\npercent match small result   "<< percent_match_value_double << std::endl;

    gettimeofday(&start, NULL);
    CT *percent_match_PM_output = new CT[raw_match_enc_resultPM[0].size()];
TIC(t);
        vecCT percent_match_resultPM;
        precent_match(raw_match_enc_resultPM, cc, percent_match_resultPM, percent_match_PM_output);
        std::cout << "\npercent match PERCENT MATCHtime: "
                  << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

    gettimeofday(&start, NULL);

    for (int i = 0; i < (int) raw_match_enc_resultPM[0].size(); i++){
        percent_match_resultPM.push_back(percent_match_PM_output[i]);
    }
/* lior start1    
TIC(t);
    double percent_match_value;
    percent_match_decrypt(percent_match_result, percent_match_value, sk, cc);
    std::cout << "\npercent match decrypt time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

    std::cout << "\npercent match value result  = " << percent_match_value << std::endl;
    gettimeofday(&start, NULL);
*/ //lior end 1
TIC(t);
        double percent_match_valuePM;
        percent_match_decrypt(percent_match_resultPM, percent_match_valuePM, sk, cc);
        std::cout << "\npercent match PERCENT MATCHdecrypt time: "
                  << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
        std::cout << "\npercent match value result  = " << percent_match_valuePM << std::endl;
    

    int num_wildcards = 0;
    for(int x = 0; x < (int) homo.size(); x++){
        if (tolower(homo[x]) == 'x'){
            num_wildcards++;
        }
    }
    CT **pattern_match_array = new CT*[genome_len- homo_len+1 - num_wildcards];
    for (int i = 0; i < genome_len- homo_len+1- num_wildcards; i++){
        pattern_match_array[i] = new CT[4];
    }

    gettimeofday(&start, NULL);
TIC(t);
    vector<vecCT> pattern_match_enc_result_homo;
    pattern_match_enc_homolog(ct_genome, ct_homo, pattern_match_enc_result_homo, one_hot_homo, cc, homo, pattern_match_array,sk);
    std::cout << "\npattern match enc homolog time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
    
    //printf("\nenter roate\n");

    //rotate
    CT **rot2 = new CT*[4];
    for (int i = 0; i < 4; i++){
        rot2[i] = new CT[genome_len- homo_len+1-num_wildcards];
    }

    for (int i = 0; i < genome_len- homo_len+1-num_wildcards; i++){
        for (int j = 0; j < 4; j++){
            rot2[j][i] = pattern_match_array[i][j];
        }
    }
    //populate vector
    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j < genome_len - homo_len + 1 - num_wildcards; j++){
            temp.push_back(rot2[i][j]);
        }
        pattern_match_enc_result_homo.push_back(temp);
    }

    CT* percent_match_homo_array = new CT[genome_len - homo_len + 1 - num_wildcards];

    gettimeofday(&start, NULL);
TIC(t);
    vecCT percent_match_result_for_homolog;
    precent_match_homolog(pattern_match_enc_result_homo, cc, percent_match_result_for_homolog, homo, ct_homo, percent_match_homo_array);
    std::cout << "\npercent match homolog time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);
    
    //populate the vector
    for (int i = 0; i < genome_len - homo_len + 1 - num_wildcards; i++){
        percent_match_result_for_homolog.push_back(percent_match_homo_array[i]);
    }

    //printf("oy3\n");

    vector<char*> get_the_homolog_result;
    char* homo_array = new char[homo.size()];

    gettimeofday(&start, NULL);
TIC(t);
    get_the_homolog(percent_match_result_for_homolog, get_the_homolog_result, homo, cc, sk, ct_genome, ct_homo, homo_array);
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
        for (int i = 0; i < (int) homo.size(); i++){
            std::cout << item[i];
        }
        printf("\n");
    }
    
    return 0;

}

void pattern_match_enc_homolog(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, vecChar pattern, CT **populate_me, LWEPrivateKey sk){

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

void true_false_index(CT* input_array, CT &output_boolean, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> enc_result){
     for (int i = 0; i < (int) enc_result[0].size(); i++){
        LWEPlaintext t;
        cc.Decrypt(sk, input_array[i], &t);
        if (t){
            printf("INDEX is %d\n", i);
        }
    }
    return;
}
void true_false_helper(CT* input_array, CT &output_boolean, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> enc_result){

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

void get_the_homolog(vecCT percent_match_result_for_homolog, vector<char*> &get_the_homolog_result, vecChar pattern, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> ct_genome, vector<vecCT> ct_pattern, char* homo_array2){

    //printf("get the homolog\n");
    //printf("%lu\n", percent_match_result_for_homolog.size() );

#pragma omp parallel for
    for (int i = 0; i < (int) percent_match_result_for_homolog.size(); i++){
        LWEPlaintext res;
        cc.Decrypt(sk, percent_match_result_for_homolog[i], &res);
        //printf("hello1\n");

        if (res){ //i contains the start index of the match
            //vecChar homolog;
            char *homo = new char[pattern.size()];
            //char homo[pattern.size()];
            for (int j = 0; j < (int) pattern.size(); j++){
                //printf("hello\n");

                LWEPlaintext res0;
                LWEPlaintext res1;
                LWEPlaintext res2;
                LWEPlaintext res3;

                cc.Decrypt(sk, ct_genome[0][i + j], &res0);
                cc.Decrypt(sk, ct_genome[1][i + j], &res1);
                cc.Decrypt(sk, ct_genome[2][i + j], &res2);
                cc.Decrypt(sk, ct_genome[3][i + j], &res3);  

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

void precent_match_homolog(vector<vecCT> pattern_match_result, BinFHEContext cc, vecCT &result, vecChar pattern, vector<vecCT> ct_pattern, CT *array){
    
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

void raw_match(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, int offset, CT** populate_me, LWEPrivateKey sk){
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

void true_false_found(vector<vecCT> enc_result, vector<vecCT> ct_pattern, CT &any_found_result, BinFHEContext cc, CT* array_to_return, LWEPrivateKey sk){

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

void pattern_match_enc_threaded(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc){

    printf("\nenter threaded pattern match for normal\n");

    


#pragma omp parallel for
    for (int row = 0; row < (int) ct_genome.size(); row++){ //4 rows

        vecCT aggregate_for_row;

        for (int i_genome = 0; i_genome < (int) (ct_genome[row].size() - ct_pattern[row].size() + 1); i_genome++){ //len of each row of genome
            
            printf("row, i_genome, i_pattern: , %d, %d, %d\n ", row, i_genome, 0);
            CT aggregate = cc.EvalBinGate(XNOR, 
                                          ct_pattern[row][0], 
                                          ct_genome[row][i_genome + 0]);

            for (int i_pattern = 1; i_pattern < (int) ct_pattern[row].size(); i_pattern++){ //len of the pattern
                printf("row, i_genome, i_pattern: , %d, %d, %d\n ", row, i_genome, i_pattern);
                //match up the pattern
                aggregate = cc.EvalBinGate(AND, 
                                           aggregate,
                                           cc.EvalBinGate(XNOR, 
                                                          ct_pattern[row][i_pattern], 
                                                          ct_genome[row][i_genome + i_pattern]));
            }
            aggregate_for_row.push_back(aggregate);

        }
        mv.lock();
        result.push_back(aggregate_for_row);
        mv.unlock();

    }

    return;
}

void pattern_match_enc(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, CT **populate_me){
    //printf("OU");
    //printf("hereee\n");
    //printf("%lu", ct_genome.size());

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

#pragma omp parallel for collapse(2)

    for (int i_genome = 0; i_genome < (int) (ct_genome[0].size() - ct_pattern[0].size() + 1); i_genome++){ 

        for (int row = 0; row < 4; row++){ //len of each row of genome
            
            CT aggregate = cc.EvalBinGate(XOR, 
                                          tempp[0][row], 
                                          tempg[i_genome + 0][row]);

            for (int i_pattern = 0; i_pattern < (int) ct_pattern[0].size(); i_pattern++){ 
                aggregate = cc.EvalBinGate(OR, 
                                           aggregate,
                                           cc.EvalBinGate(XOR, 
                                                          tempp[i_pattern][row], 
                                                          tempg[i_genome + i_pattern][row]));
                
            }

            populate_me[i_genome][row] = aggregate;

        }
    }
    return;
}

void myfun(BinFHEContext cc, int i, int j, CT * input, int length, CT **my_global_arraylior){
    CT templior = input[0];
    for (int x = 1; x < length; x++){
        templior = cc.EvalBinGate(AND, templior, input[x]);
    }
    my_global_arraylior[i][j] = templior;
    return;
}

void pattern_match_enc_try2(vector<vecCT> ct_genome, vector<vecCT> ct_pattern, vector<vecCT> &result, vector<vecInt> pt_pattern, BinFHEContext cc, vecChar pattern, CT **populate_me, LWEPrivateKey sk){

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

// CT temp = cc.Encrypt(sk, 1);
// CT aggregate = temp;


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

    return;
}

void encrypt_me_threaded_genome(vector<vecInt> one_hot_genome,  vector<vecInt> one_hot_pattern, BinFHEContext cc, vector<vecCT> &ct_genome, vector<vecCT> &ct_pattern, LWEPrivateKey sk, string DATAFOLDER, bool serialize, CT **cipher){

    int len = one_hot_genome[0].size();

#pragma omp parallel for collapse(2)
    //for (int i = 0; i < 4; i++){ 
    for (int j = 0; j < len; j++){
        //for (int j = 0; j < len; j++){
        for (int i = 0; i < 4; i++){

            //printf("\nattempt enc row %d of genome\n", i);

            std::string val = "";
            switch (i){
            case 0:
                val = "zero";
                break;
            case 1:
                val = "one";
                break;
            case 2:
                val = "two";
                break;
            case 3:
                val = "three";
                break;
            default:
                break;
            }

            auto temp = cc.Encrypt(sk, one_hot_genome[i][j]);

            if (serialize){
                //cout<<"attempt to serialize the text, A"<<endl;
                if (!Serial::SerializeToFile(DATAFOLDER + "/text/" + val + "/text_enc_" + std::to_string(j) + ".txt", temp, SerType::BINARY)) {
                    std::cerr << "Error writing serialization of text.txt" << std::endl;
                    //return 1;
                }
            }
            cipher[i][j] = temp;  
        }
         
    }

    //std::cout<< "size is " << len << std::endl;
/*
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < len; j++ ){
            printf("Here");
            LWEPlaintext tempo;
            cc.Decrypt(sk, cipher[i][j], &tempo);
            std::cout << tempo << std::endl;
        }
        std::cout << "the\n" << std::endl;
    }
    std::cout << "oyyy" << std::endl;
*/ 
    return;

}

void encrypt_me_threaded_pattern(vector<vecInt> one_hot_genome,  vector<vecInt> one_hot_pattern, BinFHEContext cc, vector<vecCT> &ct_genome, vector<vecCT> &ct_pattern, LWEPrivateKey sk, string DATAFOLDER, bool serialize, CT **cipher){
    int len = one_hot_pattern[0].size();


#pragma omp parallel for collapse(2)
    for (int i = 0; i < 4; i++){ 

        for (int j = 0; j < len; j++){

            //printf("\nattempt enc row %d of pattern\n", i);

            std::string val = "";
            switch (i){
            case 0:
                val = "zero";
                break;
            case 1:
                val = "one";
                break;
            case 2:
                val = "two";
                break;
            case 3:
                val = "three";
                break;
            default:
                break;
            }

            auto temp = cc.Encrypt(sk, one_hot_pattern[i][j]);

            if (serialize){
                //cout<<"attempt to serialize the text, A"<<endl;
                if (!Serial::SerializeToFile(DATAFOLDER + "/pattern/" + val + "/pat_enc_" + std::to_string(j) + ".txt", temp, SerType::BINARY)) {
                    std::cerr << "Error writing serialization of pattern.txt" << std::endl;
                    //return 1;
                }
            }
            cipher[i][j] = temp; 
        }   
    }
  
    return;

}

void serialize_keys_and_context(BinFHEContext cc, LWEPrivateKey sk, string DATAFOLDER, bool serialize){
    
    if (!serialize){
        return;
    }


    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptoContext.txt", cc, SerType::BINARY)) {
        std::cerr << "Error serializing the cryptocontext" << std::endl;
        //return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;
    if (!Serial::SerializeToFile(DATAFOLDER + "/refreshKey.txt", cc.GetRefreshKey(), SerType::BINARY)) {
        std::cerr << "Error serializing the refreshing key" << std::endl;
        //return 1;
    }
    std::cout << "The refreshing key has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/ksKey.txt", cc.GetSwitchKey(), SerType::BINARY)) {
        std::cerr << "Error serializing the switching key" << std::endl;
        //return 1;
    }
    //std::cout << "The key switching key has been serialized." << std::endl;
    // Serializing private keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/sk1.txt", sk, SerType::BINARY)) {
        std::cerr << "Error serializing sk1" << std::endl;
        //return 1;
    }
    std::cout << "The secret key sk1 key been serialized." << std::endl;   

}

void encrypt(vector<vecInt> input ){

}

int find_pattern_four_rows(vector<vecInt> Ma, vector<vecInt> Su){
  //only four rows
  // int rows_larger = Ma.size(); //4
  // int cols_larger = Ma[0].size();
  // int cols_smaller = Su[0].size();
  int toreturn = 0;

  vecInt possible_locations;

  printf("hi\n");

  possible_locations = KMPSearch(Su[0], Ma[0]);

  printf("\nrow 0\n");
  printf("size is %lu\n",possible_locations.size());

  if (possible_locations.size() > 0){
    toreturn = 1;
  } else {
    return 0;
  }

  for (int item: possible_locations){
    printf(" %d ", item);
  }

  for (int therow = 1; therow < 4; therow++){

    possible_locations = KMPSearch_possible_locations(Su[therow], Ma[therow], possible_locations);

    printf("\n\nrow is %d\n", therow);
    printf("size is %lu\n", possible_locations.size());

    for (int item: possible_locations){
      printf(" %d ", item);
    }


    if (possible_locations.size() > 0){
      toreturn = 1;

    } else {
      return 0;
    }
  }

  return toreturn;

}
//1 : succeed
//0: failed
int find_pattern(vector<vecInt> Ma, vector<vecInt> Su){
    int S = Ma.size();
    int T = Ma[0].size();
    int M = Su.size();
    int N = Su[0].size();
    

    int flag, i,j,p,q = 0;

    for(i=0; i<=(S-M); i++)
    {
      for(j=0; j<=(T-N); j++)
      {
          flag=0;
          for(p=0; p<M; p++)
          {
            for(int q=0; q<N; q++)
            {
                if(Ma[i+p][j+q] != Su[p][q])
                {
                  flag=1;

                  break;
                }
            }
          }
          if(flag==0)
          {
              printf("Match Found in the Main Matrix at starting location %d, %d",(i+1) ,(j+1));
              return 1;
            break;
          }
      }
      if(flag==0)
      {
          printf("Match Found in the Main Matrix at starting location %d, %d",(i+1) ,(j+1));
          return 1;
      }
    }
    return 0;
    
    std::cout << q << std::endl;

}

vecInt KMPSearch_possible_locations(vecInt pattern, vecInt txt, vecInt possible_locations)
{
	int M = pattern.size();
	int N = txt.size();

	int lps[M];

  vecInt found_positions(0);

	LPSArray(pattern, M, lps);

  for(int position: possible_locations){

    int i = position; 
    int j = 0; 

    for(int x = 0; x < N; x++){
      if (pattern[j] == txt[i]) {
        j++;
        i++;
      } else{
        break;
      }

      if (j == M) {
        found_positions.push_back(position);
      }

    }
  }

  return found_positions;
}

vecInt KMPSearch(vecInt pattern, vecInt txt)
{
	int M = pattern.size();
	int N = txt.size();

	int lps[M];

  vecInt found_positions(0);

	LPSArray(pattern, M, lps);

	int i = 0; 
	int j = 0; 
  //int toreturn = 0;

	while ((N - i) >= (M - j)) {
		if (pattern[j] == txt[i]) {
			j++;
			i++;
		}

		if (j == M) {
			//printf("Found pattern at index %d ", i - j);
            found_positions.push_back(i - j);
            //toreturn = 1;
			j = lps[j - 1];
		}

		else if (i < N && pattern[j] != txt[i]) {
			if (j != 0)
				j = lps[j - 1];
			else
				i = i + 1;
		}
	}
  //printf("HIIII");

  // for (int item : found_positions){
  //   //printf("pos %d, ",item);
  // }
  //printf("exiting function \n\n");
  return found_positions;
}

void LPSArray(vecInt pattern, int M, int* lps)
{

	int len = 0;

	lps[0] = 0; 
	int i = 1;
	while (i < M) {
		if (pattern[i] == pattern[len]) {
			len++;
			lps[i] = len;
			i++;
		}
		else 
		{
			
			if (len != 0) {
				len = lps[len - 1];

			}
			else
			{
				lps[i] = 0;
				i++;
			}
		}
	}
}

void one_hot_encode(vecChar input, vector<vecInt>& output){
    printf("entering one hot encode");
    vecInt a;
    vecInt c;
    vecInt g;
    vecInt t;

    for (char character : input){
    printf("%c ",character );
      switch(tolower(character)){
        case 'a':
          a.push_back(1);
          c.push_back(0);
          g.push_back(0);
          t.push_back(0);
          break;
        case 'c':
          a.push_back(0);
          c.push_back(1);
          g.push_back(0);
          t.push_back(0);
          break;

        case 'g':
          a.push_back(0);
          c.push_back(0);
          g.push_back(1);
          t.push_back(0);
          break;

        case 't':
          a.push_back(0);
          c.push_back(0);
          g.push_back(0);
          t.push_back(1);
          break;

        // case 'x': //wildcard
        //   a.push_back(1);
        //   c.push_back(1);
        //   g.push_back(1);
        //   t.push_back(1);
        //   break;
        
        default:
          break;
      }
    }

    output.push_back(a);
    output.push_back(c);
    output.push_back(g);
    output.push_back(t);

}

uint32_t read_from_file(vecChar& a, string fname) {
  char c;

  ifstream in_file;
  in_file.open(fname);
  if (!in_file) {
    cerr << "Can't open file for input: "<<fname;
    exit(-1); //error exit
  }

  while (in_file >> c) {
	  a.push_back(c);
  }
  in_file.close();
  return a.size();
}

void get_input_from_term(vecChar& a) {
    //source: OpenFHE
    // function to get string input from terminal and return as vector of char
  string cstr;
  cin.ignore(numeric_limits<streamsize>::max(),'\n'); //flushes buffer
  std::getline(std::cin, cstr);
  cout <<"Pattern is `"<<cstr<<"'"<<endl;
  for(auto c: cstr) {
	  a.push_back(c);
  }
  cout <<"Pattern is "<<a.size()<<" characters"<<endl;
  return;
}

uint32_t get_input_from_file(vecChar& a, string fname) {
    //source: OpenFHE
    // function to read text from a file and return as vector of char
  char c;

  ifstream in_file;
  in_file.open(fname);
  if (!in_file) {
    cerr << "Can't open file for input: "<<fname;
    exit(-1); //error exit
  }

  while (in_file >> c) {
	  a.push_back(c);
  }
  cout <<"Read "<<a.size()<<" characters"<<endl;
  in_file.close();
  return a.size();
}
