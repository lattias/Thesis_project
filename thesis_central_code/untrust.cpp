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

#include <filesystem>

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
void get_the_homolog(vecCT percent_match_result_for_homolog, vector<char*> &get_the_homolog_result, vecChar pattern, BinFHEContext cc, LWEPrivateKey sk, vector<vecCT> ct_genome, vector<vecCT> ct_pattern, char* homo_array2);

mutex mv;

namespace fs = std::filesystem;
int main(){
    //cross platform time reporting:
    TimeVar t;
    struct timeval start, end;
    long mtime, secs, usecs;

    vector<vecCT> ct_genome(0);
    vector<vecCT> ct_pattern;
    vector<vecCT> ct_homo;
    vector<vecCT> ct_percentmatch;

    printf("Deserializing the ciphertexts\n");

    deserialize_ciphertexts(ct_genome, ct_pattern, ct_homo, ct_percentmatch);

    printf("Creating a new binary context\n");
    //BinFHEContext cc = BinFHEContext();
    //cc.GenerateBinFHEContext(STD128); //default is GINX = CGGI scheme

    //printf("start pattern match\n");
    int genome_len = ct_genome[0].size();
    int pattern_len = ct_pattern[0].size();
    int homo_len = ct_homo[0].size();
    int percentmatch_len = ct_percentmatch[0].size();

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

    //test get secret key
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

   for (int i = 0; i < 4; i++){
    for (int j = 0; j < genome_len; j++){
        // std::cout << rot[i][j];
        printf(" ");
        LWEPlaintext t;
        cc.Decrypt(sk, ct_genome[i][j], &t);
        std::cout << t << " ";
    }
    printf("\n");
   }
    
    printf("pattern\n");
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < pattern_len; j++){
            // std::cout << rot[i][j];
            printf(" ");
            LWEPlaintext t;
            cc.Decrypt(sk, ct_pattern[i][j], &t);
            std::cout << t << " ";
        }
        printf("\n");
   }

   printf("homo\n");
    for (int i = 0; i < 4; i++){
    for (int j = 0; j < homo_len; j++){
        // std::cout << rot[i][j];
        printf(" ");
        LWEPlaintext t;
        cc.Decrypt(sk, ct_homo[i][j], &t);
        std::cout << t << " ";
    }
    printf("\n");
   }

    printf("pm\n");
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < percentmatch_len; j++){
            // std::cout << rot[i][j];
            printf(" ");
            LWEPlaintext t;
            cc.Decrypt(sk, ct_percentmatch[i][j], &t);
            std::cout << t << " ";
        }
    printf("\n");
   }

printf("hi");
    populate_arrays_from_vector(ct_genome, temp_genome);
    populate_arrays_from_vector(ct_pattern, temp_pattern);
    populate_arrays_from_vector(ct_homo, temp_homo);
    populate_arrays_from_vector(ct_percentmatch, temp_percentmatch);

    //LIOR DELETE THIS
    printf("genome array size ");
    std::cout << (int) ct_genome[0].size() << std::endl;

    printf("\ngenome array result\n");
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < (int) ct_genome[0].size(); j++){
            // std::cout << rot[i][j];
            printf(" ");
            LWEPlaintext t;
            cc.Decrypt(sk, temp_genome[i][j], &t);
            std::cout << t << " ";
        }
    printf("\n");
   }

    printf("\n pattern array result\n");
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < (int) ct_pattern[0].size(); j++){
            // std::cout << rot[i][j];
            printf(" ");
            LWEPlaintext t;
            cc.Decrypt(sk, temp_pattern[i][j], &t);
            std::cout << t << " ";
        }
    printf("\n");
   }

printf("hiiiii");
    //populate the vectors
    // for (int i = 0; i < 4; i++){
    //     vecCT temp;
    //     for (int j = 0; j< genome_len; j++ ){
    //         temp.push_back(temp_genome[i][j]);
    //     }
    //     ct_genome.push_back(temp);
    // }

    // for (int i = 0; i < 4; i++){
    //     vecCT temp;
    //     for (int j = 0; j< pattern_len; j++ ){
    //         temp.push_back(temp_pattern[i][j]);
    //     }
    //     ct_pattern.push_back(temp);
    // }

    // for (int i = 0; i < 4; i++){
    //     vecCT temp;
    //     for (int j = 0; j< homo_len; j++ ){
    //         temp.push_back(temp_homo[i][j]);
    //     }
    //     ct_homo.push_back(temp);
    // }
    // for (int i = 0; i < 4; i++){
    //     vecCT temp;
    //     for (int j = 0; j< percentmatch_len; j++ ){
    //         temp.push_back(temp_percentmatch[i][j]);
    //     }
    //     ct_percentmatch.push_back(temp);
    // }

    vector<vecCT> enc_result;
    //printf("start pattern match\n");

    CT **populate_me = new CT*[genome_len-pattern_len+1];
    for (int i = 0; i < genome_len-pattern_len+1; i++){
        populate_me[i] = new CT[4];
    }
    
    gettimeofday(&start, NULL);
    TIC(t);

    pattern_match_enc_try2(ct_genome, ct_pattern, enc_result, cc, populate_me); //this works LIOR
    std::cout << "PATTERN MATCH match enc try2time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

        //LIOR DELETE THIS


    printf("size is");
    std::cout << (int) (genome_len-pattern_len+1) << std::endl;

    printf("pattern match result\n");
    for (int i = 0; i < 5; i++){
        for (int j = 0; j < 4; j++){
            // std::cout << rot[i][j];
            printf(" ");
            LWEPlaintext t;
            cc.Decrypt(sk, populate_me[i][j], &t);
            std::cout << t << " ";
        }
    printf("\n");
   }

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

    //populate vector
    for (int i = 0; i < 4; i++){
        vecCT temp;
        for (int j = 0; j < genome_len - pattern_len + 1; j++){
            temp.push_back(rot[i][j]);
        }
        enc_result.push_back(temp);
    }
    

//     //LIOR DELETE THIS
//     printf("size is");
//     std::cout << (int) enc_result[0].size() << std::endl;

//     printf("pattern match result\n");
//     for (int i = 0; i < 4; i++){
//         for (int j = 0; j < (int) enc_result[0].size(); j++){
//             // std::cout << rot[i][j];
//             printf(" ");
//             LWEPlaintext t;
//             cc.Decrypt(sk, enc_result[i][j], &t);
//             std::cout << t << " ";
//         }
//     printf("\n");
//    }

    CT any_found_result;
    CT *true_false_found_array = new CT[enc_result[0].size()];
gettimeofday(&start, NULL);
TIC(t);
    true_false_found(enc_result, ct_pattern, any_found_result, cc, true_false_found_array); //this works, unthread currently
    std::cout << "\ntrue false found time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

    gettimeofday(&start, NULL);	
TIC(t);
    true_false_helper(true_false_found_array,any_found_result,cc, enc_result );
    std::cout << "\ntrue false helper time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    gettimeofday(&end, NULL);
    secs  = end.tv_sec  - start.tv_sec;
    usecs = end.tv_usec - start.tv_usec;
    mtime = ((secs) * 1000 + usecs/1000.0) + 0.5;
    printf("Elapsed time: %ld millisecs\n", mtime);

    //serialize the array for true_false_index (for the trusted env)
    std::string ciphertext_result_true_false_index_array = "../ciphertext_result_true_false_index_array";

    for (int i = 0 ; i <(int) enc_result.size()+1; i++){
        if (!Serial::SerializeToFile(ciphertext_result_true_false_index_array + "/tf_index_enc_" + std::to_string(i) + ".txt", true_false_found_array[i], SerType::BINARY)) {
                        std::cerr << "Error writing serialization of tf_index_array" << std::endl;
                        //return 1;
        }
    }

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

    

    //populate any found result!
    any_found_result_function(any_found_result, true_false_found_array, enc_result, cc);

    //serialize result of true_false_found (one bit) (for the trusted env)
    std::string ciphertext_result_true_false_found = "../ciphertext_result_true_false_found";

    if (!Serial::SerializeToFile(ciphertext_result_true_false_found + "/tf_any_found_result.txt", any_found_result, SerType::BINARY)) {
                    std::cerr << "Error writing serialization of any found result" << std::endl;
                    //return 1;
    }
    


//LIOR NEEDS TO GO IN TRUST
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

    // lior remove small pattern match
gettimeofday(&start, NULL);
TIC(t);
    raw_match(ct_genome, ct_pattern, raw_match_enc_result, cc, offset, raw_match_array);
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
    //lior end remove small pattern match

    gettimeofday(&start, NULL);
TIC(t);
        raw_match(ct_genome, ct_percentmatch, raw_match_enc_resultPM, cc, offset, raw_match_arrayPM);
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
    
    //serialize result percent match SMALL (1D array) for the trusted env
    std::string ciphertext_result_percent_match_small = "../ciphertext_result_percent_match_small";

    for (int i = 0; i < (int) percent_match_result.size(); i++){
        if (!Serial::SerializeToFile(ciphertext_result_percent_match_small + "/pm_result_" + std::to_string(i) + ".txt", percent_match_result[i], SerType::BINARY)) {
                        std::cerr << "Error writing serialization of percent match result for small pattern match" << std::endl;
                        //return 1;
        }
    }

    //lior goes into trusted env
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

    //serialize result percent match SMALL (1D array) for the trusted env
    std::string ciphertext_result_percent_match_large = "../ciphertext_result_percent_match_large";

    for (int i = 0; i < (int) percent_match_resultPM.size(); i++){
        if (!Serial::SerializeToFile(ciphertext_result_percent_match_large + "/pm_result_" + std::to_string(i) + ".txt", percent_match_resultPM[i], SerType::BINARY)) {
                        std::cerr << "Error writing serialization of percent match result for large genome match" << std::endl;
                        //return 1;
        }
    }
    //lior goes into trusted env
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
    

    //LIOR to trusted env
    std::string homo = "txx";
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
    pattern_match_enc_homolog(ct_genome, ct_homo, pattern_match_enc_result_homo, cc, pattern_match_array);
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
    precent_match_homolog(pattern_match_enc_result_homo, cc, percent_match_result_for_homolog, ct_homo, percent_match_homo_array);
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

    //serialize result of wildcard search
    std::string ciphertext_result_wildcard_search = "../ciphertext_result_wildcard_search";

    for (int i = 0; i < (int) percent_match_result_for_homolog.size(); i++){
        if (!Serial::SerializeToFile(ciphertext_result_wildcard_search + "/wildcard_result_" + std::to_string(i) + ".txt", percent_match_result_for_homolog[i], SerType::BINARY)) {
                        std::cerr << "Error writing serialization result for wildcard search" << std::endl;
                        //return 1;
        }
    }


    // printf("LIOR START\n");
    // vector<vecCT> ct_genome2(0);
    // vector<vecCT> ct_pattern2;
    // vector<vecCT> ct_percentmatch2;
    // vector<vecCT> ct_homo2; //DONT USE THIS
    // deserialize_ciphertexts(ct_genome2, ct_pattern2, ct_homo2, ct_percentmatch2);
    // printf("size is %d\n", (int) percent_match_result_for_homolog.size());

    // vecCT row_1;
    // // datafolder = "../ciphertext_result_wildcard_search";
    // int length_of_sequence = 0;
    // // path = datafolder;
    // for (const auto & entry : fs::directory_iterator(ciphertext_result_wildcard_search)){
    //     // std::cout << entry.path() << std::endl;
    //     // std::cout << entry.path().filename() << std::endl;
    //     if (entry.path().filename() == ".DS_Store"){
    //         length_of_sequence--;
    //     }
    //     length_of_sequence++;
    // }
    // printf("len of seq is %d\n ", length_of_sequence);
    // for (int i = 0; i < length_of_sequence; i++){
    //     LWECiphertext ct;
    //     if (Serial::DeserializeFromFile(ciphertext_result_wildcard_search + "/wildcard_result_" + std::to_string(i) + ".txt", ct, SerType::BINARY) == false) {
    //         std::cerr << "Could not deserialize the ciphertext" << std::endl;
    //         std::cerr << "wildcard search result index " << i << std::endl;
    //         return 1;
    //     }
    //     row_1.push_back(ct);
    // }

//lior this goes into trusted
    gettimeofday(&start, NULL);
TIC(t);
    vecChar thehomo = {'t','x','x'};

    //get_the_homolog(row_1, get_the_homolog_result, thehomo, cc, sk, ct_genome2, ct_homo2, homo_array);
    get_the_homolog(percent_match_result_for_homolog, get_the_homolog_result, thehomo, cc, sk, ct_genome, ct_homo, homo_array);
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

    //return 1;

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
         any_found_result = cc.EvalBinGate(OR, any_found_result, input_array[i]);
    }
}

