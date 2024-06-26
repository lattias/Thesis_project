//0. includes and namespaces

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

#include "cereal-master/include/cereal/archives/portable_binary.hpp"
#include "cereal-master/include/cereal/archives/json.hpp"
#include "cereal-master/include/cereal/cereal.hpp"
#include "cereal-master/include/cereal/types/map.hpp"
#include "cereal-master/include/cereal/types/memory.hpp"
#include "cereal-master/include/cereal/types/polymorphic.hpp"
#include "cereal-master/include/cereal/types/string.hpp"
#include "cereal-master/include/cereal/types/vector.hpp"


#include "binfhe/binfhecontext.h"


using namespace lbcrypto;
using namespace std;
using namespace cereal;

//data types we will need
//using CT = lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ; //ciphertext
//using CT = lbcrypto::Ciphertext<lbcrypto::LWECiphertext>;
using CT = lbcrypto::LWECiphertext;

using PT = lbcrypto::Plaintext ; //plaintext
using vecCT = vector<CT>; //vector of ciphertexts
using vecPT = vector<PT>; //vector of plaintexts
using vecInt = vector<int64_t>; // vector of ints
using vecChar = vector<char>; // vector of characters

//forward declarations
void get_input_from_term(vecChar& a);
uint32_t get_input_from_file(vecChar& a, string fname);
vecInt search(vecChar &pat, vecChar &txt, int ps);
CT encrypt_repeated_integer(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc, lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk,  int64_t in, size_t n);
CT encMultD(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc, CT in);
vecCT encrypted_search(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,  lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk, vecCT &epat, vecCT &etxt, int ps);
int serializeme();
int deserializeme();
void test_simple();
uint32_t read_from_file(vecChar& a, string fname);
void one_hot_encode(vecChar input, vector<vecInt>& output);
int find_pattern(vector<vecInt> larger_matrix, vector<vecInt> submatrix);
int find_pattern_four_rows(vector<vecInt> Ma, vector<vecInt> Su);
vecInt KMPSearch(vecInt pattern, vecInt txt);
void LPSArray(vecInt pattern, int M, int* lps);
vecInt KMPSearch_possible_locations(vecInt pattern, vecInt txt, vecInt possible_locations);
bool myfunction (int i, int j);
void serialize_keys_and_context(BinFHEContext cc, LWEPrivateKey sk, string DATAFOLDER, bool serialize);
void encrypt_me(vector<vecInt> one_hot_genome,  vector<vecInt> one_hot_pattern, BinFHEContext cc, vector<vecCT> &ct_genome, vector<vecCT> &ct_pattern, LWEPrivateKey sk, string DATAFOLDER, bool serialize);

//const int d = 256;

// header files needed for serialization


//const std::string DATAFOLDER = "/Users/lior/Documents/research-bellovin/code2/liors_project/serialized_data";


//const std::string DATAFOLDER = "thesis_drive:\\ser_data";

int main(){

    vecChar genome;
    string infilename;
    vector<vecInt> one_hot_genome;
    vecChar pattern;
    vector<vecInt> one_hot_pattern;

    vector<vecCT> ct_genome(0);
    vector<vecCT> ct_pattern;

    //infilename = "/Users/lior/Documents/research-bellovin/data/addgene-plasmid-66562-sequence-136499.gbk";
    //infilename = "/Users/lior/Documents/research-bellovin/data/test_very_small.txt";
    //infilename = "/Users/lior/Documents/research-bellovin/data/test_large.txt";
    infilename = "/Users/lior/Documents/research-bellovin/data/test_large_plaintext.txt";

    bool serialize = true;

    read_from_file(genome, infilename);

    one_hot_encode(genome, one_hot_genome);

    pattern = {'a','a','t','t','t'};
    //pattern = {'t','t','t','t','t','t','t','t','t','t','t','t'};
    one_hot_encode(pattern, one_hot_pattern);
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

    int result = find_pattern_four_rows(one_hot_genome, one_hot_pattern);
    if (result){
      printf("\n\nfound!\n");
    } else{
      printf("\n\nnot found\n");
    }

    printf("Creating binary context\n");

    //auto cc = BinFHEContext();
    BinFHEContext cc = BinFHEContext();

    cc.GenerateBinFHEContext(STD128);
    LWEPrivateKey sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto switchy_key = cc.GetSwitchKey();
    const std::string small_folder = "/Users/lior/Documents/research-bellovin/code2/liors_project/serialized_data_big_correct";
    
    serialize_keys_and_context(cc, sk, small_folder, serialize);

    printf("\nencrypting pattern\n");

    encrypt_me(one_hot_genome, one_hot_pattern, cc, ct_genome, ct_pattern, sk, small_folder, serialize);

    return 1;
    


}

void encrypt_me(vector<vecInt> one_hot_genome,  vector<vecInt> one_hot_pattern, BinFHEContext cc, vector<vecCT> &ct_genome, vector<vecCT> &ct_pattern, LWEPrivateKey sk, string DATAFOLDER, bool serialize){
    int index_onehot = 0;
    int index_cipher = 0;

    for (vecInt item: one_hot_pattern){
      vecCT cipher(0);
      
      printf("\nattempt enc row %d of pattern\n", index_onehot);
      index_cipher = 0;
      for (int c : item){
        std::string val = "";
        switch (index_onehot){
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
        auto temp = cc.Encrypt(sk, c);
        cipher.push_back(temp);

        if (serialize){
            cout<<"attempt to serialize the text, A"<<endl;
            if (!Serial::SerializeToFile(DATAFOLDER + "/pattern/" + val + "/pat_enc_" + std::to_string(index_cipher) + ".txt", temp, SerType::BINARY)) {
                std::cerr << "Error writing serialization of pattern.txt" << std::endl;
                //return 1;
            }
        }
        index_cipher++;
      }
      index_onehot++;
      ct_pattern.push_back(cipher);
    } 

    printf("\nencrypting text\n");

    index_onehot = 0;
    index_cipher = 0;
    for (vecInt item: one_hot_genome){
      vecCT cipher(0);
      
      printf("\nattempt enc row %d of text\n", index_onehot);
      index_cipher = 0;
      for (int c : item){
        std::string val = "";
        switch (index_onehot){
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
        auto temp = cc.Encrypt(sk, c);
        cipher.push_back(temp);
        
        if(serialize){
            cout<<"attempt to serialize the text, A"<<endl;
            if (!Serial::SerializeToFile(DATAFOLDER + "/text/" + val + "/text_enc_" + std::to_string(index_cipher) + ".txt", temp, SerType::BINARY)) {
                std::cerr << "Error writing serialization of text.txt" << std::endl;
                //return 1;
            }
        }
        index_cipher++;
      }
      index_onehot++;
      ct_genome.push_back(cipher);
    } 

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
    std::cout << "The key switching key has been serialized." << std::endl;
    // Serializing private keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/sk1.txt", sk, SerType::BINARY)) {
        std::cerr << "Error serializing sk1" << std::endl;
        //return 1;
    }
    std::cout << "The secret key sk1 key been serialized." << std::endl;   

}

void encrypt(vector<vecInt> input ){

}

int enc_equal(int a, int b){
    //auto ct_xor = cc.EvalBinGate(XOR, a, b);
   // auto result = 
   return 1;
}
int find_pattern_encrypted(vector<vecInt> Ma, vector<vecInt> Su){
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

bool myfunction (int i, int j) {
  return (i==j);
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

void prologue(){

}

void one_hot_encode(vecChar input, vector<vecInt>& output){
    printf("entering one hot encode");
    vecInt a;
    vecInt c;
    vecInt g;
    vecInt t;

    for (char character : input){
    printf("%c ",character );
      switch(character){
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
        
        default:
          break;
      }
    }

    output.push_back(a);
    output.push_back(c);
    output.push_back(g);
    output.push_back(t);

}

void test_simple(){

}

/*
int deserializeme(){


    // Deserialize the crypto context
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    PublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
        return 1;
    }
    
    std::cout << "The public key has been deserialized." << std::endl;

    std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
    if (!emkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval mult key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval mult keys." << std::endl;

    std::ifstream erkeys(DATAFOLDER + "/key-eval-rot.txt", std::ios::in | std::ios::binary);
    if (!erkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-rot.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalAutomorphismKey(erkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval rotation key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval rotation keys." << std::endl;

    Ciphertext<DCRTPoly> ct1;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext1.txt", ct1, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }

    Ciphertext<DCRTPoly> pattern;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/pattern.txt", ct1, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The first ciphertext has been deserialized." << std::endl;
    return 1;
}


*/

/*
int serializeme()
{
    
    vecChar bigtxt;
    int p = 786433; //plaintext prime modulus
    vecChar pat;
    string infilename;

    //int p = 65537; //note this causes exception

    cout<<"p "<<p<<endl;
    uint32_t plaintextModulus = p;
    uint32_t multDepth = 32;

    double sigma = 3.2;
    lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_128_classic;
    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetStandardDeviation(sigma);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetMultiplicationTechnique(HPS);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    std::cout << "The cryptocontext has been generated." << std::endl;

    // Serialize cryptocontext
    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        return 1;
    }

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    std::cout << "The key pair has been generated." << std::endl;

    // Serialize the public key
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
        return 1;
    }
    std::cout << "The public key has been serialized." << std::endl;

    // Serialize the secret key
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been serialized." << std::endl;

    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "The eval mult keys have been generated." << std::endl;

    // Serialize the relinearization (evaluation) key for homomorphic
    // multiplication
    std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt", std::ios::out | std::ios::binary);
    if (emkeyfile.is_open()) {
        if (cryptoContext->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval mult keys to "
                         "key-eval-mult.txt"
                      << std::endl;
            return 1;
        }
        std::cout << "The eval mult keys have been serialized." << std::endl;

        emkeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval mult keys" << std::endl;
        return 1;
    }

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    std::cout << "The rotation keys have been generated." << std::endl;

    // Serialize the rotation keyhs
    std::ofstream erkeyfile(DATAFOLDER + "/" + "key-eval-rot.txt", std::ios::out | std::ios::binary);
    if (erkeyfile.is_open()) {
        if (cryptoContext->SerializeEvalAutomorphismKey(erkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval rotation keys to "
                         "key-eval-rot.txt"
                      << std::endl;
            return 1;
        }
        std::cout << "The eval rotation keys have been serialized." << std::endl;

        erkeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval rotation keys" << std::endl;
        return 1;
    }

    std::cout << "\n attempting to run program" << std::endl;

    infilename = "/Users/lior/Documents/research-bellovin/data/testsmall.gbk";
    uint32_t textSize(0);

    textSize = get_input_from_file(bigtxt, infilename);
    uint32_t offset(0);
    cout << "Limiting search to "<<textSize<< " characters "
        <<"starting at offset "<<offset<<endl;

    vecChar::const_iterator first = bigtxt.begin() + offset;
    vecChar::const_iterator last = bigtxt.begin() + offset+textSize;
    vecChar txt(first, last);


    //pattern
    pat = {'a','a','t','t'};

    cout<<"p "<<p<<endl;
    TIC(auto t1);

    auto presult = search(pat, txt, p);
    auto plain_time_ms = TOC_MS(t1);
    cout<< "Plaintext execution time "<<plain_time_ms<<" mSec."<<endl;

    cout <<"setting up BFV RNS crypto system"<<endl;

    cout<<"attempt Encrypt pattern"<<endl;
    //encrypt the pattern
    vecInt vin(0);
    vecCT epat(0);
    uint32_t j(0);

    CT ct(0);

    for (auto ch: pat) {
        cout<<j<< '\r'<<flush;
        j++;
        vin.push_back(ch);
        PT pt= cryptoContext->MakePackedPlaintext(vin);
        vin.clear();
        CT ct = cryptoContext->Encrypt(keyPair.publicKey, pt);
        epat.push_back(ct);
    }

    //{
    //cereal::CEREAL_REGISTER_TYPE(vecCT);
        //std::ostream os("outpattern.cereal", std::ios::binary);

        // std::ofstream ofs(DATAFOLDER + "/" + "pattern.txt", std::ios::binary);
        // cereal::BinaryOutputArchive archive(ofs);
        // archive(epat);
   //}

     cout<<"attempt to serialize the pattern"<<endl;
    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "pattern.txt", epat, SerType::BINARY)) {
        std::cerr << "Error writing serialization of pattern.txt" << std::endl;
        return 1;
    }


    cout<<"attempt encrypt text"<<endl;
    //encrypt the text
    auto ringsize = cryptoContext->GetRingDimension();
    cout << "ringsize = "<<ringsize << endl;
    cout << "txt size = "<<txt.size() << endl;
    uint32_t nbatch = int(ceil(float(txt.size())/float(ringsize)));
    cout << "can store "<<nbatch <<" batches in the ct"<<endl;

    vecCT etxt(0);
    auto pt_len(0);
    for (usint i = 0; i < txt.size(); i++) {
        cout<<i<< '\r'<<flush;
        vin.push_back(txt[i]);
        lbcrypto::Plaintext pt= cryptoContext->MakePackedPlaintext(vin);
        pt_len = pt->GetLength();
        vin.clear();
        CT ct = cryptoContext->Encrypt(keyPair.publicKey, pt);
        etxt.push_back(ct);
    }

    cout<<"attempt to serialize the text"<<endl;
    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext1.txt", etxt, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
        std::cerr<<pt_len<<std::endl;
        return 1; 
    }

    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
    return 1;

    
}


*/

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


// below is the functions from OpenFHE example

// function to get string input from terminal and return as vector of char
void get_input_from_term(vecChar& a) {
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

// function to read text from a file and return as vector of char
uint32_t get_input_from_file(vecChar& a, string fname) {
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

// // plaintext string search of pat within txt, with modulus of ps
// vecInt search(vecChar &pat, vecChar &txt, int ps) {
//   int64_t p(ps);
//   OPENFHE_DEBUG_FLAG(false);
//   size_t M = pat.size();
//   OPENFHE_DEBUGEXP(M);
//   size_t N = txt.size();
//   OPENFHE_DEBUGEXP(N);
//   size_t i, j;
//   int64_t ph = 0;  // hash value for pattern
//   int64_t th = 0; // hash value for txt
//   int64_t h = 1;

//   size_t nfound = 0;

//   // The value of h would be "pow(d, M-1)%p"
//   for (i = 0; i < M-1; i++) {
//     h = (h*d)%p;
//     OPENFHE_DEBUGEXP(h);
//   }
//   OPENFHE_DEBUG(" hfinal: "<<h);

//   // Calculate the hash value of pattern and first window of text
//   for (i = 0; i < M; i++) {
//     ph = (d * ph + pat[i]) % p;
//     th = (d * th + txt[i]) % p;
//   }
//   OPENFHE_DEBUG(" initial ph: "<<ph);
//   OPENFHE_DEBUG(" initial th: "<<th);
//   vecInt pres(0);
//   // Slide the pattern over text one by one
//   for (i = 0; i <= N - M; i++) {

//     // Check the hash values of current window of text and pattern
//     // If the hash values match then only check for characters on by one
//     pres.push_back((ph-th)%p);
//     if ( ph == th )	{
//       /* Check for characters one by one */
//       for (j = 0; j < M; j++) {
//       if (txt[i + j] != pat[j])
//         break;
//       }
//       if (j == M) { // if ph == t and pat[0...M-1] = txt[i, i+1, ...i+M-1]

//       cout<<"Pattern found at index "<< i << endl;
//       nfound++;
//       }
//     }

//     // Calculate hash value for next window of text: Remove leading digit,
//     // add trailing digit
//     if ( i < N - M ) {
//       th = (d * (th - txt[i] * h) + txt[i + M]) % p;

//       // We might get negative value of t, converting it to positive
//       if (th < 0) {
//       th = (th + p);
//       }

//     }
//   } //end for

//   cout<<"total occurances " <<nfound<<endl;
//   return pres;
// }

// // helper function to encrypt an integer repeatedly into a packed plaintext
// // and encrypt it
// CT encrypt_repeated_integer(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc, lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk,  int64_t in, size_t n){

//   vecInt v_in(n, in);
//   PT pt= cc->MakePackedPlaintext(v_in);
//   CT ct = cc->Encrypt(pk, pt);

//   return ct;
// }

// // helper function to multiply by constant 256 using binary tree addition
// CT encMultD(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc, CT in){
//   if (d !=256){
//     cout <<"error d not 256"<<endl;
//     exit(-1);
//   }
//   auto tmp(in);
//   for (auto i = 0; i< 8; i++ ){
// 	  tmp = cc->EvalAdd(tmp, tmp);
//   }

//   return(tmp);
// }

// //Single value encrypted search
// vecCT encrypted_search(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,  lbcrypto::PublicKey<lbcrypto::DCRTPoly> &pk, vecCT &epat, vecCT &etxt, int ps) {

//   int64_t p(ps);
//   OPENFHE_DEBUG_FLAG(false);
//   size_t M = epat.size();
//   OPENFHE_DEBUGEXP(M);
//   size_t N = etxt.size();
//   OPENFHE_DEBUGEXP(N);
//   size_t i;

//   PT dummy;
  

//   size_t nrep(1);
//   OPENFHE_DEBUG("encrypting small ct");
//   CT phct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for pattern
//   CT thct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for txt

//   OPENFHE_DEBUG("encrypting hct");
//   // The value of h would be "pow(d, M-1)%p"
//   int64_t h = 1;
//   for (i = 0; i < M-1; i++) {
// 	  h = (h*d)%p;
//   }
//   CT hct = encrypt_repeated_integer(cc, pk, h, nrep);  // encrypted h

//   OPENFHE_DEBUG("encrypting first hashes" );
//   // Calculate the hash value of pattern and first window of text
//   for (i = 0; i < M; i++) {
//     auto tmp = encMultD(cc, phct);
//     phct = cc->EvalAdd(tmp, epat[i]);

//     tmp = encMultD(cc, thct);
//     thct = cc->EvalAdd(tmp, etxt[i]);
//   }

//   vecCT eres(0);
//   // Slide the pattern over text one by one
//   OPENFHE_DEBUG("sliding" );
//   for (i = 0; i <= N - M; i++) {
// 	cout<<i<< '\r'<<flush;

// 	// Check the hash values of current window of text and pattern
// 	// If the hash values match then only check for characters on by one
// 	// subtract the two hashes, zero is equality
// 	OPENFHE_DEBUG("sub" );
// 	eres.push_back(cc->EvalSub(phct, thct));

// 	// Calculate hash value for next window of text: Remove leading digit,
// 	// add trailing digit
// 	if ( i < N - M ) {
// 	  OPENFHE_DEBUG("rehash" );
// 	  //th = (d * (th - txt[i] * h) + txt[i + M]) % p;

// 	  auto tmp = encMultD(cc,
// 						  cc->EvalSub(thct,
// 									  cc->EvalMult(etxt[i], hct)
// 									  )
// 						  );
// 	  thct = cc->EvalAdd(tmp, etxt[i+M] );

// 	}

//   } //end for
//   return eres;
// }



