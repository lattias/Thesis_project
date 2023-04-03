//0. includes and namespaces

#include "openfhe.h"
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>

using namespace lbcrypto;
using namespace std;



//data types we will need--Palisades
using CT = Ciphertext<DCRTPoly> ; //ciphertext
using PT = Plaintext ; //plaintext
using vecCT = vector<CT>; //vector of ciphertexts
using vecPT = vector<PT>; //vector of plaintexts
using vecInt = vector<int64_t>; // vector of ints
using vecChar = vector<char>; // vector of characters

//forward declerations for palisades
void get_input_from_term(vecChar& a);
void get_input_from_file(vecChar& a, string fname);
vecInt search(vecChar &pat, vecChar &txt, int ps);
CT encrypt_repeated_integer(CryptoContext<DCRTPoly> &cc, LPPublicKey<DCRTPoly> &pk,  int64_t in, size_t n);
CT encMultD(CryptoContext<DCRTPoly> &cc, CT in);
vecCT encrypted_search(CryptoContext<DCRTPoly> &cc,  LPPublicKey<DCRTPoly> &pk, vecCT &epat, vecCT &etxt, int ps);


const int d = 256;

//for now, just place everything into main
int main(){
    //1. Selet a scheme to use. I will use BGV = BGVrns

    //2. create a CryptoContext
    
    //2A. run a parameter generation function
        //use default, or make your own which must include:
            //  decide on lattice parameters (ring dimension, size of moduli)

            // decide on encoding parameters (plaintext modulus)

            // decide on scheme-specific parameters
    // the functions on the CCParams object are listed here
        //https://openfhe-development.readthedocs.io/en/latest/api/classlbcrypto_1_1Params.html?highlight=setmultiplicative
    
    CCParams<CryptoContextBGVRNS> parameters;

    //std::cout << parameters << std::endl;  // prints all parameter values

    parameters.SetMultiplicativeDepth(2);
    parameters.SetPlaintextModulus(65537);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    //2B. enable the algorithms I want to use, such as:
        // Enable(ENCRYPTION) - allows for key generation and encrypt/decrypt

        // Enable(PRE) - allows for the use of proxy re-encryption

        // Enable(SHE) - enables SHE operations such as EvalAdd and EvalMult

        // Enable(MULTIPARTY) - enables threshold FHE operations
        // Enable features that you wish to use
    
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(FHE);

    // attempt to do simple string match

    std::cout << "liordddrr" << std::endl;
}

// below is the functions from palisades

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
void get_input_from_file(vecChar& a, string fname) {
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
  return;
}

// plaintext string search of pat within txt, with modulus of ps          
vecInt search(vecChar &pat, vecChar &txt, int ps) {
  int64_t p(ps);
  DEBUG_FLAG(false);
  size_t M = pat.size();
  DEBUGEXP(M);
  size_t N = txt.size();
  DEBUGEXP(N);
  size_t i, j;
  int64_t ph = 0;  // hash value for pattern
  int64_t th = 0; // hash value for txt
  int64_t h = 1;

  size_t nfound = 0;
     
  // The value of h would be "pow(d, M-1)%p"
  for (i = 0; i < M-1; i++) {
    h = (h*d)%p;
    DEBUGEXP(h);
  }
  DEBUG(" hfinal: "<<h);

  // Calculate the hash value of pattern and first window of text
  for (i = 0; i < M; i++) {
    ph = (d * ph + pat[i]) % p;
    th = (d * th + txt[i]) % p;
  }
  DEBUG(" initial ph: "<<ph);
  DEBUG(" initial th: "<<th);
  vecInt pres(0);
  // Slide the pattern over text one by one
  for (i = 0; i <= N - M; i++) {
    
    // Check the hash values of current window of text and pattern
    // If the hash values match then only check for characters on by one
    pres.push_back((ph-th)%p);
    if ( ph == th )	{
      /* Check for characters one by one */
      for (j = 0; j < M; j++) {
      if (txt[i + j] != pat[j])
        break;
      }
      if (j == M) { // if ph == t and pat[0...M-1] = txt[i, i+1, ...i+M-1]

      cout<<"Pattern found at index "<< i << endl;
      nfound++;
      }
    }
      
    // Calculate hash value for next window of text: Remove leading digit,
    // add trailing digit
    if ( i < N - M ) {
      th = (d * (th - txt[i] * h) + txt[i + M]) % p;

      // We might get negative value of t, converting it to positive
      if (th < 0) {
      th = (th + p);
      }

    }
  } //end for

  cout<<"total occurances " <<nfound<<endl;
  return pres;
}

// helper function to encrypt an integer repeatedly into a packed plaintext
// and encrypt it
CT encrypt_repeated_integer(CryptoContext<DCRTPoly> &cc, LPPublicKey<DCRTPoly> &pk,  int64_t in, size_t n){
  
  vecInt v_in(n, in);
  PT pt= cc->MakePackedPlaintext(v_in);
  CT ct = cc->Encrypt(pk, pt);

  return ct;
}

// helper function to multiply by constant 256 using binary tree addition
CT encMultD(CryptoContext<DCRTPoly> &cc, CT in){
  if (d !=256){
    cout <<"error d not 256"<<endl;
    exit(-1);
  }
  auto tmp(in);
  for (auto i = 0; i< 8; i++ ){
	  tmp = cc->EvalAdd(tmp, tmp);
  }
  
  return(tmp);
}

//Single value encrypted search     
vecCT encrypted_search(CryptoContext<DCRTPoly> &cc,  LPPublicKey<DCRTPoly> &pk, vecCT &epat, vecCT &etxt, int ps) {

  int64_t p(ps);
  DEBUG_FLAG(false);
  size_t M = epat.size();
  DEBUGEXP(M);
  size_t N = etxt.size();
  DEBUGEXP(N);
  size_t i;

  PT dummy;
  
  size_t nrep(1);
  DEBUG("encrypting small ct");
  CT phct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for pattern
  CT thct = encrypt_repeated_integer(cc, pk, 0, nrep);  // hash value for txt

  DEBUG("encrypting hct");     
  // The value of h would be "pow(d, M-1)%p"
  int64_t h = 1;
  for (i = 0; i < M-1; i++) {
	  h = (h*d)%p;
  }
  CT hct = encrypt_repeated_integer(cc, pk, h, nrep);  // encrypted h

  DEBUG("encrypting first hashes" );     
  // Calculate the hash value of pattern and first window of text
  for (i = 0; i < M; i++) {
    auto tmp = encMultD(cc, phct);	
    phct = cc->EvalAdd(tmp, epat[i]);

    tmp = encMultD(cc, thct);
    thct = cc->EvalAdd(tmp, etxt[i]);
  }

  vecCT eres(0);
  // Slide the pattern over text one by one
  DEBUG("sliding" );     
  for (i = 0; i <= N - M; i++) {
	cout<<i<< '\r'<<flush;
	
	// Check the hash values of current window of text and pattern
	// If the hash values match then only check for characters on by one
	// subtract the two hashes, zero is equality
	DEBUG("sub" );     
	eres.push_back(cc->EvalSub(phct, thct));
     
	// Calculate hash value for next window of text: Remove leading digit,
	// add trailing digit
	if ( i < N - M ) {
	  DEBUG("rehash" );     
	  //th = (d * (th - txt[i] * h) + txt[i + M]) % p;

	  auto tmp = encMultD(cc,
						  cc->EvalSub(thct,
									  cc->EvalMult(etxt[i], hct)
									  )
						  );
	  thct = cc->EvalAdd(tmp, etxt[i+M] );

	}

  } //end for
  return eres;
}


