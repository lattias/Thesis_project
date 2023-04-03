#ifndef SERIALIZEVECTOR_H
#define SERIALIZEVECTOR_H

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


using namespace lbcrypto;
using namespace std;
using namespace cereal;

//data types we will need
using CT = lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ; //ciphertext
using PT = lbcrypto::Plaintext ; //plaintext
using vecCT = vector<CT>; //vector of ciphertexts
using vecPT = vector<PT>; //vector of plaintexts
using vecInt = vector<int64_t>; // vector of ints
using vecChar = vector<char>; // vector of characters

//forward declarations


class SerializeVector
{
public:
    friend class cereal::access;
    template <class Archive>
    int serializeme();
    int deserializeme();
};

#endif