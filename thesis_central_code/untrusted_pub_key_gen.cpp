#include "openfhe.h"
// #include <direct.h>
// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;



int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////
    int plaintextModulus = 65537;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetScalingModSize(60);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // Turn on features
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(PRE);

    // // Initialize Key Pair Containers
    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    if (!keyPair.good()) {
        std::cout << "key generation failed!" << std::endl;
        return (false);
    }

    // save off bob's keys

    // Serialize the public key
    std::string DATAFOLDER = "../bob_keys";
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
        return 1;
    }

    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
        return 1;
    }
    std::cout << "Bobs private key has been serialized." << std::endl;

    
}
