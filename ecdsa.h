#ifndef ECDSA_H
#define ECDSA_H

#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>

class ecdsa
{
public:
    //using namespace CryptoPP;
    using PrivateKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey;
    using PublicKey  = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey;

    ecdsa();

    static void find_elapidae();
    static const PrivateKey& gen_private();
    static PublicKey const& make_public( const PrivateKey& priv );
    static std::string extract_text( const PublicKey& pub );
};

#endif // ECDSA_H
