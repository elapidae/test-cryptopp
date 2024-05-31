#ifndef ECDSA_H
#define ECDSA_H

#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include "vbyte_buffer.h"

class ecdsa
{
public:
    //using namespace CryptoPP;
    using PrivateKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey;
    using PublicKey  = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey;

    ecdsa();

    static void lets_elap();

    static void follow_example();
    static void follow_priv_example();

    static void find_elapidae();
    static const PrivateKey& gen_private();
    static PublicKey const& make_public( const PrivateKey& priv );
    static std::string extract_text( const PublicKey& pub );
    static std::string hex_public( const PublicKey& pub );

    static std::string from_hex( std::string hex );

    static vbyte_buffer int_to_hex( CryptoPP::Integer const & val );

    static std::string sha256_hex( std::string data );
    static std::string sha256_bin( std::string data );
    static std::string ripemd160_hex( std::string data );

    static std::string to_base58( std::string data );
    static std::string from_base58( std::string data );
};

extern "C" {
    bool sha256_impl_for_b58(void *digest, const void *data, size_t datasz);
}

#endif // ECDSA_H
