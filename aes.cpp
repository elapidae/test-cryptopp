#include "aes.h"

#include <crypto++/xed25519.h>
#include <crypto++/osrng.h>
#include <crypto++/aes.h>
#include <crypto++/cryptlib.h>
#include <crypto++/hex.h>
#include <crypto++/secblock.h>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>

#include <iostream>
#include "vlog.h"
#include "vbyte_buffer.h"
#include <memory>


using namespace CryptoPP;


//=======================================================================================
std::string aes_cbc_mode_encrypt(std::string &plain, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    std::string cipher;
    std::string output;

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e(key, key.size(), iv);

        CryptoPP::StringSource(plain, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) // HexEncoder
    ); // StringSource
    return output;
}
//=======================================================================================
std::string aes_cbc_mode_decrypt(std::string &encoded, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    std::string cipher;
    std::string output;

    CryptoPP::StringSource(encoded, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(cipher)
        ) //HexDecoder
    ); //StringSource

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d(key, key.size(), iv);
        CryptoPP::StringSource(cipher, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(output)
            ) //StreamTransformationFilter
        ); //StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
    return output;
}
//=======================================================================================
class aes::pimpl
{
public:
    using Encryption = CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption;
    using Decryption = CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption;

    pimpl()
        : key( CryptoPP::AES::DEFAULT_KEYLENGTH )
    {
        AutoSeededRandomPool prng;
        prng.GenerateBlock( key, key.size() );
        prng.GenerateBlock( iv, sizeof(iv) );

        e.reset( new Encryption(key, key.size(), iv) );
        d.reset( new Decryption(key, key.size(), iv) );
    }

    SecByteBlock key;
    byte iv[AES::BLOCKSIZE];

    std::unique_ptr<Encryption> e;
    std::unique_ptr<Decryption> d;
};
//=======================================================================================
aes::aes()
{
    p = new pimpl;
}
//=======================================================================================
aes::~aes()
{
    delete p;
}
//=======================================================================================
std::string aes::encrypt( std::string msg )
{
    //CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e(p->key, p->key.size(), p->iv);
    std::string cipher;

    CryptoPP::StringSource(msg, true,
        new CryptoPP::StreamTransformationFilter(*p->e.get(),
            new CryptoPP::StringSink(cipher)
        ) //StreamTransformationFilter
    ); // StringSource

    return cipher;
}
//=======================================================================================
std::string aes::decrypt( std::string cipher )
{
    //CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d(p->key, p->key.size(), p->iv);
    std::string output;

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::StreamTransformationFilter(*p->d.get(),
            new CryptoPP::StringSink(output)
        ) //StreamTransformationFilter
    ); //StringSource

    return output;
}
//=======================================================================================
