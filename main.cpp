/*

https://github.com/hieunguyen1053/cryptopp-example/blob/master/AES-CFB-mode.cpp

*/

#include "mainwindow.h"

#include <QApplication>
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

#include "ecdsa.h"


static vbyte_buffer init( unsigned char * data, size_t size )
{
    auto v = static_cast<void *>(data);
    auto c = static_cast<char *>(v);
    return std::string(c, size);
}

using namespace CryptoPP;


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


int main(int argc, char *argv[])
{
    ecdsa _; (void)_;
    return 0;

    AutoSeededRandomPool prng;

    SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    //byte key[AES::DEFAULT_KEYLENGTH];
    //prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    vdeb << "AES key, iv sizes:" << AES::DEFAULT_KEYLENGTH << AES::BLOCKSIZE;
    vdeb << "AES key:" << init(key, AES::DEFAULT_KEYLENGTH).tohex();
    vdeb << "AES iv: " << init(iv, AES::BLOCKSIZE).tohex();

    std::string msg5 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exerci";

    std::string cipher = aes_cbc_mode_encrypt( msg5, key, iv );
    vdeb << "encrypted:" << cipher;
    vdeb << "AES iv: " << init(iv, AES::BLOCKSIZE).tohex();

    auto dec = aes_cbc_mode_decrypt( cipher, key, iv );
    vdeb << "decrypted:" << dec;

    return 0;

    ed25519::Signer signer;
    signer.AccessPrivateKey().GenerateRandom(prng);

    const ed25519PrivateKey& privKey = dynamic_cast<const ed25519PrivateKey&>(signer.GetPrivateKey());
    const Integer& x = privKey.GetPrivateExponent();
    privKey.GetPublicKeyBytePtr();
    std::cout << x << std::endl;

    ed25519::Verifier verifier(signer);

//    signer.Sign()
    return 0;


    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
