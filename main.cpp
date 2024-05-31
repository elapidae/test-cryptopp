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
#include <crypto++/base64.h>
#include <crypto++/basecode.h>
#include <crypto++/secblock.h>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>

#include <iostream>
#include "vlog.h"
#include "vbyte_buffer.h"

#include "ecdsa.h"
#include "aes.h"

using namespace CryptoPP;

static vbyte_buffer init( unsigned char * data, size_t size )
{
    auto v = static_cast<void *>(data);
    auto c = static_cast<char *>(v);
    return std::string(c, size);
}

int main(int argc, char *argv[])
{
    ecdsa _; (void)_;
    return 0;

    std::string msg = "Lorem ipsum dor";
    aes es;
    for ( int i = 0; i < 10; ++i)
    {
        auto c = es.encrypt( msg );
        auto d = es.decrypt( c );
        vdeb << vbyte_buffer(c).tohex() << "||" << d;
    }
    return 0;
//    QApplication a(argc, argv);
//    MainWindow w;
//    w.show();
//    return a.exec();
}


//    ed25519::Signer signer;
//    signer.AccessPrivateKey().GenerateRandom(prng);

//    const ed25519PrivateKey& privKey = dynamic_cast<const ed25519PrivateKey&>(signer.GetPrivateKey());
//    const Integer& x = privKey.GetPrivateExponent();
//    privKey.GetPublicKeyBytePtr();
//    std::cout << x << std::endl;

//    ed25519::Verifier verifier(signer);

////    signer.Sign()
//    return 0;


