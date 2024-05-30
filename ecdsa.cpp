#include "ecdsa.h"

#include "vlog.h"
#include <iostream>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include "vbyte_buffer.h"
#include "vtime_meter.h"
#include <set>

using namespace std;
using namespace CryptoPP;

std::string ECDSA_createSignature(std::string message, CryptoPP::AutoSeededRandomPool &prng, CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privateKey) {
    std::string signature;
    std::string output;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(privateKey);
    CryptoPP::StringSource(message, true,
        new CryptoPP::SignerFilter(prng, signer,
            new CryptoPP::StringSink(signature)
        ) //SignerFilter
    ); //StringSource

    CryptoPP::StringSource(signature, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) //HexEncoder
    ); //StringSource
    return output;
}

bool ECDSA_verifySignature(std::string message, std::string signature, CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> publicKey) {
    std::string decoded;
    std::string output;
    bool result = false;

    CryptoPP::StringSource(signature, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(decoded)
        ) //StringSink
    ); //StringSource

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(publicKey);
    CryptoPP::StringSource(message+decoded, true,
        new CryptoPP::SignatureVerificationFilter(
            verifier,
            new CryptoPP::ArraySink((CryptoPP::byte*) &result, sizeof(result)),
                CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_END
        ) //SignatureVerificationFilter
    ); //StringSource
    return result;
}

template<class> class TD;

ecdsa::ecdsa()
{
    find_elapidae();

    CryptoPP::AutoSeededRandomPool prng;

    {
        ECDSA<ECP, SHA256>::PrivateKey k1;
        //k1.Initialize( prng, ASN1::secp256k1() );
        k1.Initialize( prng, ASN1::secp256k1() );

        const Integer& x1 = k1.GetPrivateExponent();
        vdeb << "K1: " << x1;

        ECDSA<ECP, SHA256>::PublicKey p1;
        k1.MakePublicKey( p1 );

        const auto& pub1 = p1.GetPublicElement();
        vdeb << "pub-X1:" << pub1.x;
        vdeb << "pub-Y1:" << pub1.y;

        auto ec = p1.GetGroupParameters().GetCurve();
        vdeb << "A:" << ec.GetA();
        vdeb << "B:" << ec.GetB();
        vdeb << "Field modu:" << ec.GetField().GetModulus();
        vdeb << "Field size:" << ec.FieldSize();
        vdeb << "Field:" << ec.GetField().GetModulus();

        FileSink fs("test-ecdsa.pem", false);
        p1.Save( fs );

        //ECDSA<ECP, SHA256>::PublicKey pubKey;

        OID sec = CryptoPP::ASN1::secp256k1();
        //sec.DEREncode()
        //sec.Print(cout);
        //TD<decltype(sec)> fff;

        return;
    }

    std::string msg1 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exerci";
    std::string signature;

    std::chrono::_V2::system_clock::time_point start, end;
    std::chrono::microseconds duration;

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privateKey;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params(CryptoPP::ASN1::secp256k1());
    privateKey.Initialize(prng, params);
    vdeb << privateKey.GetAlgorithmID();

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        signature = ECDSA_createSignature(msg1, prng, privateKey);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << "Message: " << msg1 << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

}
//=======================================================================================
static std::string get_only_nick( std::string str )
{
    int pos = 0;
    int size = str.size();

    // 1. find # or @ or $
    for ( ; pos < size; ++pos )
    {
        auto c = str[pos];
        if ( c == '@' || c == '#' || c == '$' )
        {
            return str.substr( pos );
        }
    }
    return {};
}
//=======================================================================================
void ecdsa::find_elapidae()
{
    std::string tmpl = "@elapidae";
    auto sz = tmpl.size();
    vtime_meter tm;
    long cnt = 0;
    int printed = 1;
    while (1)
    {
        ++cnt;
        if ( tm.elapsed().sec().count() > 15 * printed )
        {
            vdeb << cnt << "rounds," << tm.elapsed().sec() << ", still running...";
            printed += 1;
        }
        auto priv = gen_private();
        auto pub = make_public(priv);
        auto text = extract_text(pub);
        text = get_only_nick(text);
        if ( text.size() < 4 ) continue;
        int i;
        for ( i = 1; i < sz; ++i )
        {
            if ( text[i] != tmpl[i] ) break;
        }
        if ( i < 5 ) continue;

        printed = 1;
        auto elapsed = tm.restart().sec();
        vdeb << text << elapsed;
        FileSink f( (text.substr(1) + ".der").c_str() );
        priv.Save( f );
    }
}
//=======================================================================================
static CryptoPP::AutoSeededRandomPool prng;
static ecdsa::PrivateKey ec_private_key;
static ecdsa::PublicKey  ec_public_key;
ecdsa::PrivateKey const& ecdsa::gen_private()
{
    ec_private_key.Initialize( prng, ASN1::secp256k1() );
    return ec_private_key;
}
//=======================================================================================
ecdsa::PublicKey const& ecdsa::make_public( const PrivateKey &priv )
{
    priv.MakePublicKey( ec_public_key );
    return ec_public_key;
}
//=======================================================================================
string ecdsa::extract_text( const PublicKey& pub )
{
    string res;
    const auto& el = pub.GetPublicElement();

    auto proc_int = [&](auto & x)
    {
        for ( auto i = 0; i < x.ByteCount(); ++i )
        {
            auto c = x.GetByte(i);
            if ( c >= 'A' && c <= 'Z' ) c += ( 'a' - 'A' ); // correct up case to low case

            if ( c >= '0' && c <= '9' ) { res.push_back( c ); continue; }
            if ( c >= 'a' && c <= 'z' ) { res.push_back( c ); continue; }
            if ( c == '_' ) { res.push_back( c ); continue; }
            if ( c == '@' ) { res.push_back( c ); continue; }
            if ( c == '#' ) { res.push_back( c ); continue; }
            if ( c == '$' ) { res.push_back( c ); continue; }
        }
    };
    proc_int( el.x );
    proc_int( el.y );
    return res;
}
//=======================================================================================

static auto _text = []
{
    set<char> res;
    for (auto c = '0'; c < '9'; ++c) res.insert( c );
    for (auto c = 'A'; c < 'Z'; ++c) res.insert( c );
    for (auto c = 'a'; c < 'z'; ++c) res.insert( c );
    res.insert( '!' );
    res.insert( '@' );
    res.insert( '#' );
    res.insert( '$' );
    res.insert( '%' );
    res.insert( '&' );
    res.insert( '*' );
    res.insert( '(' );
    res.insert( ')' );
    res.insert( '[' );
    res.insert( ']' );
    res.insert( '{' );
    res.insert( '}' );
    res.insert( '<' );
    res.insert( '>' );
    res.insert( '/' );
    res.insert( '?' );
    res.insert( '.' );
    res.insert( ',' );
    res.insert( ';' );
    res.insert( ':' );
    res.insert( '+' );
    res.insert( '-' );
    res.insert( '_' );
    res.insert( '=' );
    res.insert( '~' );
    return res;
}();
