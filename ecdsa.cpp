/*
https://github.com/bitcoin/libbase58/blob/master/base58.c
https://en.bitcoin.it/wiki/Base58Check_encoding
https://en.bitcoin.it/wiki/Wallet_import_format
*/

#include "ecdsa.h"

#include "vlog.h"
#include <iostream>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include <cryptopp/ripemd.h>
#include "vtime_meter.h"
#include <set>
#include "vcat.h"
#include "libbase58.h"

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
    follow_priv_example();
    return;

    follow_example();
    return;

    lets_elap();
    return;

    find_elapidae();
    return;

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
static string bin( CryptoPP::Integer ii )
{
    string res;
    for ( int i = 0; i < ii.ByteCount(); ++i )
        res.push_back( ii.GetByte(i) );
    return res;
}

void ecdsa::lets_elap()
{
    auto elap_path = "/home/el/red/SOURCES/ELAP-ECDSA-KEYS/elap3d.der";
    FileSource f( elap_path, true );
    PrivateKey priv;
    priv.Load( f );
    vdeb << priv.GetAlgorithmID();
    PublicKey pub1, pub2;
    priv.MakePublicKey(pub1);

    ECPPoint pt = pub1.GetPublicElement();
    auto hex = hex_public(pub1);
    vdeb << hex << hex.size();
    return;

    auto x = bin(pub1.GetPublicElement().y);
    for ( auto c: x )
    {
        vdeb.hex() << int(c) << "(" << c << ")";
    }
    auto y = bin(pub1.GetPublicElement().y);
    for ( auto c: y )
    {
        vdeb.hex() << int(c) << "(" << c << ")";
    }
}
/*
https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
*/
void ecdsa::follow_example()
{
    AutoSeededRandomPool prng;

    auto _priv_key = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725h";
    Integer _priv_exp( _priv_key );

    //auto _priv0 = gen_private();
    //auto _priv_key = from_hex( _priv_key_h );
    PrivateKey priv_key;
    //priv_key.Initialize( prng, ASN1::secp256k1() );
    priv_key.AccessGroupParameters() = ASN1::secp256k1();
    priv_key.SetPrivateExponent( _priv_exp );

    if ( !priv_key.Validate(prng, 16) )
        vwarning << "checking fail";

    vdeb.hex() << _priv_exp << priv_key.GetAlgorithmID();

    PublicKey pub_key;
    priv_key.MakePublicKey(pub_key);

    vdeb << hex << pub_key.GetPublicElement().x;
    vdeb << int_to_hex( pub_key.GetPublicElement().x );

    std::string y_even = pub_key.GetPublicElement().y.IsEven() ? "02" : "03";
    auto xx = y_even + int_to_hex( pub_key.GetPublicElement().x );
    auto xxtest = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
    assert(xx == xxtest);

    auto shaxx = sha256_hex( vbyte_buffer::from_hex(xx) );
    auto shaxxtest = "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98";
    assert( shaxx == shaxxtest );

    auto ripemd160 = ripemd160_hex( vbyte_buffer::from_hex(shaxx) );
    auto ripemdtest = "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31";
    assert( ripemd160 == ripemdtest );

    auto main_network = "00";
    ripemd160 = main_network + ripemd160;

    auto sha2 = sha256_hex( vbyte_buffer::from_hex(ripemd160) );
    auto sha2test = "ad3c854da227c7e99c4abfad4ea41d71311160df2e415e713318c70d67c6b41c";
    assert( sha2 == sha2test );

    auto sha3test = "c7f18fe8fcbed6396741e58ad259b5cb16b7fd7f041904147ba1dcffabf747fd";
    auto sha3 = sha256_hex( vbyte_buffer::from_hex(sha2) );
    assert( sha3 == sha3test );

    auto checksum = vbyte_buffer::from_hex(sha3).left(4);
    vdeb << vbyte_buffer(checksum).tohex() << "c7f18fe8";

    auto addr = vbyte_buffer::from_hex(ripemd160) + checksum;
    assert( addr == vbyte_buffer::from_hex("00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8") );

    auto wallet = to_base58( addr );
    vdeb << wallet << " 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";

    follow_priv_example();
}
//=======================================================================================
void ecdsa::follow_priv_example()
{
    vdeb << "========= priv =============";
    AutoSeededRandomPool prng;

    // 1. Take a private key. 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    string priv_exp_hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
    auto priv_exp_bin = vbyte_buffer::from_hex(priv_exp_hex);

    //2. Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses. Also add a 0x01 byte at the end if the private key will correspond to a compressed public key.
    auto prefix = string( true ? "80": "ef" );
    auto s2_hex = prefix + priv_exp_hex;
    auto s2_bin = vbyte_buffer::from_hex(s2_hex);

    //3. Perform SHA-256 hash on the extended key.
    string s3_test = "8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592";
    s3_test = vbyte_buffer::from_hex(s3_test).tohex();
    auto s3_hex = sha256_hex( s2_bin );
    assert( s3_hex == s3_test );

    //4. Perform SHA-256 hash on result of SHA-256 hash.
    string s4_test = "507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714";
    s4_test = vbyte_buffer::from_hex(s4_test).tohex();
    auto s4_hex = sha256_hex( vbyte_buffer::from_hex(s3_hex) );
    assert( s4_hex == s4_test );

    // 5. Take the first 4 bytes of the second SHA-256 hash; this is the checksum.
    auto s5_sum = vbyte_buffer::from_hex(s4_hex).left(4);
    vdeb << s5_sum.toHex() << "507A5B8D";

    //6. Add the 4 checksum bytes from point 5 at the end of the extended key from point 2.
    string s6_test = "800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D";
    auto s6_bin = s2_bin + s5_sum;
    assert( s6_bin == vbyte_buffer::from_hex(s6_test) );

    // 7. Convert the result from a byte string into a base58 string using Base58Check encoding.
    //    This is the wallet import format (WIF).
    auto s7_test = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    auto s7_b58 = to_base58( s6_bin );
    assert( s7_test == s7_b58 );

    b58_sha256_impl = sha256_impl_for_b58;

    auto ok =
    //b58check( priv_exp_bin.data(), priv_exp_bin.size(), s7_b58.c_str(), s7_b58.size() );
    b58check( s6_bin.data(), s6_bin.size(), s7_b58.c_str(), s7_b58.size() );
    vdeb << "b58 check:" << ok;

    std::string res; res.resize( priv_exp_bin.size() * 2 + 1 );
    size_t sz = res.size();
    auto encoded =
    b58check_enc( res.data(), &sz, 0x80, priv_exp_bin.data(), priv_exp_bin.size() );
    if (sz > 0) sz -= 1; // remove zero terminate
    res.resize(sz);
    vdeb << "encoded:" << encoded << res;
    assert(res == s7_test);
//    PrivateKey priv_key;
//    priv_key.AccessGroupParameters() = ASN1::secp256k1();
//    priv_key.SetPrivateExponent( _priv_k );

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
string ecdsa::hex_public( const PublicKey &pub )
{
    std::string res;
    auto &x = pub.GetPublicElement().x;
    auto &y = pub.GetPublicElement().y;

    //x.Encode()
    std::stringstream ss;
    ss << std::hex << x << " " << y;
    return ss.str();
}
//=======================================================================================
string ecdsa::from_hex( std::string hex )
{
    string res;
    CryptoPP::StringSource(hex, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(res)
        ) //StringSink
    ); //StringSource
    return res;

    ByteQueue queue;
    HexEncoder he;

}
//=======================================================================================
vbyte_buffer ecdsa::int_to_hex( const CryptoPP::Integer &val )
{
//    vbyte_buffer res;
//    for ( int i = 0; i < val.ByteCount(); ++i )
//        res.append( val.GetByte(i) );
//    return res.tohex();
    stringstream ss;
    ss << hex << val;
    auto str = ss.str();
    return str.substr(0, str.size() - 1);
}


//=======================================================================================
string ecdsa::sha256_hex(std::string data)
{
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter
        ( hash,
            new CryptoPP::HexEncoder
            (
                new CryptoPP::StringSink(digest), false
            )
        )
    );

    return digest;
}
//=======================================================================================
auto _sha256_bin_test_ = []()
{
    auto m1 = vbyte_buffer::from_hex(ecdsa::sha256_hex("1"));
    auto m2 = ecdsa::sha256_bin("1");
    if (m1 != m2) throw verror;
    return 0;
}();
string ecdsa::sha256_bin(std::string data)
{
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter
        ( hash, new CryptoPP::StringSink(digest), false )
    );

    return digest;
}
//=======================================================================================
string ecdsa::ripemd160_hex( std::string data )
{
    std::string digest;
    CryptoPP::RIPEMD160 hash;

    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter
        ( hash,
            new CryptoPP::HexEncoder
            (
                new CryptoPP::StringSink(digest), false
            )
        )
    );

    return digest;
}
//=======================================================================================
string ecdsa::to_base58( std::string data )
{
    std::string res;
    res.resize( data.size() * 2 );
    size_t out_size = res.size();
    auto ok = b58enc( res.data(), &out_size, data.c_str(), data.size() );
    if (!ok) throw verror;
    res.resize( out_size - 1 ); // without zero
    return res;
}
//=======================================================================================
string ecdsa::from_base58(std::string data)
{
    throw verror;
}
//=======================================================================================

//=======================================================================================
extern "C" {
    bool sha256_impl_for_b58(void *digest, const void *data, size_t datasz)
    {
        std::string d( static_cast<const char*>(data), datasz );
        auto sha = ecdsa::sha256_bin(d);
        std::copy( sha.begin(), sha.end(), static_cast<char*>(digest) );
        return true;
    }
}
//=======================================================================================
