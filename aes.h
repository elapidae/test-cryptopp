#ifndef AES_H
#define AES_H

#include <string>

//=======================================================================================
class aes final
{
public:
    aes();
    ~aes();

    std::string encrypt( std::string msg );
    std::string decrypt( std::string cip );

    class pimpl;
    pimpl *p;
};
//=======================================================================================

#endif // AES_H
