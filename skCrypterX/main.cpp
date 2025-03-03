#include "skCrypterX.h"
#include <iostream>

int main()
{
    
    auto test_string = skCryptX("TestString");                         //encrypt at compile-time

    auto test_string2 = "TestString 0x2";                              // non encrypted string 

   // printf(test_string2);
    
    printf(skCryptX("Decrypted: %s\n"), test_string.decrypt());       // print the decrypted string

        
    test_string.encrypt();                                            // re-encrypt the string
        
    
    printf(skCryptX("Encrypted: %s\n"), test_string.get());           // print the re-encrypted string

    getchar();

    return 0;
}
