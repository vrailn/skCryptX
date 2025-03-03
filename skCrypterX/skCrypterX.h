#pragma once


/*____________________________________________________________________________________________________________

Original Author: skadro
Github: https://github.com/skadro-official
License: See end of file

skCrypter
		Compile-time, Usermode + Kernelmode, safe and lightweight string crypter library for C++11+

							*Not removing this part is appreciated*
____________________________________________________________________________________________________________*/


#ifdef _KERNEL_MODE
namespace std
{
    template <class _Ty>
    struct remove_reference {
        using type = _Ty;
    };

    template <class _Ty>
    struct remove_reference<_Ty&> {
        using type = _Ty;
    };

    template <class _Ty>
    struct remove_reference<_Ty&&> {
        using type = _Ty;
    };

    template <class _Ty>
    using remove_reference_t = typename remove_reference<_Ty>::type;

    template <class _Ty>
    struct remove_const {
        using type = _Ty;
    };

    template <class _Ty>
    struct remove_const<const _Ty> {
        using type = _Ty;
    };

    template <class _Ty>
    using remove_const_t = typename remove_const<_Ty>::type;
}
#else
#include <type_traits>
#endif

namespace skc
{
    template<class _Ty>
    using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

    constexpr uint32_t _fnv1a(const char* str)
    {
        uint32_t hash = 2166136261u;
        uint32_t primes[] = { 20312767, 20400413, 20507437, 20621087, 20731397, 20849741, 20973761 };

        size_t i = 0;
        while (*str)
        {
            hash ^= static_cast<unsigned char>(*str++);
            hash *= primes[i % (sizeof(primes) / sizeof(primes[0]))];
            i++;
        }
        return hash;
    }

    constexpr uint32_t _seed()
    {
        return _fnv1a(__FILE__)
            ^ _fnv1a(__TIME__)
            ^ static_cast<uint32_t>(__LINE__)
            ^ static_cast<uint32_t>(__COUNTER__);
    }

    constexpr uint32_t combine_integers(uint32_t a, uint32_t b)
    {
        return a ^ b;
    }

    template <int _size, uint32_t _key, typename T>
    class skCrypterX
    {
    public:
        __forceinline constexpr skCrypterX(T* data)
        {
            crypt(data);
        }

        __forceinline T* get()
        {
            return _storage;
        }

        __forceinline int size() // (w)char count
        {
            return _size;
        }

        __forceinline uint32_t key()
        {
            return _key;
        }

        __forceinline T* encrypt()
        {
            if (!isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline T* decrypt()
        {
            if (isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline bool isEncrypted()
        {
            return _storage[_size - 1] != 0;
        }

        __forceinline void clear() // set full storage to 0
        {
            for (int i = 0; i < _size; i++)
            {
                _storage[i] = 0;
            }
        }

        __forceinline operator T* ()
        {
            decrypt();
            return _storage;
        }

    private:
        __forceinline constexpr void crypt(T* data)
        {
            uint32_t combined_key = _key;

            for (int i = 0; i < _size; i++)
            {
                _storage[i] = data[i] ^ static_cast<char>((combined_key >> (i % 4 * 8)) & 0xFF);
            }
        }

        T _storage[_size]{};
    };
}

#define skCryptX(str) skCrypt_keyX(str, skc::_seed())
#define skCrypt_keyX(str, key) []() { \
            constexpr static auto crypted = skc::skCrypterX \
                <sizeof(str) / sizeof(str[0]), key, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
                    return crypted; }()

/*________________________________________________________________________________

MIT License

Copyright (c) 2020 skadro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

________________________________________________________________________________*/
