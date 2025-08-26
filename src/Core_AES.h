/*
 * Copyright (C) 2015,2018 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include "Core_BlockCipher.h"

// Determine which AES implementation to export to applications.
#if defined(ESP32)
#define CRYPTO_AES_ESP32 1
#else
#define CRYPTO_AES_DEFAULT 1
#endif

#if defined(CRYPTO_AES_DEFAULT) || defined(CRYPTO_DOC)

class Core_AESTiny128;
class Core_AESTiny256;
class Core_AESSmall128;
class Core_AESSmall256;

class AESCommon : public Core_BlockCipher
{
public:
    virtual ~AESCommon();

    size_t blockSize() const;

    void encryptBlock(uint8_t *output, const uint8_t *input);
    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

protected:
    AESCommon();

    /** @cond aes_internal */
    uint8_t rounds;
    uint8_t *schedule;

    static void subBytesAndShiftRows(uint8_t *output, const uint8_t *input);
    static void inverseShiftRowsAndSubBytes(uint8_t *output, const uint8_t *input);
    static void mixColumn(uint8_t *output, uint8_t *input);
    static void inverseMixColumn(uint8_t *output, const uint8_t *input);
    static void keyScheduleCore(uint8_t *output, const uint8_t *input, uint8_t iteration);
    static void applySbox(uint8_t *output, const uint8_t *input);
    /** @endcond */

    friend class Core_AESTiny128;
    friend class Core_AESTiny256;
    friend class Core_AESSmall128;
    friend class Core_AESSmall256;
};



class Core_AES128 : public AESCommon
{
public:
    Core_AES128();
    virtual ~Core_AES128();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint8_t sched[176];
};



class Core_AES192 : public AESCommon
{
public:
    Core_AES192();
    virtual ~Core_AES192();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint8_t sched[208];
};



class Core_AES256 : public AESCommon
{
public:
    Core_AES256();
    virtual ~Core_AES256();

    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

private:
    uint8_t sched[240];
};



class Core_AESTiny256 : public Core_BlockCipher
{
public:
    Core_AESTiny256();
    virtual ~Core_AESTiny256();

    size_t blockSize() const;
    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

    void encryptBlock(uint8_t *output, const uint8_t *input);
    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

private:
    uint8_t schedule[32];
};



class Core_AESSmall256 : public Core_AESTiny256
{
public:
    Core_AESSmall256();
    virtual ~Core_AESSmall256();

    bool setKey(const uint8_t *key, size_t len);

    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

private:
    uint8_t reverse[32];
};



class Core_AESTiny128 : public Core_BlockCipher
{
public:
    Core_AESTiny128();
    virtual ~Core_AESTiny128();

    size_t blockSize() const;
    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

    void encryptBlock(uint8_t *output, const uint8_t *input);
    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

private:
    uint8_t schedule[16];
};



class Core_AESSmall128 : public Core_AESTiny128
{
public:
    Core_AESSmall128();
    virtual ~Core_AESSmall128();

    bool setKey(const uint8_t *key, size_t len);

    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

private:
    uint8_t reverse[16];
};

#endif // CRYPTO_AES_DEFAULT





#if defined(CRYPTO_AES_ESP32)

/** @cond aes_esp_rename */

// The esp32 SDK keeps moving where aes.h is located, so we have to
// declare the API functions ourselves and make the context opaque.
//
// About the only thing the various SDK versions agree on is that the
// first byte is the length of the key in bytes.
//
// Some versions of esp-idf have a 33 byte AES context, and others 34.
// Allocate up to 40 to make space for future expansion.
#define CRYPTO_ESP32_CONTEXT_SIZE 40

// Some of the esp-idf system headers define enumerations for AES128,
// AES192, and AES256 to identify the hardware-accelerated algorithms.
// These can cause conflicts with the names we use in our library.
// Define our class names to something else to work around esp-idf.
#undef AES128
#undef AES192
#undef AES256
#define AES128 Core_AES128_ESP
#define AES192 Core_AES192_ESP
#define AES256 Core_AES256_ESP

/** @endcond */

class AESCommon : public Core_BlockCipher
{
public:
    virtual ~AESCommon();

    size_t blockSize() const;
    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

    void encryptBlock(uint8_t *output, const uint8_t *input);
    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

protected:
    AESCommon(uint8_t keySize);

private:
    uint8_t ctx[CRYPTO_ESP32_CONTEXT_SIZE];
};



class Core_AES128 : public AESCommon
{
public:
    Core_AES128() : AESCommon(16) {}
    virtual ~Core_AES128();
};



class Core_AES192 : public AESCommon
{
public:
    Core_AES192() : AESCommon(24) {}
    virtual ~Core_AES192();
};



class Core_AES256 : public AESCommon
{
public:
    Core_AES256() : AESCommon(32) {}
    virtual ~Core_AES256();
};


// The ESP32 AES context is so small that it already qualifies as "tiny".
typedef Core_AES128 Core_AESTiny128;
typedef Core_AES256 Core_AESTiny256;
typedef Core_AES128 Core_AESSmall128;
typedef Core_AES256 Core_AESSmall256;

#endif // CRYPTO_AES_ESP32

