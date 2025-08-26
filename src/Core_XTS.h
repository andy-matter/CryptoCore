/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
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

class Core_XTSSingleKeyCommon;

class Core_XTSCommon
{
public:
    virtual ~Core_XTSCommon();

    virtual size_t keySize() const;
    size_t tweakSize() const;

    size_t sectorSize() const { return sectSize; }
    bool setSectorSize(size_t size);

    virtual bool setKey(const uint8_t *key, size_t len);
    bool setTweak(const uint8_t *tweak, size_t len);

    void encryptSector(uint8_t *output, const uint8_t *input);
    void decryptSector(uint8_t *output, const uint8_t *input);

    void clear();

protected:
    Core_XTSCommon();
    void setBlockCiphers(Core_BlockCipher *cipher1, Core_BlockCipher *cipher2)
    {
        blockCipher1 = cipher1;
        blockCipher2 = cipher2;
    }

private:
    Core_BlockCipher *blockCipher1;
    Core_BlockCipher *blockCipher2;
    uint32_t twk[4];
    size_t sectSize;

    friend class Core_XTSSingleKeyCommon;
};


class Core_XTSSingleKeyCommon : public Core_XTSCommon
{
public:
    virtual ~Core_XTSSingleKeyCommon();

    size_t keySize() const;
    bool setKey(const uint8_t *key, size_t len);

protected:
    Core_XTSSingleKeyCommon() : Core_XTSCommon() {}
};


template <typename T1, typename T2 = T1>
class Core_XTS : public Core_XTSCommon
{
public:
    Core_XTS() { setBlockCiphers(&cipher1, &cipher2); }
    ~Core_XTS() {}

private:
    T1 cipher1;
    T2 cipher2;
};


template <typename T>
class Core_XTSSingleKey : public Core_XTSSingleKeyCommon
{
public:
    Core_XTSSingleKey() { setBlockCiphers(&cipher, &cipher); }
    ~Core_XTSSingleKey() {}

private:
    T cipher;
};

