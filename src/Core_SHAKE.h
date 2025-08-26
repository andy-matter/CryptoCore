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

#include "Core_XOF.h"
#include "Core_KeccakCore.h"

class Core_SHAKE : public Core_XOF
{
public:
    virtual ~Core_SHAKE();

    size_t blockSize() const;

    void reset();
    void update(const void *data, size_t len);

    void extend(uint8_t *data, size_t len);
    void encrypt(uint8_t *output, const uint8_t *input, size_t len);

    void clear();

protected:
    Core_SHAKE(size_t capacity);

private:
    Core_KeccakCore core;
    bool finalized;
};

class Core_SHAKE128 : public Core_SHAKE
{
public:
    Core_SHAKE128() : Core_SHAKE(256) {}
    virtual ~Core_SHAKE128();
};

class Core_SHAKE256 : public Core_SHAKE
{
public:
    Core_SHAKE256() : Core_SHAKE(512) {}
    virtual ~Core_SHAKE256();
};

