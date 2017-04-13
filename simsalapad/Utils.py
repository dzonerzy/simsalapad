"""
The MIT License (MIT)

Copyright (c) 2016

    The Zero <io@thezero.org>
    Daniele Linguaglossa <danielelinguaglossa@gmail.com>

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
FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import binascii

class Utils(object):

    def splitBlocks(self, ciphertext, block_size):
        return [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    def xorForNextPadding(self, block, current_padding_position):
        for pad_reverse_position in range(1, current_padding_position+1):
            block[-pad_reverse_position] ^= current_padding_position ^ current_padding_position+1

    def strXor(self, string_a, string_b):
        tmp = ""
        for i in range(0, len(string_a)):
            tmp += chr(ord(string_a[i]) ^ ord(string_b[i]))
        return tmp

    def strStrXor(self, string_a, string_b, string_c):
        tmp = ""
        for i in range(0, len(string_a)):
            tmp += chr(ord(string_a[i]) ^ ord(string_b[i]) ^ ord(string_c[i]))
        return tmp

    def block2Hex(self, block):
        if type(block) == list and type(block[0]) == int:
            return binascii.hexlify("".join(chr(x) for x in block)).upper()
        elif type(block) == str:
            return binascii.hexlify(block).upper()
        elif type(block) == list and type(block[0][0]) == str:
            return binascii.hexlify(block[0][0]).upper()

    def unHex(self, block):
        return [binascii.unhexlify(block[0])]

    def unHexOrd(self, block):
        return map(ord, list(binascii.unhexlify(block)))

    def hex2Block(self, hex):
        block = binascii.unhexlify(hex)
        return map(ord, list(block))
