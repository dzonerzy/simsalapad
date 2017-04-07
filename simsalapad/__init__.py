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
from os.path import dirname, abspath
from importlib import import_module
from ast import literal_eval
from ntpath import basename
import sys

__all__ = ["PaddingOracle"]

class PaddingOracle(object):
    _plaintext = ""
    _oracle = None
    _IV = None
    _oracle_module = None
    _path = None
    _as_library = False

    def __init__(self, oracle_path=None, iv=None, oracle=None):
        if oracle_path is not None:
            self._path = oracle_path
        else:
            if iv is not None and oracle is not None:
                if type(iv) == list and len(iv) > 0:
                    self._IV = iv
                else:
                    raise("IV object must be a list of integer greater than 0")
                if callable(oracle):
                    self._oracle = oracle
                else:
                    raise("Oracle object must be a method")
            else:
                raise("You must specify and IV and an oracle method")

    def error(self, text):
        sys.stderr.write("[ERROR] {0}\n".format(text))

    def info(self, text):
        sys.stdout.write("[INFO] {0}\n".format(text))

    def _remove_padding(self, data):
        if 0 < ord(data[-1]) <= 0x10:
            if data[-ord(data[-1]):] != data[-1]*ord(data[-1]):
                return False
            return data[:-ord(data[-1])]
        return data

    def _load_oracle(self, path):
        sys.path.append(dirname(abspath(path)))
        try:
            self._oracle_module= import_module(basename(path)[:-3])
            self._oracle = self._oracle_module.oracle
            if type(self._oracle_module.IV) == str:
                IV = map(ord, list(self._oracle_module.IV))
            self._IV = IV
        except ImportError:
            if not self._as_library:
                self.error("Your oracle module must implement an IV and an oracle method!")
            sys.exit(-1)

    def _crack_block(self, org_previous_block, next_block, oracle):
        dummy_block = list([0] * 16)
        half_plain = ""
        for reverse_position in range(1, len(next_block)+1):
            for byte_guess in range(0, 256):
                dummy_block[-reverse_position] = byte_guess
                tmp = "".join(chr(k) for k in dummy_block) + "".join(chr(k) for k in next_block)
                if oracle(tmp):
                    half_plain = chr(reverse_position ^ org_previous_block[-reverse_position] ^ byte_guess) + half_plain
                    for pad_reverse_position in range(1, reverse_position+1):
                        dummy_block[-pad_reverse_position] ^= reverse_position ^ reverse_position+1
                    break
        return half_plain

    def attack(self, ciphertext):
        if self._IV is None and self._oracle is None:
            self._load_oracle(self._path)
        else:
            self._as_library = True
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        C = [self._IV] + [map(ord, list(b)) for b in blocks]
        for i in xrange(0,len(C)-1):
            self._plaintext += self._crack_block(list(C[i]), list(C[i+1]), self._oracle)
        if self._as_library:
            return self._remove_padding(self._plaintext)
        else:
            self.info("Plaintext recovered: {0}".format(self._remove_padding(self._plaintext)))