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
from . import PaddingOracle
import argparse
import base64
import sys


def main():
    args = argparse.ArgumentParser(description="Padding Oracle attack made easy")
    args.add_argument("path", metavar="PATH", help="Path to the oracle (python file)", type=str)
    args.add_argument("ciphertext", metavar="CIPHERTEXT", help="Ciphertext that should be cracked", type=str)
    args.add_argument("-b", action="store_true", help="Base64 decode the ciphertext before start", default=False,
                      dest="base64")
    args = args.parse_args()
    padding_oracle = PaddingOracle(args.path)
    try:
        padding_oracle.info("Starting bruteforce...")
        if args.base64:
            try:
                args.ciphertext = base64.b64decode(args.ciphertext)
            except TypeError:
                padding_oracle.error("Please insert a valid base64")
                sys.exit(-1)
        else:
            args.ciphertext = literal_eval(args.ciphertext)
        padding_oracle.attack(args.ciphertext)
    except Exception as e:
        padding_oracle.error("Something goes wrong => {0}".format(e))

if __name__ == "__main__":
    main()