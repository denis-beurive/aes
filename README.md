# AES implementation

## Prerequisite

### MSYS2

Install [MSYS2](https://www.msys2.org/).

#### Installation of the the build tools

Where are installed MINGW development tools ?

    C:\msys64\mingw64\bin

List all installed package:

    pacman -Q

Searching for a package:

    pacman -Ss cmake
    pacman -Ss gcc
    pacman -Ss make
    pacman -Ss libz

Install `cmake`:

    pacman -S mingw-w64-x86_64-cmake
    pacman -S mingw-w64-x86_64-gcc
    pacman -S mingw-w64-x86_64-make
    pacman -S mingw-w64-x86_64-libzip
    pacman -S mingw-w64-i686-libzip

Find `cmake`, `gcc`:

    pacman -Ql mingw-w64-x86_64-cmake
    pacman -Ql mingw-w64-ucrt-x86_64-gcc
    pacman -Ql mingw-w64-x86_64-make
    pacman -Ql mingw-w64-x86_64-libzip
    pacman -Ql mingw-w64-i686-libzip

Result:

>   * **make**: `/mingw64/bin/mingw32-make.exe`
>   * **libz-64**: `/mingw64/bin/libzip.dll`
>   * **libz-32**: `/mingw32/bin/libzip.dll`

Uninstall a package:

    pacman -Rs mingw-w64-ucrt-x86_64-gcc

#### Customization

    alias make="/mingw64/bin/mingw32-make.exe"

## Build

Execute [MSYS2](https://www.msys2.org/) shell.

    cmake .
    ninja all

## Links

AES:

* https://www.samiam.org/rijndael.html
* https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
* https://en.wikipedia.org/wiki/Rijndael_MixColumns
* https://en.wikipedia.org/wiki/Rijndael_S-box
* https://braincoke.fr/blog/2020/08/the-aes-encryption-algorithm-explained/#s-box-table
* https://github.com/m3y54m/aes-in-c?tab=readme-ov-file#aes-operations-subbytes-shiftrow-mixcolumn-and-addroundkey
* https://braincoke.fr/blog/2020/08/the-aes-encryption-algorithm-explained/#aes-in-summary
* https://www.herongyang.com/Cryptography/AES-Example-Vector-of-AES-Encryption.html
* https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-ecb.test-vectors
* https://www.davidwong.fr/blockbreakers/aes_5_state.html
* https://legacy.cryptool.org/en/cto/aes-step-by-step

C language:

* https://stackoverflow.com/questions/22842707/size-of-uint8-uint16-and-uint32  


