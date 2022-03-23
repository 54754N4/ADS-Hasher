# ADS Hasher

Hashes files while taking into account their alternate data streams. Most hashers only use the default stream. This program hashes each stream separately then concatenates them using an unambiguous delimiter to allow each unique combination of inputs to have a unique output.

# Usage

```
Usage: hasher.exe <OPTIONS> <file>
Options:
        -h,--help       Prints this help message
        -n,--no-ads     Hashes default stream only
        -md5    Includes MD5 hash
        -sha1   Includes SHA1 hash
        -sha256 Includes SHA256 hash
        -sha384 Includes SHA384 hash
        -sha512 Includes SHA512 hash
```

