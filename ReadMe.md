# ADS Hasher

Hashes files while taking into account their alternate data streams. Most hashers only use the default stream. This program hashes each stream separately then concatenates them using an unambiguous delimiter to allow each unique combination of inputs to have a unique output.

# Usage

```
Usage: hasher.exe <OPTIONS> <file>
Options:
        -h,--help       Prints this help message
        -n,--no-ads     Hashes default stream only
        -md5            Includes MD5 hash
        -sha1           Includes SHA1 hash
        -sha256         Includes SHA256 hash
        -sha384         Includes SHA384 hash
        -sha512         Includes SHA512 hash
```

# Examples

By listing the directory where `test.txt` is stored, we can see there's an alternate data stream used called `stream1.txt`:

```
$ dir /R

03/23/2022  03:06 PM    <DIR>          .
03/23/2022  03:06 PM    <DIR>          ..
03/23/2022  12:26 AM    <DIR>          ADS Hasher
03/23/2022  12:26 AM               218 ADS Hasher.csproj
03/23/2022  12:26 AM             1,125 ADS Hasher.sln
03/23/2022  12:26 AM    <DIR>          bin
03/23/2022  01:01 AM    <DIR>          obj
03/23/2022  03:06 PM            10,244 Program.cs
03/23/2022  03:06 PM               694 ReadMe.md
03/23/2022  01:50 AM             1,066 test.txt
                                    35 test.txt:stream1.txt:$DATA
               5 File(s)         13,347 bytes
               5 Dir(s)  54,557,798,400 bytes free
```

We can then hash using any of the supported algorithms as such:
```
$ hasher.exe -md5 -sha1 test.txt
md5:    19aad03aeb7f17cd64a4564bb7153679
sha1:   ba8fa525b784f4e46dcd27a82562c8b479afcb2b
```

Or hash only the default stream:
```
$ hasher.exe -n -md5 -sha1 test.txt
md5:    bea1affc9277fc4f14fc63594e0693c4
sha1:   50f1edf78a816dd0c4d978afaf4b3fd82d256b62
```