# ACH-1
### Aquino Cryptographic Hash version 1

ACH-1 is a 1024 byte (8192 bit) hashing function made from scratch using file names and samples from text as seeding. 

**DO NOT** expect this project to be of the most practical use or fast. It is mainly an expiriment and a potential tool for any of my future projects.

***
# Downloads:

(NuGet package or any official releases have not been created yet. Stay tuned!)

***
# USAGE:

ACH-1 Implements IDIsposable, meaning it can be used in a `using` statement or be disposed of later in code using `Dispose()`.

`ACH1(ACH1.InitType)` constructor asks for a parameter that dictates how the program will compute a hash. The three modes are:
* InitType.file
> Computes a hash using a file path. Sequentially reads the bytes of the file to save memory.
* InitType.text
> Computes a hash using text input.
* InitType.bytes
> Computes a hash using byte[] input.

## ACH1.ComputeHash()
### Overloads:
`ComputeHash(object)` where object is a type of `byte[]` or `string` and uses the method specified in the constructor.
> Returns a 1024 byte hash using ACH-1.

`ComputeHash(object)` where object is a type of `byte[]` or `string` and uses the method specified in the constructor. The second parameter byte[] is for an alternate File Name Key seed.
> Returns a 1024 byte hash using ACH-1.

## ACH1.GetFNK()
### Overloads:
`GetFNK(object, out byte[])` where object is a type of `byte[]` or `string` and uses the method specified in the constructor.
> Returns a 128 byte File Name Key.

## ACH1.OverrideMode()
### Overloads:
`OverrideMode(InitType)`
> Changes the hash generation method used by the current instance of ACH1.

## ACH1.Clear()
### Overloads:
`Clear()`
> Forcfully clears larger fields in the current instance of ACH1.
***
# Notes:
No part of this project is backed by extensive research, so I really have no idea if this is __truly__ secure or not. 
