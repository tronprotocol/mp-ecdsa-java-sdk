# mp-ecdsa-java-sdk
a multi-party-ecdsa jni library

# Pull source
```
$ git clone git@github.com:tronprotocol/mp-ecdsa-java-sdk.git --recursive
```
OR
```
$ git clone git@github.com:tronprotocol/mp-ecdsa-java-sdk.git
$ git submodule update --init --recursive
```

# Required

cmake (version >= 3.10.2)

rust (edition = 2018)

# Dependency

This project needs [`gmp`](https://gmplib.org/) (version >= 6.2.0) library, and you must install
 `gmp` first 
before build this project.

# build 

Step into `cpp` directory, run
```
$ cmake . && make install
```
