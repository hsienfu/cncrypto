## 可追踪的一次性地址方案

### Dependencies

```
  $ sudo apt install -y cmake libboost-all-dev libssl-dev libsodium-dev
```

### Buid & Install

```
  $ cd path/to/project
  $ mkdir build bin
  $ cd build
  $ cmake ..
  $ cmake --build .
  $ cmake --install . --prefix ../bin
```

### Running

```
  $ cd path/to/project
  $ ./bin/crypto-2p
  $ ./bin/crypto-3p
```
