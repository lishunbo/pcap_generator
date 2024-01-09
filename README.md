# PcapGenerator

在一些场景下，需要有办法分析webrtc的rtp流，由于Web的API限制，没有办法直接接触未加密的原始流，所以需要业务上将码流以某些形式写入文件，然后用工具将该码流生成pcap文件，进而利用wireshark进行码流的分析

## How To Use

1. 将rtp包以hexstring的方式添加毫秒时间戳+上下行写入文件
2. 该前面生成的文件作为参数运行本工具即可

本工具的主要功能是读取一个文本文件，每一行的格式为：
[毫秒时间戳]空格['0'|'1']空格[rtp hex string]
其中0|1表示上行包、下行包的方向

通过解析时间戳，方向，将hex string转成binary，进而添加eth头、ip头、udp头组装成一个网络包，最后使用libpcap写入文件

注意对于相同时间戳的连续两个包，会通过添加计数的方式表示先后顺序，即时间戳全填0也是可以的

### Example
```txt
0 0 80900011
```

## Build

```bash
tar xf libpcap-1.10.4.tar.gz
cd libpcap-1.10.4
./configure --disable-shared --disable-netmap --disable-bluetooth --disable-dbus --disable-rdma
make -j12
cd ..
cmake -S . -B build
cmake --build build
```

## TODO

- 增加tcp包支持
- 增加srtp支持
