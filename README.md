# TCP Block

Blocks TCP connections by injecting user-crafted TCP packets with flags set. Especially, FIN/ACK is used to deal with HTTP packets, and RST/ACK is used in other situations.

## Getting started

### Overview

* Monitor and inject packets
    * HTTP packets are recognized by the request methods {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"}
        * Forward RST and Backward FIN
    * Other TCP packets
        * Forward RST and Backward RST

*In any case, setting appropriate SEQ and ACK numbers is essential.*

### Program Flow

1. Receive network packet.
2. Parse to discover which protocol it uses.
3. Inject appropriate RST or FIN packets with the right SEQ and ACK numbers set.

*Any 'non-TCP/IP' packet is out of consideration.*

### Development Environment

```bash
$ uname -a
Linux ubuntu 4.15.0-30-generic #32~16.04.1-Ubuntu SMP Thu Jul 26 20:25:39 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

$ g++ --version
g++ (Ubuntu 5.4.0-6ubuntu1~16.04.10) 5.4.0 20160609
```

### Prerequisites

This program includes the following headers. Make sure you have the right packages.

```c
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
```

Install with the following commands.

```bash
$ sudo apt install libpcap-dev
$ sudo apt install libnet-dev
```

## Running the program

### Build

Simply hit 'make' to create object files and executable.

```bash
$ make
```

### Run

Format

```bash
$ ./tcp_block <interface>
```

Example

```bash
$ ./tcp_block eth0
```

You might need root priviledges to capture network packets.

## Acknowledgements

* [Simple pcap programming](https://gitlab.com/gilgil/network/wikis/ethernet-packet-dissection/pcap-programming)
* [libnet api](https://github.com/korczis/libnet)
* [Winpcap user's manual](https://www.winpcap.org/docs/docs_40_2/html/group__wpcap.html)
* [Winpcap user's manual - def](https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__def.html)

## Authors

* **James Sung** - *Initial work* - [sjkywalker](https://github.com/sjkywalker)
* Copyright © 2018 James Sung. All rights reserved.

