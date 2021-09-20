# ops-inject

A network traffic annotation tool, capable of adding arbitrary implementations of IP/TCP/UDP options to select packets.
Packets are chosen for annotation using `iptables` and `NetfilterQueue`.

## Usage

Create an `iptables` rule to divert packets to the userspace process (i.e.: `ops-inject`).
Since we plan to inject an IP option, we select ICMP packets since those are the only ones with a snowball's chance in hell not to be dropped by middleboxes.
```
# iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 0 --queue-bypass
```

Next, start the annotation tool (run with `--help` for details about the options).
The tool takes a file (or in this case, a PseudoTerminal Slave) as input. This file must contain a sequence of bytes representing the codepoints of the desired protocol options. These will be decoded into actual Type-Length-Value (TLV) entries and placed in this exact order in the options section.
Right now, we tell it to inject only an *IP Record Route* (0x07) option. For more info, see [IANA IPv4 Parameters](https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml) and [RFC791](https://tools.ietf.org/html/rfc791).
```
# ./bin/ops-inject -p ip -q 0 -w <(printf '\x07')
```

Finally, we need to generate some traffic. To this end, we are going to ping DigitalOcean.
Why DigitalOcean? Because they are the only cloud provider we could find that consistently handles IP Options well. If this doesn't work, your ISP is probably blocking IP options. In this case, try getting access to a network like GÉANT and [affiliates](https://www.geant.org/Projects/GEANT_Project_GN4/Pages/Partners.aspx) (NOTE: university networks should do nicely).
At this point you may want to start a `Wireshark` or `tcpdump` instance, but it's not really necessary. It will be clear immediately if it worked or not.
```
$ ping $(dig +short digitalocean.com | head -n 1)
    PING 104.16.182.15 (104.16.182.15) 56(84) bytes of data.
    64 bytes from 104.16.182.15: icmp_seq=1 ttl=57 time=46.7 ms
    RR:     141.85.13.15
            37.128.225.226
            37.128.232.178
            37.128.232.177
            80.97.248.33
            162.158.16.1
            104.16.182.15
            104.16.182.15
            162.158.16.1

    64 bytes from 104.16.182.15: icmp_seq=2 ttl=57 time=14.2 ms     (same route)
    64 bytes from 104.16.182.15: icmp_seq=3 ttl=57 time=18.2 ms     (same route)
```

Pretty simple, right? Luckily, the `ping` utility knows how to interpret the *Record Route* option since it can generate it itself (check the `-R` flag).
Notice that the route is not fully recorded; it cuts out pretty early on the return path. That's because the IP and TCP options sections are at most 40 bytes long (limited by the size of the `IHL` and `offset` fields respectively). Tacking into account the option's codepoint (1 byte) and its length field (1 byte), we are left with enough space for only 9 IPv4 addresses.

## Code Structure
- **main.cpp**: contains the NetfilterQueue callback. There, three stages follow.
    - **Option Decoding:** the TLV list is generated based on the sequence of codepoints and the contents of the packet.
    - **Packet Reassembly:** the newly generated options are integrated into the packet. Depeding on whether the `-w` flag was given, existing options may be overwritten (very likely to have those in TCP sessions).
    - **Checksum Recalculation:** Even if we don't touch the TCP or UDP content, their checksum is still dependent on fields in the IP header (like `Total Length`).
- **decoders.cpp:** contains parsers for each supported type of option (i.e.: IP, TCP, UDP). Based on a priority level (described in next entry), the decoder must be able to change the order in which the codepoints are decoded, but not their final order in the options section (e.g.: alternative checksum option needs to be computed last but comes first in options list). If you want to add support for a new protocol (I think DCCP also had options), this is the place to start.
- **ops_${PROTO}:** these files contain the implementation of `${PROTO}`-specific options. If you want to add (or change) an option, check the other functions first to get a feel for the API and calling conventions. When you're done, add the newly created function in the two vtables at the bottom of the file using the option's codepoint as in index. Note: these sources are written in C, not C++. Why? Because I like [Designated Initializers](https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html) and `g++` doesn't support them.
- **reassemblers.cpp:** here are the protocol-specific reassembler functions. These take the options sections generated in **decoders.cpp** and integrate them into the original packet.
- **csum.c:** checksum calculation functions, for after the reassembly phase. There is a caveat you should know about: in order to support a layer 4 protocol (not talking about adding options for it; simply having it work), you must implement a csum recalculation function. For example, if we add IP options, UDP and TCP *do* need csum recalculations but ICMP *doesn't*. But the program doesn't care. It will pass through this step nonetheless. So we don't tell it not to recalculate the ICMP csum. Instead, we simply give it an empty function and pretend like it did its job.
- **cli_args.cpp:** does command line argument parsing using `argp`.
- **str_proto.c:** contains some debug information about l4 protocols. Ignore this.

## TODO
- **Session Tracking:** Right now, `ops-inject` can generate options only based on the contents of the current packet. Even if they are implemented, options like *TCP Echo Request* will not function properly. At most, they can be used to check that the initial packet successfully traversed the network.
- **Available Options Table:** Add a table with implemented options in this README.
- **Cleaner Explanations in README:** some info about queue redirection and some illustrations.

