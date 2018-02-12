# com-diag-codex

Slightly Simpler Open Secure Socket Layer (OpenSSL) API in C.

## Copyright

Copyright 2018 Digital Aggregates Corporation, Arvada Colorado USA

## Trademarks

"Digital Aggregates Corporation" is a registered trademark.

"Chip Overclock" is a registered trademark.

## License

Licensed under the terms in LICENSE.txt.

## Abstract

Codex provides a slightly simpler higher-level C-based application programming
interface to the Open Secure Socket Layer (OpenSSL) API. Mostly it's my
excuse to learn how to use the OpenSSL C API for both authentication and
encryption for the kinds of low-level, usually C or C++, code that I typically
am asked to develop.

## Theory of Operation

The API for Codex is architected in three separate layers: Core (the lowest),
Machine, and Handshake. Each higher layer depends on the lower layers, and each
layer can be used, depending on the application, without resorting to using the
higher layers. Each layer has its own unit test demonstrating its use in a
simple client server application in which multiple clients connect to a common
server, send the server data, and expect to receive the exact same data in
return. The client portions of each unit test checksums the data sent to and
received from the server to verify it was the same.

The Core layer allows peers to establish secure (authenticated, encrypted)
stream connections and pass data in a full-duplex fashion.

The Machine layer allows peers to establish secure stream connections and pass
variable sized packets in a full-duplex fashion. In addition, the peers may
pass "indications" in-band to signal actions to the far end. This is implemented
using finite state machines to iteratively handle the I/O streams; this also
simplifies multiplexing the OpenSSL sockets using the select(2) system call.

The Handshake layer allows peers to establish secure stream connections, pass
variable sized packets in full-duplex fashion, and use indications to coordinate
the renegotiation of the session so that new encryption keys can be established
and each end can be re-authenticated. This is especially important for long
lived connections, since the longer an encryption key is used, the more likely it
is that it will be cracked.

Empirical evidence suggests that regardless of what the OpenSSL documentation
may suggest, both unidirectional streams of the full-duplex connection must be
empty of application data for the renegotiation to succeed. This is because
the handshake for the renegotiation is done in-band, and the protocol does not
know how to handle unexpected application data. This is probably not a problem
in typical web-based OpenSSL applications, whose communication consists of
half-duplex HTTP requests and responses. But in the Internet of Things (IoT)
world of sensors and real-time data, this is not the case.

Using the Handshake unit test as an example, either the Server or the Client
processes that implement the unit test can initiate a renegotiation; this is
done by the tester by sending any of the processes a SIGHUP (hangup) signal.
A SIGHUP sent to a client causes it to initiate a renegotiation with the server
just for its connection. A SIGHUP sent to the server cuases it to initiate a
renegotiation with all of its clients. In any case, both uni-directional
(read, write) streams of the full-duplex connection must be emptied for the
handshake to succeed.

The unit test implements a simple protocol consisting of a FAREND (start)
indication sent from the requestor to the requestee while at the same time the
requestor ceases writing data packets to the connection. The requestee responds
with a READY indication while at the same time ceasing writing to the requestor.
Once the handshake is complete, the requestor writes a DONE indication which the
requestee reads, and then full-duplex communication resumes.

In the case of the server side of the Handshake unit test being the requestor,
the server must buffer incoming packets that were in-flight at the time it
sent the client a FAREND indication in order to quiesce its output stream.
The amount of data it must buffer will be two times the bandwidth delay product
of the communication channel between the client and the server. This can be
substantial (thousands of packets, each containing hundreds of bytes). Any
application expecting to renegotiate an OpenSSL connection being used for
full-duplex communication must take this into account.

Important safety tip: I haven't tried to make the Handshake unit test robust
against two peers simultaneously requesting a renegotiation. But that's a
legitimate concern that a real-world application should worry about.

## Building

Clone and build Diminuto 48.0.0.

    cd ~
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-diminuto
    cd com-diag-diminuto/Diminuto
    git checkout 376e3bb623d3cbb76b17995803eaaedaec486a5c
    make pristine depend all
    # sudo make install # Optional to install in /usr/local .

Clone and build Codex.

    cd ~
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-codex
    cd com-diag-codex/Codex
    make pristine depend all
    # sudo make install # Optional to install in /usr/local .

Run the Codex unit tests.

    cd ~/src/com-diag-codex/Codex
    . out/host/bin/setup # Sets up PATH etc. in environment.
    unittest-sanity
    unittest-core
    unittest-machine
    unittest-handshake
    
These unit tests will deliberately fail as a test of verification failure
either by the client (the server fails to authenticate) or the server (the
client fails to authenticate).

    unittest-verification-client
    unittest-verification-server

## Contact

Chip Overclock  
<coverclock@diag.com>  
Digital Aggregates Corporation  
<http://www.diag.com>  
3440 Youngfield St. #209  
Wheat Ridge CO 80033 USA  

## Dependencies

Linux nickel 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC
2017 x86_64 x86_64 x86_64 GNU/Linux

Ubuntu 16.04.3 LTS "xenial"

gcc (Ubuntu 5.4.0-6ubuntu1~16.04.5) 5.4.0 20160609

OpenSSL 1.0.2g  1 Mar 2016

Diminuto 48.0.0 35bd7e6cd0e5f80e3095223940c005ee0676f921

## References

D. Adrian et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in
Practice", 22nd ACM Conference on Computer and Communication Security, 2015-10,
<https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf>

K. Ballard, "Secure Programming with the OpenSSL API",
<https://www.ibm.com/developerworks/library/l-openssl/>,
IBM, 2012-06-28

E. Barker et al., "Transitions: Recommendation for Transitioning the Use of
Cryptographic Algorithms and Key Lengths", NIST, SP 800-131A Rev. 1, 2015-11

D. Barrett, R. Silverman, R. Byrnes, _SSH, The Secure Shell_, 2nd ed.,
O'Reilly, 2005

J. Davies, _Implementing SSL/TLS_, Wiley, 2011

D. Gibbons, personal communication, 2018-01-17

D. Gillmor, "Negotiated Finite Diffie-Hellman Ephemeral Parameters for
Transport Layer Security (TLS)", RFC 7919, 2016-08

HP, "SSL Programming Tutorial", HP OpenVMS Systems Documentation,
<http://h41379.www4.hpe.com/doc/83final/ba554_90007/ch04s03.html>

Karthik et al., "SSL Renegotiation with Full Duplex Socket Communication",
Stack Overflow, 2013-12-14,
<https://stackoverflow.com/questions/18728355/ssl-renegotiation-with-full-duplex-socket-communication>

V. Kruglikov et al., "Full-duplex SSL/TLS renegotiation failure", OpenSSL
Ticket #2481, 2011-03-26,
<https://rt.openssl.org/Ticket/Display.html?id=2481&user=guest&pass=guest>

OpenSSL, documentation, <https://www.openssl.org/docs/>

OpenSSL Wiki, "FIPS mode and TLS", <https://wiki.openssl.org/index.php/FIPS_mode_and_TLS>

I. Ristic, _OpenSSL Cookbook_, Feisty Duck,
<https://www.feistyduck.com/books/openssl-cookbook/>

L. Rumcajs, "How to perform a rehandshake (renegotiation) with OpenSSL API",
Stack Overflow, 2015-12-04,
<https://stackoverflow.com/questions/28944294/how-to-perform-a-rehandshake-renegotiation-with-openssl-api>

J. Viega, M. Messier, P. Chandra, _Network Security with OpenSSL_, O'Reilly, 2002

J. Viega, M. Messier, _Secure Programming Cookbook_, O'Reilly, 2003

## Acknowledgements

Special thanks to Doug Gibbons, my long-time friend, occasional colleague, and
one-time office mate, who was extraordinarily generous with his special
expertise in this area.