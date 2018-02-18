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
interface to the Open Secure Socket Layer (OpenSSL) 1.0.2 API. Mostly it's my
excuse to learn how to use the OpenSSL C API for both authentication and
encryption for the kinds of low-level, usually C or C++, code that I typically
am asked to develop.

I recently ported this library to work under BoringSSL 1.1.0, Google's fork
of OpenSSL. I don't have renegotiation (which BoringSSL only supports when
initiated by the server-side) working yet. But otherwise the unit tests all
pass.

That work in turn made it fairly easy to get this library to work under
OpenSSL 1.1.1, similarly without renegotiation working.

**Important safety tip**: the OpenSSL API is a quickly moving target. There are
no guarantee that successive (or prior) versions do not break Codex. I continue
to noodle around with other SSL implementations and versions.

## Contact

Chip Overclock  
<coverclock@diag.com>  
Digital Aggregates Corporation  
<http://www.diag.com>  
3440 Youngfield St. #209  
Wheat Ridge CO 80033 USA  

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
may suggest, both unidirectional byte streams of the full-duplex connection must
be empty of application data for the renegotiation to succeed. This is because
the handshake for the renegotiation is done in-band, and the protocol does not
know how to handle unexpected application data. This is probably
not a problem in typical web-based OpenSSL applications, whose communication
consists of half-duplex HTTP requests and responses. But in the Internet of
Things (IoT) domain of sensors and real-time data, this may not be the case.
Furthermore, the handshake itself is implemented on the requestee side by state
machines in OpenSSL which piggy-back the handshake protocol on application-driven
I/O. So the requestee must drive those state machines on its side of the
handshake by doing I/O, whether it has any data to send or receive or not.

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

**Important safety tip**: I haven't tried to make the Handshake unit test robust
against a client and a server simultaneously requesting a renegotiation. But
that's a legitimate concern that a real-world application should worry about.

## Dependencies

Ubuntu 16.04.3 LTS "xenial"

Linux nickel 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC
2017 x86_64 x86_64 x86_64 GNU/Linux

gcc (Ubuntu 5.4.0-6ubuntu1~16.04.5) 5.4.0 20160609

OpenSSL 1.0.2g *or* BoringSSL 1.1.0 *or* OpenSSL 1.1.1-pre2-dev

Diminuto 48.3.1

## Targets

"nickel"    
Intel NUC5i7RYH    
Intel Core i7-5557U @ 3.10GHz x 8    

## Building

If you want to use OpenSSL 1.0.2, which is the default version for the release
of Ubuntu I use, install it using the Aptitude package manager.

    sudo apt-get install openssl libssl-dev libssl-doc

If you want to use BoringSSL 1.1.0, which is the current version of Google's
fork of OpenSSL, clone and build it.

    cd
    mkdir -p src
    cd src
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    mkdir build
    cd build
    cmake -DBUILD_SHARED_LIBS=1 -DBORINGSSL_SHARED_LIBRARY=1 -DBORING_IMPLEMENTATION=1 ..
    make
    
If you want to use OpenSSL 1.1.1, which is the current version from the OpenSSL
project, clone and build it.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/openssl/openssl
    cd openssl
    ./config
    make

Clone and build Diminuto 48.3.1, a library I wrote that Codex is built upon.
(Later versions of Diminuto may work providing I haven't altered the portions
of the API on which Codex depends.)

    cd
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-diminuto
    cd com-diag-diminuto/Diminuto
    git checkout 48.3.1
    make pristine depend all

Clone and build Codex, a library I wrote, choosing the flavor of OpenSSL
library you want to use.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-codex
    cd com-diag-codex/Codex
    make pristine depend all FLAVOR=openssl-1.0.2
    # *or*
    make pristine depend all FLAVOR=boringssl-1.1.0
    # *or*
    make pristine depend all FLAVOR=openssl-1.0.2

## Testing

Run the Codex unit tests.

    cd ~/src/com-diag-codex/Codex
    . out/host/bin/setup # Sets PATH, LD_LIBRARY_PATH, etc. in environment.
    unittest-sanity
    unittest-core
    unittest-machine
    
This unit test allows you to test renegotiation from either side of the
connection by sending the server process or a client process a "hangup" signal
a.k.a. SIGHUP. You can find the process identifiers (PID) for the processes in
the log output to standard error. You can use the kill(1) command to send
a SIGHUP to the process you want to instigate a renegotiation with its
peer.

    unittest-handshake
    
These unit tests will deliberately fail as a test of verification failure
either by the client (the server fails to authenticate) or the server (the
client fails to authenticate).

    unittest-verification-client
    unittest-verification-server


## Repositories

<https://github.com/coverclock/com-diag-codex>

<https://github.com/coverclock/com-diag-diminuto>

<https://github.com/openssl/openssl>

<https://boringssl.googlesource.com/boringssl>

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

D. Gibbons, personal communication, 2018-02-12

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

## Notes

