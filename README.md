# com-diag-codex

Slightly Simpler Open Secure Socket Layer (OpenSSL) API in C.

## Copyright

Copyright 2018 Digital Aggregates Corporation, Arvada Colorado USA

## License

Licensed under the terms in LICENSE.txt.

## Trademarks

"Digital Aggregates Corporation" is a registered trademark.

"Chip Overclock" is a registered trademark.

## Abstract

Codex provides a slightly simpler higher-level C-based application programming
interface to the Open Secure Socket Layer (OpenSSL) API. Mostly it's my
excuse to learn how to use the OpenSSL C API for both authentication and
encryption for the kinds of low-level, usually C or C++, code that I typically
am asked to develop.

I first developed Codex under OpenSSL 1.0.2 (the default version under
Ubuntu "xenial"). I later ported it to OpenSSL 1.1.1 (the development version
at the time I did this work), OpenSSL 1.0.1 (the default version under Raspbian
"jessie" on the Raspberry Pi 2 and 3), and BoringSSL 1.1.0 (Google's fork of
OpenSSL 1.1.0). The renegotiation feature in Codex only works under OpenSSL
1.0.2.

## Contact

Chip Overclock  
<coverclock@diag.com>  
Digital Aggregates Corporation  
<http://www.diag.com>  
3440 Youngfield St. #209  
Wheat Ridge CO 80033 USA  

## Remarks

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

OpenSSL 1.0.2g *or* BoringSSL 1.1.0 *or* OpenSSL 1.1.1-pre2-dev *or* OpenSSL 1.0.1t

Diminuto 48.3.3 (later releases may work as well)

## Targets

"Nickel"    
Intel NUC5i7RYH    
Intel Core i7-5557U @ 3.10GHz x 8    
Ubuntu 16.04.3 LTS "xenial"    
Linux 4.10.0    
gcc 5.4.0    

"Lead"   
Raspberry Pi 3 Model B (64-bit ARM)    
Broadcom BCM2837 Cortex-A53 ARMv7 @ 1.2GHz x 4    
Raspbian GNU/Linux 8.0 "jessie"    
Linux 4.4.34    
gcc 4.9.2    

"Bronze" 
Raspberry Pi 2 Model B (32-bit ARM)  
Broadcom BCM2836 Cortex-A7 ARMv7 @ 900MHz x 4  
Raspbian GNU/Linux 8.0 "jessie"  
Linux 4.4.34  
gcc 4.9.2  

## Building

If you want to use OpenSSL 1.0.2 on an X86_64 running Ubuntu "xenial" system,
you can install it with the Aptitude package manager using the command
below. This same command, minus libssl-doc, will install OpenSSL 1.0.1 for
Raspbian "jessie" on the Raspberry Pi.

    sudo apt-get install openssl libssl-dev libssl-doc

If you want to build OpenSSL 1.0.1t, which is the version used by the current
Raspbian (jessie) on the Raspberry Pi 2 and 3, use the commands below.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/openssl/openssl openssl-1.0.1t
    cd openssl-1.0.1t
    git checkout OpenSSL_1_0_1t
    ./config -shared
    make depend
    make

If you want to build BoringSSL 1.1.0, which is the current version of Google's
fork of OpenSSL, use the commands below.

    cd
    mkdir -p src
    cd src
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    mkdir build
    cd build
    cmake -DBUILD_SHARED_LIBS=1 -DBORINGSSL_SHARED_LIBRARY=1 -DBORING_IMPLEMENTATION=1 ..
    make
    
If you want to build OpenSSL 1.1.1, which is the current version from the
OpenSSL project, use the commands below.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/openssl/openssl
    cd openssl
    ./config
    make

Clone and build Diminuto 48.3.3, a library I wrote that Codex is built upon.
(Later versions of Diminuto may work providing I haven't altered the portions
of the API on which Codex depends.)

    cd
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-diminuto
    cd com-diag-diminuto/Diminuto
    git checkout 48.3.2
    make pristine depend all

Clone and build Codex, a library I wrote, choosing the FLAVOR of OpenSSL
library you want to use.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-codex
    cd com-diag-codex/Codex
    make pristine depend all FLAVOR=!FLAVOR!

Here !FLAVOR! is one of the following choices:

    openssl
    openssl-1.0.1
    boringssl-1.1.0
    openssl-1.1.1

in which FLAVOR=openssl uses the default installed version on the build
system, e.g. OpenSSL-1.0.2 on Ubuntu "xenial", OpenSSL-1.0.1 on Raspbian
"jessie". When in doubt, run unittest-sanity and it will display what
version of OpenSSL it thinks Codex was built with; similarly, you can run
vintage and it will display what the value of FLAVOR was when Codex was
built.

## Testing

Run the Codex unit tests.

    cd ~/src/com-diag-codex/Codex
    . out/host/bin/setup # Sets PATH, LD_LIBRARY_PATH, etc. in environment.
    unittest-sanity
    unittest-core
    unittest-machine
    
This unit test allows you to test renegotiation from either side of the
connection on OpenSSL-1.0.2 (only) by sending the server process or a client
process a "hangup" signal a.k.a. SIGHUP. You can find the process identifiers
(PID) for the processes in the log output to standard error. You can use the
kill(1) command to send a SIGHUP to the process you want to instigate a
renegotiation with its peer. (The unit test will run on other OpenSSL flavors,
you just won't be able to get negotiation to work.)

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
