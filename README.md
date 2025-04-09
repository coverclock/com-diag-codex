com-diag-codex
==============

Slightly Simpler Open Secure Socket Layer (OpenSSL) API in C.

# Copyright

Copyright 2018-2025 Digital Aggregates Corporation, Arvada Colorado USA

# License

Licensed under the terms in LICENSE.txt (FSF LGPL 2.1).

# Trademarks

"Digital Aggregates Corporation" is a registered trademark.

"Chip Overclock" is a registered trademark.

# Abstract

Codex provides a slightly simpler higher-level C-based application
programming interface to the Open Secure Socket Layer (OpenSSL)
API. Mostly it's my excuse to learn how to use the OpenSSL C API for
both authentication and encryption for the kinds of low-level, usually
C or C++, code that I typically am asked to develop. Codex is built on
top of Diminuto, my C-based systems programming library I've been using
for years in both personal and commercial development projects.

(If you got here via "prairiethorn.org", that is a test domain I use
for this project and others. It is sometimes dynamically forwarded to
the GitHub page for this repository.)

**Note**: Version 11.0.0 and beyond of this repository
contains significate changes from prior versions, although the only
API change was the elimination of the handshake renegotiation function
call (which was a really bad idea anyway, and only briefly supported
by OpenSSL).  If you want the prior version before I started committing
violence to it, check out tag 10.1.1.  Version 11.0.0 has passed the
Sanity, Functional, Failures, and Extra test suites.

**Note**: I have yet to cause the OpenSSL library to return the errors
` SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE`.  Hence the
code to handle those conditions in the applications `stagecoach` or
`codextool`  has not been tested. (It's not for lack of trying on my
part.) If you are using the `codex_machine` API, you can respond to
an `SSL_ERROR_WANT_WRITE` return by writing a header with a length
field (a.k.a. "indication") of zero. Such a header will automatically be
tossed away by the far end, but will satisfy OpenSSL's need for a write.

# Disclaimer

This is not my area of expertise, which is why nothing about the Secure
Socket Layer or cyber-security shows up on my resume. But people learn in
different ways, and my way has always been hands-on learn-by-doing. Codex
has been a useful mechanism through which I would like to think I've
learned enough to use OpenSSL in the kinds of Internet of Things product
development efforts on which I get paid to work. No warranty is
expressed or implied.

# What Works

I first developed Codex under OpenSSL 1.0.2 on Ubuntu "xenial". I later
ported it to (not necessarily in this order):

* OpenSSL 1.0.1 on Raspbian "jessie" on the Raspberry Pi 2 and 3;
* OpenSSL 1.1.0 on Raspbian "stretch";
* BoringSSL 1.1.0 which is Google's fork of OpenSSL 1.1.0 from which it is substantially different;
* OpenSSL 1.1.1;
* OpenSSL 3.0.2;
* OpenSSL 3.0.13;
* OpenSSL 3.0.15.

When I make changes, Codex gets tested on a variety of OpenSSL versions
depending on what test system I run it on. As later versions of OpenSSL
deprecate functions, I port Codex to that version, so I can't guarantee
the latest release of Codex will still work under earlier versions.

The Codex handshake (renegotiation) feature in Codex only worked under OpenSSL
1.0.2. It's of questionable value anyway, but it was an enlightening
exercise. The function call has been removed (it was a big security hole,
as it turns out).

I have run the unit tests on a variety of systems, including an x86_64
running Ubuntu, and an ARM (Raspberry Pi) running Raspberry Pi OS
(Raspbian).

I have also run the client and server unit tests programs talking between
the x86_64 and the ARMs, each using Codex built against their "native"
versions of OpenSSL, as a demonstration of interoperability. This use of an
X86_64 server with ARM clients is a typical IoT configuration on the kinds of
stuff on which I typically work.

# Contact

Chip Overclock  
<mailto:coverclock@diag.com>  
Digital Aggregates Corporation  
<http://www.diag.com>  
3440 Youngfield St. #209  
Wheat Ridge CO 80033 USA  

# Remarks

The application programming interface for Codex is split into a *public* API
and a *private* API. The public API is defined in the header file

    Codex/inc/com/diag/codex/codex.h
    
and is intended for application developers using the library. This header file
would be installed in, for example, ```/usr/local/include``` and could be included
using a statement like

    #include <com/diag/codex/codex.h>

or maybe

    #include "com/diag/codex/codex.h"

depending on what flags you pass to the C compiler.

The private API is defined in the header file

    Codex/src/codex.h

and is intended for use by the Codex implementation itself and by library
installers and maintainers. It is typically only visible to translation units
compiled with access to the Codex source code. It could, for example, be
included using a statement like

    #include "../src/codex.h"

The public API for Codex is architected in three separate layers: Core (the
lowest), Machine, and Handshake (the highest). Each higher layer depends
on the lower layers, and each layer can be used, depending on the
application, without resorting to using the higher layers. Each layer
has its own unit test demonstrating its use in a simple client server
application in which multiple clients connect to a common server, send
the server data, and expect to receive the exact same data in return. The
client portions of each unit test checksums the data sent to and received
from the server to verify it was the same.

### Core

The Core layer allows peers to establish secure (authenticated, encrypted)
stream connections and pass data in a full-duplex fashion. The Core
layer API has several sub-layers: initializing the library, creating
a server or a client context (which defines all the encryption and
authentication parameters), creating a server rendezvous (which is used
to accept connections from clients), creating a client connection to a
server rendezvous, creating a server connection from the rendezvous to
accept the connection from a specific client, and read and write commands
against a connection (either client or server).

**Important safety tip**: There are also some simple helpers to
assist with using ```select(2)``` with this library. As the unit
tests demonstrate, I've multiplexed multiple SSL connections using
```select(2)``` via the Diminuto mux feature. But in SSL there is a
*lot* going on under the hood. The byte stream the application reads
and writes is an artifact of all the authentication and crypto going on
in ```libssl``` and ```libcrypto```. The Linux socket and multiplexing
implementation in the kernel lies below all of this and knows *nothing*
about it. So the fact that there's data to be read on the socket doesn't
mean there's *application* data to be read. And the fact that the
```select(2)``` doesn't fire doesn't mean there isn't application data
waiting to be read in a decryption buffer. A lot of application reads
and writes may merely be driving the underlying protocol and associated
state machines in the SSL implementation.  Hence multiplexing isn't as
useful as it might seem, and certainly not as easy as in non-OpenSSL
applications. A multi-threaded server approach, which uses blocking reads
and writes, albeit less scalable, might ultimately be more useful. But as
the unit tests demonstrate, multiplexing via ```select(2)``` can be done.

### Machine

The Machine layer allows peers to establish secure stream connections
and pass variable sized packets in a full-duplex fashion. In addition,
the peers may pass "indications" in-band to signal actions to the far
end. This is implemented using finite state machines to iteratively
handle the I/O streams; this also simplifies multiplexing the OpenSSL
sockets using the ```select(2)``` system call. The Machine layer allows
the SSL byte stream to be used in a datagram-like fashion.

# Applications

I have written applications included in this repo, two of which are
named for the sub-projects that they support in other repositories.
These applications are in the ```app``` directory.

* App codextool reads from an SSL connection and writes to stdout, and reads from stdin and writes to an SSL connection.

* App stagecoach supports GNSS rovers and a GNSS base station communicating with an RTK router (all of these are part of the Hazer project) by forwarding datagrams in either direction over an SSL connection (in return for some violence done to the real-time nature of those datagrams).

* App wheatstone supports experiments with LTE-M modems used with remote sensors (mostly DEPRECATED since AT&T dropped their inexpensive LTE-M service).

# Targets

Intel(R) Core(TM) i7-7567U CPU @ 3.50GHz     
x86_64 x4     
Ubuntu 22.04.1 LTS (Jammy Jellyfish)     
Linux 5.15.0-56-generic     
gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0     
ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35     
GNU ld (GNU Binutils for Ubuntu) 2.38     
GNU Make 4.3     
x86_64-linux-gnu-gcc-11     
x86_64-linux-gnu     
Little Endian     

Raspberry Pi 4 Model B Rev 1.1 BCM2835 c03111     
aarch64 x4     
Debian GNU/Linux 11 (bullseye)     
Linux 5.15.76-v8+     
gcc (Debian 10.2.1-6) 10.2.1 20210110     
ldd (Debian GLIBC 2.31-13+rpt2+rpi1+deb11u5) 2.31     
GNU ld (GNU Binutils for Debian) 2.35.2     
GNU Make 4.3     
aarch64-linux-gnu-gcc-10     
aarch64-linux-gnu     
Little Endian     

Raspberry Pi 4 Model B Rev 1.4 BCM2835 d03114     
aarch64 x4     
Ubuntu 22.04.1 LTS (Jammy Jellyfish)     
Linux 5.15.0-1021-raspi     
gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0     
ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35     
GNU ld (GNU Binutils for Ubuntu) 2.38     
GNU Make 4.3     
aarch64-linux-gnu-gcc-11     
aarch64-linux-gnu     
Little Endian     

Raspberry Pi 5 Model B Rev 1.0 d04170    
aarch64 x4    
Debian GNU/Linux 12 (bookworm)    
Linux 6.6.62+rpt-rpi-2712    
gcc (Debian 12.2.0-14) 12.2.0    
ldd (Debian GLIBC 2.36-9+rpt2+deb12u9) 2.36    
GNU ld (GNU Binutils for Debian) 2.40    
GNU Make 4.3    
aarch64-linux-gnu-gcc-12    
aarch64-linux-gnu    
Little Endian    

# Certificates

The build ```Makefile``` for Codex builds root, certificate authority (CA),
client, and server certificates anew. It is these certificates that allow
clients to authenticate their identities to servers and vice versa. (The
```Makefile``` uses both root and CA certificates just to exercise certificate
chaining.) These are the certificates that the build process creates for unit
testing.

* ```bogus.pem``` is a certificate signed by root with incorrect CN(s).
* ```ca.pem``` is a CA certificate for testing chaining.
* ```client.pem``` is a certificate signed by root for client-side unit tests.
* ```self.pem``` is a self-signed certificate.
* ```server.pem``` is a certificate signed by root and CA for server-side unit tests.
* ```revoked.pem``` is a certificate whose serial number is in the generated list of revoked certificates.
* ```revokedtoo.pem``` is another certificate whose serial number is in the generated list of revoked certificates.
* ```root.pem``` is a root certificate.

When building Codex on different computers and then running the unit tests
between those computers, the signing certificates (root, and additional CA
if it is used) for the far end have to be something the near end trusts.
Otherwise the SSL handshake between the near end and the far end fails.

The easiest way to do this is to generate the root and CA credentials on
the near end (for example, the server end), and propagate them to the far
end (the client end) *before* the far end credentials are generated. Then
those same root and CA credentials will be used to sign the certificates
on the far end during the build, making the near end happy when they are
used in the unit tests. This is basically what occurs when you install
a root certificate using your browser, or generate a public/private key
pair so that you can use ```ssh(1)``` and ```scp(1)``` without entering
a password - you are installing shared credentials trusted by both peers.

Codex builds just enough Public Key Infrastructure (PKI) to run the unit
tests.

# Passwords

The certificates built by the ```Makefile``` for the unit tests are password
protected: the unit tests (or, indeed, any application that tries to
use them) has to provide the OpenSSL API with the password. This is a
good idea for your own certificates for all sorts of reasons.

Codex automates this process in such a way it can seem a little
mysterious. The Codex ```Makefile``` creates build artifacts in the output
directory that contain the passwords which it extracted from the
certificate configuration files. It also creates a ```setup``` script
(cited below) that when included into a ```bash``` session extracts the
passwords from those files and stores them in environmental variables. The
Codex API expects to find those environmental variables and uses a
callback to read them and pass their values to OpenSSL when it opens
the certificates.

These environmental variables are ```COM_DIAG_CODEX_SERVER_PASSWORD```
for a Codex server context, and ```COM_DIAG_CODEX_CLIENT_PASSWORD```
for a Codex client context; however, you can change these names in the
```Makefile```, or at run-time via the settors in the Codex private API, or
if you roll your own context using the "generic" version of the Codex
context API, you can name them anything you want at run-time.

# Verification

In addition to using the usual OpenSSL verification mechanisms, Codex provides a
verification function that may be invoked by the application.
```codex_connection_verify()``` returns a mask of bits, defined by
```codex_verify_t```, that determines if and how the certificate associated
with the specified connection was verified. The default criteria for accepting
a connection from either the server or the client is specified in the function
```codex_connection_verified()```, but applications are free to apply their
own criteria. The default criteria is as follows.

* Codex rejects self-signed certificates, unless this requirement is explicitly
disabled at build time in the ```Makefile``` or at run-time through a settor
in the private API. This is implemented through the standard OpenSSL
verification call back.

* If the application chooses to initialize Codex with a list of revoked
certificate serial numbers (see below), Codex requires that *every* certificate
in a certificate chain have a serial number that is not revoked. This is
implemented through the standard OpenSSL verification call back.

* Codex requires that either the Common Name (```CN```) or the
Fully-Qualified Domain Name or FQDN (coded as a ```DNS``` value in
```subjectAltName```) match the expected name the application provides to the
Codex API (or the expected name is null, in which case Codex ignores this
requirement.) See the example certificate configuration files that Codex uses
for the unit tests in the ```etc``` directory.

* Codex expects a DNS name encoded in the certificate in a standards
complaint fashion (as a ```subjectAltName```). Multiple DNS names may be
encoded. At least *one* of these DNS names must resolve to the IP address
from which the SSL connection is coming.

* It is *not* required that the FQDN that matches against the expected name be the
*same* FQDN that resolves via DNS to an IP address of the SSL connection. Here
is an example of why. The server may expect "*.prairiethorn.org", which could
be either the CN or a FQDN entry in the client certificate, but the certificate
will also have multiple actual DNS-resolvable FQDNs like
"alpha.prairiethorn.org", "beta.prairiethorn.org", etc.

* It is also *not* required that if a peer connects with both an IPv4 and an IPv6
address (typically it will; see below) that they match the *same* FQDN
specified in the certificate, or that *both* of the IPv4 and the IPv6 address
matches. Here's an example of why. Depending on how ```/etc/host``` is
configured on a peer, its IPv4 DNS address for "localhost" could be 127.0.0.1,
and its IPv6 DNS address for "localhost" can legitimately be either
::ffff:127.0.0.1 or ::1. The former is an IPv4 address cast in IPv6-compatible
form, and the latter is the standard IPv6 address for "localhost". Either is
valid. If the peer named "localhost" connects via IPv4, its far end IPv4
address as seen by the near end will be 127.0.0.1 and its IPv6 address will be
::ffff:127.0.0.1. If it connects via IPv6, its far end IPv4 address may be
0.0.0.0 (because there is no IPv4-compatible form of its IPv6 address) and its
far end IPv6 address will be ::1. The ```/etc/host``` entry for "localhost"
may be 127.0.0.1 (IPv4), or ::1 (IPv6), or both. Furthermore, for non-local
hosts, peers don't always have control of whether they connect via IPv4 or
IPv6, depending on what gateways they may pass through. Finally, it's not
unusual for the IPv4 and IPv6 addresses for a single host to be given different
fully-qualified domain names in DNS, for example ```alpha.prairiethorn.org```
for IPv4 and ```alpha-6.prairiethorn.org``` for IPv6; this allows hosts trying
to connect to ```foo``` to be able to select the IP version by using a different
host name when it is resolved via DNS.

# Certificate Revocation Lists

The Codex library does *not* directly handle signed certificate revocation lists
or the real-time revocation of certificates using the Online Certificate Status
Protocol (OCSP). It will however import a simple ASCII list of hexadecimal
certificate serial numbers, and reject any connection whose certificate chain
has a serial number on that list. The Codex CRL is a simple ASCII file
containing a human readable and editable list of serial numbers, one per line.
Here is an example.

    9FE8CED0A7934174
    9FE8CED0A7934175

The serial numbers are stored in-memory in a red-black tree (a kind of
self-balancing binary tree), so the search time is relatively efficient.

# Configuration

Codex has a number of OpenSSL-related configuration parameters. The
defaults can be configured at build-time by changing the make variables in
```cfg/codex.mk```. Some of the defaults can be overridden at run-time by
settors defined in the private API. Here are the defaults.

* RSA asymmetric cipher with 3072-bit keys is used for encrypting certificates.
* SHA256 message digest cryptographic hash function is used for signing certificates.
* TLS protocol is used (meaning: the two ends negotiate to the highest level of protocol both support).
* Diffie-Hellman generator function 2 is used to generate the DH parameters.
* Diffie-Hellman with 2048-bit keys is used for exchanging keys.
* Symmetric cipher selection string "TLS+FIPS:kRSA+FIPS:!eNULL:!aNULL" is used for encrypting the data stream.

# Directories
 
* ```bin``` - utility source files.
* ```cfg``` - makefile configuration files.
* ```dat``` - unit, function, and perforamnce testing artifacts.
* ```etc``` - certificate configuration files.
* ```inc``` - public header files.
* ```out``` - build artifacts in a ```TARGET``` subdirectory.
* ```src``` - implementation source files and private header files.
* ```tst``` - unit test source files and scripts.

```TARGET=host``` is the default, which builds Codex (or Diminuto) for the
target system on which ```make``` is running. But the Makefile has the
flexibility to cross-compile and generate build-artifacts into other
```TARGET``` directories. I've used this capability for Diminuto. But I build
Codex on the x86_64 and ARM targets on which I intend to run it.

# Dependencies

You'll need to clone and build Diminuto, my C systems programming library, and
install packages for OpenSSL.

## Versions

Diminuto 105.2.8 (or probably latest; may work with other versions but I may not have tested it).

OpenSSL 3.0.15 (may work with other versions but I may not have tested it).

## Repositories

<https://github.com/coverclock/com-diag-codex>

<https://github.com/coverclock/com-diag-diminuto>

<https://github.com/openssl/openssl>

## Packages

    sudo apt-get install openssl libssl-dev libssl-doc

# Unit Tests

Preceed with . out/host/bin/setup to setup PATH etc.

* make sanity-test - These tests will take a few minutes to run.
* make failures-test - These tests will take a few minutes to run.
* make functional-test - These tests will take a coffee break to run.
* make extra-test - These tests will take a coffee break to run.

# Logging

Diminuto provides a logging framework that is widely used in Codex. If a
process has a controlling terminal, log messages are displayed on standard
error; otherwise they are sent to the system log via the standard
```syslog(3)``` mechanism. The logging API is defined in the
```Diminuto/inc/com/diag/diminuto/diminuto_log.h``` header file in the
Diminuto source code directory.

Diminuto supports eight different levels of log message severity. From highest
priority to lowest, they are:

* Emergency;
* Alert;
* Critical;
* Error;
* Warning;
* Notice;
* Information; and
* Debug.

By default, log messages at Information or lower are suppressed. Codex logs
exceptional conditions at levels above Information, possibly useful
operational details at Information, and detailed debugging details at Debug.

The Diminuto log API provides a function call to set the bit mask that
determines which levels are logged and which are suppressed. The Codex unit
tests import this bit mask from the value of the environmental variable
```COM_DIAG_DIMINUTO_LOG_MASK```, which can be set to a numerical value such
as ```0xfe``` or ```254```, with the lowest priority log levels being the
lowest order bits. ```0xfe``` (all but Debug) is the value set by the
```out/host/bin/setup``` script used in the unit test description below.

## Issues

If you abort a unit test prematurely such that it does not
go through a normal OpenSSL shutdown - e.g. via a "kill -9"
or via a control-C interactively - trying to run it again
will fail for a while, until the underlying socket pipeline
gets cleaned up. For the unit tests that are intended to fail,
I inserted a thirty second delay between tests.

# Documentation

Codex, like Diminuto, has embedded Doxygen comments in the header files
that define the public API. If you have the Doxygen and TeX packages
installed, you can generate HTML and man page documentation.

    make documentation

If you have the full (enormous) TeX system installed, plus some standard
PDF utilities, you can generate PDF manuals.

    make documentation-ancillary

# References

D. Adrian, et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails
in Practice", 22nd ACM Conference on Computer and Communication Security,
2015-10, <https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf>

K. Ballard, "Secure Programming with the OpenSSL API",
<https://www.ibm.com/developerworks/library/l-openssl/>, IBM, 2012-06-28

E. Barker, et al., "Transitions: Recommendation for Transitioning the
Use of Cryptographic Algorithms and Key Lengths", NIST, SP 800-131A
Rev. 1, 2015-11

D. Barrett, et al., _SSH, The Secure Shell_, 2nd ed.,
O'Reilly, 2005

D. Cooper, et al., "Internet X.509 Public Key Infrastructure Certificate
and Certificate Revocation List (CRL) Profile", RFC 5280, 2008-05

J. Davies, _Implementing SSL/TLS_, Wiley, 2011

A. Diquet, "Everything You've Always Wanted to Know About Certificate
Validation with OpenSSL (but Were Afraid to Ask)", iSECpartners, 2012-10-29,
<https://github.com/iSECPartners/ssl-conservatory/blob/master/openssl/everything-you-wanted-to-know-about-openssl.pdf?raw=true>

Frank4DD, "certserial.c", 2014,
<http://fm4dd.com/openssl/certserial.htm>

V. Geraskin, "OpenSSL and select()", 2014-02-21,
<http://www.past5.com/tutorials/2014/02/21/openssl-and-select/>

M. Georgiev, et. al., "The Most Dangerous Code in the World: Validating SSL
Certificates in Non-Browser Software", 19nd ACM Conference on Computer and
Communication Security (CCS'12), Raleigh NC USA, 2012-10-16..18,
<https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf>

D. Gibbons, personal communication, 2018-01-17

D. Gibbons, personal communication, 2018-02-12

D. Gillmor, "Negotiated Finite Diffie-Hellman Ephemeral Parameters for
Transport Layer Security (TLS)", RFC 7919, 2016-08

HP, "SSL Programming Tutorial", HP OpenVMS Systems Documentation,
<http://h41379.www4.hpe.com/doc/83final/ba554_90007/ch04s03.html>

Karthik, et al., "SSL Renegotiation with Full Duplex Socket Communication",
Stack Overflow, 2013-12-14,
<https://stackoverflow.com/questions/18728355/ssl-renegotiation-with-full-duplex-socket-communication>

V. Kruglikov et al., "Full-duplex SSL/TLS renegotiation failure", OpenSSL
Ticket #2481, 2011-03-26,
<https://rt.openssl.org/Ticket/Display.html?id=2481&user=guest&pass=guest>

OpenSSL, documentation, <https://www.openssl.org/docs/>

OpenSSL, "HOWTO keys", ```openssl/doc/HOWTO/keys.txt```

OpenSSL, "HOWTO proxy certificates",
```openssl/doc/HOWTO/proxy_certificates.txt```

OpenSSL, "HOWTO certificates", ```openssl/doc/HOWTO/certificates.txt```

OpenSSL, "Fingerprints for Signing Releases", ```openssl/doc/fingerprints.txt```

OpenSSL Wiki, "FIPS mode and TLS",
<https://wiki.openssl.org/index.php/FIPS_mode_and_TLS>

E. Rescorla, "An Introduction to OpenSSL Programming (Part I)", Version
1.0, 2001-10-05, <http://www.past5.com/assets/post_docs/openssl1.pdf>
(also Linux Journal, September 2001)

E. Rescorla, "An Introduction to OpenSSL Programming (Part II)", Version
1.0, 2002-01-09, <http://www.past5.com/assets/post_docs/openssl2.pdf>
(also Linux Journal, September 2001)

I. Ristic, _OpenSSL Cookbook_, Feisty Duck,
<https://www.feistyduck.com/books/openssl-cookbook/>

I. Ristic, "SSL and TLS Deployment Best Practices", Version 1.6-draft,
Qualys/SSL Labs, 2017-05-13,
<https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices>

L. Rumcajs, "How to perform a rehandshake (renegotiation) with OpenSSL API",
Stack Overflow, 2015-12-04,
<https://stackoverflow.com/questions/28944294/how-to-perform-a-rehandshake-renegotiation-with-openssl-api>

J. Viega, et al., _Network Security with OpenSSL_, O'Reilly,
2002

J. Viega, et al., _Secure Programming Cookbook for C and C++_, O'Reilly,
2003

# Articles

Chip Overclock, "Using The Open Secure Socket Layer In C", 2018-04,
<https://coverclock.blogspot.com/2018/04/using-open-secure-socket-layer-in-c.html>

Chip Overclock, "When Learning By Doing Goes To Eleven", 2020-03,
<https://coverclock.blogspot.com/2020/03/when-learning-by-doing-goes-to-eleven.html>

# Soundtrack

<https://www.youtube.com/playlist?list=PLd7Yo1333iA8yVIm-Pw5yfTcHNTbhNSux>

# Acknowledgements

Special thanks to Doug Gibbons, my long-time friend, occasional colleague,
and one-time office mate, who was extraordinarily generous with his
deep expertise in this area.
