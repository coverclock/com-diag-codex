# com-diag-codex

Slightly Simpler Open Secure Socket Layer (OpenSSL) API in C.

## Copyright

Copyright 2018 Digital Aggregates Corporation, Arvada Colorado USA

## License

Licensed under the terms in LICENSE.txt (FSF LGPL 2.1).

## Trademarks

"Digital Aggregates Corporation" is a registered trademark.

"Chip Overclock" is a registered trademark.

## Abstract

Codex provides a slightly simpler higher-level C-based application
programming interface to the Open Secure Socket Layer (OpenSSL)
API. Mostly it's my excuse to learn how to use the OpenSSL C API for
both authentication and encryption for the kinds of low-level, usually
C or C++, code that I typically am asked to develop. Codex is built on
top of Diminuto, my C-based systems programming library I've been using
for years in both personal and commercial development projects.

## Disclaimer

This is not my area of expertise, which is why nothing about the Secure
Socket Layer or cyber-security shows up on my resume. But people learn in
different ways, and my way has always been hands-on learn-by-doing. Codex
has been a useful mechanism through which I would like to think I've
learned enough to use OpenSSL in the kinds of Internet of Things product
development efforts on which I get paid to work. No warranty is
expressed or implied.

## What Works

I first developed Codex under OpenSSL 1.0.2 (the default version under
Ubuntu "xenial"). I later ported it to OpenSSL 1.1.1 (the development
version at the time I did this work), OpenSSL 1.0.1 (the default version
under Raspbian "jessie" on the Raspberry Pi 2 and 3), OpenSSL 1.1.0 (the
default verison under Raspbian "stretch"), and BoringSSL 1.1.0
(Google's fork of OpenSSL 1.1.0).

The Codex handshake (renegotiation) feature in Codex only works under OpenSSL
1.0.2. It's of questionable value anyway, but it was an enlightening
exercise. The Codex handshake unit test however remains very useful since it
only attempts a renegotiation if either end, client or server, receives a
hangup signal (```SIGHUP```).

I have run all the unit tests on an x86_64 Ubuntu "xenial" system, and
on both a Raspberry Pi 2 (ARM 32-bit) and 3 (ARM 64-bit) running Raspbian
"jessie".

I have also run the client and server unit tests programs talking between
the x86_64 and the ARMs, each using Codex built against their "native"
versions of OpenSSL, as a demonstration of interoperability. This use of an
X86_64 server with ARM clients is a typical IoT configuration on the kinds of
stuff on which I typically work.

## Contact

Chip Overclock  
<coverclock@diag.com>  
Digital Aggregates Corporation  
<http://www.diag.com>  
3440 Youngfield St. #209  
Wheat Ridge CO 80033 USA  

## Remarks

The application programming interface for Codex is split into a *public* API
and a *private* API. The public API is defined in the header file

    Codex/inc/com/diag/codex/codex.h
    
and is intended for application developers using the library. This header file
would be installed in, for example, ```/usr/local``` and could be included
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

### Handshake

The Handshake layer - the handshake portion of which only works in OpenSSL
1.0.2 - allows peers to establish secure stream connections, pass variable
sized packets in full-duplex fashion, and use indications to coordinate the
of the session so that new encryption keys can be established and each end can
be re-authenticated. This is especially important for long lived connections,
since the longer an encryption key is used, the more likely it is that
it will be cracked. However, TLS 1.3, due to arrive when OpenSSL 1.1.1
is fully released, makes this technique obsolete by replacing it with
a native key change capability. Never the less, it was an interesting
intellectual exercise, and certainly led me to a better understanding
of how the OpenSSL implementation of the SSL protocol works.

Empirical evidence suggests that regardless of what the OpenSSL
documentation may suggest, both unidirectional byte streams of
the full-duplex connection must be empty of application data for
the renegotiation to succeed. This is because the handshake for the
renegotiation is done in-band, and the protocol does not know how to
handle unexpected application data. This is probably not a problem in
typical web-based OpenSSL applications, whose communication consists of
half-duplex HTTP requests and responses. But in the Internet of Things
(IoT) domain of sensors and real-time data, this may not be the case.
Furthermore, the handshake itself is implemented on the requestee side
by state machines in OpenSSL which piggy-back the handshake protocol on
application-driven I/O. So the requestee must drive those state machines
on its side of the handshake by doing I/O, whether it has any data to
send or receive or not.

Using the Handshake unit test as an example, either the Server or
the Client processes that implement the unit test can initiate a
renegotiation; this is done by the tester by sending any of the processes
a ```SIGHUP``` (hangup) signal.  A ```SIGHUP``` sent to a client causes
it to initiate a renegotiation with the server just for its connection. A
SIGHUP sent to the server causes it to initiate a renegotiation with all
of its clients. In any case, both unidirectional (read, write) streams of
the full-duplex connection must be emptied for the handshake to succeed.

The unit test implements a simple protocol consisting of a FAREND
(a.k.a. start) indication sent from the requestor to the requestee
while at the same time the requestor ceases writing data packets to
the connection. The requestee responds with a READY indication while
at the same time ceasing writing to the requestor.  Once the handshake
is complete, the requestor writes a DONE indication which the requestee
reads, and then full-duplex communication resumes.

In the case of the server side of the Handshake unit test being the
requestor, the server must buffer incoming packets that were in-flight at
the time it sent the client a FAREND indication in order to quiesce its
output stream.  The amount of data it must buffer will be two times the
bandwidth delay product of the communication channel between the client
and the server. This can be substantial (thousands of packets, each
containing hundreds of bytes). Any application expecting to renegotiate
an OpenSSL connection being used for full-duplex communication must take
this into account.

**Important safety tip**: I haven't tried to make the Handshake unit
test robust against a client and a server simultaneously requesting
a renegotiation. But that's a legitimate concern that a real-world
application should worry about.

## Dependencies

OpenSSL 1.0.2g
*or*
BoringSSL 1.1.0
*or*
OpenSSL 1.1.1-pre2-dev
*or*
OpenSSL 1.0.1t
*or*
OpenSSL 1.1.0

Diminuto 48.4.1 (later releases may work as well)

## Targets

"Nickel"    
Intel NUC5i7RYH    
Intel Core i7-5557U @ 3.10GHz x 8    
Ubuntu 16.04.3 LTS "xenial"    
Linux 4.10.0    
gcc 5.4.0    

"Lead" or "Copper"    
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

"Cobalt"    
Raspberry Pi 3 Model B (64-bit ARM)    
Broadcom BCM2837 Cortex-A53 ARMv7 @ 1.2GHz x 4    
Raspbian GNU/Linux 9.4 "stretch"    
Linux 4.14.30    
gcc 6.3.0    

## Certificates

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

The ```Makefile``` has a helper target that uses ```ssh(1)``` and ```scp(1)```
to copy the near end signing certificates to the far end where they will
be used to sign the far end's credentials when you build the far end. This
helper target makes some assumptions about the far end directory tree
looking something like the near end directory tree, at least relative
to the home directory on either ends.

For example, I exported root and CA credentials from my x86_64 Ubuntu
system "nickel", that were generated during the build of that Codex,
to my ARM Raspbian systems "lead" and "bronze", prior to the build of
Codex on those systems.

    make exported FAREND="pi@lead"
    make exported FAREND="pi@bronze"

Codex builds just enough Public Key Infrastructure (PKI) to run the unit
tests.

## Passwords

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

## Verification

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
valid. If the peer mamed "localhost" connects via IPv4, its far end IPv4
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

## Certificate Revocation Lists

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

## Configuration

Codex has a number of OpenSSL-related configuration parameters. The
defaults can be configured at build-time by changing the make variables in
```cfg/codex.mk```. Some of the defaults can be overridden at run-time by
settors defined in the private API. Here are the defaults.

* RSA asymmetric cipher with 3072-bit keys is used for encrypting certificates.
* SHA256 message digest cryptographic hash function is used for signing certificates.
* TLS v1.2 protocol is used.
* Diffie-Hellman generator function 2 is used to generate the DH parameters.
* Diffie-Hellman with 2048-bit keys is used for exchanging keys.
* Symmetric cipher selection string "TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL" is used for encrypting the data stream.

## Directories
 
* ```bin``` - utility source files.
* ```cfg``` - makefile configuration files.
* ```dat``` - performance testing artifacts.
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

## Building

If you want to use OpenSSL 1.0.2 on an X86_64 running Ubuntu "xenial"
system, you can install it with the Aptitude package manager using the
command below. This same command, minus ```libssl-doc```, will install
OpenSSL 1.0.1 for Raspbian "jessie" on the Raspberry Pi.

    sudo apt-get install openssl libssl-dev libssl-doc

If you want to build OpenSSL 1.0.1t, which is the version used by the
current Raspbian (jessie) on the Raspberry Pi 2 and 3, use the commands
below.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/openssl/openssl openssl-1.0.1t
    cd openssl-1.0.1t
    git checkout OpenSSL_1_0_1t
    ./config -shared
    make depend
    make

If you want to build BoringSSL 1.1.0, which is the current version of
Google's fork of OpenSSL, use the commands below.

    cd
    mkdir -p src
    cd src
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    mkdir build
    cd build
    cmake -DBUILD_SHARED_LIBS=1 -DBORINGSSL_SHARED_LIBRARY=1 -DBORING_IMPLEMENTATION=1 ..
    make
    
If you want to build OpenSSL 1.1.1, which is the current version from
the OpenSSL project, use the commands below.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/openssl/openssl
    cd openssl
    ./config
    make

Clone and build Diminuto 48.4.1, a library I wrote that Codex is built
upon.  (Later versions of Diminuto may work providing I haven't altered
the portions of the API on which Codex depends.)

    cd
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-diminuto
    cd com-diag-diminuto/Diminuto
    git checkout 48.4.1
    make pristine depend all

Clone and build Codex, a library I wrote, choosing the flavor of OpenSSL
library you want to use based on the make configuration files available in
the directory ```cfg```.

    cd
    mkdir -p src
    cd src
    git clone https://github.com/coverclock/com-diag-codex
    cd com-diag-codex/Codex
    make pristine depend all FLAVOR=!FLAVOR!

Here are the FLAVORs I've tested with Codex.

* ```FLAVOR=openssl``` is the default installed version on the build system,
e.g. OpenSSL 1.0.2 on Ubuntu "xenial", or OpenSSL 1.0.1 on Raspbian "jessie";
* ```FLAVOR=openssl-1.0.1``` is OpenSSL 1.0.1 as used on Raspbian "jessie" but
which I built for testing on Ubuntu "xenial";
* ```FLAVOR=boringssl-1.1.0``` is Google's fork of OpenSSL;
* ```FLAVOR=openssl-1.1.1``` is the development version of OpenSSL at the time
I did this work.

When in doubt, you can ask Codex what how it was built.

    cd ~/src/com-diag-codex/Codex
    . out/host/bin/setup
    ./out/host/tst/unittest-sanity
    ./out/host/bin/vintage

Note the space between the dot and the path to the setup script. This script
is included by Bash to define ```PATH```, ```LD_LIBRARY_PATH``` and other
necessary variables in the environment, so that you can test without installing
Codex or Diminuto.

## Logging

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

## Testing

Run the Codex unit tests without having to install anything in, for
example,``` /usr/local```.

    cd ~/src/com-diag-codex/Codex
    . out/host/bin/setup
    unittest-sanity
    unittest-core
    unittest-machine
    
This unit test allows you to test renegotiation from either side of the
connection on OpenSSL-1.0.2 (only) by sending the server process or a
client process a "hangup" signal a.k.a. ```SIGHUP```. You can find the
process identifiers (PID) for the processes in the log output to standard
error. You can use the ```kill(1)``` command to send a ```SIGHUP``` to
the process you want to instigate a renegotiation with its peer. (The
unit test will run on other OpenSSL flavors, you just won't be able to
get negotiation to work.)

    unittest-handshake
    
These unit tests will deliberately fail as a test of verification failure
either by the client (the server fails to authenticate) or the server
(the client fails to authenticate).

    unittest-verification-client
    unittest-verification-server
    unittest-verification-bogus
    unittest-verification-self
    unittest-verification-revoked

These unit tests disable verification and therefore pass.

    unittest-noverification-client
    unittest-noverification-server
    unittest-noverification-bogus
    unittest-noverification-self
    unittest-noverification-revoked

These unit test scripts that have my network host names baked in, but you
can trivially modify them so that you can easily run tests between computers.
You will also have to edit the configuration files for the certificates used
by these unit tests since the host names are also baked into the certificates
and Codex requires that they match to authenticate both sides in the
connection.

    unittest-server
    unittest-client

There is a Control unittest that duplicates the functionality of
the Core unittest but without using SSL at all. I use this to
compare the performance of applications with and without SSL.

    unittest-control

You can run the ```openssl s_client``` command against the
```unittest-server``` server-side unit test and see what Codex is
actually telling the client.

    openssl s_client -connect localhost:49302 2>&1 < /dev/null

An example of the output of such a command can be found in
```txt/unittest-server-nickel.txt```.

## Documentation

Codex, like Diminuto, has embedded Doxygen comments in the header files
that define the public API. If you have the Doxygen and TeX packages
installed, you can generate HTML and man page documentation.

    make documentation

If you have the full (enormous) TeX system installed, plus some standard
PDF utilities, you can generate PDF manuals.

    make documentation-ancillary

## Performance

There are a number of scripts in the ```tst``` directory that I used to do
some performance testing by comparing the total CPU time of ```unittest-core```
against that of ```unittest-control``` for various workloads and configurations.
I then used ```awk```, R, and Excel to post-process the data. The results can
be found in the ```dat``` directory. This is even more a work in progress than
the rest of this effort. The scripts and artifacts are somewhat misnamed as
"unittest" because they were derived from what was originally a unit test
script.

## Repositories

<https://github.com/coverclock/com-diag-codex>

<https://github.com/coverclock/com-diag-diminuto>

<https://github.com/openssl/openssl>

<https://boringssl.googlesource.com/boringssl>

## References

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
Communication Security (*CCS'12), Raleigh NC USA, 2012-10-16..18,
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

## Acknowledgements

Special thanks to Doug Gibbons, my long-time friend, occasional colleague,
and one-time office mate, who was extraordinarily generous with his
deep expertise in this area.
