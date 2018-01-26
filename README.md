# com-diag-codex

Learning How to Use the Open Secure Socket Layer (OpenSSL) API

## Copyright

Copyright 2018 Digital Aggregates Corporation, Arvada Colorado USA

## Trademarks

"Digital Aggregates Corporation" is a registered trademark.

"Chip Overclock" is a registered trademark.

## License

Licensed under the terms in LICENSE.txt.

## Abstract

Codex provides a simple higher-level C-based application programming
interface to the Open Secure Socket Layer (OpenSSL) API. Mostly it's my
excuse to learn how to use OpenSSL for both authentication and encryption
for the kinds of low-level, typically C or C++, code that I get paid
to develop.

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

J. Viega, M. Messier, P. Chandra, _Network Security with OpenSSL_, O'Reilly, 2002

J. Viega, M. Messier, _Secure Programming Cookbook_, O'Reilly, 2003

## Acknowledgements

Special thanks to Doug Gibbons, my long-time friend, occasional colleague, and
one-time office mate, who was extraordinarily generous with his special
expertise in this area.