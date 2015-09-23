# EC-SRP Java Card Applet

This Java Card applet is an implementation of the elliptic curve variant of the Secure Remote Password (SRP-5)
password-authenticated secure channel protocol from IEEE Std 1363.2-2008 [1]. In combination with an
implementation of an off-card application, such as an Android application using
our [EC-SRP Android Library](https://github.com/mobilesec/secure-channel-ec-srp-android-lib),
you can establish a secure communication channel that is mutually authenticated
with a PIN or password. This implementation relys on standard Java Card 2.2 API
functionality as well as NXP extended APIs v2.4.1.R3. In order to use this secure channel protocol implementation you will therefore need a JCOP 2.4.1 based smart card. 

Although secure elements with Java Card 2.2 API are usually
equipped with the necessary hardware for computation of modulo operations as used
in SRP, limitations of the standard Java Card 2.2 API prevent direct access to
the necessary cryptographic primitives. Hence, this makes it challenging to
implement SRP with acceptable performance. However, by exploiting the RSA
encryption and the ECDH key agreement API provided by the platform, we show that it is possible to compute
exponentiations and multiplications with support of the cryptographic
co-processor. This, and minor adaptations to the protocol, made it possible to
implement the elliptic curve variant of SRP server-side in a Java Card applet with reasonable
computation time. This work was initially presented in the MoMM2014 paper [2]. The extended version of this paper includes the elliptic curve variant of SRP and was published in IJPCC [3].


## DISCLAIMER

You are using this application at your own risk. *We are not responsible for any
damage caused by this application, incorrect usage or inaccuracies in this manual.*

## LITERATURE

[1] IEEE Computer Society, "*IEEE Standard Specifications for Password-Based Public-Key Cryptographic Techniques*," IEEE Std 1363.2-2008, pp. 1-127, Jan. 2009.

[2] M. Hölzl, E. Asnake, R. Mayrhofer, and M. Roland: "*Mobile Application to Java Card Applet Communication using a Password-authenticated Secure Channel*," in Proceedings of the 12th International Conference on Advances in Mobile Computing & Multimedia (MoMM2014), pp. 147-156, ACM, December 2014.

[3] M. Hölzl, E. Asnake, R. Mayrhofer, and M. Roland: "*A Password-authenticated Secure Channel for App to Java Card Applet Communication*," in International Journal of Pervasive Computing and Communications (IJPCC), In Press.
