# Cryptographic Algorithm implementation and validation of SHA3 and XTS-AES (Cryptographic Algorithmic Validation Program (CAVP))
One of the important steps in certifying cryptographic algorithm is Cryptographic Algorithmic Validation Program (CAVP). NIST has enunciated a procedure for carrying out algorithmic validation as implemented for publicly known as well as non-publicly known key ciphers and their known variants. NIST has also provided for each of these algorithms a set of test vectors and expected response. The algorithm that we have chosen for implementation are hash function (SHA3 bit oriented) and block cipher mode of operation (XTS-AES). Their implementation is not publicly available. SHA3 algorithm uses Keccak Permutation. We have implemented the algorithm in Java language on Windows based OS.

These are some more details and working of project(CAVP). 
![General FLOW of CAVP](https://github.com/coolnishant/Cryptographic-Algorithm-implementation-and-validation-of-SHA3-and-XTS-AES-CAVP-/tree/master/images/CAVP.JPG)
# General FLOW of CAVP

![Stakeholders in CAVP](https://github.com/coolnishant/Cryptographic-Algorithm-implementation-and-validation-of-SHA3-and-XTS-AES-CAVP-/tree/master/images/Stakeholders.JPG)
# Stakeholders in CAVP

![CAVP System](https://github.com/coolnishant/Cryptographic-Algorithm-implementation-and-validation-of-SHA3-and-XTS-AES-CAVP-/tree/master/images/CAVP sys.JPG)
# CAV System

![Use Case of CAVS](https://github.com/coolnishant/Cryptographic-Algorithm-implementation-and-validation-of-SHA3-and-XTS-AES-CAVP-/tree/master/images/CAVP.JPG)
# Use Case of CAVS
CST : Cryptographic System Testing (A part of CAVS)

# SHA-3-Bit-Oriented-Implementation-
It's SHA-3 224 256 384 512 bit oriented implementation. It is tested on NIST test vectors for Short and Long messages of all the 224 256 384 512 output bit.

# XTS-AES is block cipher mode for encryption of storage data.
