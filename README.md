# LWE, CryCom
Repo for CryCom project.

The project is split into two subprojects each with their own folder. 

A folder, SimpleScheme, containing our efforts towards implementing the first learning with errors (LWE)-based public-key encryption scheme introduced by Regev in https://cims.nyu.edu/~regev/papers/qcrypto.pdf . 

While the second folder, LeveledFHE, encompasses a version of the BGV-scheme (Brakerski, Gentry and Vaikuntanathan, http://doi.acm.org/10.1145/2633600) with certain aspects simplified. These simplifications related to limiting the scheme by solely basing it on LWE, as opposed of deciding between LWE and Ring-LWE.

# SimpleScheme
Apart from possibly overlooked elements, then there should be an extensive Java-doc associated with this project. And as such, we will not go into details with specific methods.

The protocol is not designed to work over a network; it only emulates the scheme and nothing else. This also makes it easy to try out on a single computer.

This can be done using the ‘PrintOfProtocol’-file. The program emulates the protocol run between two parties and prints the intermediate values. This can be done by passing arguments to the program in the following order; bit to encrypt, the bit length of the modulus. Or running the program with no arguments and being promoted for the arguments in System.in.

# LeveledFHE
The implementation of the scheme does not work - are unable to locate the error(s).

The protocol is not designed to work over a network; it only emulates the scheme and nothing else. This also makes it easy to try out on a single computer.

This can be done using the ‘PrintOfProtocol’-file. The program emulates the protocol run between two parties and prints the intermediate values. 
This can be done by passing arguments to the program in the following order; bit to encrypt, the security parameter lambda, and the variance of the error distribution. 
Or running the program with no arguments and being promoted for the arguments in System.in.
And it will output (1 ⊕ (0 · (1 ⊕ w))) · (1 ⊕ (0 · (1 ⊕ w))) · (1 ⊕ (0 · (1 ⊕ w))) (An always true blood type test).