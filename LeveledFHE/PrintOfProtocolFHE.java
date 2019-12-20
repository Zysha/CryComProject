import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;

public class PrintOfProtocolFHE {
    public static void main(String[] args) {
        int lambda,chi,w;
        if (args.length < 1) {
            Scanner in = new Scanner(System.in);
            System.out.println("This program prints an emulation of the BGV scheme from http://doi.acm.org/10.1145/2633600.");
            System.out.println("Enter 'w', the bit to be encrypted:");
            w = in.nextInt();
            System.out.println("Enter 'lambda', security parameter:");
            lambda = in.nextInt();
            System.out.println("Enter 'chi', defining the error distribution:");
            chi = in.nextInt();
        } else {
            w = Integer.parseInt(args[0]);
            lambda = Integer.parseInt(args[1]);
            chi = Integer.parseInt(args[2]);
        }
        System.out.println("The following has been registered as the bit, dimension, modulus:");
        System.out.println("w:" + w + ", lambda:" + lambda + ", chi:" + chi);
        FHEParty p1 = new FHEParty(lambda, chi, 6);
        p1.keyGen();
        BigInteger[] x0 = p1.encrypt(w);
        BigInteger[] one0 = p1.encrypt(1);
        BigInteger[] c1 = p1.addCiphers(one0, x0);

        BigInteger[] y0 = p1.encrypt(0);
        BigInteger[] c2 = p1.multCiphers(y0, c1);

        BigInteger[] one1 = p1.encrypt(1);
        BigInteger[] c3 = p1.multCiphers(one1, c2);

        BigInteger[] x1 = p1.encrypt(w);
        BigInteger[] one3 = p1.encrypt(1);
        BigInteger[] c4 = p1.addCiphers(one3, x1);

        BigInteger[] y1 = p1.encrypt(0);
        BigInteger[] c5 = p1.multCiphers(y1, c4);

        BigInteger[] one4 = p1.encrypt(1);
        BigInteger[] c6 = p1.multCiphers(one4, c5);

        BigInteger[] c7 = p1.multCiphers(c3, c6);

        BigInteger[] x2 = p1.encrypt(w);
        BigInteger[] one5 = p1.encrypt(1);
        BigInteger[] c8 = p1.addCiphers(one5, x2);

        BigInteger[] y2 = p1.encrypt(0);
        BigInteger[] c9 = p1.multCiphers(y2, c8);

        BigInteger[] one6 = p1.encrypt(1);
        BigInteger[] c10 = p1.multCiphers(one6, c9);

        BigInteger[] encryptedResult = p1.multCiphers(c7, c10);

        System.out.println("(1 ⊕ (0 · (1 ⊕ w))) · (1 ⊕ (0 · (1 ⊕ w))) · (1 ⊕ (0 · (1 ⊕ w))): " + p1.decrypt(encryptedResult));
    }
}