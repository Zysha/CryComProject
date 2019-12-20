import java.util.Arrays;
import java.util.Scanner;

public class PrintOfProtocol {
    private static int w, n, q;
    public static void main(String[] args) {
        if (args.length < 1) {
            Scanner in = new Scanner(System.in);
            System.out.println("This program prints an emulation of the LWE public key cryptosystem from Regev's 09 text.");
            System.out.println("Enter 'w', the bit to be encrypted:");
            w = in.nextInt();
            System.out.println("Enter 'n', the dimension of the secret key:");
            n = in.nextInt();
            System.out.println("Enter 'log_2(q)', the bit length of modulus used:");
            q = in.nextInt();
        } else {
            w = Integer.parseInt(args[0]);
            n = Integer.parseInt(args[1]);
            q = Integer.parseInt(args[2]);
        }
        System.out.println("The following has been registered as the bit, dimension, bit length of modulus:");
        System.out.println("w:" + w + ", n:" +  n + ", log_2(q):" + q);
        Party p1 = new Party(n, q);
        Party p2 = new Party(n, q);
        p1.generateKeys();
        System.out.println("The following key pair has been produced:");
        System.out.println("Secret key: " + Arrays.toString(p1.getSecretKey()));
        System.out.println("Public key: " + Arrays.deepToString(p1.getAOfPublicKey()) + Arrays.toString(p1.getBOfPublicKey()));
        p2.retrievePublicKey(p1.getAOfPublicKey(), p1.getBOfPublicKey());
        p2.encryptBit(w);
        System.out.println("Using the public key, this encryption has been produced:");
        System.out.println("(u, v): " + Arrays.deepToString(p2.sendCiphertext()));
        p1.receiveCiphertext(p2.sendCiphertext());
        System.out.println("(u, v) has been decrypted to " + p1.decryptToBit());
    }
}