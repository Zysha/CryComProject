import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.NoSuchElementException;

public class Party {
    private int n, m, k;
    private long q;
    private long[] secretKey;
    private long[][] a;
    private long[] b;
    private long[][] encryptionOfABit,uv = new long[2][];

    /**
     Constructs a Party object for the simple LWE encryption scheme.
     m is the number of "equations.
     k defines the distribution.
     * @param n is the dimension of the secret key.
     * @param qBitLength is the modulus of the scheme.
     */
    public Party(int n, int qBitLength){
        SecureRandom rand = new SecureRandom();
        this.n = n;
        this.q = BigInteger.probablePrime(qBitLength, rand).abs().longValue();
        System.out.println(q);
        this.m = ((2 * n + 1) * (int) log(q));
        this.k = (int) Math.floor(q /(2.* (m)));
        this.a = new long[m][n];
        this.b = new long[m];
    }

    /**
     * Creates a SimpleKeyPair object that generates a key pair based on the Party's initialisation values.
     */
    public void generateKeys(){
        SimpleKeyPair kp = new SimpleKeyPair(n, m, q, k);
        secretKey = kp.getSecretKey();
        a = kp.getA_iPublicKey();
        b = kp.getB_iPublicKey();
    }

    /**
     * Emulates the retrieval of a public key.
     * @param a the a_i's of the public key.
     * @param b the b_i's of the public key.
     */
    public void retrievePublicKey(long[][] a, long[] b){
        this.a = a;
        this.b = b;
    }

    /**
     * The encryption function described in
     * On Lattices, Learning with Errors, Random Linear Codes, and Cryptography - Oded Regev (https://cims.nyu.edu/~regev/papers/qcrypto.pdf)
     * @param w is the bit to be encrypted.
     */
    public void encryptBit(int w){
        if (w < 0 || w > 1){
            throw new InputMismatchException("Invalid input for encryption - the input must be a bit, {0,1}.");
        } else {
            SecureRandom rand = new SecureRandom();
            boolean[] b = new boolean[m];
            for (int i = 0; i < m; i++) {
                b[i] = rand.nextInt(2) == 1;
            }
            long[][] sum = new long[2][n];
            for (int i = 0; i < m; i++) {
                if (b[i]) {
                    sum[0] = basicArrayAddition(sum[0], a[i]);
                    sum[1][0] = mod((sum[1][0] + this.b[i]), q);
                }
            }
            sum[1][0] = mod(sum[1][0] + ((long) Math.ceil(((double) q) / 2.0) * w), q);
            encryptionOfABit = sum;
        }
    }

    /**
     * Emulates the sending of a ciphertext over a network.
     * @return Returns the an encryption of a bit.
     */
    public long[][] sendCiphertext(){
        if (Arrays.deepEquals(encryptionOfABit, new long[2][])){
            throw new NoSuchElementException("No bit has been encrypted - a ciphertext has to be computed before it can be sent.");
        } else {
            return encryptionOfABit;
        }
    }

    /**
     * The decryption function described in
     * On Lattices, Learning with Errors, Random Linear Codes, and Cryptography - Oded Regev (https://cims.nyu.edu/~regev/papers/qcrypto.pdf)
     * The ciphertext is (u,v) - u = 'uv[0]', v = 'uv[1][0]'. 'vsu' = v - su, where s is the secret key.
     *  @return Returns the bit encrypted.
     */
    public int decryptToBit(){
        long vsu = mod(mod(uv[1][0], q) - mod((dotProduct(uv[0], secretKey)), q), q);
        long qHalves = ((long) Math.ceil(((double) q) / 2.0));
        if (vsu >  qHalves / 2 && vsu < qHalves + qHalves / 2){
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Emulates the receiving of a message over a network.
     *  @param uv the tuple (u, v) to decrypt.
     *            u = ∑a_i, v = ∑(a_i * s + e_i) + ⌈q/2⌉ where i ∈ S defined by 'm' random bits.
     */
    public void receiveCiphertext(long[][] uv){
        this.uv = uv;
    }

    /**
     * Used as holder of public keys and for the sake of printing - should not be considered part of the scheme.
     * @return Returns the a_i's of the public key.
     */
    public long[][] getAOfPublicKey() {
        return a;
    }

    /**
     * Used as holder of public keys and for the sake of printing - should not be considered part of the scheme.
     * @return Returns the b_i's of the public key.
     */
    public long[] getBOfPublicKey() {
        return b;
    }

    /**
     * Method only used for the sake of printing - should not be considered part of the scheme.
     * @return Returns the secret key.
     */
    public long[] getSecretKey() {
        return secretKey;
    }

    /**
     * A simple method for adding two array to one another.
     * @param x the first array.
     * @param y the second array.
     * @return Returns [x_1 + y_1, x_2 + y_2, .., x_n + y_n].
     */
    private long[] basicArrayAddition(long[] x, long[] y) {
        long[] result = new long[x.length];
        for (int i = 0; i < x.length; i++) {
            result[i] = mod((x[i] + y[i]), q);
        }
        return result;
    }

    /**
     * A simple method for computing the dot product of two vectors.
     * @param u the first vector in the dot product - must be defined as an array of 'longs'.
     * @param s the second vector in the dot product - must be defined as an array of 'longs'.
     * @return Returns ∑u[l] · s[l] for l = [0, dim(u)]
     */
    private long dotProduct(long[] u, long[] s) {
        long sum = 0;
        for (int i = 0; i < u.length; i++) {
            sum = mod((sum + (u[i] * s[i])),q);
        }
        return sum;
    }

    /**
     * Simple method used to compute modulus.
     * @param x a number.
     * @param y the modulus.
     * @return Returns x mod y.
     */
    private long mod(long x, long y){
        long result = x % y;
        if (result < 0){
            return result + y;
        }
        else {
            return result;
        }
    }

    /**
     * A method for computing log_2 of ints.
     * @param x an int.
     * @return log_2(x)
     */
    private long log(long x){
        return (long)(Math.log(x)/Math.log(2)+1e-12);
    }
}
