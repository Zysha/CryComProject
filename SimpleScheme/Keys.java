import java.security.SecureRandom;

class SimpleSecretKey {
    private long[] secretKey;
    private final int n;
    private final long q;

    private SecureRandom rand = new SecureRandom();

    /**
     * Constructs a SimpleSecretKey object for the simple LWE encryption scheme.
     * @param n is the dimension of the secret key.
     * @param q is the modulus of the scheme.
     */
    public SimpleSecretKey(int n, long q){
        this.n = n;
        this.q = q;
        secretKey = new long[n];
    }

    /**
     * Generates a secret key based on the parameters chosen at initialisation.
     */
    public void genSecretKey(){
        for (int i = 0; i < n; i++){
            secretKey[i] = mod(rand.nextLong(), q);
        }
    }

    /**
     * Simple getter method for retrieving the secret key.
     * @return Returns the secret key.
     */
    public long[] getSecretKey() {
        return secretKey;
    }

    /**
     * Simple method used to compute modulus.
     * @param x a number.
     * @param y the modulus.
     * @return Returns x mod y.
     */
    private long mod(long x, long y) {
        long result = x % y;
        if (result < 0){
            return result + y;
        } else {
            return result;
        }
    }
}

class SimplePublicKey {
    private final int k;
    private final long q;
    private int m, n;
    private long[][] a;
    private long[] b;
    private final SimpleSecretKey secretKey;
    private SecureRandom rand = new SecureRandom();

    /**
     * Constructs a SimplePublicKey object for the simple LWE encryption scheme.
     * @param secretKey is the secret key, s, used in a_i · s + e_i.
     * @param m is the number of "equations".
     * @param k is the error parameter - k defines the binomial distribution ψ_k.
     */
    SimplePublicKey(SimpleSecretKey secretKey, int n, int m, long q, int k){
        this.secretKey = secretKey;
        this.q = q;
        this.m = m;
        this.k = k;
        this.n = n;
        this.a = new long[m][n];
        this.b = new long[m];
    }

    /**
     * Generates a public key based on the parameters chosen at initialisation.
     */
    public void genPublicKey(){
        for (int i = 0; i < m; i++){
            for (int j = 0; j < n; j++){
                a[i][j] = mod(rand.nextLong(), q);
            }
            b[i] = mod((dotProduct(a[i], secretKey.getSecretKey()) + getBinomial(k)), q);
        }
    }

    /**
     * Simple method used to compute modulus.
     * @param x a number.
     * @param y the modulus.
     * @return Returns x mod y.
     */
    private long mod(long x, long y) {
        long result = x % y;
        if (result < 0){
            return result + y;
        } else {
            return result;
        }
    }

    /**
     * Simple getter method for the a_i's of the public key.
     * @return Returns the first part of a public key defined by a long[][]-array.
     */
    public long[][] getA() {
        return a;
    }

    /**
     * Simple getter method for the b_i's of the public key.
     * @return Returns the second part of a public key defined by a long[]-array.
     */
    public long[] getB() {
        return b;
    }

    /**
     * A simple method for computing the dot product of two vectors.
     * @param a_i the first vector in the dot product - must be defined as an array of 'longs'.
     * @param s the second vector in the dot product - must be defined as an array of 'longs'.
     * @return Returns ∑a_i[l] · s[l] for l = [0, dim(a_i)]
     */
    private static long dotProduct(long[] a_i, long[] s) {
        long sum = 0;
        for (int i = 0; i < a_i.length; i++) {
            sum = a_i[i] * s[i];
        }
        return sum;
    }

    /**
     * Samples from a centered binomial distribution - mean = 0, variance k/2.
     * Is based on approached described in 'Post-quantum key exchange – a new hope∗' (https://eprint.iacr.org/2015/1092.pdf)
     * @param k defines the sample space.
     * @return Returns a sample.
     */
    private int getBinomial(int k) {
        int sum = 0;
        for (int i = 0; i < k - 1; i++){
            int b_0 = rand.nextInt(2);
            int b_1 = rand.nextInt(2);
            sum += b_0 - b_1;
        }
        return sum;
    }

    /**
     * Simple coin-flipping algorithm to sample from a binomial distribution.
     * @param n is the number of trials.
     * @param p is the probability of success in each trial.
     * @return Returns a sample.
     */
    public int getBinomial(int n, double p) {
        int sum = 0;
        for (int i = 0; i < n; i++) {
            if(rand.nextDouble() < p)
                sum++;
        }
        return sum;
    }
}

class SimpleKeyPair {
    private final SimpleSecretKey secretKey;
    private SimplePublicKey publicKey;

    private final int k, n;
    private final long q;

    /**
     Constructs a SimpleKeyPair object for the simple LWE encryption scheme.
     * @param n is the dimension of the secret key.
     * @param q is the modulus of the scheme.
     * @param m is the number of "equations".
     * @param k is the error parameter - k defines the binomial distribution ψ_k.
     */
    SimpleKeyPair(int n, int m, long q, int k) {
        this.secretKey = new SimpleSecretKey(n, q);
        this.publicKey = new SimplePublicKey(secretKey, n, m, q, k);
        this.k = k;
        this.q = q;
        this.n = n;
    }

    /**
     * Simple getter method for the secret key.
     * @return Returns the secret key.
     */
    public long[] getSecretKey () {
        secretKey.genSecretKey();
        return secretKey.getSecretKey();
    }

    /**
     * Simple getter method for the public key.
     * @return Returns the public key.
     */
    public long[][] getA_iPublicKey () {
        publicKey.genPublicKey();
        return publicKey.getA();
    }

    public long[] getB_iPublicKey() {
        return publicKey.getB();
    }

    /**
     * Generates a new public key based on possibly different number of equations.
     * @param m number of equations in the public key.
     */
    public void genNewPubKey (int m) {
        publicKey = new SimplePublicKey (secretKey, m, k, q, n);
    }
}