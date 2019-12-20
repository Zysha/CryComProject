import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class EParty {
    private int n, m, chi;
    private BigInteger q;
    private BigInteger[] secretKey;
    private BigInteger[][] publicKey;
    private BigInteger[] sprime;
    private double nextGaussian;
    private boolean hasNextGaussian = false;

    public EParty(int lambda, int mu, int chi) {
        SecureRandom rand = new SecureRandom();
        q = BigInteger.probablePrime(mu, rand).abs();
        this.n = (lambda * log((int) Math.floor(q.doubleValue() / log(chi))));
        this.chi = chi;
        m = (2 * n + 1) * q.bitLength();
        secretKey = new BigInteger[n + 1];
        publicKey = new BigInteger[m][n + 1];
        sprime = new BigInteger[n];
    }

    public static void main(String[] args) {
        EParty p = new EParty(10, 10, 3);
        p.secretKeyGen();
        p.setPublicKey(p.publicKeyGen(p.getM(), p.getN()));
        int w = 0;
        BigInteger[] c = p.encrypt(w);
        System.out.println("Hopefully "+w+": " + p.decrypt(c));
    }

    private int getM() {
        return m;
    }

    public void secretKeyGen() {
        SecureRandom rand = new SecureRandom();
        secretKey[0] = BigInteger.ONE;
        for (int i = 1; i <= n; i++) {
            do {
                secretKey[i] = new BigInteger(q.bitLength(), rand);
            } while (secretKey[i].compareTo(q) >= 0);
            sprime[i - 1] = secretKey[i];
        }
    }

     public BigInteger[][] publicKeyGen(int m, int n) {
        SecureRandom rand = new SecureRandom();
        BigInteger[][] A = new BigInteger[m][n];
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < n; j++) {
                byte[] bytes = new byte[(int) Math.ceil( q.bitLength()/7.0)];
                rand.nextBytes(bytes);
                A[i][j] = new BigInteger(bytes).mod(q);
            }
        }
        BigInteger[] e = new BigInteger[m];
        for (int i = 0; i < m; i++){
            if (hasNextGaussian){
                e[i] = BigInteger.valueOf(Math.round(nextGaussian));
                hasNextGaussian = false;
            } else {
                e[i] = BigInteger.valueOf(Math.round(getGaussian(0, chi)));
            }
        }
        BigInteger[] b = vecAdd(matrixMultVec(A, sprime), constMultVector(BigInteger.TWO,e, q));
        return constructX(b, A);
    }

    public BigInteger[][] publicKeyGen(BigInteger[] s, int m) {
        SecureRandom rand = new SecureRandom();
        BigInteger[] sprime = new BigInteger[s.length - 1];
        System.arraycopy(s, 1, sprime, 0, s.length - 1);
        BigInteger[][] A = new BigInteger[m][s.length - 1];
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < s.length - 1; j++) {
                byte[] bytes = new byte[(int) Math.ceil( q.bitLength()/7.0)];
                rand.nextBytes(bytes);
                A[i][j] = new BigInteger(bytes).mod(q);
            }
        }
        BigInteger[] e = new BigInteger[m];
        for (int i = 0; i < m; i++){
            if (hasNextGaussian){
                e[i] = BigInteger.valueOf(Math.round(nextGaussian));
                hasNextGaussian = false;
            } else {
                e[i] = BigInteger.valueOf(Math.round(getGaussian(0, chi)));
            }
        }
        BigInteger[] b = vecAdd(matrixMultVec(A, sprime), constMultVector(BigInteger.TWO,e, q));
        return constructX(b, A);
    }

    public void setPublicKey(BigInteger[][] publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger[] encrypt(int w){
        BigInteger[] wVec = allZeroVec(n + 1);
        wVec[0] = BigInteger.valueOf(w);

        BigInteger[] r = allZeroVec(m);
        SecureRandom rand = new SecureRandom();
        for (int i = 0; i < m; i++){
            r[i] = BigInteger.valueOf(rand.nextInt(2));
        }
        return vecAdd(wVec, matrixMultVec(transpose(publicKey), r));
    }

    public int decrypt(BigInteger[] c){
        return dotProduct(c,secretKey).mod(BigInteger.TWO).intValue();
    }

    public void updateModulus(BigInteger q) {
        this.q = q;
    }

    /**
     * Gaussian sampling based on Box–Muller transform.
     * @param mean the mean of the distribution.
     * @param variance the variance of the distribution.
     * @return returns a sample from a Gaussian distribution.
     */
    public double getGaussian(int mean, int variance) {
        if (hasNextGaussian) {
            hasNextGaussian = false;
            return nextGaussian;
        } else {
            SecureRandom rand = new SecureRandom();
            double U1 = rand.nextDouble();
            double U2 = rand.nextDouble();
            double Z1 = Math.sqrt(-2 * Math.log(U1)) * Math.cos(2 * Math.PI * U2);
            double Z2 = Math.sqrt(-2 * Math.log(U1)) * Math.sin(2 * Math.PI * U2);
            nextGaussian = Z2 * variance + mean;
            hasNextGaussian = true;
            return Z1 * variance + mean;
        }
    }

    private int getBinomial(int k) {
        int sum = 0;
        SecureRandom rand = new SecureRandom();
        for (int i = 0; i < k - 1; i++) {
            int b_0 = rand.nextInt(2);
            int b_1 = rand.nextInt(2);
            sum += b_0 - b_1;
        }
        return sum;
    }

    public BigInteger[] tensorVecSelf(){
        int elementsToBeStored = ((n+1)*(n))/2;
        BigInteger[] sTensorS = new BigInteger[elementsToBeStored];
        if (n >= 0) System.arraycopy(secretKey, 1, sTensorS, 0, n);
        int offset;
        for (int i = 1; i < n; i++){
            if (i == 1){
                offset = n;
            } else {
                offset = (n * i - (i * (i - 1)) / 2);
            }
            for (int j = i; j < n + 1; j++){
                sTensorS[(offset + (j - i))] = secretKey[i].multiply(secretKey[j]).mod(q);
            }
        }
        return sTensorS;
    }

    public BigInteger getQ() {
        return q;
    }

    /**
     * Is only available to the party who produced the keys.
     * Needed for keyswitching in current state.
     * @return the secret key of the scheme.
     */
    public BigInteger[] getSecretKey() {
        return secretKey;
    }

    public int getN() {
        return n;
    }

    private BigInteger[][] constructX(BigInteger[] b, BigInteger[][] A){
        BigInteger[][] X = new BigInteger[A.length][A[0].length + 1];
        BigInteger[][] AMinus = matrixSub(allZeroMat(A.length, A[0].length), A);
        for (int i = 0; i < A.length; i++){
            for (int j = 0; j < A[0].length + 1; j++){
                if (j == 0){
                    X[i][j] = b[i];
                } else {
                    X[i][j] = AMinus[i][j - 1];
                }
            }
        }
        return X;
    }

    private BigInteger[] matrixMultVec(BigInteger[][] A, BigInteger[] s){
        BigInteger[] As = allZeroVec(A.length);
        for (int i = 0; i < A.length; i++) {
            for (int j = 0; j < A[0].length; j++) {
                As[i] = As[i].add(A[i][j].multiply(s[j])).mod(q);
            }
        }
        return As;
    }

    private BigInteger[][] matrixSub(BigInteger[][] M, BigInteger[][] A){
        BigInteger[][] MSubA = new BigInteger[A.length][A[0].length];
        for (int i = 0; i < A.length; i++){
            for (int j = 0; j < A[0].length; j++){
                MSubA[i][j] = M[i][j].subtract(A[i][j]).mod(q);
            }
        }
        return MSubA;
    }

    private BigInteger[][] transpose(BigInteger[][] M){
        BigInteger[][] MT = new BigInteger[M[0].length][M.length];
        for (int i = 0; i < M[0].length; i++){
            for (int j = 0; j < M.length; j++){
                MT[i][j] = M[j][i];
            }
        }
        return MT;
    }

    private BigInteger dotProduct(BigInteger[] c, BigInteger[] s) {
        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < c.length; i++) {
            sum = sum.add(c[i].multiply(s[i]));
        }
        return sum.mod(q);
    }

    private BigInteger[] vecAdd(BigInteger[] v, BigInteger[] u){
        BigInteger[] vAddU = new BigInteger[v.length];
        for (int i = 0; i < v.length; i++){
            vAddU[i] = v[i].add(u[i]).mod(q);
        }
        return vAddU;
    }

    private BigInteger[] constMultVector(BigInteger c, BigInteger[] v, BigInteger q) {
        BigInteger[] cTimesV = new BigInteger[v.length];
        for (int i = 0; i < v.length; i++) {
            cTimesV[i] = c.multiply(v[i]).mod(q);
        }
        return cTimesV;
    }

    private int log(int x){
        return (int)(Math.log(x)/Math.log(2)+1e-12);
    }

    private BigInteger[][] allZeroMat(int N, int n){
        BigInteger[][] allZero = new BigInteger[N][n];
        for (int i = 0; i < allZero.length; i++){
            for (int j = 0; j < allZero[0].length; j++){
                allZero[i][j] = BigInteger.ZERO;
            }
        }
        return allZero;
    }

    private BigInteger[] allZeroVec(int n){
        BigInteger[] allZero = new BigInteger[n];
        Arrays.fill(allZero, BigInteger.ZERO);
        return allZero;
    }
}