import java.math.BigInteger;
import java.util.Arrays;

public class FHEParty {

    private int L;
    private EParty[] parties;
    private BigInteger[][][] publicKey;

    public FHEParty(int lambda, int chi, int L){
        this.parties = new EParty[L + 1];
        int mu = log(lambda) + log(L);
        for (int j = L; j >= 0; j--){
            parties[j] = new EParty(lambda, (j + 1) * mu, chi);
        }
        this.L = L;
    }

    public void keyGen(){
        BigInteger[][] sjprime = new BigInteger[L + 1][];
        BigInteger[][][] sjprimeprime = new BigInteger[L + 1][][];
        BigInteger[][][] tau = new BigInteger[L][][];
        for (int j = L; j >= 0; j--){
            BigInteger qj = parties[j].getQ();
            int nj = parties[j].getN();
            parties[j].secretKeyGen();
            parties[j].setPublicKey(parties[j].publicKeyGen((2 * nj + 1)*qj.bitLength(), nj));
            sjprime[j] = parties[j].tensorVecSelf();
            sjprimeprime[j] = bitDecompVector(sjprime[j], qj);
        }
        for (int j = L-1; j > 0; j--) {
            tau[j] = switchKeyGen(sjprimeprime[j], parties[j], parties[j - 1], parties[j].getQ());
        }
        publicKey = tau;
    }

    public BigInteger[] encrypt(int w){
        BigInteger[] c = new BigInteger[parties[L].getN() + 2];
        for (int i = 0; i < parties[L].getN() + 1; i++){
            c[i] = parties[L].encrypt(w)[i];
        }
        c[parties[L].getN() + 1] = BigInteger.valueOf(L);
        return c;
    }

    public int decrypt(BigInteger[] c){
        int level = c[c.length - 1].intValue();
        BigInteger[] cMinusLevel = new BigInteger[c.length - 1];
        System.arraycopy(c, 0, cMinusLevel, 0, c.length - 1);

        return parties[level].decrypt(cMinusLevel);
    }

    public BigInteger[] addCiphers(BigInteger[] c1, BigInteger[] c2){
        while (!(c1[c1.length - 1].intValue() == c2[c2.length - 1].intValue())){
            if (c1[c1.length - 1].intValue() < c2[c2.length - 1].intValue()){
                refresh(c2);
            }else {
                refresh(c1);
            }
        }
        BigInteger[] c3 = vecAdd(c1, c2, parties[c1.length - 1].getQ());
        return refresh(c3);
    }

    public BigInteger[] multCiphers(BigInteger[] c1, BigInteger[] c2){
        while (!(c1[c1.length - 1].intValue() == c2[c2.length - 1].intValue())){
            if (c1[c1.length - 1].intValue() < c2[c2.length - 1].intValue()){
                refresh(c2);
            }else {
                refresh(c1);
            }
        }
        int level = c1[c1.length - 1].intValue();
        BigInteger[] c3 = vecMult(c1, c2, parties[level].getQ());
        return refresh(c3);
    }

    public BigInteger[] refresh(BigInteger[] c){
        int level = c[c.length - 1].intValue();
        BigInteger[] c1 = powersOf2(c, parties[level].getQ());
        BigInteger[] c2 = scale(c1, parties[level].getQ(), parties[level - 1].getQ(), BigInteger.TWO);
        return switchKey(publicKey[level - 1], c2, parties[level - 1].getQ());
    }

    private BigInteger[] scale(BigInteger[] c, BigInteger q, BigInteger p, BigInteger r) {
        BigInteger pDivQ = p.divide(q);
        BigInteger[] cMod = new BigInteger[c.length];
        for (int i = 0; i < c.length; i++){
            cMod[i] = c[i].mod(pDivQ);
        }
        BigInteger[] res = vecSub(c,cMod,pDivQ);
        for (int i = 0; i < c.length; i++){
            res[i] = res[i].remainder(p);
        }
        if (res[c.length / 2].mod(r).equals(c[c.length / 2].mod(r))){
            return res;
        } else {
            throw new ArithmeticException("Correctness wasn't preserved. " + res[c.length / 2].mod(r) +"  should be equal  "+ c[c.length / 2].mod(r));
        }
    }


    private BigInteger[][] bitDecompVector(BigInteger[] x, BigInteger q) {
        BigInteger[][] xDecomp = new BigInteger[x.length][q.bitLength()];
        for (int i = 0; i < x.length; i++) {
            xDecomp[i] = bitDecompElement(x[i], q);
        }
        return xDecomp;
    }

    private BigInteger[] bitDecompElement(BigInteger x, BigInteger q) {
        BigInteger[] xDecomp = new BigInteger[q.bitLength()];
        for (int i = 0; i < q.bitLength(); i++) {
            xDecomp[i] = x.mod(BigInteger.TWO);
            x = x.divide(BigInteger.TWO);
        }
        return xDecomp;
    }

    private BigInteger[][] powersOf2Mat(BigInteger[][] x, BigInteger q) {
        BigInteger[][] xToPowersOf2Mat = new BigInteger[x.length][x[0].length];
        for (int i = 0; i < x[0].length; i++){
            for (int j = 0; j < x.length; j++){
                xToPowersOf2Mat[j][i] = BigInteger.TWO.pow(i).multiply(x[j][i]).mod(q);
            }
        }
        return xToPowersOf2Mat;
    }

    private BigInteger[] powersOf2(BigInteger[] x, BigInteger q) {
        BigInteger[] xToPowersOf2 = new BigInteger[x.length * q.bitLength()];
        for (int i = 0; i < q.bitLength(); i++){
            for (int j = 0; j < x.length; j++){
                xToPowersOf2[i * x.length + j] = BigInteger.TWO.pow(i).multiply(x[j]);
            }
        }
        return xToPowersOf2;
    }

    private BigInteger[][] switchKeyGen(BigInteger[][] sjprimeprime, EParty p1, EParty p2, BigInteger q){
        BigInteger[][] A = p2.publicKeyGen(p2.getSecretKey(), (sjprimeprime.length * q.bitLength()));
        BigInteger[] pow2SjprimeprimeVec = new BigInteger[sjprimeprime.length * sjprimeprime[0].length];
        BigInteger[][] pow2Sjprimeprime = powersOf2Mat(sjprimeprime, q);
        for (int i = 0; i < pow2Sjprimeprime.length; i++){
            System.arraycopy(pow2Sjprimeprime[i], 0, pow2SjprimeprimeVec, i * pow2Sjprimeprime[0].length, pow2Sjprimeprime[0].length);
        }
        for (int i = 0; i < A.length; i++){
                A[i][0] = A[i][0].add(pow2SjprimeprimeVec[i]).mod(q);
        }
        return A;
    }

    private BigInteger[] switchKey(BigInteger[][] tau, BigInteger[] c1, BigInteger q){
        BigInteger[] c1DecompVec = new BigInteger[tau.length];
        BigInteger[][] c1Decomp = bitDecompVector(c1, q);
        for (int i = 0; i < c1Decomp.length; i++){
            System.arraycopy(c1Decomp[i], 0, c1DecompVec, i * c1Decomp[0].length, c1Decomp[0].length);
        }
        return matrixMultVec(tau, c1DecompVec, q);
    }

    private BigInteger[] tensorVecs(BigInteger[] c1, BigInteger[] c2, BigInteger q) {
        BigInteger[] c1Tensorc2 = new BigInteger[(c1.length - 1) * (c2.length - 1) + 1];
        c1Tensorc2[(c1.length - 1) * (c2.length - 1)] = c1[c1.length - 1];
        for (int i = 0; i < c1.length - 1; i++) {
            for (int j = 0; j < c2.length - 1; j++){
                c1Tensorc2[i * (c1.length - 1) + j] = c1[i].multiply(c2[j]).mod(q);
            }
        }
        return c1Tensorc2;
    }

    private BigInteger[] constMultVec(BigInteger c, BigInteger[] v, BigInteger q) {
        BigInteger[] cTimesV = new BigInteger[v.length];
        for (int i = 0; i < v.length - 1; i++) {
            cTimesV[i] = v[i].multiply(c).mod(q);
        }
        return cTimesV;
    }

    private BigInteger[] matrixMultVec(BigInteger[][] M, BigInteger[] v, BigInteger q){
        BigInteger[] As = allZeroVec(M.length + 1);
        for (int i = 0; i < M.length; i++) {
            for (int j = 0; j < M[0].length; j++) {
                As[i] = As[i].add(M[i][j].multiply(v[j])).mod(q);
            }
        }
        As[M.length] = As[M.length].subtract(BigInteger.ONE);
        return As;
    }

    private BigInteger[] vecMult(BigInteger[] v, BigInteger[] u, BigInteger q){
        BigInteger[] vMultU = allZeroVec(v.length);
        for (int i = 0; i < v.length; i++){
            vMultU[i] = v[i].multiply(u[i]).mod(q);
        }
        return vMultU;
    }

    private BigInteger[] vecAdd(BigInteger[] v, BigInteger[] u, BigInteger q){
        BigInteger[] vAddU = allZeroVec(v.length);
        for (int i = 0; i < v.length; i++){
            vAddU[i] = v[i].add(u[i]).mod(q);
        }
        return vAddU;
    }

    private BigInteger[] vecSub(BigInteger[] v, BigInteger[] u, BigInteger q){
        BigInteger[] vSubU = allZeroVec(v.length);
        for (int i = 0; i < v.length; i++){
            vSubU[i] = v[i].subtract(u[i]).mod(q);
        }
        return vSubU;
    }

    private int log(int x){
        return (int)(Math.log(x)/Math.log(2)+1e-12);
    }

    private BigInteger[] allZeroVec(int n){
        BigInteger[] allZero = new BigInteger[n];
        Arrays.fill(allZero, BigInteger.ZERO);
        return allZero;
    }
}
