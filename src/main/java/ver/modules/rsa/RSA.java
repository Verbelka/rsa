package ver.modules.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private SecureRandom random;

    public RSA(int bitLength) {
        random = new SecureRandom();
        p = BigInteger.probablePrime(bitLength, random);
        q = BigInteger.probablePrime(bitLength, random);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitLength / 2, random);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
            e = e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi);
    }

    public byte[] encrypt(byte[] message) {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }

    public byte[] decrypt(byte[] message) {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }

    /*public static void main(String[] args) {
        RSA rsa = new RSA(1024);
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter your text: ");
        String message = scanner.nextLine();
        byte[] encrypted = rsa.encrypt(message.getBytes());
        byte[] decrypted = rsa.decrypt(encrypted);
        System.out.println("Result: " + new String(decrypted));
    }*/
}
