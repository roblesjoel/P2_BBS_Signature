package ch.bfh.evg.signature;

import ch.bfh.evg.bls12_381.Scalar;
import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.G2Point;
import ch.bfh.evg.jni.JNI;

import java.util.Arrays;
import java.util.List;

/**
 * BLS12_381 PARAMETERS
 * G1 Curve        : y^2 = x^3 + 4
 * G2 Curve        : y^2 = x^3 + 4(u + 1)
 * Field Modulus   : p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
 * Group Order     : r = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
 * Co-Factor       : h = 0x396C8C005555E1568C00AAAB0000AAAB
 * Embedding Degree: k = 12
 *
 * Source: page 17 of https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-02
 */
public class BLS extends JNI {

    public static KeyPair<Scalar, G2Point> generateKeyPair() {
        var sk = Scalar.getRandom();
        var pk = G2Point.GENERATOR.times(sk);
        return new KeyPair<>(sk, pk);
    }

    public static G1Point generateSignature(Scalar sk, String message) {
        return generateSignature(sk, message.getBytes());
    }

    public static G1Point generateSignature(Scalar sk, byte[] message) {
        var hash = G1Point.hashAndMap(message);
        return hash.times(sk);
    }

    public static boolean verifySignature(G2Point pk, String message, G1Point signature) {
        return verifySignature(pk, message.getBytes(), signature);
    }

    public static boolean verifySignature(G2Point pk, byte[] message, G1Point signature) {
        var hash = G1Point.hashAndMap(message);
        var e1 = hash.pair(pk);
        var e2 = signature.pair(G2Point.GENERATOR);
        return e1.equals(e2);
    }

    public static G1Point combineSignatures(List<G1Point> signatures) {
        return signatures.stream().reduce(G1Point.ZERO, G1Point::add);
    }
    public static G1Point combineSignatures(G1Point... signatures) {
        return Arrays.stream(signatures).reduce(G1Point.ZERO, G1Point::add);
    }

    public static G2Point combinePublicKey(List<G2Point> publicKeys) {
        return publicKeys.stream().reduce(G2Point.ZERO, G2Point::add);
    }

    public static G2Point combinePublicKey(G2Point... publicKeys) {
        return Arrays.stream(publicKeys).reduce(G2Point.ZERO, G2Point::add);
    }
}
