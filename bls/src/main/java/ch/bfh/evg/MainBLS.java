package ch.bfh.evg;

import ch.bfh.evg.signature.BLS;
import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.G2Point;
import ch.bfh.evg.group.GroupElement;

public class MainBLS {

    public static void main(String[] args) {
        var m = "Hello";
        var mPrime = "Hello";

        // First signature
        var keyPair1 = BLS.generateKeyPair();
        var sk1 = keyPair1.getSecretKey();
        var pk1 = keyPair1.getPublicKey();
        var sig1 = BLS.generateSignature(sk1, m);
        boolean v1 = BLS.verifySignature(pk1, mPrime, sig1);

        System.out.println("Generator 1      : " + G1Point.GENERATOR);
        System.out.println("Secret Key 1     : " + sk1);
        System.out.println("Public Key 1     : " + pk1);
        System.out.println("Short signature 1: " + sig1.serialize());
        System.out.println("Signature 1      : " + sig1);
        System.out.println("Verification 1   : " + v1);

        // Second signature
        var keyPair2 = BLS.generateKeyPair();
        var sk2 = keyPair2.getSecretKey();
        var pk2 = keyPair2.getPublicKey();
        var sig2 = BLS.generateSignature(sk2, m);
        boolean v2 = BLS.verifySignature(pk2, mPrime, sig2);

        System.out.println("Generator 2      : " + G2Point.GENERATOR);
        System.out.println("Secret Key 2     : " + sk2);
        System.out.println("Public Key 2     : " + pk2);
        System.out.println("Short signature 2: " + sig2.serialize());
        System.out.println("Signature 2      : " + sig2);
        System.out.println("Verification     : " + v2);

        // Signature aggregation
        var pk = BLS.combinePublicKey(pk1);
        var sig = BLS.combineSignatures(sig1);
        boolean v = BLS.verifySignature(pk, mPrime, sig);

        System.out.println("Public Key       : " + pk);
        System.out.println("Short signature  : " + sig.serialize());
        System.out.println("Signature        : " + sig);
        System.out.println("Verification     : " + v);

        // Serialization
        var pkSerialized = pk.serialize();
        var sigSerialized = sig.serialize();
        System.out.println("Serial.Public Key: " + pkSerialized);
        System.out.println("Serial.Signature : " + sigSerialized);

        // Deserialization
        try {
            var pkStar = G2Point.deserialize(pkSerialized);
            var sigStar = G1Point.deserialize(sigSerialized);
            boolean vPrime = BLS.verifySignature(pkStar, mPrime, sigStar);

            System.out.println("Public Key*      : " + pkStar);
            System.out.println("Signature*       : " + sigStar);
            System.out.println("Verification*    : " + vPrime);
        } catch (GroupElement.DeserializationException exception) {
            exception.printStackTrace();
        }
    }

}
