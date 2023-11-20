package ch.bfh.evg.signature;

import ch.bfh.evg.bls12_381.FrElement;
import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.G2Point;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BLSTest {

    static final int n = 100;
    static final List<KeyPair<FrElement, G2Point>> keyPairs = Stream.generate(BLS::generateKeyPair).limit(n).toList();
    static final List<String> messages = List.of("", "Message1", "Message2");

    @Test
    void testVerifySignature() {
        var otherPk = G2Point.getRandom();
        var otherSignature = G1Point.getRandom();
        var otherMessage = "Other Message";
        for (var keyPair : keyPairs) {
            var sk = keyPair.getSecretKey();
            var pk = keyPair.getPublicKey();
            for (var message : messages) {
                var signature = BLS.generateSignature(sk, message);
                assertTrue(BLS.verifySignature(pk, message, signature));
                assertFalse(BLS.verifySignature(otherPk, message, signature));
                assertFalse(BLS.verifySignature(pk, otherMessage, signature));
                assertFalse(BLS.verifySignature(pk, message, otherSignature));
            }
        }
    }

    @Test
    void testAggregate() {
        var otherPk = G2Point.getRandom();
        var otherSignature = G1Point.getRandom();
        var otherMessage = "Other Message";
        var pk = BLS.combinePublicKey(keyPairs.stream().map(KeyPair::getPublicKey).toList());
        for (var message : messages) {
            var signature = BLS.combineSignatures(keyPairs.stream().map(KeyPair::getSecretKey).map(sk -> BLS.generateSignature(sk, message)).collect(Collectors.toList()));
            assertTrue(BLS.verifySignature(pk, message, signature));
            assertFalse(BLS.verifySignature(otherPk, message, signature));
            assertFalse(BLS.verifySignature(pk, otherMessage, signature));
            assertFalse(BLS.verifySignature(pk, message, otherSignature));
        }
        var emptyPk = BLS.combinePublicKey();
        var emptySignature = BLS.combineSignatures();
        for (var message : messages) {
            assertTrue(BLS.verifySignature(emptyPk, message, emptySignature));
            assertTrue(BLS.verifySignature(emptyPk, otherMessage, emptySignature)); // signature valid for all messages
            assertFalse(BLS.verifySignature(otherPk, message, emptySignature));
            assertFalse(BLS.verifySignature(emptyPk, message, otherSignature));
        }
    }

}