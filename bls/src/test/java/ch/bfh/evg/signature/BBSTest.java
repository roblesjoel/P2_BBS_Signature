package ch.bfh.evg.signature;

import ch.openchvote.util.set.IntSet;
import ch.openchvote.util.sequence.Vector;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BBSTest {

    static String header = "Stanford University Faculty Members - Fall 2022";
    static String msg1 = "Dan";
    static String msg2 = "Boneh";
    static String msg3 = "5/1/1969";
    static String msg4 = "Computer Security Lab";
    static String msg5 = "Co-Director";
    static Vector<String> messages = Vector.of(msg1, msg2, msg3, msg4, msg5);

    @Test
    void testSignature() {
        var keyPair = BBS.generateKeyPair();
        var sk = keyPair.getFirst();
        var pk = keyPair.getSecond();

        var signature = BBS.generateSignature(sk, pk, header, messages);
        assertTrue(BBS.verifySignature(pk, signature, header, messages));
    }

    @Test
    void testProof() {
        var keyPair = BBS.generateKeyPair();
        var sk = keyPair.getSecretKey();
        var pk = keyPair.getPublicKey();
        var signature = BBS.generateSignature(sk, pk, header, messages);
        int L = messages.getLength();

        var disclosedIndices = IntSet.of(3, 4);
        var disclosedIndices1 = IntSet.of();
        var disclosedIndices2 = IntSet.of(1);
        var disclosedIndices3 = IntSet.of(2);
        var disclosedIndices4 = IntSet.of(1, 2);
        var disclosedIndices5 = IntSet.of(1, 3);
        var disclosedIndices6 = IntSet.of(1, 2, 3);
        var disclosedIndices7 = IntSet.of(1, 2, 4);
        var disclosedIndices8 = IntSet.of(1, 2, 3, 4);
        var disclosedIndices9 = IntSet.of(1, 2, 3, 4, 5);
        var disclosedIndices10 = IntSet.of(1, 6); // 6 is an invalid index
        var headerPrime = "Test";
        var ph = "NONCE: B8091CF762829A78DE762827A783738C";
        var proof = BBS.generateProof(pk, signature, header, ph, messages, disclosedIndices);
        assertTrue(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices), disclosedIndices));
        assertFalse(BBS.verifyProof(pk, proof, headerPrime, ph, messages.select(disclosedIndices), disclosedIndices));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices1), disclosedIndices1));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices2), disclosedIndices2));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices3), disclosedIndices3));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices4), disclosedIndices4));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices5), disclosedIndices5));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices6), disclosedIndices6));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices7), disclosedIndices7));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices8), disclosedIndices8));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices9), disclosedIndices9));
        assertFalse(BBS.verifyProof(pk, proof, header, ph, messages.select(disclosedIndices10), disclosedIndices10));
        System.out.println(messages.select(disclosedIndices10));
    }

}