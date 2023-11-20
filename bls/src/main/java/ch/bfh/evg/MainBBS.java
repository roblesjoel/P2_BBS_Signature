package ch.bfh.evg;

import ch.bfh.evg.signature.BBS;
import ch.openchvote.util.set.IntSet;
import ch.openchvote.util.sequence.Vector;

public class MainBBS {

    public static void main(String[] args) {

        // key generation
        var keyPair = BBS.generateKeyPair();
        var sk = keyPair.getSecretKey();
        var pk = keyPair.getPublicKey();
        System.out.println("Private Key       : " + sk);
        System.out.println("Public Key        : " + pk);

        // messages
        var header = "Stanford University Faculty Members - Fall 2022";
        var msg1 = "Dan";
        var msg2 = "Boneh";
        var msg3 = "5/1/1969";
        var msg4 = "Computer Security Lab";
        var msg5 = "Co-Director";
        var messages = Vector.of(msg1, msg2, msg3, msg4, msg5);
        int L = messages.getLength();
        System.out.println("Messages          : " + messages);

        // signature generation and verification
        var signature = BBS.generateSignature(sk, pk, header, messages);
        boolean vs = BBS.verifySignature(pk, signature, header, messages);
        System.out.println("Signature         : " + signature);
        System.out.println("Verify Signature  : " + vs);

        // disclosed messages
        var disclosedIndices = IntSet.of(3, 4);
        var disclosedMessages = messages.select(disclosedIndices);
        System.out.println("Disclosed Messages: " + disclosedMessages);

        // proof generation and verification
        var ph = "NONCE_B8091CF762829A78DE762827A783738C";
        var proof = BBS.generateProof(pk, signature, header, ph, messages, disclosedIndices);
        boolean vp = BBS.verifyProof(pk, proof, header, ph, disclosedMessages, disclosedIndices);
        System.out.println("Proof             : " + proof);
        System.out.println("Verify Proof      : " + vp);
    }

}

