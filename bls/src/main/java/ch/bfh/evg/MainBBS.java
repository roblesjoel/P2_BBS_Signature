/** Demo BBS implementation
 * Base is a copy of Rolf Haenni's BBS implementation
 */

package ch.bfh.evg;

import ch.bfh.evg.signature.BBS;
import ch.openchvote.util.set.IntSet;

import java.math.BigInteger;
import java.util.Arrays;
import ch.openchvote.util.sequence.Vector;

public class MainBBS {

    public static void main(String[] args) {

        // key generation

        byte[] key_material = new byte[256];
        byte[] key_info = new byte[0];
        byte[] key_dst = new byte[0];

        BigInteger secretKey = BigInteger.valueOf(0);

        try{
            secretKey = BBS.generateSecretKey(key_material,key_info,key_dst);
        }catch (Exception e){
            System.out.println(e);
            System.exit(-1);
        }

        System.out.println("Secret Key:    " + secretKey);

        byte[] publicKey = BBS.generatePublicKey(secretKey);
        System.out.println("Public Key:    " + Arrays.toString(publicKey));

        Vector<byte[]> messages = Vector.of(("Hello").getBytes(), ("BBS").getBytes());
        Vector<byte[]> emptyMessages = Vector.of();
        byte[] header = new byte[0];
        byte[] ph = new byte[0];
        int[] disclosed_indexes = new int[]{0};

        try{
            byte[] signature = BBS.Sign(secretKey, publicKey, header, messages);
            System.out.println("Signature:   " + Arrays.toString(signature));
            boolean result = BBS.Verify(publicKey, signature, header, messages);
            System.out.println("Signature is:   " + result);
            byte[] proof = BBS.ProofGen(publicKey, signature, header, ph, messages, disclosed_indexes);
            System.out.println("Proof is:   " + Arrays.toString(proof));
        }catch (Exception e){
            System.out.println(e);
            System.exit(-1);
        }




        /*var keyPair = BBS.generateKeyPair();
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
        System.out.println("Verify Proof      : " + vp);*/
    }

}

