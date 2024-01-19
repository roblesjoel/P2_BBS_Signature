/** Demo BBS implementation
 * Base is a copy of Rolf Haenni's BBS implementation
 */

package ch.bfh.evg;

import ch.bfh.evg.bls12_381.Scalar;
import ch.bfh.evg.signature.BBS;
import ch.openchvote.util.set.IntSet;

import java.math.BigInteger;
import java.util.Arrays;
import ch.openchvote.util.sequence.Vector;
import ch.openchvote.util.set.IntSet;

import java.util.Arrays;

public class MainBBS {

    public static void main(String[] args) {
        // Create Generator function -> just seen that hashAndMap == hashAndMapToG1
        // Maybe use direct connection to Gx and not GxPoint, discuss
        // Tests
        // Documentation
        // Better (more descriptive) Errors
        // Not using/not use openchvote utils, to discuss
        // Output as Hex
        // Ziel ist Aktueller Draft, 1 zu 1 umgesezt
        // Logisch gesehen, Test bestehen
        // Mod funktion in scalar

        try{
            // Generate the keys
            OctetString key_material = new OctetString(new byte[256]);
            OctetString key_info = new OctetString(new byte[0]);
            OctetString key_dst = new OctetString(new byte[0]);
            Scalar secretKey = BBS.KeyGen(key_material,key_info,key_dst);
            System.out.println("Secret Key:    " + secretKey.toString());
            OctetString publicKey = BBS.SkToPk(secretKey);
            System.out.println("Public Key:    " + publicKey.toString()); // as hex

            // Generate and validate the Signature
            OctetString msg1 = OctetString.valueOf("Hello");
            OctetString msg2 = OctetString.valueOf("BBS");
            OctetString msg3 = OctetString.valueOf("test");
            Vector<OctetString> messages = Vector.of(msg1, msg2, msg3);
            Vector<OctetString> empty = Vector.of();


            OctetString header = new OctetString(new byte[0]);
            OctetString ph = new OctetString(new byte[0]);
            OctetString signature = BBS.Sign(secretKey, publicKey, header, messages);
            System.out.println("Signature:   " + signature.toString());
            boolean result = BBS.Verify(publicKey, signature, header, messages);
            System.out.println("Signature is:   " + result);

            // Generate and verify the Proof
            var disclosed_indexes_test = IntSet.of(1, 3);
            Vector<OctetString> disclosedMessages = messages.select(disclosed_indexes_test);//Vector.of(msg1, msg3);
            Vector<Integer> disclosed_indexes = Vector.of(1,2,3);
            Vector<Integer> disclosed_indexes_empty = Vector.of();
            OctetString proof = BBS.ProofGen(publicKey, signature, header, ph, messages, disclosed_indexes);
            System.out.println("Proof:   " + proof.toString());
            boolean proofValid = BBS.ProofVerify(publicKey, proof, header, ph, messages, disclosed_indexes);
            System.out.println("Proof is:   " + proofValid);
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

