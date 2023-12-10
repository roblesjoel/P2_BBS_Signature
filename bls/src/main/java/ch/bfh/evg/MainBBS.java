/** Demo BBS implementation
 * Base is a copy of Rolf Haenni's BBS implementation
 */

package ch.bfh.evg;

import ch.bfh.evg.signature.BBS;

import java.math.BigInteger;
import java.util.Arrays;

public class MainBBS {

    public static void main(String[] args) {

        // Create Generator function -> just seen that hashAndMap == hashAndMapToG1
        // Commitment already serialized
        // Maybe use direct connection to Gx and not GxPoint, discuss
        // Tests
        // Documentation
        // Better (more descriptive) Errors
        // Not using/not use openchvote utils, to discuss
        // Output as Hex
        // Ziel ist Aktueller Draft, 1 zu 1 umgesezt
        // Logisch gesehen, Test bestehen
        // Code 1 zu 1 pseudo code, zb concat von string octets
        // Vector Builder

        /*BigInteger R = new BigInteger("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);

        G2Point test = G2Point.GENERATOR.times(FrElement.of(BigInteger.TWO));

        System.out.println("test");*/



        try{
            // Generate the keys
            byte[] key_material = new byte[256];
            byte[] key_info = new byte[0];
            byte[] key_dst = new byte[0];
            BigInteger secretKey = BBS.KeyGen(key_material,key_info,key_dst);
            System.out.println("Secret Key:    " + secretKey);
            byte[] publicKey = BBS.SkToPk(secretKey);
            System.out.println("Public Key:    " + Arrays.toString(publicKey)); // as hex

            // Generate and validate the Signature
            byte[][] messages = new byte[][]{("Hello").getBytes(), ("BBS").getBytes(), ("test").getBytes()};
            byte[] header = new byte[0];
            byte[] ph = new byte[0];
            byte[] signature = BBS.Sign(secretKey, publicKey, header, messages);
            System.out.println("Signature:   " + Arrays.toString(signature));
            boolean result = BBS.Verify(publicKey, signature, header, messages);
            System.out.println("Signature is:   " + result);

            // Generate and verify the Proof
            byte[][] disclosedMessages = new byte[][]{("Hello").getBytes(), ("test").getBytes()};
            int[] disclosed_indexes = new int[]{0,2};
            // Take out Verify from ProofGen
            byte[] proof = BBS.ProofGen(publicKey, signature, header, ph, messages, disclosed_indexes); // Must first verify the signature
            System.out.println("Proof:   " + Arrays.toString(proof));
            boolean proofValid = BBS.ProofVerify(publicKey, proof, header, ph, disclosedMessages, disclosed_indexes);
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

