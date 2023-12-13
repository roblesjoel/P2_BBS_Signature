package ch.bfh.evg;

import ch.bfh.evg.signature.BBS;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

public class MainDemo {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        /*while(true){
            try{
                System.out.println("Enter your messages, separated by a ;");
                String inputs = scanner.nextLine();
                if (Objects.equals(inputs, "q")) break;
                String[] splitInputs = inputs.split(";");
                byte[][] messages = new byte[splitInputs.length][];
                for (int i = 0; i < splitInputs.length; i++) {
                    messages[i] = splitInputs[i].getBytes();
                }
                // Generate Keys
                byte[] key_material = new byte[256];
                byte[] key_info = new byte[0];
                byte[] key_dst = new byte[0];
                BigInteger secretKey = BBS.KeyGen(key_material,key_info,key_dst);
                System.out.println("Secret Key:    " + secretKey);
                byte[] publicKey = BBS.SkToPk(secretKey);
                System.out.println("Public Key:    " + Arrays.toString(publicKey));

                // Generate and validate the Signature
                byte[] header = new byte[0];
                byte[] ph = new byte[0];
                byte[] signature = BBS.Sign(secretKey, publicKey, header, messages);
                System.out.println("Signature:   " + Arrays.toString(signature));
                boolean result = BBS.Verify(publicKey, signature, header, messages);
                System.out.println("Signature is:   " + result);

                // Proof of disclosed messages
                System.out.println("Which messages do you wish to disclose (separate with ;)? 0-" + (messages.length-1));
                String messagesToDiscloseString = scanner.nextLine();
                String[] messagesToDiscloseStringSplit = messagesToDiscloseString.split(";");
                int[] messagesToDisclose = new int[messagesToDiscloseStringSplit.length];
                for (int i = 0; i < messagesToDisclose.length; i++) {
                    messagesToDisclose[i] = Integer.parseInt(messagesToDiscloseStringSplit[i].replace(" ", ""));
                }
                System.out.println("Messages to be disclosed:");
                byte[][] disclosedMessages = new byte[messagesToDisclose.length][];
                for (int i = 0; i < messages.length; i++) {
                    for (int j = 0; j < messagesToDisclose.length; j++) {
                        if(messagesToDisclose[j] == i){
                            System.out.println(new String(messages[i]));
                            disclosedMessages[i] = messages[i];
                        }
                    }
                }
                byte[] proof = BBS.ProofGen(publicKey, signature, header, ph, messages, messagesToDisclose); // Must first verify the signature
                System.out.println("Proof:   " + Arrays.toString(proof));
                boolean proofValid = BBS.ProofVerify(publicKey, proof, header, ph, disclosedMessages, messagesToDisclose);
                System.out.println("Proof is:   " + proofValid);

            }catch (Exception e) {
                System.out.println(e);
            }
        }*/
        scanner.close();
    }
}
