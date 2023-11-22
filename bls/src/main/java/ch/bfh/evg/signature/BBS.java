/**
 * BBS Helper Methods
 * Base made by Rolf Haenni
 */

package ch.bfh.evg.signature;

import ch.bfh.evg.Exception.AbortException;
import ch.bfh.evg.Exception.InvalidException;
import ch.bfh.evg.bls12_381.FrElement;
import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.G2Point;
import ch.bfh.evg.bls12_381.GTElement;
import ch.bfh.evg.group.GroupElement;
import ch.bfh.evg.jni.JNI;
import ch.openchvote.util.sequence.ByteArray;
import ch.openchvote.util.sequence.Vector;
import ch.openchvote.util.set.IntSet;
import ch.openchvote.util.tuples.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.temporal.Temporal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.IntStream;

import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import org.bouncycastle.crypto.digests.SHAKEDigest;

public class BBS extends JNI {

    /**
     * Definitions
     */
    public static final String CIPHERSUITE_ID = "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_"; // Ciphersuite ID,BLS12-381-SHAKE-256
    private static final G1Point P1 = G1Point.GENERATOR; // Generator point in G1
    private static final G2Point P2 = G2Point.GENERATOR; // Generator point in G2
    private static final SecureRandom SECURE_RANDOM = new SecureRandom(); // Random generator method
    private static final int Octet_Scalar_Length = 32;
    private static final int Octet_Point_Length = 48;
    private static final String Hash_To_Curve_Suite = "BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
    private static final int Expand_Len = 48;
    private static final BigInteger r = new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    /**
     * Signature
     */
    public static class Signature extends Triple<G1Point, FrElement, FrElement> {
        public Signature(G1Point A, FrElement e, FrElement s) {
            super(A, e, s);
        }
    }

    public static byte[] Sign(BigInteger secretKey, byte[] publicKey, byte[] header, Vector<byte[]> messages) throws InvalidException {
        byte[] api_id = (CIPHERSUITE_ID + "H2G_HM2S_").getBytes();
        try{
            BigInteger[] message_scalars = messages_to_scalars(messages, api_id);
            Vector<G1Point> generators = createGenerators(message_scalars.length+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            byte[] signature = CoreSign(secretKey, publicKey, generators, header, message_scalars, G1Point.GENERATOR, api_id);
            return signature;
        }catch (Exception e) {
            System.out.println(e);
            throw new InvalidException("Signature is Invalid");
        }
    }

    public static boolean Verify(byte[] publicKey, byte[] signature, byte[]header, Vector<byte[]> messages) throws InvalidException{
        byte[] api_id = (CIPHERSUITE_ID + "H2G_HM2S_").getBytes();
        try{
            BigInteger[] message_scalars = messages_to_scalars(messages, api_id);
            Vector<G1Point> generators = createGenerators(message_scalars.length+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            boolean result = CoreVerify(publicKey, signature, generators, header, message_scalars, api_id);
            return result;
        }catch (Exception e){
            System.out.println(e);
            throw new InvalidException("Signature Verification failed");
        }
    }

    private static boolean CoreVerify(byte[] publicKey, byte[] signature_octets, Vector<G1Point> generators, byte[] header, BigInteger[] messages, byte[] api_id) throws InvalidException, GroupElement.DeserializationException, AbortException {
        Signature signature = octets_to_signature(signature_octets);
        G2Point W = G2Point.deserialize(ByteArray.of(publicKey));
        int messagesCount = messages.length;
        if(generators.getLength() != messagesCount + 1) throw new InvalidException("To few generators or to many messages");
        G1Point Q1 = generators.getValue(1);
        G1Point[] H_Points = new G1Point[generators.getLength()-1];
        for (int i = 2; i <= generators.getLength(); i++) {
            H_Points[i-2] = generators.getValue(i);
        }
        BigInteger domain = calculate_domain(publicKey, Q1, H_Points, header, api_id);
        G1Point B = P1.add(Q1.times(FrElement.of(domain)));
        for (int i = 1; i <= messagesCount; i++) {
            BigInteger message = messages[i-1];
            B.add(generators.getValue(i).times(FrElement.of(message)));
        }
        G2Point G2Data = W.add(G2Point.GENERATOR.times(signature.getSecond()));
        GTElement firstPairing = signature.getFirst().pair(G2Data);
        GTElement secondPairing = B.pair(G2Point.GENERATOR.negate());
        GTElement multiplicatedElements = firstPairing.multiply(secondPairing);
        if(!multiplicatedElements.equals(GTElement.ONE)) throw new InvalidException("Signature is not valid. Verification failed");
        return true;
    }

    private static Signature octets_to_signature(byte[] signature_octets) throws InvalidException, GroupElement.DeserializationException {
        int expected_len = Octet_Point_Length + Octet_Scalar_Length;
        if(signature_octets.length != expected_len) throw new InvalidException("Signature has incorrect length");
        byte[] A_octets = new byte[Octet_Point_Length];
        System.arraycopy(signature_octets, 0, A_octets, 0, Octet_Point_Length);
        G1Point A = G1Point.deserialize(ByteArray.of(A_octets));
        if(A == G1Point.ZERO) throw new InvalidException("Error while deserializing. Point in Signature is the identity point");
        byte[] eBytes = new byte[Octet_Scalar_Length];
        System.arraycopy(signature_octets, Octet_Point_Length, eBytes, 0, Octet_Scalar_Length);
        BigInteger e = os2ip(eBytes);
        if(e == BigInteger.ZERO || e.compareTo(r) == 1) throw new InvalidException("Scalar e is either 0 or to big");
        Signature signature = new Signature(A, FrElement.of(e), FrElement.of(BigInteger.ZERO));
        System.out.println("Signature (A):  " + A);
        System.out.println("Signature (e):  " + e);
        return signature;
    }

    private static byte[] CoreSign(BigInteger secretKey, byte[] publicKey, Vector<G1Point> generators, byte[] header, BigInteger[] messages, G1Point commitment, byte[] api_id) throws AbortException, InvalidException{
        int messageCount = messages.length;
        if(generators.getLength() < messageCount + 1) throw new AbortException("To many messages or to few generators");

        byte[] signatureDstBase = ("H2S_").getBytes();
        byte[] signature_dst = new byte[api_id.length + signatureDstBase.length];
        System.arraycopy(api_id,0, signature_dst, 0, api_id.length);
        System.arraycopy(signatureDstBase,0, signature_dst, api_id.length, signatureDstBase.length);

        G1Point Q1 = generators.getValue(1);
        G1Point[] H_Points = new G1Point[generators.getLength()-1];
        for (int i = 2; i <= generators.getLength(); i++) {
            H_Points[i-2] = generators.getValue(i);
        }
        BigInteger domain = calculate_domain(publicKey, Q1, H_Points, header, api_id);
        byte[] comm = new byte[0];
        Object[] commitmentArray = new Object[]{commitment};
        if(commitment != G1Point.GENERATOR) {
            byte[] serializedCommitment = serialize(commitmentArray);
            System.arraycopy(serializedCommitment, 0, comm, 0, serializedCommitment.length);
        }
        Object[] dataToBeSerialized = new Object[2+messageCount]; //new Object[3+messageCount];
        dataToBeSerialized[0] = secretKey;
        dataToBeSerialized[1] = domain;
        System.arraycopy(messages,0, dataToBeSerialized, dataToBeSerialized.length-messages.length, messages.length);
        //dataToBeSerialized[dataToBeSerialized.length-1] = comm;
        // Commitment is already serialized?
        byte[] serializedData = serialize(dataToBeSerialized);
        byte[] serializedBytes = new byte[serializedData.length];
        System.arraycopy(serializedData, 0, serializedBytes, 0, serializedData.length);
        BigInteger e = hash_to_scalar(serializedBytes, signature_dst);
        G1Point B = P1.add(Q1.times(FrElement.of(domain)));
        for (int i = 1; i <= messageCount; i++) {
            BigInteger message = messages[i-1];
            B.add(generators.getValue(i).times(FrElement.of(message)));
        }
        BigInteger denumerator = secretKey.add(e);
        var A = B.times(FrElement.of(denumerator.modInverse(r)));
        System.out.println("Signature (A):  " + A);
        System.out.println("Signature (e):  " + e);
        Signature signature = new Signature(A, FrElement.of(e), FrElement.of(BigInteger.ZERO));
        return signature_to_octets(signature);
    }

    private static byte[] signature_to_octets(Signature signature) throws InvalidException {
        Object[] splitSignature = new Object[]{signature.getFirst(), signature.getSecond().toBigInteger()};
        byte[] serializedSignatureArray = serialize(splitSignature);
        byte[] serializedSignature = new byte[serializedSignatureArray.length];
        System.arraycopy(serializedSignatureArray,0,serializedSignature,0,serializedSignatureArray.length);
        return serializedSignature;
    }

    private static BigInteger calculate_domain(byte[] publicKey, G1Point Q1, G1Point[] H_Points, byte[] header, byte[] api_id) throws AbortException, InvalidException{
        int lenghtH_Points = H_Points.length;
        if(header.length > Math.pow(2,64)-1 || lenghtH_Points > Math.pow(2,64)-1) throw new AbortException("The header or generator points are to long");
        byte[] domainDSTByte = ("H2S_").getBytes();
        byte[] domain_dst = new byte[api_id.length + domainDSTByte.length];
        System.arraycopy(api_id, 0, domain_dst, 0, api_id.length);
        System.arraycopy(domainDSTByte, 0, domain_dst, api_id.length, domainDSTByte.length);
        Object[] dom_array = new Object[2+H_Points.length];
        dom_array[0] = lenghtH_Points;
        dom_array[1] = Q1;
        System.arraycopy(H_Points, 0, dom_array, 2, H_Points.length);
        byte[] serializedDomArray = serialize(dom_array);
        byte[] dom_octs = new byte[serializedDomArray.length+ api_id.length];
        System.arraycopy(serializedDomArray, 0, dom_octs, 0, serializedDomArray.length);
        System.arraycopy(api_id, 0, dom_octs, serializedDomArray.length, api_id.length);
        BigInteger headerLenght = BigInteger.valueOf(header.length);
        byte[] serializedHeaderLenght = i2osp(headerLenght, 8);
        byte[] dom_input = new byte[publicKey.length + dom_octs.length + serializedHeaderLenght.length + header.length];
        System.arraycopy(publicKey, 0, dom_input, 0, publicKey.length);
        System.arraycopy(dom_octs, 0, dom_input, publicKey.length, dom_octs.length);
        System.arraycopy(serializedHeaderLenght, 0, dom_input, dom_octs.length + publicKey.length, serializedHeaderLenght.length);
        System.arraycopy(header, 0, dom_input, serializedHeaderLenght.length + dom_octs.length + publicKey.length, header.length);
        return hash_to_scalar(dom_input, domain_dst);
    }

    private static byte[] serialize(Object[] input_array) throws InvalidException{
        byte[] octect_result = new byte[0];
        for (Object el : input_array) {
            switch (el.getClass().getName()) {
                case "ch.bfh.evg.bls12_381.G1Point" -> {
                    G1Point element = (G1Point) el;
                    byte[] bArray = element.serialize().toByteArray();
                    byte[] octectCache = octect_result;
                    octect_result = new byte[octect_result.length + bArray.length];
                    System.arraycopy(octectCache, 0, octect_result, 0, octectCache.length);
                    System.arraycopy(element.serialize().toByteArray(), 0, octect_result, octect_result.length - bArray.length, bArray.length);
                }
                case "ch.bfh.evg.bls12_381.G2Point" -> {
                    G2Point element = (G2Point) el;
                    byte[] bArray = element.serialize().toByteArray();
                    byte[] octectCache = octect_result;
                    octect_result = new byte[octect_result.length + bArray.length];
                    System.arraycopy(octectCache, 0, octect_result, 0, octectCache.length);
                    System.arraycopy(element.serialize().toByteArray(), 0, octect_result, octect_result.length - bArray.length, bArray.length);
                }
                case "java.math.BigInteger" -> {
                    byte[] element = i2osp((BigInteger) el, Octet_Scalar_Length);
                    byte[] octectCache = octect_result;
                    octect_result = new byte[octect_result.length + element.length];
                    System.arraycopy(octectCache, 0, octect_result, 0, octectCache.length);
                    System.arraycopy(element, 0, octect_result, octect_result.length - element.length, element.length);
                }
                case "java.lang.Integer" -> {
                    int element = (int) el;
                    if (element < 0 || element > Math.pow(2,64)-1) throw new InvalidException("Int number is to big");
                    byte[] serialized = i2osp(BigInteger.valueOf(element), 8);
                    byte[] octectCache = octect_result;
                    octect_result = new byte[octect_result.length + serialized.length];
                    System.arraycopy(octectCache, 0, octect_result, 0, octectCache.length);
                    System.arraycopy(serialized, 0, octect_result, octect_result.length - serialized.length, serialized.length);
                }
                default -> throw new InvalidException("Type cannot be serialized");
            }
        }

        return octect_result;
    }


    // Try to implement it myself
    /*private static void create_generators(int count, byte[] seed, byte[] api_id) throws AbortException{
        if(count > Math.pow(2, 64) -1) throw new AbortException("Count is to high. To many messages");
        byte[] seedAsByte = ("SIG_GENERATOR_SEED_").getBytes();
        byte[] generatorAsByte = ("SIG_GENERATOR_DST_").getBytes();
        byte[] generatorSeedAsByte = ("MESSAGE_GENERATOR_SEED").getBytes();

        byte[] seed_dst = new byte[api_id.length + seedAsByte.length];
        byte[] generator_dst = new byte[api_id.length + generatorAsByte.length];
        byte[] generator_seed = new byte[api_id.length + generatorSeedAsByte.length];

        System.arraycopy(api_id, 0, seed_dst, 0, api_id.length);
        System.arraycopy(seedAsByte, 0, seed_dst, api_id.length, seedAsByte.length);
        System.arraycopy(api_id, 0, generator_dst, 0, api_id.length);
        System.arraycopy(generatorAsByte, 0, generator_dst, api_id.length, generatorAsByte.length);
        System.arraycopy(api_id, 0, generator_seed, 0, api_id.length);
        System.arraycopy(generatorSeedAsByte, 0, generator_seed, api_id.length, generatorSeedAsByte.length);

        String v = expand_message_xof(Arrays.toString(generator_seed), Arrays.toString(seed_dst), Expand_Len);

        for (int i = 0; i < count; i++) {
            v = expand_message_xof(v+ Arrays.toString(i2osp(BigInteger.valueOf(i), 8)), Arrays.toString(seed_dst), Expand_Len);
            var generator_i = hash_to_curve_g1(v, generator_dst);
            hash_an
        }

    }*/

    /**
     * Map messages to scalars
     * @param messages The Messages to be mapped
     * @param api_id The api id
     * @return Returns the mapped messages as scalar
     * @throws AbortException Throws exception if there are to many messages
     */
    private static BigInteger[] messages_to_scalars(Vector<byte[]> messages, byte[] api_id) throws AbortException{
        int messagesLength = messages.getLength();
        if(messagesLength > Math.pow(2,64) -1) throw new AbortException("To many messages!");
        byte[] separationTag = ("MAP_MSG_TO_SCALAR_AS_HASH_").getBytes();
        byte[] map_dst = new byte[separationTag.length + api_id.length];
        System.arraycopy(api_id, 0, map_dst, 0, api_id.length);
        System.arraycopy(separationTag, 0, map_dst, api_id.length, separationTag.length);
        BigInteger[] messageScalars = new BigInteger[messagesLength];
        for (int i = messages.getMinIndex(); i <= messagesLength; i++) {
            BigInteger messageScalar_i = hash_to_scalar(messages.getValue(i), map_dst);
            messageScalars[i-1] = messageScalar_i;
        }
        return messageScalars;
    }

    /**
     * Generate the public key to a given secret Key
     * @param secretKey The secret key
     * @return The public key as octets
     */
    public static byte[] generatePublicKey(BigInteger secretKey){
        FrElement fr = FrElement.of(secretKey);
        G2Point W = P2.times(fr);
        return W.serialize().toByteArray(); // Mayyybe implement the point to octets function
    }

    /**
     * Generator function for the secret key
     * @param key_material Random input from which the key will be generated. Must be at least 32 byte
     * @param key_info May be used to derive distinct keys from the same key material. Defaults to an empty string.
     * @param key_dst Represents the domain separation. Defaults to the octet string CIPHERSUITE_ID || "KEYGEN_DST_".
     */
    public static BigInteger generateSecretKey(byte[] key_material, byte[] key_info, byte[] key_dst) throws InvalidException {
        if(key_material.length < 32) throw new InvalidException("key_material is to short");
        if(key_info.length > 65535) throw new InvalidException("key_info is to long");
        try {
            if(key_dst.length == 0) key_dst = (CIPHERSUITE_ID + "KEYGEN_DST").getBytes();
            byte[] serializedInfoLength = i2osp(BigInteger.valueOf(key_info.length), 2);
            byte[] derive_input = new byte[key_material.length + serializedInfoLength.length + key_info.length];
            System.arraycopy(key_material, 0, derive_input, 0, key_material.length);
            System.arraycopy(serializedInfoLength, 0, derive_input, key_material.length, serializedInfoLength.length);
            System.arraycopy(key_info, 0, derive_input, key_material.length + serializedInfoLength.length, key_info.length);
            var secretKey = hash_to_scalar(derive_input, key_dst);
            return secretKey;
        }catch (Exception e){
            System.out.println(e);
            throw new InvalidException("Secret Key is not valid");
        }
    }

    /**
     * Stream to Octet
     * @param i The BigInt to be converted
     * @param size The Size of the octet
     * @return The converted BigInt
     */
    private static byte[] i2osp(final BigInteger i, final int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Size of the octet string should be at least 1 but is " + size);
        }
        if (i == null || i.signum() == -1 || i.bitLength() > size * Byte.SIZE) {
            throw new IllegalArgumentException("Integer should be a positive number or 0, no larger than the given size");
        }
        final byte[] signed = i.toByteArray();
        if (signed.length == size) {
            return signed;
        }
        final byte[] os = new byte[size];
        if (signed.length < size) {
            System.arraycopy(signed, 0, os, size - signed.length, signed.length);
            return os;
        }
        System.arraycopy(signed, 1, os, 0, size);
        return os;
    }

    /**
     * Octet to Stream
     * @param data the octets to be converted
     * @return The converted data
     */
    private static BigInteger os2ip(final byte[] data) {
        return new BigInteger(1, data);
    }

    /**
     * Hash message to scalar
     * @param msg_octets The messages to be hashed
     * @param dst The domain separation tag
     * @return The hashed message as a scalar
     * @throws AbortException Throws an exception id the dst is too long
     */
    private static BigInteger hash_to_scalar(byte[] msg_octets, byte[] dst) throws AbortException{
        if(dst.length > 255) throw new AbortException("dst is to long");
        var uniform_bytes = expand_message_xof(msg_octets, dst, Expand_Len);
        return os2ip(uniform_bytes.getBytes()).mod(r);
    }

    /**
     * Expand message with variable output function
     * @param msg The message to be digested
     * @param DST a domain separation tag
     * @param len_in_bytes The length of the output
     * @return The hashed message
     * @throws AbortException Throws an exception if len_in_bytes or DST are too big
     * as defined in https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xof
     */
    private static String expand_message_xof(byte[] msg, byte[] DST, int len_in_bytes) throws AbortException {
        if(len_in_bytes > 65535 || DST.length > 255) throw new AbortException("Either len_in_bytes, or DST is to big");
        byte[] serializedDstLenght = i2osp(BigInteger.valueOf(DST.length),1);
        byte[] DST_prime = new byte[DST.length + serializedDstLenght.length];
        System.arraycopy(DST, 0, DST_prime, 0, DST.length);
        System.arraycopy(serializedDstLenght, 0, DST_prime, DST.length, serializedDstLenght.length);
        byte[] serializedLenInBytes = i2osp(BigInteger.valueOf(len_in_bytes), 2);
        byte[] msg_prime = new byte[msg.length + serializedLenInBytes.length + DST_prime.length];
        System.arraycopy(msg, 0, msg_prime, 0, msg.length);
        System.arraycopy(serializedLenInBytes, 0, msg_prime, msg.length, serializedDstLenght.length);
        System.arraycopy(DST_prime, 0, msg_prime, serializedDstLenght.length+msg.length, DST_prime.length);
        byte[] uniform_bytes = shakeDigest(msg_prime, len_in_bytes);
        return Arrays.toString(uniform_bytes);
    }

    /**
     * Shake message digest
     * @param data The Data to be digested
     * @param returnLength The length of the returned data
     * @return The hashed data
     */
    public static byte[] shakeDigest(byte[] data, int returnLength){
        SHAKEDigest digest = new SHAKEDigest(256);
        byte[] hashBytes = new byte[data.length];
        digest.update(data, 0, data.length);
        digest.doFinal(hashBytes, 0);
        digest.reset();
        return Arrays.copyOf(hashBytes, returnLength);
    }

    /*// see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-11#name-point-serialization-procedu
    public static void point_to_octets_g2(){
        var C_bit = 1; // We want compression, see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar
        var I_bit = 0; // 1 if point is at infinity, else 0
        var S_bit = sign_GF_p^2(y); // 0 if point at infinity or if compression is not used.

        var m_byte = (C_bit * Math.pow(2,7)) + (I_bit * Math.pow(2,6)) + (S_bit * Math.pow(2,5));
    }*/



    public static KeyPair<FrElement, G2Point> generateKeyPair() {
        var sk = FrElement.getRandom();
        var PK = P2.times(sk);
        return new KeyPair<>(sk, PK);
    }

    /**
     * Proof
     */
    public static class Proof extends Nonuple<G1Point, G1Point, G1Point, FrElement, FrElement, FrElement, FrElement, FrElement, Vector<FrElement>> {
        public Proof(G1Point A_prime, G1Point A_bar, G1Point D, FrElement c, FrElement e_hat, FrElement r2_hat, FrElement r3_hat, FrElement s_hat, Vector<FrElement> bold_m_j) {
            super(A_prime, A_bar, D, c, e_hat, r2_hat, r3_hat, s_hat, bold_m_j);
        }
    }

    public static byte[] ProofGen(byte[] publicKey, byte[] signature, byte[] header, byte[] ph, Vector<byte[]> messages, int[] disclosed_indexes) throws InvalidException {
        byte[] api_id = (CIPHERSUITE_ID + "H2G_HM2S_").getBytes();
        try{
            BigInteger[] message_scalars = messages_to_scalars(messages, api_id);
            Vector<G1Point> generators = createGenerators(message_scalars.length+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            byte[] proof = CoreProofGen(publicKey, signature, generators, header, ph, message_scalars, disclosed_indexes, api_id);
            return proof;
        }catch (Exception e) {
            System.out.println(e);
            throw new InvalidException("Proof is invalid");
        }
    }

    private static byte[] CoreProofGen(byte[] publicKey, byte[] signature_octets, Vector<G1Point> generators, byte[] header, byte[] ph, BigInteger[] messages, int[] disclosed_indexes, byte[] api_id) throws InvalidException, GroupElement.DeserializationException, AbortException {
        Signature signature = octets_to_signature(signature_octets);
        int messagesCount = messages.length;
        int disclosedCount = disclosed_indexes.length;
        if(disclosedCount > messagesCount) throw new InvalidException("More disclosed indexes than messages");
        int undisclosedCount = messagesCount-disclosedCount;
        int[] not_disclosed_indexes = new int[undisclosedCount];
        int counter = 0;
        for (int i = 0; i < messagesCount; i++) {
            for (int j = 0; j < disclosedCount; j++) {
                if(i != disclosed_indexes[j]) {
                    not_disclosed_indexes[counter] = i;
                    counter++;
                }
            }
        }
        BigInteger[] disclosed_messages = new BigInteger[disclosedCount];
        BigInteger[] undisclosed_messages = new BigInteger[undisclosedCount];
        for (int i = 0; i < disclosedCount; i++) {
            disclosed_messages[i] = messages[disclosed_indexes[i]];
        }
        for (int i = 0; i < undisclosedCount; i++) {
            undisclosed_messages[i] = messages[not_disclosed_indexes[i]];
        }
        BigInteger[] random_scalars = calculate_random_scalars(3+undisclosedCount);
        Quadruple init_res = ProofInit(publicKey, signature, generators, random_scalars, header, messages, not_disclosed_indexes, api_id);
        BigInteger challenge = ProofChallengeCalculate(init_res, disclosed_indexes, disclosed_messages, ph, api_id);
        var proof = ProofFinalize(init_res, challenge, signature.getSecond().toBigInteger(), random_scalars, undisclosed_messages);
        return proof;
    }

    public static byte[] ProofFinalize(Quadruple init_res, BigInteger challenge, BigInteger e_value, BigInteger[] random_scalars, BigInteger[] undisclosed_messages) throws InvalidException {
        int undisclosedLength = undisclosed_messages.length;
        if(random_scalars.length != (undisclosedLength+3)) throw new InvalidException("There to many or to few random scalars");
        BigInteger r1 = random_scalars[0];
        BigInteger r2 = random_scalars[1];
        BigInteger r3 = random_scalars[2];
        BigInteger[] randomScalarsCut = new BigInteger[random_scalars.length-3];
        System.arraycopy(random_scalars, 3, randomScalarsCut, 0, random_scalars.length-3);
        G1Point Abar = (G1Point) init_res.getFirst();
        G1Point Bbar = (G1Point) init_res.getSecond();
        BigInteger r4 = r1.modInverse(r).negate();
        BigInteger r2Calc = r2.add(e_value.multiply(r4).multiply(challenge)).mod(r);
        BigInteger r3Calc = r3.add(r4.multiply(challenge)).mod(r);
        BigInteger[] calcMessages = new BigInteger[undisclosedLength];
        for (int i = 0; i < undisclosedLength; i++) {
            BigInteger calcMessage = randomScalarsCut[i].add(undisclosed_messages[i].multiply(challenge)).mod(r);
            calcMessages[i] = calcMessage;
        }
        Object[] proof = new Object[5 + calcMessages.length];
        proof[0] = Abar;
        proof[1] = Bbar;
        proof[2] = r2Calc;
        proof[3] = r3Calc;
        System.arraycopy(calcMessages, 0, proof, 4, calcMessages.length);
        proof[proof.length-1] = challenge;
        return proof_to_octets(proof);
    }

    private static byte[] proof_to_octets(Object[] proof) throws InvalidException {
        return serialize(proof);
    }

    public static BigInteger ProofChallengeCalculate(Quadruple init_res, int[] i_array, BigInteger[] msg_array, byte[] ph, byte[] api_id) throws AbortException, InvalidException {
        byte[] dst = ("H2S_").getBytes();
        byte[] challenge_dst = new byte[api_id.length+ dst.length];
        System.arraycopy(api_id, 0, challenge_dst, 0, api_id.length);
        System.arraycopy(dst, 0, challenge_dst, api_id.length, dst.length);
        int disclosedMessagesIndex = i_array.length;
        if(disclosedMessagesIndex > Math.pow(2,64)-1 || disclosedMessagesIndex != msg_array.length) throw new AbortException("To many or to few message indexes");
        if (ph.length > Math.pow(2,64)-1) throw new AbortException("Ph is to long");
        Object[] c_arr = new Object[4 + i_array.length + msg_array.length]; // Abar, Bbar, T, lenght + irray lenght, + msg lenght + domain
        c_arr[0] = init_res.getFirst();
        c_arr[1] = init_res.getSecond();
        c_arr[2] = init_res.getThird();
        for (int i = 0; i < i_array.length ; i++) {
            c_arr[i+3] = i_array[i];
        }
        System.arraycopy(msg_array, 0, c_arr, 3+i_array.length, msg_array.length);
        c_arr[c_arr.length-1] = init_res.getFourth();
        byte[] serializedData = serialize(c_arr);
        byte[] serilizedPhLenght = i2osp(BigInteger.valueOf(ph.length), 8);
        byte[] c_octs = new byte[serializedData.length + serilizedPhLenght.length + ph.length];
        System.arraycopy(serializedData, 0, c_octs, 0, serializedData.length);
        System.arraycopy(serilizedPhLenght, 0, c_octs, serializedData.length, serilizedPhLenght.length);
        System.arraycopy(ph, 0, c_octs, serializedData.length + serilizedPhLenght.length, ph.length);
        return hash_to_scalar(c_octs, challenge_dst);
    }

    public static Quadruple ProofInit(byte[] publicKey, Signature signature, Vector<G1Point> generators, BigInteger[] random_scalars, byte[] header, BigInteger[] messages, int[] undisclosed_indexes, byte[] api_id) throws InvalidException, AbortException {
        int messageCount = messages.length;
        int undisclosedCount = undisclosed_indexes.length;
        if(undisclosedCount > messageCount) throw new AbortException("The number of the undisclosed messages is higher than the number of the disclosed messages");
        if(random_scalars.length != (undisclosedCount+3)) throw new InvalidException("The number of Random Scalars needs to be the same as the number of undisclosed indexes + 3");
        BigInteger r1 = random_scalars[0];
        BigInteger r2 = random_scalars[1];
        BigInteger r3 = random_scalars[2];
        BigInteger[] randomScalarsCut = new BigInteger[random_scalars.length-3];
        System.arraycopy(random_scalars, 3, randomScalarsCut, 0, random_scalars.length-3);
        if (generators.getLength() != (messageCount+1)) throw new InvalidException("The number of generators is not the same as the number of messages + 1");
        G1Point Q1 = generators.getValue(1);
        G1Point[] MsgGenerators = new G1Point[generators.getLength()-1];
        for (int i = 2; i <= generators.getLength(); i++) {
            MsgGenerators[i-2] = generators.getValue(i);
        }
        G1Point[] undisclosedGenerators = new G1Point[undisclosedCount];
        for (int i = 0; i < undisclosed_indexes.length; i++) {
            int undisclosedIndex = undisclosed_indexes[i];
            if(undisclosedIndex < 0 || undisclosedIndex >= messageCount) throw new AbortException("Undisclosed message index out of range");
            undisclosedGenerators[i] = generators.getValue(undisclosedIndex);
        }
        BigInteger domain = calculate_domain(publicKey, Q1, MsgGenerators, header, api_id);
        G1Point B = P1.add(Q1.times(FrElement.of(domain)));
        for (int i = 1; i <= messageCount; i++) {
            BigInteger message = messages[i-1];
            B.add(generators.getValue(i).times(FrElement.of(message)));
        }
        G1Point Abar = signature.getFirst().times(FrElement.of(r1));
        G1Point Abare = Abar.times(signature.getSecond());
        G1Point Bbar = B.times(FrElement.of(r1)).subtract(Abare);
        G1Point BbarR3 = Bbar.times(FrElement.of(r3));
        G1Point T = Abar.times(FrElement.of(r2)).add(BbarR3);
        for (int i = 0; i < undisclosedGenerators.length; i++) {
            G1Point temp = undisclosedGenerators[i].times(FrElement.of(randomScalarsCut[i]));
            T.add(temp);
        }
        return new Quadruple(Abar, Bbar, T, domain);
    }

    public static BigInteger[] calculate_random_scalars(int count){
        BigInteger[] randomScalars = new BigInteger[count];
        for (int i = 0; i < count; i++) {
            randomScalars[i] = os2ip(randomBytes(Expand_Len)).mod(r);
        }
        return randomScalars;
    }








    // SIGNATURE SCHEME METHODS



    public static Signature generateSignature(FrElement sk, G2Point PK, String header, Vector<String> strMessages) {
        var messages = strMessages.map(FrElement::hashAndMap);
        // Definitions
        int L = messages.getLength();
        // Precomputations
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Procedure
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var e_s = FrElement.hashAndMap(new Triple<>(sk, domain, messages), 2);
        var e = e_s.getValue(1);
        var s = e_s.getValue(2);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        var A = B.times(sk.add(e).inverse());
        return new Signature(A, e, s);
    }

    public static boolean verifySignature(G2Point PK, Signature signature, String header, Vector<String> strMessages) {
        var messages = strMessages.map(FrElement::hashAndMap);
        // Definitions
        int L = messages.getLength();
        // Precomputations
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Procedure
        var A = signature.getFirst();
        var e = signature.getSecond();
        var s = signature.getThird();
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        return A.pair(PK.add(G2Point.GENERATOR.times(e))).multiply(B.pair(P2.negate())).isOne();
    }

    public static Proof generateProof(G2Point PK, Signature signature, String header, String ph, Vector<String> strMessages, IntSet disclosedIndices) {
        var messages = strMessages.map(FrElement::hashAndMap);
        // Definitions
        int L = messages.getLength();
        int R = (int) disclosedIndices.getSize();
        int U = L - R;
        int prfLen = FrElement.BYTE_LENGTH;
        // Precomputations
        var validIndices = IntSet.range(1, L);
        var undisclosedIndices = validIndices.difference(disclosedIndices); // size = U
        var undisclosedMessages = messages.select(undisclosedIndices);
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Procedure
        var A = signature.getFirst();
        var e = signature.getSecond();
        var s = signature.getThird();
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var scalars = FrElement.hashAndMap(randomBytes(prfLen), 6);
        var r1 = scalars.getValue(1);
        var r2 = scalars.getValue(2);
        var e_tilde = scalars.getValue(3);
        var r2_tilde = scalars.getValue(4);
        var r3_tilde = scalars.getValue(5);
        var s_tilde = scalars.getValue(6);
        var bold_m_tilde = FrElement.hashAndMap(randomBytes(prfLen), U);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        var r3 = r1.inverse();
        var A_prime = A.times(r1);
        var A_bar = A_prime.times(e.negate()).add(B.times(r1));
        var D = B.times(r1).add(Q1.times(r2));
        var s_prime = r2.multiply(r3).add(s);
        var C1 = A_prime.times(e_tilde).add(Q1.times(r2_tilde));
        var C2 = D.times(r3_tilde.negate()).add(Q1.times(s_tilde)).add(sumOfProducts(MsgGenerators.select(undisclosedIndices), bold_m_tilde));
        var c_array = new Decuple<>(A_prime, A_bar, D, C1, C2, R, disclosedIndices, messages.select(disclosedIndices), domain, ph);
        var c = FrElement.hashAndMap(c_array);
        var e_hat = e.multiply(c).add(e_tilde);
        var r2_hat = r2.multiply(c).add(r2_tilde);
        var r3_hat = r3.multiply(c).add(r3_tilde);
        var s_hat = s_prime.multiply(c).add(s_tilde);
        var bold_m_hat = undisclosedMessages.map(msg -> msg.times(c)).map(bold_m_tilde, FrElement::add);
        return new Proof(A_prime, A_bar, D, c, e_hat, r2_hat, r3_hat, s_hat, bold_m_hat);
    }

    public static boolean verifyProof(G2Point PK, Proof proof, String header, String ph, Vector<String> disclosedStrMessages, IntSet disclosedIndices) {
        var disclosedMessages = disclosedStrMessages.map(FrElement::hashAndMap);
        // Definitions
        int R = (int) disclosedIndices.getSize();
        int U = proof.getNinth().getLength();
        int L = R + U;
        // Precomputations
        var validIndices = IntSet.range(1, L);
        var undisclosedIndices = validIndices.difference(disclosedIndices); // size = U
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Preconditions
        if (disclosedStrMessages.getLength() != R) return false;
        if (!validIndices.containsAll(disclosedIndices)) return false;
        // Procedure
        var A_prime = proof.getFirst();
        var A_bar = proof.getSecond();
        var D = proof.getThird();
        var c = proof.getFourth();
        var e_hat = proof.getFifth();
        var r2_hat = proof.getSixth();
        var r3_hat = proof.getSeventh();
        var s_hat = proof.getEighth();
        var bold_m_hat = proof.getNinth();
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var C1 = A_bar.subtract(D).times(c).add(A_prime.times(e_hat).add(Q1.times(r2_hat)));
        var T = P1.add(Q2.times(domain)).add(sumOfProducts(MsgGenerators.select(disclosedIndices), disclosedMessages));
        var C2 = T.times(c).subtract(D.times(r3_hat)).add(Q1.times(s_hat)).add(sumOfProducts(MsgGenerators.select(undisclosedIndices), bold_m_hat));
        var cv_array = new Decuple<>(A_prime, A_bar, D, C1, C2, R, disclosedIndices, disclosedMessages, domain, ph);
        var cv = FrElement.hashAndMap(cv_array);
        if (!c.equals(cv)) return false;
        if (A_prime.isZero()) return false;
        return A_prime.pair(PK).multiply(A_bar.pair(P2.negate())).isOne();
    }

    // PRIVATE HELPER METHODS

    private static G1Point sumOfProducts(Vector<G1Point> bases, Vector<FrElement> exponents) {
        return bases.map(exponents, G1Point::times).toStream().reduce(G1Point.ZERO, G1Point::add);
    }

    // simplified version for testing
    private static Vector<G1Point> createGenerators(int count) {
        var builder = new Vector.Builder<G1Point>();
        IntStream.rangeClosed(1, count)
                .mapToObj(i -> "Generator-" + i)
                .map(G1Point::hashAndMap)
                .forEach(builder::addValue);
        return builder.build();
    }

    private static byte[] randomBytes(int n) {
        var randomBytes = new byte[n];
        SECURE_RANDOM.nextBytes(randomBytes);
        return randomBytes;
    }

}
