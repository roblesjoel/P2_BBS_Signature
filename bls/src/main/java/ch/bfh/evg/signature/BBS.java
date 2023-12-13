/**
 * BBS Helper Methods
 * Base made by Rolf Haenni
 */

package ch.bfh.evg.signature;

import ch.bfh.evg.Exception.AbortException;
import ch.bfh.evg.Exception.InvalidException;
import ch.bfh.evg.bls12_381.Scalar;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.IntStream;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class BBS extends JNI {

    //TODO
    //create generator function

    /**
     * Definitions
     */
    public static final OctetString CIPHERSUITE_ID = OctetString.valueOf("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_"); // Ciphersuite ID,BLS12-381-SHAKE-256
    private static final G1Point P1 = G1Point.GENERATOR; // Generator point in G1
    private static final G2Point P2 = G2Point.GENERATOR; // Generator point in G2
    private static final SecureRandom SECURE_RANDOM = new SecureRandom(); // Random generator method
    private static final OctetString Octet_Scalar_Length = OctetString.valueOf(32);
    private static final OctetString Octet_Point_Length = OctetString.valueOf(48);
    private static final int Expand_Len = 48;
    private static final Scalar r = Scalar.of(new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16));

    /**
     * Signature
     */

    /**
     * Message sign function
     * @param secretKey The secret key as a scalar
     * @param publicKey The public key as an OctetString
     * @param header Context and application information as an OctetString
     * @param messages The messages to be signed as an OctetString Vector
     * @return Returns a valid Signature
     * @throws InvalidException Throws an Invalid Exception if an error occurred while generation the signature
     */
    public static OctetString Sign(Scalar secretKey, OctetString publicKey, OctetString header, Vector<OctetString> messages) throws InvalidException {
        OctetString api_id = CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        try{
            Vector<Scalar> message_scalars = messages_to_scalars(messages, api_id);
            Vector<G1Point> generators = createGenerators(message_scalars.getLength()+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            Signature signature = CoreSign(secretKey, publicKey, generators, header, message_scalars, G1Point.GENERATOR, api_id);
            return signature;
        }catch (Exception e) {
            System.out.println(e);
            throw new InvalidException("Signature is Invalid");
        }
    }

    /**
     * Message verify function
     * @param publicKey The public key as an OctetString
     * @param signature The signature of the messages
     * @param header Context and application information as an OctetString
     * @param messages The messages to be signed as an OctetString Vector
     * @return Returns true if the signature is valid, if not throws an error
     * @throws InvalidException Throws an Invalid Exception if an error occurred while verifying the signature
     */
    public static boolean Verify(OctetString publicKey, OctetString signature, OctetString header, Vector<OctetString> messages) throws InvalidException{
        OctetString api_id = CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        try{
            Vector<Scalar> message_scalars = messages_to_scalars(messages, api_id);
            Vector<G1Point> generators = createGenerators(message_scalars.getLength()+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            boolean result = CoreVerify(publicKey, signature, generators, header, message_scalars, api_id);
            return result;
        }catch (Exception e){
            System.out.println(e);
            throw new InvalidException("Signature Verification failed");
        }
    }

    /**
     * The core verify function
     * @param publicKey The public key as an Octet string
     * @param signature_octets The signature as an octet string
     * @param generators The generators
     * @param header Context and application information as an OctetString
     * @param messages The messages as a Scalar Vector
     * @param api_id The apiId as an Octet string
     * @return Returns true if the signature is valid
     * @throws InvalidException Throws an Invalid exception if the Signature is invalid
     * @throws GroupElement.DeserializationException Throws an GroupElement.DeserializationException if the Group element cannot be deserialized
     * @throws AbortException Throws an AbortException if there was error while verifing
     */
    private static boolean CoreVerify(OctetString publicKey, OctetString signature_octets, Vector<G1Point> generators, OctetString header, Vector<Scalar> messages, OctetString api_id) throws InvalidException, GroupElement.DeserializationException, AbortException {
        Signature signature = octets_to_signature(signature_octets);
        G2Point W = G2Point.deserialize(publicKey.toBytes());
        int L = messages.getLength();
        if(generators.getLength() != (L + 1)) throw new InvalidException("To few generators or to many messages");
        G1Point Q_1 = generators.getValue(1);
        Vector<G1Point> H_x = getHPoints(generators);
        Scalar domain = calculate_domain(publicKey, Q_1, H_x, header, api_id);
        G1Point B = P1.add(Q_1.times(domain)).add(G1Point.sumOfScalarMultiply(H_x, messages));
        if(!signature.getPoint().pair(W.add(G2Point.GENERATOR.times(signature.getScalar()))).multiply(B.pair(G2Point.GENERATOR.negate())).equals(GTElement.ONE)) throw new InvalidException("Signature is not valid. Verification failed");
        return true;
    }

    /**
     * Gets the needed HPoints from the Vector of generators
     * @param generators The Vector of generators
     * @return Returns a new Vector of generators
     */
    private static Vector<G1Point> getHPoints(Vector<G1Point> generators){
        Vector.Builder<G1Point> builder = new Vector.Builder<>(generators.getLength()-1);
        for (int i = 2; i <= generators.getLength(); i++) {
            builder.setValue(i, generators.getValue(i));
        }
        return builder.build();
    }

    /**
     * Parse the Signature octets to the signature type
     * @param signature_octets The signature octets
     * @return The Signature Object
     * @throws InvalidException Throws an InvalidException if the signature octets are not correct
     * @throws GroupElement.DeserializationException Throws a GroupElement.DeserializationException if the Group Element could not be deserialized
     */
    private static Signature octets_to_signature(OctetString signature_octets) throws InvalidException, GroupElement.DeserializationException {
        int expected_len = Octet_Point_Length.toInt() + Octet_Scalar_Length.toInt();
        if(signature_octets.length != expected_len) throw new InvalidException("Signature has incorrect length");
        OctetString A_octets = signature_octets.split(0, Octet_Point_Length.length -1);
        G1Point A = G1Point.deserialize(ByteArray.of(A_octets.toBytes()));
        if(A == G1Point.ZERO) throw new InvalidException("Error while deserializing. Point in Signature is the identity point");
        int index = Octet_Point_Length.length;
        int end_index = index + Octet_Scalar_Length.length - 1;
        Scalar e = os2ip(signature_octets.split(index, end_index));
        if(e.isZero() || e.biggerThan(r)) throw new InvalidException("Scalar e is either 0 or to big");
        return new Signature(A, e);
    }

    /**
     * The Core Signature function
     * @param secretKey The secret key as a Scalar
     * @param publicKey The public key as a Octet String
     * @param generators A Vector with G1Points
     * @param header Context and application information as an OctetString
     * @param messages The messages as a Scalar Vector
     * @param commitment A point on G1
     * @param api_id The apiId as an Octet string
     * @return Returns the Signature as an Octet String
     * @throws AbortException Throws an Abort Exception if there is an error why signing
     * @throws InvalidException Throws an Invalid Exception if an input is not valid
     */
    private static OctetString CoreSign(Scalar secretKey, OctetString publicKey, Vector<G1Point> generators, OctetString header, Vector<Scalar> messages, G1Point commitment, OctetString api_id) throws AbortException, InvalidException{
        OctetString signature_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        int L = messages.getLength();
        if(generators.getLength() < L + 1) throw new AbortException("To many messages or to few generators");
        G1Point Q1 = generators.getValue(1);
        Vector<G1Point> H_x = getHPoints(generators);
        Scalar domain = calculate_domain(publicKey, Q1, H_x, header, api_id);
        OctetString comm = OctetString.valueOf("");
        if(commitment != G1Point.ZERO) comm = serialize(new Object[]{commitment});
        Scalar e = hash_to_scalar(serialize(prepareSignSerializationData(secretKey, domain, messages, comm)), signature_dst);
        G1Point B = P1.add(Q1.times(domain).add(G1Point.sumOfScalarMultiply(H_x, messages)));
        var A = B.times(Scalar.of(secretKey.add(e).toBigInteger().modInverse(r.toBigInteger())));
        return signature_to_octets(new Signature(A, e));
    }

    /**
     * Prepare all the data that will be hashed to a scalar
     * @param secretKey The secret key as a scalar
     * @param domain The domain as a scalar
     * @param messages The messages as a Scalar Vector
     * @param comm The serialized commitment
     * @return An Object array with all the data to be serialized
     */
    private static Object[] prepareSignSerializationData(Scalar secretKey, Scalar domain, Vector<Scalar> messages, OctetString comm){
        Object[] dataToBeSerialized = new Object[2+messages.getLength()];
        dataToBeSerialized[0] = secretKey;
        dataToBeSerialized[1] = domain;
        System.arraycopy(messages.toArray(),0, dataToBeSerialized, 2, messages.getLength());
        return dataToBeSerialized;
    }

    /**
     * Serialize the signature
     * @param signature The signature object
     * @return The serialized signature as an octet String
     * @throws InvalidException Throws an Invalid Exception if the input is invalid
     */
    private static OctetString signature_to_octets(Signature signature) throws InvalidException {
        return serialize(new Object[]{signature.getPoint(), signature.getScalar()});
    }

    /**
     * Calculate the domian Scalar
     * @param publicKey The public key as an Octet string
     * @param Q1 A generator point on G1
     * @param H_Points Multiple Generator Points on G1
     * @param header Context and application information as an OctetString
     * @param api_id The apiId as an Octet string
     * @return Returns the domain as a scalar
     * @throws AbortException Throws a AbortException if there is an error while calculation the domain
     * @throws InvalidException Throws a InvalidException if an input is invalid
     */
    private static Scalar calculate_domain(OctetString publicKey, G1Point Q1, Vector<G1Point> H_Points, OctetString header, OctetString api_id) throws AbortException, InvalidException{
        OctetString domain_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        int L = H_Points.getLength();
        if(header.length > Math.pow(2,64)-1 || L > Math.pow(2,64)-1) throw new AbortException("The header is to long or there are to many generator points");
        Object[] dom_array = serializationPreparationForDomain(L, Q1, H_Points);
        OctetString dom_octs = serialize(dom_array);
        OctetString dom_input = publicKey.concat(dom_octs).concat(i2osp(Scalar.of(BigInteger.valueOf(header.length)), 8)).concat(header);
        return hash_to_scalar(dom_input, domain_dst);
    }

    /**
     * Makes an Object array for serialization
     * @param L The length of the H_points
     * @param Q_1 A generator point on G1
     * @param H_Points Multiple Generator Points on G1
     * @return Returns an Object array with the data
     */
    private static Object[] serializationPreparationForDomain(int L, G1Point Q_1, Vector<G1Point> H_Points){
        Object[] dataToBeSerialized = new Object[2+H_Points.getLength()];
        dataToBeSerialized[0] = L;
        dataToBeSerialized[1] = Q_1;
        System.arraycopy(H_Points.toArray(),0, dataToBeSerialized, 2, H_Points.getLength());
        return dataToBeSerialized;
    }

    /**
     * Serialize an Object array
     * @param input_array The objects to be serialized
     * @return The serialized objects as an Octet string
     * @throws InvalidException Throws an InvalidException of a given int so to big or a wrong type is given
     */
    private static OctetString serialize(Object[] input_array) throws InvalidException{
        OctetString octect_result = new OctetString();
        for (Object el : input_array) {
            switch (el.getClass().getName()) {
                case "ch.bfh.evg.bls12_381.G1Point" -> {
                    G1Point element = (G1Point) el;
                    octect_result.concat(new OctetString(element.serialize().toByteArray()));
                }
                case "ch.bfh.evg.bls12_381.G2Point" -> {
                    G2Point element = (G2Point) el;
                    octect_result.concat(new OctetString(element.serialize().toByteArray()));
                }
                case "ch.bfh.evg.bls12_381.Scalar" -> {
                    octect_result.concat(i2osp((BigInteger) el, Octet_Scalar_Length.toInt()))
                }
                case "java.lang.Integer" -> {
                    int element = (int) el;
                    if (element < 0 || element > Math.pow(2,64)-1) throw new InvalidException("Int number is to big");
                    octect_result.concat(i2osp(BigInteger.valueOf(element), 8));
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
    private static Vector<Scalar> messages_to_scalars(Vector<OctetString> messages, OctetString api_id) throws AbortException{
        OctetString map_dst = api_id.concat(OctetString.valueOf("MAP_MSG_TO_SCALAR_AS_HASH_", StandardCharsets.US_ASCII));
        if(messages.getLength() > Math.pow(2,64) -1) throw new AbortException("To many messages!");
        var builder = new Vector.Builder<Scalar>();
        for (int i = 1; i <= messages.getLength(); i++) {
            Scalar msg_scalar_i = hash_to_scalar(messages.getValue(i), map_dst);
            builder.addValue(msg_scalar_i);
        }
        return builder.build();
    }

    /**
     * Generate the public key to a given secret Key
     * @param secretKey The secret key
     * @return The public key as octets
     */
    public static OctetString SkToPk(Scalar secretKey){
        G2Point W = P2.times(secretKey);
        return new OctetString(W.serialize().toByteArray());
    }

    /**
     * Generator function for the secret key
     * @param key_material Random input from which the key will be generated. Must be at least 32 byte
     * @param key_info May be used to derive distinct keys from the same key material. Defaults to an empty string.
     * @param key_dst Represents the domain separation. Defaults to the octet string CIPHERSUITE_ID || "KEYGEN_DST_".
     */
    public static Scalar KeyGen(OctetString key_material, OctetString key_info, OctetString key_dst) throws InvalidException {
        try {
            if(key_dst.length == 0) key_dst = CIPHERSUITE_ID.concat("KEYGEN_DST");
            if(key_material.length < 32) throw new InvalidException("key_material is to short");
            if(key_info.length > 65535) throw new InvalidException("key_info is to long");
            OctetString derive_input = key_material.concat(i2osp(key_info.length), 2).concat(key_info);
            Scalar SK = hash_to_scalar(derive_input, key_dst);
            return SK;
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
    private static OctetString i2osp(Scalar i, int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Size of the octet string should be at least 1 but is " + size);
        }
        if (i == null || i.toBigInteger().signum() == -1 || i.toBigInteger().bitLength() > size * Byte.SIZE) {
            throw new IllegalArgumentException("Integer should be a positive number or 0, no larger than the given size");
        }
        byte[] signed = i.toBigInteger().toByteArray();
        if (signed.length == size) {
            return new OctetString(signed);
        }
        byte[] os = new byte[size];
        if (signed.length < size) {
            System.arraycopy(signed, 0, os, size - signed.length, signed.length);
            return new OctetString(os);
        }
        System.arraycopy(signed, 1, os, 0, size);
        return new OctetString(os);
    }

    /**
     * Octet to Stream
     * @param data the octets to be converted
     * @return The converted data
     */
    static Scalar os2ip(OctetString data) {
        return Scalar.of(new BigInteger(1, data.toBytes()));
    }

    /**
     * Hash message to scalar
     * @param msg_octets The messages to be hashed
     * @param dst The domain separation tag
     * @return The hashed message as a scalar
     * @throws AbortException Throws an exception id the dst is too long
     */
    static Scalar hash_to_scalar(OctetString msg_octets, OctetString dst) throws AbortException{
        if(dst.length > 255) throw new AbortException("dst is to long");
        var uniform_bytes = expand_message_xof(msg_octets, dst, Expand_Len);
        return Scalar.of(os2ip(uniform_bytes).toBigInteger().mod(r.toBigInteger()));
    }

    /**
     * Expand message with variable output function
     * @param msg The message to be digested
     * @param dst a domain separation tag
     * @param len_in_bytes The length of the output
     * @return The hashed message
     * @throws AbortException Throws an exception if len_in_bytes or DST are too big
     * as defined in https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xof
     */
    public static OctetString expand_message_xof(OctetString msg, OctetString dst, int len_in_bytes) throws AbortException {
        if(len_in_bytes > 65535 || dst.length > 255) throw new AbortException("Either len_in_bytes or DST is to big");
        OctetString serializedDstLenght = i2osp(Scalar.of(BigInteger.valueOf(dst.length)),1);
        OctetString dstPrime = dst.concat(serializedDstLenght);
        OctetString serializedLenInBytes = i2osp(Scalar.of(BigInteger.valueOf(len_in_bytes)), 2);
        OctetString msg_prime = msg.concat(serializedLenInBytes).concat(dstPrime);
        return shakeDigest(msg_prime, len_in_bytes);
    }

    /**
     * Shake message digest
     * @param data The Data to be digested
     * @param returnLength The length of the returned data
     * @return The hashed data
     */
    public static OctetString shakeDigest(OctetString data, int returnLength){
        SHAKEDigest digest = new SHAKEDigest(256);
        byte[] hashBytes = new byte[data.length];
        digest.update(data.toBytes(), 0, data.length);
        digest.doFinal(hashBytes, 0);
        digest.reset();
        return new OctetString(Arrays.copyOf(hashBytes, returnLength));
    }


    // To be redefined


    /**
     * Proof
     */

    public static boolean ProofVerify(byte[] publicKey, byte[] proof, byte[] header, byte[] ph, byte[][] disclosed_messages, int[] disclosed_indexes) throws InvalidException, AbortException {
        try{
            byte[] api_id = (CIPHERSUITE_ID + "H2G_HM2S_").getBytes();
            int proof_len_floor = (2 * Octet_Point_Length) + (3 * Octet_Scalar_Length);
            if(proof.length < proof_len_floor) throw new InvalidException("Proof is to short");
            int U = (int) Math.floor((proof.length-proof_len_floor)/Octet_Scalar_Length);
            int disclosedIndexesLenght = disclosed_indexes.length;
            BigInteger[] messageScalars = messages_to_scalars(disclosed_messages, api_id);
            Vector<G1Point> generators = createGenerators(U+disclosedIndexesLenght+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            boolean result = CoreProofVerify(publicKey, proof, generators, header, ph, messageScalars, disclosed_indexes, api_id);
            return result;
        }catch (Exception e){
            System.out.println(e);
            throw new InvalidException("Proof is not valid");
        }
    }

    private static boolean CoreProofVerify(byte[] publicKey, byte[] proof_octets, Vector<G1Point> generators, byte[] header, byte[] ph, BigInteger[] disclosed_messages, int[] disclosed_indexes, byte[] api_id) throws InvalidException, GroupElement.DeserializationException, AbortException {
        Object[] proof_result = octets_to_proof(proof_octets);
        G1Point Abar = (G1Point) proof_result[0];
        G1Point Bbar = (G1Point) proof_result[1];
        BigInteger r2Calc = (BigInteger) proof_result[2];
        BigInteger r3Calc = (BigInteger) proof_result[3];
        BigInteger[] commitments = (BigInteger[]) proof_result[4];
        BigInteger cp = (BigInteger) proof_result[5];
        G2Point W = G2Point.deserialize(ByteArray.of(publicKey));
        Quadruple init_res = ProofVerifyInit(publicKey, proof_result, generators, header, disclosed_messages, disclosed_indexes, api_id);
        BigInteger challenge = ProofChallengeCalculate(init_res, disclosed_indexes, disclosed_messages, ph, api_id);
        if(!cp.equals(challenge)) throw new InvalidException("Cp and challenge do not match");
        GTElement Apairing = Abar.pair(W);
        GTElement Bpairing = Bbar.pair(G2Point.GENERATOR.negate());
        GTElement multiplicatedElement = Apairing.multiply(Bpairing);
        if(!multiplicatedElement.equals(GTElement.ONE)) throw new InvalidException("Pairing is not correct");
        return true;
    }

    private static Quadruple ProofVerifyInit(byte[] publicKey, Object[] proof, Vector<G1Point> generators, byte[] header, BigInteger[] disclosed_messages, int[] disclosed_indexes, byte[] api_id) throws InvalidException, AbortException {
        G1Point Abar = (G1Point) proof[0];
        G1Point Bbar = (G1Point) proof[1];
        BigInteger r2Calc = (BigInteger) proof[2];
        BigInteger r3Calc = (BigInteger) proof[3];
        BigInteger[] commitments = (BigInteger[]) proof[4];
        BigInteger cp = (BigInteger) proof[5];
        int commitmentLength = commitments.length;
        int disclosedLength = disclosed_indexes.length;;
        int L = commitmentLength + disclosedLength;
        int[] indexes = new int[L];
        for (int i = 0; i < L; i++) {
            if(!Arrays.asList(disclosed_indexes).contains(i)) indexes[i] = i;
        }
        if(generators.getLength() != L+1) throw new InvalidException("To many or to few generators");
        G1Point Q1 = generators.getValue(1);
        G1Point[] MsgGenerators = new G1Point[generators.getLength()-1];
        G1Point[] disclosedGenerators = new G1Point[disclosedLength];
        G1Point[] commitmentGenerators = new G1Point[commitmentLength];
        for (int i = 2; i <= generators.getLength(); i++) {
            G1Point generator = generators.getValue(i);
            MsgGenerators[i-2] = generator;
            if((i-2) < disclosedLength) disclosedGenerators[i-2] = generators.getValue(disclosed_indexes[i-2]+1);
            if((i-2) < commitmentLength) commitmentGenerators[i-2] = generator;
        }
        if(disclosed_messages.length != disclosedLength) throw new AbortException("There are to many or to few disclosed messages");
        BigInteger domain = calculate_domain(publicKey, Q1, MsgGenerators, header, api_id);
        G1Point D = P1.add(Q1.times(Scalar.of(domain)));
        for (int i = 0; i < disclosedLength; i++) {
            D.add(disclosedGenerators[i].times(Scalar.of(disclosed_messages[i])));
        }
        G1Point T = Abar.times(Scalar.of(r2Calc)).add(Bbar.times(Scalar.of(r3Calc)));
        for (int i = 0; i < commitmentLength; i++) {
            T.add(commitmentGenerators[i].times(Scalar.of(commitments[i])));
        }
        T = T.add(D.times(Scalar.of(cp)));
        return new Quadruple(Abar, Bbar, T, domain);
    }

    private static Object[] octets_to_proof(byte[] proof_octets) throws GroupElement.DeserializationException, InvalidException {
        int proof_len_floor = (2* Octet_Point_Length) + (3*Octet_Scalar_Length);
        if(proof_octets.length < proof_len_floor) throw new InvalidException("To few proof octets");
        G1Point[] proofPoints = new G1Point[2];
        int index = 0;
        for (int i = 0; i < 2; i++) {
            int end_index = index + Octet_Point_Length - 1;
            byte[] octets = Arrays.copyOfRange(proof_octets, index, end_index + 1);
            G1Point A_i = G1Point.deserialize(ByteArray.of(octets));
            if(A_i.isZero()) throw new InvalidException("A_i is identity");
            proofPoints[i] = A_i;
            index += Octet_Point_Length;
        }
        ArrayList<BigInteger> scalars = new ArrayList<>();
        int j = 0;
        for (;index < proof_octets.length; index += Octet_Scalar_Length) {
            int end_index = index + Octet_Scalar_Length - 1;
            byte[] octets = Arrays.copyOfRange(proof_octets, index, end_index + 1);
            BigInteger s_j = os2ip(octets);
            if(s_j.equals(BigInteger.ZERO) || s_j.compareTo(r) >= 0) throw new InvalidException("Scalar is zero or bigger than r");
            scalars.add(s_j);
            j += 1;
        }
        if(index != proof_octets.length) throw new InvalidException("Index length is not the same as the octet length");
        BigInteger[] msg_commitments = new BigInteger[j-3];
        if(j > 3){
            for (int i = 3; i < j; i++) {
                msg_commitments[i-3] = scalars.get(i);
            }
        }
        Object[] proof = new Object[6];
        System.arraycopy(proofPoints, 0, proof, 0, proofPoints.length);
        proof[2] = scalars.get(0);
        proof[3] = scalars.get(1);
        proof[4] = msg_commitments;
        proof[5] = scalars.get(scalars.size()-1);
        return proof;
    }

    public static byte[] ProofGen(byte[] publicKey, byte[] signature, byte[] header, byte[] ph, byte[][] messages, int[] disclosed_indexes) throws InvalidException {
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
            int tempI = i;
            if(IntStream.of(disclosed_indexes).anyMatch(x -> x == tempI)) continue;
            not_disclosed_indexes[counter] = i;
            counter++;
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
            undisclosedGenerators[i] = generators.getValue(undisclosedIndex+1);
        }
        BigInteger domain = calculate_domain(publicKey, Q1, MsgGenerators, header, api_id);
        G1Point B = P1.add(Q1.times(Scalar.of(domain)));
        for (int i = 1; i <= messageCount; i++) {
            BigInteger message = messages[i-1];
            B.add(generators.getValue(i).times(Scalar.of(message)));
        }
        G1Point Abar = signature.getFirst().times(Scalar.of(r1));
        G1Point Abare = Abar.times(signature.getSecond());
        G1Point Bbar = B.times(Scalar.of(r1)).subtract(Abare);
        G1Point BbarR3 = Bbar.times(Scalar.of(r3));
        G1Point T = Abar.times(Scalar.of(r2)).add(BbarR3);
        for (int i = 0; i < undisclosedGenerators.length; i++) {
            G1Point temp = undisclosedGenerators[i].times(Scalar.of(randomScalarsCut[i]));
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



    public static Signature generateSignature(Scalar sk, G2Point PK, String header, Vector<String> strMessages) {
        var messages = strMessages.map(Scalar::hashAndMap);
        // Definitions
        int L = messages.getLength();
        // Precomputations
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Procedure
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = Scalar.hashAndMap(domArray);
        var e_s = Scalar.hashAndMap(new Triple<>(sk, domain, messages), 2);
        var e = e_s.getValue(1);
        var s = e_s.getValue(2);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        var A = B.times(sk.add(e).inverse());
        return new Signature(A, e, s);
    }

    public static boolean verifySignature(G2Point PK, Signature signature, String header, Vector<String> strMessages) {
        var messages = strMessages.map(Scalar::hashAndMap);
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
        var domain = Scalar.hashAndMap(domArray);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        return A.pair(PK.add(G2Point.GENERATOR.times(e))).multiply(B.pair(P2.negate())).isOne();
    }

    // PRIVATE HELPER METHODS

    private static G1Point sumOfProducts(Vector<G1Point> bases, Vector<Scalar> exponents) {
        return bases.map(exponents, G1Point::times).toStream().reduce(G1Point.ZERO, G1Point::add);
    }

    // simplified version for testing
    static Vector<G1Point> createGenerators(int count) {
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
