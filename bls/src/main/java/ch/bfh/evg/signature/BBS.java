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
import ch.bfh.evg.proof.InitRes;
import ch.bfh.evg.proof.Proof;
import ch.openchvote.util.sequence.ByteArray;
import ch.openchvote.util.sequence.Vector;

import java.lang.reflect.Array;
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
    public static final OctetString CIPHERSUITE_ID = OctetString.valueOf("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_", StandardCharsets.US_ASCII); // Ciphersuite ID,BLS12-381-SHAKE-256
    private static final G1Point P1 = G1Point.GENERATOR; // Generator point in G1
    private static final G2Point P2 = G2Point.GENERATOR; // Generator point in G2
    private static final SecureRandom SECURE_RANDOM = new SecureRandom(); // Random generator method
    private static final OctetString Octet_Scalar_Length = OctetString.valueOf(32);
    private static final OctetString Octet_Point_Length = OctetString.valueOf(48);
    private static final int Expand_Len = 48;
    private static final BigInteger r = new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

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
            OctetString signature = CoreSign(secretKey, publicKey, generators, header, message_scalars, G1Point.GENERATOR, api_id);
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
        G2Point W = G2Point.deserialize(ByteArray.of(publicKey.toBytes()));
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
            builder.addValue(generators.getValue(i));
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
        OctetString A_octets = signature_octets.split(0, Octet_Point_Length.toInt() -1);
        G1Point A = G1Point.deserialize(ByteArray.of(A_octets.toBytes()));
        if(A == G1Point.ZERO) throw new InvalidException("Error while deserializing. Point in Signature is the identity point");
        int index = Octet_Point_Length.toInt();
        int end_index = index + Octet_Scalar_Length.toInt() - 1;
        Scalar e = os2ip(signature_octets.split(index, end_index));
        if(e.isZero() || e.toBigInteger().compareTo(r) >= 0) throw new InvalidException("Scalar e is either 0 or to big");
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
        G1Point B = G1Point.GENERATOR.add(Q1.times(domain).add(G1Point.sumOfScalarMultiply(H_x, messages)));
        var A = B.times(Scalar.of(secretKey.add(e).toBigInteger().modInverse(r)));
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
                    octect_result = octect_result.concat(new OctetString(element.serialize().toByteArray()));
                }
                case "ch.bfh.evg.bls12_381.G2Point" -> {
                    G2Point element = (G2Point) el;
                    octect_result = octect_result.concat(new OctetString(element.serialize().toByteArray()));
                }
                case "ch.bfh.evg.bls12_381.Scalar" -> {
                    octect_result = octect_result.concat(i2osp((Scalar) el, Octet_Scalar_Length.toInt()));
                }
                case "java.lang.Integer" -> {
                    int element = (int) el;
                    if (element < 0 || element > Math.pow(2,64)-1) throw new InvalidException("Int number is to big");
                    octect_result = octect_result.concat(i2osp(Scalar.of(BigInteger.valueOf(element)), 8));
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
    public static Vector<Scalar> messages_to_scalars(Vector<OctetString> messages, OctetString api_id) throws AbortException{
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
        G2Point W = G2Point.GENERATOR.times(secretKey);
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
            if(key_dst.length == 0) key_dst = CIPHERSUITE_ID.concat("KEYGEN_DST_", StandardCharsets.US_ASCII);
            if(key_material.length < 32) throw new InvalidException("key_material is to short");
            if(key_info.length > 65535) throw new InvalidException("key_info is to long");
            OctetString derive_input = key_material.concat(i2osp(Scalar.of(BigInteger.valueOf(key_info.length)), 2)).concat(key_info);
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
    public static OctetString i2osp(Scalar i, int size) {
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
    public static Scalar os2ip(OctetString data) {
        return Scalar.of(new BigInteger(data.toBytes()).mod(r));
    }

    /**
     * Hash message to scalar
     * @param msg_octets The messages to be hashed
     * @param dst The domain separation tag
     * @return The hashed message as a scalar
     * @throws AbortException Throws an exception id the dst is too long
     */
    public static Scalar hash_to_scalar(OctetString msg_octets, OctetString dst) throws AbortException{
        if(dst.length > 255) throw new AbortException("dst is to long");
        var uniform_bytes = expand_message_xof(msg_octets, dst, Expand_Len);
        return Scalar.of(os2ip(uniform_bytes).toBigInteger().mod(r));
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
        SHAKEDigest digest = new SHAKEDigest();
        byte[] hashBytes = new byte[Math.max(data.length, 32)];
        digest.update(data.toBytes(), 0, data.length);
        digest.doOutput(hashBytes, 0, hashBytes.length);
        digest.reset();
        return new OctetString(Arrays.copyOf(hashBytes, returnLength));
    }

    /**
     * Proof
     */

    /**
     * Verify the Proof
     * @param publicKey The public key as an octet string
     * @param proof The proof as an octet string
     * @param header The application header as an octet string
     * @param ph The presentation header as an octet string
     * @param disclosed_messages A Vector of octet strings of the disclosed messages
     * @param disclosed_indexes A Vector of integers of the indexes of thr disclosed messages
     * @return Returns true if the proof is valid
     * @throws InvalidException Throws an Invalid Exception if some went wrong while verifying the proof
     */
    public static boolean ProofVerify(OctetString publicKey, OctetString proof, OctetString header, OctetString ph, Vector<OctetString> disclosed_messages, Vector<Integer> disclosed_indexes) throws InvalidException {
        try{
            OctetString api_id =  CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
            int proof_len_floor = (2 * Octet_Point_Length.toInt()) + (3 * Octet_Scalar_Length.toInt());
            if(proof.length < proof_len_floor) throw new InvalidException("Proof is to short");
            int U = (int) Math.floor((proof.length-proof_len_floor)/Octet_Scalar_Length.toInt());
            int R = disclosed_indexes.getLength();
            Vector<Scalar> messageScalars = messages_to_scalars(disclosed_messages, api_id);
            Vector<G1Point> generators = createGenerators(U+R+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            boolean result = CoreProofVerify(publicKey, proof, generators, header, ph, messageScalars, disclosed_indexes, api_id);
            return result;
        }catch (Exception e){
            System.out.println(e);
            throw new InvalidException("Proof is not valid");
        }
    }

    /**
     * The core proof verify function
     * @param publicKey The public key as an octet string
     * @param proof_octets The proof as an octet string
     * @param generators The generators as a vector
     * @param header The application header as an octet string
     * @param ph The presentation header as an octet string
     * @param disclosed_messages A Vector of scalars of the disclosed messages
     * @param disclosed_indexes A Vector of integers of the indexes of thr disclosed messages
     * @param api_id The api id as an Octet string
     * @return Returns true if the proof is valid
     * @throws InvalidException Throws this exception if the given values are incorrect
     * @throws GroupElement.DeserializationException Throws this exception if a group element could not be deserilized
     * @throws AbortException Throws this exception if there was an error while verifying
     */
    private static boolean CoreProofVerify(OctetString publicKey, OctetString proof_octets, Vector<G1Point> generators, OctetString header, OctetString ph, Vector<Scalar> disclosed_messages, Vector<Integer> disclosed_indexes, OctetString api_id) throws InvalidException, GroupElement.DeserializationException, AbortException {
        Proof proof_result = octets_to_proof(proof_octets);
        G1Point Abar = proof_result.getA_0();
        G1Point Bbar = proof_result.getA_1();
        Scalar cp = proof_result.getS_j_1();
        G2Point W = G2Point.deserialize(ByteArray.of(publicKey.toBytes()));
        InitRes init_res = ProofVerifyInit(publicKey, proof_result, generators, header, disclosed_messages, disclosed_indexes, api_id);
        Scalar challenge = ProofChallengeCalculate(init_res, disclosed_indexes, disclosed_messages, ph, api_id);
        if(!cp.equals(challenge)) throw new InvalidException("Cp and challenge do not match");
        GTElement Apairing = Abar.pair(W);
        GTElement Bpairing = Bbar.pair(G2Point.GENERATOR.negate());
        GTElement multiplicatedElement = Apairing.multiply(Bpairing);
        if(!multiplicatedElement.equals(GTElement.ONE)) throw new InvalidException("Pairing is not correct");
        return true;
    }

    /**
     * The proof verification init method
     * @param PK The public key
     * @param proof The proof object
     * @param generators The generators
     * @param header The application header as an octet string
     * @param disclosed_messages A Vector of scalars of the disclosed messages
     * @param disclosed_indexes A Vector of integers of the indexes of thr disclosed messages
     * @param api_id The api id as an Octet string
     * @return Returns a InitRes object
     * @throws InvalidException Throws this exception if the given values are incorrect
     * @throws AbortException Throws this exception if the InitRes could not be calculated
     */
    private static InitRes ProofVerifyInit(OctetString PK, Proof proof, Vector<G1Point> generators, OctetString header, Vector<Scalar> disclosed_messages, Vector<Integer> disclosed_indexes, OctetString api_id) throws InvalidException, AbortException {
        G1Point Abar = proof.getA_0();
        G1Point Bbar = proof.getA_1();
        Scalar r2Calc = proof.getS_0();
        Scalar r3Calc = proof.getS_1();
        Vector<Scalar> commitments = proof.getMsg_commitments();
        Scalar cp = proof.getS_j_1();
        int U = commitments.getLength();
        int R = disclosed_indexes.getLength();
        int L = U + R;
        Vector<Integer> ix = disclosed_indexes;
        Vector<Integer> jx = splitIndexes(disclosed_indexes, L, U);
        if(generators.getLength() != L+1) throw new InvalidException("To many or to few generators");
        G1Point Q_1 = generators.getValue(1);
        Vector<G1Point> H_x = getHPoints(generators);
        Vector<G1Point> H_ix = getIndexedGenerators(generators, ix);
        Vector<G1Point> H_Jx = getIndexedGenerators(generators, jx);
        Scalar domain = calculate_domain(PK, Q_1, H_x, header, api_id);
        G1Point D = P1.add(Q_1.times(domain)).add(G1Point.sumOfScalarMultiply(H_ix, disclosed_messages));
        G1Point T = Abar.times(r2Calc).add(Bbar.times(r3Calc)).add(G1Point.sumOfScalarMultiply(H_Jx, commitments));
        T = T.add(D.times(cp));
        return new InitRes(Abar, Bbar, T, domain);
    }

    /**
     * Get generators from a generator vector at the given indexes
     * @param generators The generator vector
     * @param indexes The indexes of the wanted generators
     * @return A new generator vector
     */
    private static Vector<G1Point> getIndexedGenerators(Vector<G1Point> generators, Vector<Integer> indexes){
        Vector.Builder<G1Point> builder = new Vector.Builder<>(generators.getLength()-1);
        for (int disclosedIndex: indexes) {
            builder.addValue(generators.getValue(disclosedIndex));
        }
        return builder.build();
    }

    /**
     * Get the undisclosed indexes given the disclosed indexes
     * @param disclosed_indexes The disclosed indexes
     * @param L How many total indexes there are
     * @param U Count of undisclosed indexes
     * @return A Vector of the undisclosed indexes
     */
    private static Vector<Integer> splitIndexes(Vector<Integer> disclosed_indexes, int L, int U){
        Vector.Builder<Integer> builder = new Vector.Builder<>(U);
        for (int i = 1; i <= L; i++) {
            boolean found = false;
            for (int j = 1; j <= disclosed_indexes.getLength() ; j++) {
                if(disclosed_indexes.getValue(j) == i) {
                    found = true;
                    break;
                }
            }
            if(!found) builder.addValue(i);
        }
        return builder.build();
    }

    /**
     * Returns the Proof from the given octets
     * @param proof_octets The proof octets
     * @return The Proof object
     * @throws GroupElement.DeserializationException Throws this error when a point could not be deserialized
     * @throws InvalidException Throw this error if an input is not correct
     */
    private static Proof octets_to_proof(OctetString proof_octets) throws GroupElement.DeserializationException, InvalidException {
        int proof_len_floor = (2* Octet_Point_Length.toInt()) + (3*Octet_Scalar_Length.toInt());
        if(proof_octets.length < proof_len_floor) throw new InvalidException("To few proof octets");
        G1Point[] proofPoints = new G1Point[2];
        int index = 0;
        for (int i = 0; i <= 1; i++) {
            int end_index = index + Octet_Point_Length.toInt() - 1;
            G1Point A_i = G1Point.deserialize(ByteArray.of(proof_octets.split(index, end_index).toBytes()));
            if(A_i.isZero()) throw new InvalidException("A_i is identity");
            proofPoints[i] = A_i;
            index += Octet_Point_Length.toInt();
        }
        ArrayList<Scalar> scalars = new ArrayList<>();
        int j = 0;
        while(index< proof_octets.length){
            int end_index = index + Octet_Scalar_Length.toInt() - 1;
            Scalar s_j = os2ip(proof_octets.split(index, end_index));
            if(s_j.equals(Scalar.of(BigInteger.ZERO)) || s_j.biggerOrSameThan(r)) throw new InvalidException("Scalar is zero or bigger than r");
            scalars.add(s_j);
            index += Octet_Scalar_Length.toInt();
            j += 1;
        }
        if(index != proof_octets.length) throw new InvalidException("Index length is not the same as the octet length");
        Vector.Builder<Scalar> builder = new Vector.Builder<>(j-3);
        if(j > 3){
            for (int i = 3; i < j; i++) {
                builder.addValue(scalars.get(i));
            }
        }
        Vector<Scalar> msg_commitments = builder.build();
        return new Proof(proofPoints[0], proofPoints[1], scalars.get(0), scalars.get(1), msg_commitments, scalars.get(scalars.size()-1));
    }

    /**
     * The Proof generation function
     * @param publicKey The public key an Octet string
     * @param signature The signature as an octet string
     * @param header The application header as an octet string
     * @param ph The presentation header as an octet string
     * @param messages A vector of all messages
     * @param disclosed_indexes The indexes to be disclosed
     * @return The proof as an octet string
     * @throws InvalidException Throws this exception if the generated proof is invalid
     */
    public static OctetString ProofGen(OctetString publicKey, OctetString signature, OctetString header, OctetString ph, Vector<OctetString> messages, Vector<Integer> disclosed_indexes) throws InvalidException {
        try{
            OctetString api_id = CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
            Vector<Scalar> message_scalars = messages_to_scalars(messages, api_id);
            Vector<G1Point> generators = createGenerators(message_scalars.getLength()+1);//create_generators(message_scalars.lenght()+1, publicKey, api_id);
            OctetString proof = CoreProofGen(publicKey, signature, generators, header, ph, message_scalars, disclosed_indexes, api_id);
            return proof;
        }catch (Exception e) {
            System.out.println(e);
            throw new InvalidException("Proof is invalid");
        }
    }

    /**
     * The core proof generation method
     * @param publicKey The public key as octets
     * @param signature_octets The signature as octets
     * @param generators A Vector of generators
     * @param header The application header as an octet string
     * @param ph The presentation header as an octet string
     * @param messages A vector of all messages
     * @param disclosed_indexes The indexes to be disclosed
     * @param api_id The api_id
     * @return Returns the proof as an Octet string
     * @throws InvalidException Throws this exception if the input is invalid
     * @throws GroupElement.DeserializationException Throws this error if a point cannot be serialized
     * @throws AbortException Throws this exception if there is an error while generating the proof
     */
    private static OctetString CoreProofGen(OctetString publicKey, OctetString signature_octets, Vector<G1Point> generators, OctetString header, OctetString ph, Vector<Scalar> messages, Vector<Integer> disclosed_indexes, OctetString api_id) throws InvalidException, GroupElement.DeserializationException, AbortException {
        Signature signature = octets_to_signature(signature_octets);
        int L = messages.getLength();
        int R = disclosed_indexes.getLength();
        if(R > L) throw new InvalidException("More disclosed indexes than messages");
        int U = L-R;
        Vector<Integer> undisclosed_indexes = splitIndexes(disclosed_indexes, L, U);
        Vector<Integer> ix = disclosed_indexes;
        Vector<Integer> jx = undisclosed_indexes;
        Vector<Scalar> disclosed_messages = getIndexedMessages(messages, ix);
        Vector<Scalar> undisclosed_messages = getIndexedMessages(messages, jx);
        Vector<Scalar> random_scalars = calculate_random_scalars(3+U);
        InitRes init_res = ProofInit(publicKey, signature, generators, random_scalars, header, messages, undisclosed_indexes, api_id);
        Scalar challenge = ProofChallengeCalculate(init_res, disclosed_indexes, disclosed_messages, ph, api_id);
        OctetString proof = ProofFinalize(init_res, challenge, signature.getScalar(), random_scalars, undisclosed_messages);
        return proof;
    }

    /**
     * Get messages from a messages vector at the given indexes
     * @param messages The vector of messages
     * @param indexes The indexes of the wanted messages
     * @return A new messages vector
     */
    private static Vector<Scalar> getIndexedMessages(Vector<Scalar> messages, Vector<Integer> indexes){
        Vector.Builder<Scalar> builder = new Vector.Builder<>(indexes.getLength());
        for (int disclosedIndex: indexes) {
            builder.addValue(messages.getValue(disclosedIndex));
        }
        return builder.build();
    }

    /**
     * Finalize the proof
     * @param init_res The response of the ProofInit function
     * @param challenge The challange scalar
     * @param e_value The e value of the signature (scalar)
     * @param random_scalars Random scalars
     * @param undisclosed_messages The undisclosed messages
     * @return The proof as an octet string
     * @throws InvalidException Throws this exception if the inputs are wrong
     */
    public static OctetString ProofFinalize(InitRes init_res, Scalar challenge, Scalar e_value, Vector<Scalar> random_scalars, Vector<Scalar> undisclosed_messages) throws InvalidException {
        int U = undisclosed_messages.getLength();
        if(random_scalars.getLength() != (U+3)) throw new InvalidException("There to many or to few random scalars");
        Scalar r1 = random_scalars.getValue(1);
        Scalar r2 = random_scalars.getValue(2);
        Scalar r3 = random_scalars.getValue(3);
        Vector<Scalar> m_x = splitScalarVector(random_scalars, 4);
        Vector<Scalar> undisclosed_x = undisclosed_messages;
        G1Point Abar = init_res.getAbar();
        G1Point Bbar = init_res.getBbar();
        Scalar r4 = Scalar.of(r1.toBigInteger().modInverse(r).negate());
        Scalar r2Calc = Scalar.of(r2.add(e_value.multiply(r4).multiply(challenge)).toBigInteger().mod(r));
        Scalar r3Calc = Scalar.of(r3.add(r4.multiply(challenge)).toBigInteger().mod(r));
        Vector.Builder<Scalar> builder = new Vector.Builder<>(U);
        for (int i = 1; i <= U; i++) {
            builder.addValue(Scalar.of(m_x.getValue(i).add(undisclosed_x.getValue(i).multiply(challenge)).toBigInteger().mod(r)));
        }
        Vector<Scalar> m_j = builder.build();
        Proof proof = new Proof(Abar, Bbar, r2Calc, r3Calc, m_j, challenge);
        return proof_to_octets(proof);
    }

    /**
     * Split a Scalar Vector
     * @param scalars The scalar vector
     * @param start Where to split
     * @return A new Scalar vector starting at the given start position
     */
    private static Vector<Scalar> splitScalarVector(Vector<Scalar> scalars, int start){
        Vector.Builder<Scalar> builder = new Vector.Builder<>(scalars.getLength()-start+1);
        for (int i = start; i <= scalars.getLength(); i++) {
            builder.addValue(scalars.getValue(i));
        }
        return builder.build();
    }

    /**
     * Serialize the proof to octets
     * @param proof The proof Object
     * @return The serialized proof
     * @throws InvalidException Throws this error if there is a problem while serializing
     */
    private static OctetString proof_to_octets(Proof proof) throws InvalidException {
        return serialize(proof.toObjectArray());
    }

    /**
     * Calculate the challenge of the proof
     * @param init_res The ProofInit response
     * @param i_array The indexes of the disclosed messages
     * @param msg_array The vector of the disclosed message scalars
     * @param ph The presentation header as an octet string
     * @param api_id The api id octets
     * @return The challenge as a scalar
     * @throws AbortException Throws this exception if the challenge calculation failed
     * @throws InvalidException Throws this exception if the inputs are invalid
     */
    public static Scalar ProofChallengeCalculate(InitRes init_res, Vector<Integer> i_array, Vector<Scalar> msg_array, OctetString ph, OctetString api_id) throws AbortException, InvalidException {
        OctetString challenge_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        int R = i_array.getLength();
        if(R > Math.pow(2,64)-1 || R != msg_array.getLength()) throw new AbortException("To many or to few message indexes");
        if (ph.length > Math.pow(2,64)-1) throw new AbortException("Ph is to long");
        Object[] c_arr = createCArray(init_res, i_array, msg_array);
        OctetString c_octs = serialize(c_arr).concat(i2osp(Scalar.of(BigInteger.valueOf(ph.length)),8)).concat(ph);
        return hash_to_scalar(c_octs, challenge_dst);
    }

    /**
     * Calculates the c_arr used in ProofChallengeCalculate
     * @param init_res The ProofInit response
     * @param i_array The indexes of the disclosed messages
     * @param msg_array The vector of the message scalars
     * @return The c_arr
     */
    private static Object[] createCArray(InitRes init_res, Vector<Integer> i_array, Vector<Scalar> msg_array){
        Object[] c_arr = new Object[4 + i_array.getLength() + msg_array.getLength()];
        c_arr[0] = init_res.getAbar();
        c_arr[1] = init_res.getBbar();
        c_arr[2] = init_res.getT();
        c_arr[3] = i_array.getLength();
        for (int i = 1; i <= i_array.getLength() ; i++) {
            c_arr[i+3] = i_array.getValue(i);
        }
        for (int i = +1; i <= msg_array.getLength() ; i++) {
            c_arr[i+i_array.getLength()+3] = msg_array.getValue(i);
        }
        c_arr[c_arr.length-1] = init_res.getFourth();
        return c_arr;
    }

    /**
     * Generates random scalars
     * @param count How many scalars to generate
     * @return A Vector of the generated Scalars
     */
    public static Vector<Scalar> calculate_random_scalars(int count){
        Vector.Builder<Scalar> builder = new Vector.Builder<>(count);
        for (int i = 0; i < count; i++) {
            builder.addValue(Scalar.of(os2ip(randomBytes(Expand_Len)).toBigInteger().mod(r)));
        }
        return builder.build();
    }

    /**
     * Create a number of random generators
     * @param count How many generators to create
     * @return T Vector of the generated generators
     */
    public static Vector<G1Point> createGenerators(int count) {
        var builder = new Vector.Builder<G1Point>();
        IntStream.rangeClosed(1, count)
                .mapToObj(i -> "Generator-" + i)
                .map(G1Point::hashAndMap)
                .forEach(builder::addValue);
        return builder.build();
    }

    /**
     * Generates random bytes
     * @param n How many bytes to generate
     * @return The Octet string of the random bytes
     */
    private static OctetString randomBytes(int n) {
        var randomBytes = new byte[n];
        SECURE_RANDOM.nextBytes(randomBytes);
        return new OctetString(randomBytes);
    }

    /**
     *
     * @param publicKey
     * @param signature
     * @param generators
     * @param random_scalars
     * @param header
     * @param messages
     * @param undisclosed_indexes
     * @param api_id
     * @return
     * @throws InvalidException
     * @throws AbortException
     */
    private static InitRes ProofInit(OctetString publicKey, Signature signature, Vector<G1Point> generators, Vector<Scalar> random_scalars, OctetString header, Vector<Scalar> messages, Vector<Integer> undisclosed_indexes, OctetString api_id) throws InvalidException, AbortException {
        int L = messages.getLength();
        int U = undisclosed_indexes.getLength();
        Vector<Integer> jx = undisclosed_indexes;
        if(random_scalars.getLength() != (U+3)) throw new InvalidException("The number of Random Scalars needs to be the same as the number of undisclosed indexes + 3");
        Scalar r1 = random_scalars.getValue(1);
        Scalar r2 = random_scalars.getValue(2);
        Scalar r3 = random_scalars.getValue(3);
        Vector<Scalar> m_jx = splitScalarVector(random_scalars, 4);
        if (generators.getLength() != (L+1)) throw new InvalidException("The number of generators is not the same as the number of messages + 1");
        G1Point Q1 = generators.getValue(1);
        Vector<G1Point> MsgGenerators = getHPoints(generators);
        Vector<G1Point> H_x = MsgGenerators;
        Vector<G1Point> H_jx = getIndexedGenerators(generators, jx);
        if(U>L) throw new AbortException("More undisclosed indexes than messages");
        Scalar domain = calculate_domain(publicKey, Q1, MsgGenerators, header, api_id);
        G1Point B = P1.add(Q1.times(domain)).add(G1Point.sumOfScalarMultiply(H_x, messages));
        G1Point Abar = signature.getPoint().times(r1);
        G1Point Bbar = B.times(r1).subtract(Abar.times(signature.getScalar()));
        G1Point T = Abar.times(r2).add(Bbar.times(r3)).add(G1Point.sumOfScalarMultiply(H_jx, m_jx));
        return new InitRes(Abar, Bbar, T, domain);
    }
}