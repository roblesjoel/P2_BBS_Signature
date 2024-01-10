package ch.bfh.p2bbs.utils;

import ch.bfh.p2bbs.Types.*;
import ch.openchvote.util.sequence.Vector;
import org.bouncycastle.crypto.digests.SHAKEDigest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

import static ch.bfh.p2bbs.utils.Definitions.*;

public class helper {

    // see: https://www.rfc-editor.org/rfc/rfc8017.html#section-4.1
    public static OctetString i2osp(Scalar i, int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Size of the octet string should be at least 1 but is " + size);
        }
        if (i == null || i.signum() == -1 || i.bitLength() > size * Byte.SIZE) {
            throw new IllegalArgumentException("Integer should be a positive number or 0, no larger than the given size");
        }
        byte[] signed = i.toByteArray();
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

    // see: https://www.rfc-editor.org/rfc/rfc8017.html#section-4.2
    public static Scalar os2ip(OctetString data) {
        return Scalar.of(new BigInteger(data.toBytes()).mod(r));
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-hash-to-scalar
    public static Scalar hash_to_scalar(OctetString msg_octets, OctetString dst){
        if(dst.length > 255) return Scalar.INVALID;
        var uniform_bytes = expand_message_xof(msg_octets, dst, Expand_Len);
        return os2ip(uniform_bytes).mod(r);
    }

    // see: https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xof
    public static OctetString expand_message_xof(OctetString msg, OctetString dst, int len_in_bytes) {
        if(len_in_bytes > 65535 || dst.length > 255) return OctetString.INVALID;
        OctetString serializedDstLength = i2osp(Scalar.of(BigInteger.valueOf(dst.length)),1);
        OctetString dstPrime = dst.concat(serializedDstLength);
        OctetString serializedLenInBytes = i2osp(Scalar.of(BigInteger.valueOf(len_in_bytes)), 2);
        OctetString msg_prime = msg.concat(serializedLenInBytes).concat(dstPrime);
        return shakeDigest(msg_prime, len_in_bytes);
    }

    private static OctetString shakeDigest(OctetString data, int returnLength){
        SHAKEDigest digest = new SHAKEDigest();
        byte[] hashBytes = new byte[Math.max(data.length, 32)];
        digest.update(data.toBytes(), 0, data.length);
        digest.doOutput(hashBytes, 0, hashBytes.length);
        digest.reset();
        return new OctetString(Arrays.copyOf(hashBytes, returnLength));
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-messages-to-scalars
    public static Vector<Scalar> messages_to_scalars(Vector<OctetString> messages, OctetString api_id){
        OctetString map_dst = api_id.concat(OctetString.valueOf("MAP_MSG_TO_SCALAR_AS_HASH_", StandardCharsets.US_ASCII));
        if(messages.getLength() > Math.pow(2,64) -1) return null;
        var builder = new Vector.Builder<Scalar>();
        for (int i = 1; i <= messages.getLength(); i++) {
            Scalar msg_scalar_i = hash_to_scalar(messages.getValue(i), map_dst);
            builder.addValue(msg_scalar_i);
        }
        return builder.build();
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-generators-calculation
    public static Vector<G1Point> create_generators(int count, OctetString api_id){
        OctetString seed_dst = api_id.concat("SIG_GENERATOR_SEED_", StandardCharsets.US_ASCII);
        OctetString generator_dst = api_id.concat("SIG_GENERATOR_DST_", StandardCharsets.US_ASCII);
        OctetString generator_seed = api_id.concat("MESSAGE_GENERATOR_SEED", StandardCharsets.US_ASCII);
        if(count > Math.pow(2, 64) -1) return null;
        OctetString v = expand_message_xof(generator_seed, seed_dst, Expand_Len);
        Vector.Builder<G1Point> builder = new Vector.Builder<>();
        for (int i = 1; i <= count; i++) {
            v = expand_message_xof(v.concat(i2osp(Scalar.of(BigInteger.valueOf(i)), 8)), seed_dst, Expand_Len);
            builder.addValue(G1Point.hash_to_curve_g1(v.toBytes()));
        }
        return builder.build();
    }

    public static Vector<G1Point> getHPoints(Vector<G1Point> generators){
        Vector.Builder<G1Point> builder = new Vector.Builder<>(generators.getLength()-1);
        for (int i = 2; i <= generators.getLength(); i++) {
            builder.addValue(generators.getValue(i));
        }
        return builder.build();
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-domain-calculation
    public static Scalar calculate_domain(OctetString publicKey, G1Point Q1, Vector<G1Point> H_Points, OctetString header, OctetString api_id){
        OctetString domain_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        int L = H_Points.getLength();
        if(header.length > Math.pow(2,64)-1 || L > Math.pow(2,64)-1) return null;
        Object[] dom_array = serializationPreparationForDomain(L, Q1, H_Points);
        OctetString dom_octs = serialize(dom_array);
        OctetString dom_input = publicKey.concat(dom_octs).concat(i2osp(Scalar.of(BigInteger.valueOf(header.length)), 8)).concat(header);
        return hash_to_scalar(dom_input, domain_dst);
    }

    private static Object[] serializationPreparationForDomain(int L, G1Point Q_1, Vector<G1Point> H_Points){
        Object[] dataToBeSerialized = new Object[2+H_Points.getLength()];
        dataToBeSerialized[0] = L;
        dataToBeSerialized[1] = Q_1;
        System.arraycopy(H_Points.toArray(),0, dataToBeSerialized, 2, H_Points.getLength());
        return dataToBeSerialized;
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-serialize
    public static OctetString serialize(Object[] input_array){
        OctetString octect_result = new OctetString();
        for (Object el : input_array) {
            switch (el.getClass().getName()) {
                case "ch.bfh.p2bbs.Types.G1Point" -> {
                    G1Point element = (G1Point) el;
                    octect_result = octect_result.concat(new OctetString(element.serialize()));
                }
                case "ch.bfh.p2bbs.Types.G2Point" -> {
                    G2Point element = (G2Point) el;
                    octect_result = octect_result.concat(new OctetString(element.serialize()));
                }
                case "ch.bfh.p2bbs.Types.Scalar" -> {
                    octect_result = octect_result.concat(i2osp((Scalar) el, Octet_Scalar_Length.toInt()));
                }
                case "java.lang.Integer" -> {
                    int element = (int) el;
                    if (element < 0 || element > Math.pow(2,64)-1) return OctetString.INVALID;
                    octect_result = octect_result.concat(i2osp(Scalar.of(BigInteger.valueOf(element)), 8));
                }
                default -> {return OctetString.INVALID;}
            }
        }
        return octect_result;
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-signature-to-octets
    public static OctetString signature_to_octets(Signature signature) {
        return serialize(new Object[]{signature.getPoint(), signature.getScalar()});
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-octets-to-signature
    public static Signature octets_to_signature(OctetString signature_octets) {
        int expected_len = Octet_Point_Length.toInt() + Octet_Scalar_Length.toInt();
        if(signature_octets.length != expected_len) return null;
        OctetString A_octets = signature_octets.split(0, Octet_Point_Length.toInt() -1);
        G1Point A = G1Point.deserialize(A_octets.toBytes());
        if(A == G1Point.ZERO) return null;
        int index = Octet_Point_Length.toInt();
        int end_index = index + Octet_Scalar_Length.toInt() - 1;
        Scalar e = os2ip(signature_octets.split(index, end_index));
        if(e.isZero() || e.compareTo(r) >= 0) return null;
        return new Signature(A, e);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-octets-to-proof
    public static Proof octets_to_proof(OctetString proof_octets) {
        int proof_len_floor = (2* Octet_Point_Length.toInt()) + (3*Octet_Scalar_Length.toInt());
        if(proof_octets.length < proof_len_floor) return null;
        G1Point[] proofPoints = new G1Point[2];
        int index = 0;
        for (int i = 0; i <= 1; i++) {
            int end_index = index + Octet_Point_Length.toInt() - 1;
            G1Point A_i = G1Point.deserialize(proof_octets.split(index, end_index).toBytes());
            if(A_i.isZero()) return null;
            proofPoints[i] = A_i;
            index += Octet_Point_Length.toInt();
        }
        ArrayList<Scalar> scalars = new ArrayList<>();
        int j = 0;
        while(index< proof_octets.length){
            int end_index = index + Octet_Scalar_Length.toInt() - 1;
            Scalar s_j = os2ip(proof_octets.split(index, end_index));
            if(s_j.equals(Scalar.of(BigInteger.ZERO)) || s_j.biggerOrSameThan(r)) return null;
            scalars.add(s_j);
            index += Octet_Scalar_Length.toInt();
            j += 1;
        }
        if(index != proof_octets.length) return null;
        Vector.Builder<Scalar> builder = new Vector.Builder<>(j-3);
        if(j > 3){
            for (int i = 3; i < j; i++) {
                builder.addValue(scalars.get(i));
            }
        }
        Vector<Scalar> msg_commitments = builder.build();
        return new Proof(proofPoints[0], proofPoints[1], scalars.get(0), scalars.get(1), msg_commitments, scalars.get(scalars.size()-1));
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-challenge-calculation
    public static Scalar ProofChallengeCalculate(InitRes init_res, Vector<Integer> i_array, Vector<Scalar> msg_array, OctetString ph, OctetString api_id) {
        OctetString challenge_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        int R = i_array.getLength();
        if(R > Math.pow(2,64)-1 || R != msg_array.getLength()) return null;
        if (ph.length > Math.pow(2,64)-1) return null;
        Object[] c_arr = createCArray(init_res, i_array, msg_array);
        OctetString c_octs = serialize(c_arr).concat(i2osp(Scalar.of(BigInteger.valueOf(ph.length)),8)).concat(ph);
        return hash_to_scalar(c_octs, challenge_dst);
    }

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
}
