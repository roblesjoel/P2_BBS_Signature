package ch.bfh.p2bbs.utils;

import ch.bfh.p2bbs.Types.*;
import ch.bfh.p2bbs.excptions.Abort;
import ch.openchvote.util.sequence.Vector;
import org.bouncycastle.crypto.digests.SHAKEDigest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

import static ch.bfh.hnr1.util.Hash.expandMessageXMD_SHA_256;
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
        return Scalar.of(new BigInteger(1, data.toBytes()).mod(r));
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-hash-to-scalar
    public static Scalar hash_to_scalar(OctetString msg_octets, OctetString dst){
        if(dst.length > 255) throw new Abort("Dst is to long");
        var test = expandMessageXMD_SHA_256(msg_octets.toBytes(), dst.toBytes(), Expand_Len);
        var uniform_bytes = new OctetString(expandMessageXMD_SHA_256(msg_octets.toBytes(), dst.toBytes(), Expand_Len));//expand_message_xof(msg_octets, dst, Expand_Len);
        return os2ip(uniform_bytes).mod(r);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-messages-to-scalars
    public static Vector<Scalar> messages_to_scalars(Vector<OctetString> messages, OctetString api_id){
        var map_dst = api_id.concat(OctetString.valueOf("MAP_MSG_TO_SCALAR_AS_HASH_", StandardCharsets.US_ASCII));
        if(messages.getLength() > Math.pow(2,64) -1) throw new Abort("To many messages");
        var builder = new Vector.Builder<Scalar>();
        for (int i = 1; i <= messages.getLength(); i++) {
            var msg_scalar_i = hash_to_scalar(messages.getValue(i), map_dst);
            builder.addValue(msg_scalar_i);
        }
        return builder.build();
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-generators-calculation
    public static Vector<G1Point> create_generators(int count, OctetString api_id){
        var seed_dst = api_id.concat("SIG_GENERATOR_SEED_", StandardCharsets.US_ASCII);
        var generator_dst = api_id.concat("SIG_GENERATOR_DST_", StandardCharsets.US_ASCII);
        var generator_seed = api_id.concat("MESSAGE_GENERATOR_SEED", StandardCharsets.US_ASCII);
        if(count > Math.pow(2, 64) -1) throw new Abort("To many generators to be generated");
        var v = new OctetString(expandMessageXMD_SHA_256(generator_seed.toBytes(), seed_dst.toBytes(), Expand_Len));
        var builder = new Vector.Builder<G1Point>();
        for (int i = 1; i <= count; i++) {
            v = new OctetString(expandMessageXMD_SHA_256(v.concat(i2osp(Scalar.of(BigInteger.valueOf(i)), 8)).toBytes(), seed_dst.toBytes(), Expand_Len));
            builder.addValue(G1Point.hash_to_curve_g1(v.toBytes(), generator_dst));
        }
        return builder.build();
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-domain-calculation
    public static Scalar calculate_domain(OctetString publicKey, G1Point Q1, Vector<G1Point> H_Points, OctetString header, OctetString api_id){
        var domain_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        var L = H_Points.getLength();
        if(header.length > Math.pow(2,64)-1 || L > Math.pow(2,64)-1) throw new Abort("Header is to long or there are to many generators");
        var dom_array = serializationPreparationForDomain(L, Q1, H_Points);
        var dom_octs = serialize(dom_array).concat(api_id);
        var dom_input = publicKey.concat(dom_octs).concat(i2osp(Scalar.of(BigInteger.valueOf(header.length)), 8)).concat(header);
        return hash_to_scalar(dom_input, domain_dst);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-serialize
    public static OctetString serialize(Object[] input_array){
        var octect_result = new OctetString();
        for (Object el : input_array) {
            switch (el) {
                case G1Point element-> octect_result = octect_result.concat(new OctetString(element.serialize()));
                case G2Point element -> octect_result = octect_result.concat(new OctetString(element.serialize()));
                case Scalar element -> octect_result = octect_result.concat(i2osp(element, Octet_Scalar_Length.toInt()));
                case Integer element -> {
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
        var expected_len = Octet_Point_Length.toInt() + Octet_Scalar_Length.toInt();
        if(signature_octets.length != expected_len) return Signature.INVALID;
        var A_octets = signature_octets.split(0, Octet_Point_Length.toInt() -1);
        var A = G1Point.deserialize(A_octets.toBytes());
        if(A.equals(G1Point.ZERO)) return Signature.INVALID;
        // TODO: add subgroup check
        var index = Octet_Point_Length.toInt();
        var end_index = index + Octet_Scalar_Length.toInt() - 1;
        var e = os2ip(signature_octets.split(index, end_index));
        if(e.isZero() || e.compareTo(r) >= 0) return Signature.INVALID;
        return new Signature(A, e);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-octets-to-proof
    public static Proof octets_to_proof(OctetString proof_octets) {
        var proof_len_floor = (3* Octet_Point_Length.toInt()) + (4*Octet_Scalar_Length.toInt());
        if(proof_octets.length < proof_len_floor) return Proof.INVALID;
        var proofPoints = new G1Point[3];
        var index = 0;
        for (int i = 0; i <= 2; i++) {
            var end_index = index + Octet_Point_Length.toInt() - 1;
            var A_i = G1Point.deserialize(proof_octets.split(index, end_index).toBytes());
            if(A_i.isZero()) return Proof.INVALID;
            // TODO: subgroup check
            proofPoints[i] = A_i;
            index += Octet_Point_Length.toInt();
        }
        var scalars = new ArrayList<Scalar>();
        var j = 0;
        while(index < proof_octets.length){
            var end_index = index + Octet_Scalar_Length.toInt() - 1;
            var s_j = os2ip(proof_octets.split(index, end_index));
            if(s_j.equals(Scalar.of(BigInteger.ZERO)) || s_j.biggerOrSameThan(r)) return Proof.INVALID;
            scalars.add(s_j);
            index += Octet_Scalar_Length.toInt();
            j += 1;
        }
        if(index != proof_octets.length) return Proof.INVALID;
        var builder = new Vector.Builder<Scalar>(j-4);
        if(j > 4){
            for (int i = 3; i < j-1; i++) {
                builder.addValue(scalars.get(i));
            }
        }
        var msg_commitments = builder.build();
        return new Proof(proofPoints[0], proofPoints[1], proofPoints[2], scalars.get(0), scalars.get(1), scalars.get(2), msg_commitments, scalars.get(scalars.size()-1));
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-challenge-calculation
    public static Scalar ProofChallengeCalculate(InitRes init_res, Vector<Scalar> disclosed_messages, Vector<Integer> disclosed_indexes, OctetString ph, OctetString api_id) {
        var challenge_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        var R = disclosed_indexes.getLength();
        if(disclosed_messages.getLength() != R) return Scalar.INVALID;
        if(R > Math.pow(2,64)-1 || ph.length > Math.pow(2,64)-1) throw new Abort("To many disclosed indexes or the ph is to long");
        var c_arr = createCArray(init_res, disclosed_indexes, disclosed_messages);
        var c_octs = serialize(c_arr).concat(i2osp(Scalar.of(BigInteger.valueOf(ph.length)),8)).concat(ph);
        if(ph.length == 0) c_octs.concat(new OctetString(new byte[8])); // See note in draft
        return hash_to_scalar(c_octs, challenge_dst);
    }

    public static Vector<G1Point> getHPoints(Vector<G1Point> generators){
        Vector.Builder<G1Point> builder = new Vector.Builder<>(generators.getLength()-1);
        for (int i = 2; i <= generators.getLength(); i++) {
            builder.addValue(generators.getValue(i));
        }
        return builder.build();
    }

    private static Object[] serializationPreparationForDomain(int L, G1Point Q_1, Vector<G1Point> H_Points){
        Object[] dataToBeSerialized = new Object[2+H_Points.getLength()];
        dataToBeSerialized[0] = L;
        dataToBeSerialized[1] = Q_1;
        System.arraycopy(H_Points.toArray(),0, dataToBeSerialized, 2, H_Points.getLength());
        return dataToBeSerialized;
    }

    private static Object[] createCArray(InitRes init_res, Vector<Integer> disclosed_indexes, Vector<Scalar> disclosed_messages){
        Object[] c_arr = new Object[7 + disclosed_indexes.getLength() + disclosed_messages.getLength()];
        c_arr[0] = init_res.getAbar();
        c_arr[1] = init_res.getBbar();
        c_arr[2] = init_res.getD();
        c_arr[3] = init_res.getT1();
        c_arr[4] = init_res.getT2();
        c_arr[5] = disclosed_indexes.getLength();
        for (int i = 1; i <= disclosed_indexes.getLength() ; i++) {
            c_arr[i+5] = disclosed_indexes.getValue(i)-1;
        }
        for (int i = 1; i <= disclosed_messages.getLength() ; i++) {
            c_arr[i+disclosed_indexes.getLength()+5] = disclosed_messages.getValue(i);
        }
        c_arr[c_arr.length-1] = init_res.getDomain();
        return c_arr;
    }

    /**Out of service for the moment**/
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

    public static Vector<Scalar> mockedRandomScalars(OctetString SEED, OctetString dst, int count){
        if(count * Expand_Len > 65535) throw new Abort("To many scalars to be mocked");
        var out_len = Expand_Len * count;
        var v = new OctetString(expandMessageXMD_SHA_256(SEED.toBytes(), dst.toBytes(), out_len));
        var r_i = new Vector.Builder<Scalar>();
        for (int i = 1; i <= count; i++) {
            var start_idx = (i-1)* Expand_Len;
            var end_idx = (i * Expand_Len) - 1;
            r_i.addValue(os2ip(v.split(start_idx, end_idx)).mod(r));
        }
        return r_i.build();
    }
}
