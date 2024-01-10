package ch.bfh.p2bbs.proof;

import ch.bfh.p2bbs.Types.*;
import ch.openchvote.util.sequence.Vector;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.Definitions.*;
import static ch.bfh.p2bbs.utils.helper.*;

public class ProofGen {
    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-generation-proofgen
    public static OctetString ProofGen(OctetString publicKey, OctetString signature, OctetString header, OctetString ph, Vector<OctetString> messages, Vector<Integer> disclosed_indexes){
        OctetString api_id = CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        Vector<Scalar> message_scalars = messages_to_scalars(messages, api_id);
        Vector<G1Point> generators = create_generators(message_scalars.getLength()+1, api_id);
        OctetString proof = CoreProofGen(publicKey, signature, generators, header, ph, message_scalars, disclosed_indexes, api_id);
        return proof;
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coreproofgen
    private static OctetString CoreProofGen(OctetString publicKey, OctetString signature_octets, Vector<G1Point> generators, OctetString header, OctetString ph, Vector<Scalar> messages, Vector<Integer> disclosed_indexes, OctetString api_id) {
        Signature signature = octets_to_signature(signature_octets);
        int L = messages.getLength();
        int R = disclosed_indexes.getLength();
        if(R > L) return null;
        int U = L-R;
        Vector<Integer> undisclosed_indexes = splitIndexes(disclosed_indexes, L, U);
        Vector<Integer> ix = disclosed_indexes;
        Vector<Integer> jx = undisclosed_indexes;
        Vector<Scalar> disclosed_messages = getIndexedMessages(messages, ix);
        Vector<Scalar> undisclosed_messages = getIndexedMessages(messages, jx);
        Vector<Scalar> random_scalars = calculate_random_scalars(3+U);
        InitRes init_res = ProofInit(publicKey, signature, generators, random_scalars, header, messages, undisclosed_indexes, api_id);
        Scalar challenge = ProofChallengeCalculate(init_res, disclosed_indexes, disclosed_messages, ph, api_id);
        return ProofFinalize(init_res, challenge, signature.getScalar(), random_scalars, undisclosed_messages);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-initialization
    private static InitRes ProofInit(OctetString publicKey, Signature signature, Vector<G1Point> generators, Vector<Scalar> random_scalars, OctetString header, Vector<Scalar> messages, Vector<Integer> undisclosed_indexes, OctetString api_id) {
        int L = messages.getLength();
        int U = undisclosed_indexes.getLength();
        Vector<Integer> jx = undisclosed_indexes;
        if(random_scalars.getLength() != (U+3)) return null;
        Scalar r1 = random_scalars.getValue(1);
        Scalar r2 = random_scalars.getValue(2);
        Scalar r3 = random_scalars.getValue(3);
        Vector<Scalar> m_jx = splitScalarVector(random_scalars, 4);
        if (generators.getLength() != (L+1)) return null;
        G1Point Q1 = generators.getValue(1);
        Vector<G1Point> MsgGenerators = getHPoints(generators);
        Vector<G1Point> H_x = MsgGenerators;
        Vector<G1Point> H_jx = getIndexedGenerators(generators, jx);
        if(U>L) return null;
        Scalar domain = calculate_domain(publicKey, Q1, MsgGenerators, header, api_id);
        G1Point B = P1.add(Q1.times(domain)).add(G1Point.sumOfScalarMultiply(H_x, messages));
        G1Point Abar = signature.getPoint().times(r1);
        G1Point Bbar = B.times(r1).subtract(Abar.times(signature.getScalar()));
        G1Point T = Abar.times(r2).add(Bbar.times(r3)).add(G1Point.sumOfScalarMultiply(H_jx, m_jx));
        return new InitRes(Abar, Bbar, T, domain);
    }

    public static OctetString ProofFinalize(InitRes init_res, Scalar challenge, Scalar e_value, Vector<Scalar> random_scalars, Vector<Scalar> undisclosed_messages) {
        int U = undisclosed_messages.getLength();
        if(random_scalars.getLength() != (U+3)) return null;
        Scalar r1 = random_scalars.getValue(1);
        Scalar r2 = random_scalars.getValue(2);
        Scalar r3 = random_scalars.getValue(3);
        Vector<Scalar> m_x = splitScalarVector(random_scalars, 4);
        Vector<Scalar> undisclosed_x = undisclosed_messages;
        G1Point Abar = init_res.getAbar();
        G1Point Bbar = init_res.getBbar();
        Scalar r4 = r1.modInverse(r).negate();
        Scalar r2Calc = r2.add(e_value.multiply(r4).multiply(challenge)).mod(r);
        Scalar r3Calc = r3.add(r4.multiply(challenge)).mod(r);
        Vector.Builder<Scalar> builder = new Vector.Builder<>(U);
        for (int i = 1; i <= U; i++) {
            builder.addValue(m_x.getValue(i).add(undisclosed_x.getValue(i).multiply(challenge)).mod(r));
        }
        Vector<Scalar> m_j = builder.build();
        Proof proof = new Proof(Abar, Bbar, r2Calc, r3Calc, m_j, challenge);
        return proof_to_octets(proof);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-to-octets
    private static OctetString proof_to_octets(Proof proof) {
        return serialize(proof.toObjectArray());
    }
    
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

    private static Vector<Scalar> getIndexedMessages(Vector<Scalar> messages, Vector<Integer> indexes){
        Vector.Builder<Scalar> builder = new Vector.Builder<>(indexes.getLength());
        for (int disclosedIndex: indexes) {
            builder.addValue(messages.getValue(disclosedIndex));
        }
        return builder.build();
    }

    private static Vector<Scalar> calculate_random_scalars(int count){
        Vector.Builder<Scalar> builder = new Vector.Builder<>(count);
        for (int i = 0; i < count; i++) {
            builder.addValue(os2ip(randomBytes(Expand_Len)).mod(r));
        }
        return builder.build();
    }

    private static OctetString randomBytes(int n) {
        var randomBytes = new byte[n];
        SECURE_RANDOM.nextBytes(randomBytes);
        return new OctetString(randomBytes);
    }

    private static Vector<Scalar> splitScalarVector(Vector<Scalar> scalars, int start){
        Vector.Builder<Scalar> builder = new Vector.Builder<>(scalars.getLength()-start+1);
        for (int i = start; i <= scalars.getLength(); i++) {
            builder.addValue(scalars.getValue(i));
        }
        return builder.build();
    }

    private static Vector<G1Point> getIndexedGenerators(Vector<G1Point> generators, Vector<Integer> indexes){
        Vector.Builder<G1Point> builder = new Vector.Builder<>(generators.getLength()-1);
        for (int disclosedIndex: indexes) {
            builder.addValue(generators.getValue(disclosedIndex));
        }
        return builder.build();
    }
}
