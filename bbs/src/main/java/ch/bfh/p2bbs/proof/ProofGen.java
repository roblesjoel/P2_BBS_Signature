package ch.bfh.p2bbs.proof;

import ch.bfh.p2bbs.Types.*;
import ch.bfh.p2bbs.excptions.Abort;
import ch.openchvote.util.sequence.Vector;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.Definitions.*;
import static ch.bfh.p2bbs.utils.helper.*;

public class ProofGen {
    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-generation-proofgen
    public static OctetString ProofGen(OctetString publicKey, OctetString signature, OctetString header, OctetString ph, Vector<OctetString> messages, Vector<Integer> disclosed_indexes){
        var api_id = CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        var message_scalars = messages_to_scalars(messages, api_id);
        var generators = create_generators(message_scalars.getLength()+1, api_id);
        return CoreProofGen(publicKey, signature, generators, header, ph, message_scalars, disclosed_indexes, api_id);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coreproofgen
    private static OctetString CoreProofGen(OctetString publicKey, OctetString signature_octets, Vector<G1Point> generators, OctetString header, OctetString ph, Vector<Scalar> messages, Vector<Integer> disclosed_indexes, OctetString api_id) {
        var signature_result = octets_to_signature(signature_octets);
        if(signature_result.isInvalid()) return OctetString.INVALID;
        var L = messages.getLength();
        var R = disclosed_indexes.getLength();
        if(R > L) return OctetString.INVALID;
        var U = L-R;
        for (var el: disclosed_indexes) {
            //if(el < 0 || el > (L-1)) return OctetString.INVALID;
            // change reason, vector starts with 1 and not 0
            if(el < 1 || el > (L)) return OctetString.INVALID;
        }
        var undisclosed_indexes = splitIndexes(disclosed_indexes, L, U);
        var ix = disclosed_indexes;
        var jx = undisclosed_indexes;
        var disclosed_messages = getIndexedMessages(messages, ix);
        var undisclosed_messages = getIndexedMessages(messages, jx);
        var random_scalars = calculate_random_scalars(5+U);
        var init_res = ProofInit(publicKey, signature_result, generators, random_scalars, header, messages, undisclosed_indexes, api_id);
        if(init_res.isInvalid()) return OctetString.INVALID;
        var challenge = ProofChallengeCalculate(init_res, disclosed_messages, disclosed_indexes, ph, api_id);
        if(challenge.isInvalid()) return OctetString.INVALID;
        return ProofFinalize(init_res, challenge, signature_result.getScalar(), random_scalars, undisclosed_messages);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-initialization
    private static InitRes ProofInit(OctetString publicKey, Signature signature, Vector<G1Point> generators, Vector<Scalar> random_scalars, OctetString header, Vector<Scalar> messages, Vector<Integer> undisclosed_indexes, OctetString api_id) {
        var L = messages.getLength();
        var U = undisclosed_indexes.getLength();
        var jx = undisclosed_indexes;
        if(random_scalars.getLength() != (U+5)) return InitRes.INVALID;
        var r1 = random_scalars.getValue(1);
        var r2 = random_scalars.getValue(2);
        var e_ = random_scalars.getValue(3);
        var r1_ = random_scalars.getValue(4);
        var r3_ = random_scalars.getValue(5);
        var m_jx = splitScalarVector(random_scalars, 6);
        if (generators.getLength() != (L+1)) return InitRes.INVALID;
        var Q1 = generators.getValue(1);
        var MsgGenerators = getHPoints(generators);
        var H_x = MsgGenerators;
        var H_jx = getIndexedGenerators(generators, jx);
        for (var el: undisclosed_indexes) {
            if(el < 0 || el > (L-1)) throw new Abort("A undisclosed index is smaller than 0 or bigger that the count of messages");
        }
        if(U>L) throw new Abort("More undisclosed indexes than messages");
        var domain = calculate_domain(publicKey, Q1, MsgGenerators, header, api_id);
        var B = P1.add(Q1.times(domain)).add(G1Point.sumOfScalarMultiply(H_x, messages));
        var D = B.times(r2);
        var Abar = signature.getPoint().times((r1.multiply(r2)));
        var Bbar = D.times(r1).subtract(Abar.times(signature.getScalar()));
        var T1 = Abar.times(e_).add(D.times(r1_));
        var T2 = D.times(r3_).add(G1Point.sumOfScalarMultiply(H_jx, m_jx));
        return new InitRes(Abar, Bbar, D, T1, T2, domain);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-finalization
    private static OctetString ProofFinalize(InitRes init_res, Scalar challenge, Scalar e_value, Vector<Scalar> random_scalars, Vector<Scalar> undisclosed_messages) {
        var U = undisclosed_messages.getLength();
        if(random_scalars.getLength() != (U+5)) return OctetString.INVALID;
        var r1 = random_scalars.getValue(1);
        var r2 = random_scalars.getValue(2);
        var e_ = random_scalars.getValue(3);
        var r1_ = random_scalars.getValue(4);
        var r3_ = random_scalars.getValue(5);
        var m_jx = splitScalarVector(random_scalars, 6);
        var undisclosed_x = undisclosed_messages;
        var Abar = init_res.getAbar();
        var Bbar = init_res.getBbar();
        var D = init_res.getD();
        var r3 = r2.modInverse(r);
        var eCalc= e_.add(e_value.multiply(challenge)).mod(r);
        var r1Calc = r1_.substract(r1.multiply(challenge)).mod(r);
        var r3Calc = r3_.substract(r3.multiply(challenge)).mod(r);
        var builder = new Vector.Builder<Scalar>(U);
        for (int j = 1; j <= U; j++) {
            builder.addValue(m_jx.getValue(j).add(undisclosed_x.getValue(j).multiply(challenge)).mod(r));
        }
        var m_j = builder.build();
        var proof = new Proof(Abar, Bbar, D, eCalc, r1Calc, r3Calc, m_j, challenge);
        return proof_to_octets(proof);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-to-octets
    private static OctetString proof_to_octets(Proof proof) {
        return serialize(proof.toObjectArray());
    }

    private static Vector<Integer> splitIndexes(Vector<Integer> disclosed_indexes, int L, int U){
        var builder = new Vector.Builder<Integer>(U);
        for (int i = 1; i <= L; i++) {
            var found = false;
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
        var builder = new Vector.Builder<Scalar>(indexes.getLength());
        for (int disclosedIndex: indexes) {
            builder.addValue(messages.getValue(disclosedIndex));
        }
        return builder.build();
    }

    private static Vector<Scalar> calculate_random_scalars(int count){
        var builder = new Vector.Builder<Scalar>(count);
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
        var builder = new Vector.Builder<Scalar>(scalars.getLength()-start+1);
        for (int i = start; i <= scalars.getLength(); i++) {
            builder.addValue(scalars.getValue(i));
        }
        return builder.build();
    }

    private static Vector<G1Point> getIndexedGenerators(Vector<G1Point> generators, Vector<Integer> indexes){
        var builder = new Vector.Builder<G1Point>(generators.getLength()-1);
        for (int disclosedIndex: indexes) {
            builder.addValue(generators.getValue(disclosedIndex));
        }
        return builder.build();
    }
}
