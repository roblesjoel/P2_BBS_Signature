package ch.bfh.p2bbs.proof;

import ch.bfh.p2bbs.Types.*;
import ch.openchvote.util.sequence.Vector;

import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.Definitions.*;
import static ch.bfh.p2bbs.utils.helper.*;

public class ProofVerify {
    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-verification-proofver
    public static boolean ProofVerify(OctetString publicKey, OctetString proof, OctetString header, OctetString ph, Vector<OctetString> disclosed_messages, Vector<Integer> disclosed_indexes) {
        var api_id =  CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        var proof_len_floor = (2 * Octet_Point_Length.toInt()) + (3 * Octet_Scalar_Length.toInt());
        if(proof.length < proof_len_floor) return false;
        var U = (int) Math.floor((proof.length-proof_len_floor)/Octet_Scalar_Length.toInt());
        var R = disclosed_indexes.getLength();
        var messageScalars = messages_to_scalars(disclosed_messages, api_id);
        var generators = create_generators(U+R+1, api_id);
        return CoreProofVerify(publicKey, proof, generators, header, ph, messageScalars, disclosed_indexes, api_id);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coreproofverify
    private static boolean CoreProofVerify(OctetString publicKey, OctetString proof_octets, Vector<G1Point> generators, OctetString header, OctetString ph, Vector<Scalar> disclosed_messages, Vector<Integer> disclosed_indexes, OctetString api_id) {
        var proof_result = octets_to_proof(proof_octets);
        if(proof_result.isInvalid()) return false;
        var Abar = proof_result.getAbar();
        var Bbar = proof_result.getBbar();
        var cp = proof_result.getChallenge();
        var W = G2Point.deserialize(publicKey.toBytes());
        if(W.isInvalid()) return false;
        var init_res = ProofVerifyInit(publicKey, proof_result, generators, header, disclosed_messages, disclosed_indexes, api_id);
        if(init_res.isInvalid()) return false;
        var challenge = ProofChallengeCalculate(init_res, disclosed_messages, disclosed_indexes, ph, api_id);
        if(challenge.isInvalid()) return false;
        if(!cp.equals(challenge)) return false;
        if(!Abar.pair(W).multiply(Bbar.pair(G2Point.GENERATOR.negate())).equals(GTElement.ONE)) return false;
        return true;
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-verification-initiali
    private static InitRes ProofVerifyInit(OctetString PK, Proof proof, Vector<G1Point> generators, OctetString header, Vector<Scalar> disclosed_messages, Vector<Integer> disclosed_indexes, OctetString api_id) {
        var Abar = proof.getAbar();
        var Bbar = proof.getBbar();
        var D = proof.getD();
        var r1Calc = proof.getR1Calc();
        var r3Calc = proof.getR3Calc();
        var eCalc = proof.getECalc();
        var commitments = proof.getMsg_commitments();
        var c = proof.getChallenge();
        var U = commitments.getLength();
        var R = disclosed_indexes.getLength();
        var L = U + R;
        var ix = disclosed_indexes;
        for (var el: disclosed_indexes) {
            if(el < 0 || el > (L-1)) return InitRes.INVALID;
        }
        var jx = splitIndexes(disclosed_indexes, L, U);
        if(disclosed_messages.getLength() != R) return InitRes.INVALID;
        if(generators.getLength() != L+1) return InitRes.INVALID;
        var Q_1 = generators.getValue(1);
        var H_x = getHPoints(generators);
        var H_ix = getIndexedGenerators(generators, ix);
        var H_jx = getIndexedGenerators(generators, jx);
        var domain = calculate_domain(PK, Q_1, H_x, header, api_id);
        var T1 = Bbar.times(c).add(Abar.times(eCalc)).add(D.times(r1Calc));
        var Bv = P1.add(Q_1.times(domain)).add(G1Point.sumOfScalarMultiply(H_ix, disclosed_messages));
        var T2 = Bv.times(c).add(D.times(r3Calc)).add(G1Point.sumOfScalarMultiply(H_jx, commitments));
        return new InitRes(Abar, Bbar, D, T1, T2, domain);
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

    private static Vector<G1Point> getIndexedGenerators(Vector<G1Point> generators, Vector<Integer> indexes){
        Vector.Builder<G1Point> builder = new Vector.Builder<G1Point>(generators.getLength()-1);
        for (int disclosedIndex: indexes) {
            builder.addValue(generators.getValue(disclosedIndex));
        }
        return builder.build();
    }
}
