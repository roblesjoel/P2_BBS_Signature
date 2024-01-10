package ch.bfh.p2bbs.proof;

import ch.bfh.p2bbs.Types.*;
import ch.openchvote.util.sequence.Vector;

import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.Definitions.*;
import static ch.bfh.p2bbs.utils.helper.*;

public class ProofVerify {

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-verification-proofver
    public static boolean ProofVerify(OctetString publicKey, OctetString proof, OctetString header, OctetString ph, Vector<OctetString> disclosed_messages, Vector<Integer> disclosed_indexes) {
        OctetString api_id =  CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        int proof_len_floor = (2 * Octet_Point_Length.toInt()) + (3 * Octet_Scalar_Length.toInt());
        if(proof.length < proof_len_floor) return false;
        int U = (int) Math.floor((proof.length-proof_len_floor)/Octet_Scalar_Length.toInt());
        int R = disclosed_indexes.getLength();
        Vector<Scalar> messageScalars = messages_to_scalars(disclosed_messages, api_id);
        Vector<G1Point> generators = create_generators(U+R+1, api_id);
        return CoreProofVerify(publicKey, proof, generators, header, ph, messageScalars, disclosed_indexes, api_id);
    }

    private static boolean CoreProofVerify(OctetString publicKey, OctetString proof_octets, Vector<G1Point> generators, OctetString header, OctetString ph, Vector<Scalar> disclosed_messages, Vector<Integer> disclosed_indexes, OctetString api_id) {
        Proof proof_result = octets_to_proof(proof_octets);
        G1Point Abar = proof_result.getA_0();
        G1Point Bbar = proof_result.getA_1();
        Scalar cp = proof_result.getS_j_1();
        G2Point W = G2Point.deserialize(publicKey.toBytes());
        InitRes init_res = ProofVerifyInit(publicKey, proof_result, generators, header, disclosed_messages, disclosed_indexes, api_id);
        Scalar challenge = ProofChallengeCalculate(init_res, disclosed_indexes, disclosed_messages, ph, api_id);
        if(!cp.equals(challenge)) return false;
        GTElement Apairing = Abar.pair(W);
        GTElement Bpairing = Bbar.pair(G2Point.GENERATOR.negate());
        GTElement multiplicatedElement = Apairing.multiply(Bpairing);
        if(!multiplicatedElement.equals(GTElement.ONE)) return false;
        return true;
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-proof-verification-initiali
    private static InitRes ProofVerifyInit(OctetString PK, Proof proof, Vector<G1Point> generators, OctetString header, Vector<Scalar> disclosed_messages, Vector<Integer> disclosed_indexes, OctetString api_id) {
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
        if(generators.getLength() != L+1) return null;
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

    private static Vector<G1Point> getIndexedGenerators(Vector<G1Point> generators, Vector<Integer> indexes){
        Vector.Builder<G1Point> builder = new Vector.Builder<>(generators.getLength()-1);
        for (int disclosedIndex: indexes) {
            builder.addValue(generators.getValue(disclosedIndex));
        }
        return builder.build();
    }
    
}
