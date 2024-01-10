package ch.bfh.p2bbs.signature;

import ch.bfh.p2bbs.Types.*;
import ch.openchvote.util.sequence.ByteArray;
import ch.openchvote.util.sequence.Vector;

import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.Definitions.CIPHERSUITE_ID;
import static ch.bfh.p2bbs.utils.Definitions.P1;
import static ch.bfh.p2bbs.utils.helper.*;

public class SignVerify {

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-signature-verification-veri
    public static boolean Verify(OctetString publicKey, OctetString signature, OctetString header, Vector<OctetString> messages){
        OctetString api_id = CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        Vector<Scalar> message_scalars = messages_to_scalars(messages, api_id);
        Vector<G1Point> generators = create_generators(message_scalars.getLength()+1, api_id);
        return CoreVerify(publicKey, signature, generators, header, message_scalars, api_id);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coreverify
    private static boolean CoreVerify(OctetString publicKey, OctetString signature_octets, Vector<G1Point> generators, OctetString header, Vector<Scalar> messages, OctetString api_id) {
        Signature signature = octets_to_signature(signature_octets);
        G2Point W = G2Point.deserialize(publicKey.toBytes());
        int L = messages.getLength();
        if(generators.getLength() != (L + 1)) return false;
        G1Point Q_1 = generators.getValue(1);
        Vector<G1Point> H_x = getHPoints(generators);
        Scalar domain = calculate_domain(publicKey, Q_1, H_x, header, api_id);
        G1Point B = P1.add(Q_1.times(domain)).add(G1Point.sumOfScalarMultiply(H_x, messages));
        if(!signature.getPoint().pair(W.add(G2Point.GENERATOR.times(signature.getScalar()))).multiply(B.pair(G2Point.GENERATOR.negate())).equals(GTElement.ONE)) return false;
        return true;
    }
}
