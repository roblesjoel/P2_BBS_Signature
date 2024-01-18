package ch.bfh.p2bbs.signature;

import ch.bfh.p2bbs.Types.G1Point;
import ch.bfh.p2bbs.Types.Signature;
import ch.openchvote.util.sequence.Vector;
import ch.bfh.p2bbs.Types.Scalar;
import ch.bfh.p2bbs.Types.OctetString;


import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.Definitions.*;
import static ch.bfh.p2bbs.utils.helper.*;

public class Sign {

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-signature-generation-sign
    public static OctetString Sign(Scalar secretKey, OctetString publicKey, OctetString header, Vector<OctetString> messages) {
        var api_id = CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        var message_scalars = messages_to_scalars(messages, api_id);
        var generators = create_generators(message_scalars.getLength()+1, api_id);
        return CoreSign(secretKey, publicKey, generators, header, message_scalars, api_id);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coresign
    private static OctetString CoreSign(Scalar secretKey, OctetString publicKey, Vector<G1Point> generators, OctetString header, Vector<Scalar> messages, OctetString api_id){
        var signature_dst = api_id.concat("H2S_", StandardCharsets.US_ASCII);
        var L = messages.getLength();
        if(generators.getLength() < L + 1) return OctetString.INVALID;
        var Q1 = generators.getValue(1);
        var H_x = getHPoints(generators);
        var domain = calculate_domain(publicKey, Q1, H_x, header, api_id);
        var e = hash_to_scalar(serialize(prepareSignSerializationData(secretKey, domain, messages)), signature_dst);
        var B = P1.add(Q1.times(domain)).add(G1Point.sumOfScalarMultiply(H_x, messages));
        var A = B.times(secretKey.add(e).modInverse(r));
        var test = new Signature(A, e);
        return signature_to_octets(new Signature(A, e));
    }

    private static Object[] prepareSignSerializationData(Scalar secretKey, Scalar domain, Vector<Scalar> messages){
        var dataToBeSerialized = new Object[2+messages.getLength()];
        dataToBeSerialized[0] = secretKey;
        dataToBeSerialized[1] = domain;
        System.arraycopy(messages.toArray(),0, dataToBeSerialized, 2, messages.getLength());
        return dataToBeSerialized;
    }
}
