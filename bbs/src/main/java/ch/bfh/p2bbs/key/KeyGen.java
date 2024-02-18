package ch.bfh.p2bbs.key;

import ch.bfh.p2bbs.Types.G2Point;
import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.Definitions.*;
import static ch.bfh.p2bbs.utils.helper.*;

public class KeyGen {
    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-secret-key
    public static Scalar KeyGen(OctetString key_material, OctetString key_info, OctetString key_dst) {
        var api_id =  CIPHERSUITE_ID.concat("H2G_HM2S_", StandardCharsets.US_ASCII);
        if(key_dst.length == 0) key_dst = api_id.concat("KEYGEN_DST_", StandardCharsets.US_ASCII);
        if(key_material.length < 32) return Scalar.INVALID;
        if(key_info.length > 65535) return Scalar.INVALID;
        var derive_input = key_material.concat(i2osp(Scalar.of(BigInteger.valueOf(key_info.length)), 2)).concat(key_info);
        return hash_to_scalar(derive_input, key_dst);
    }

    // see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-public-key
    public static OctetString SkToPk(Scalar SK){
        return new OctetString(G2Point.GENERATOR.times(SK).serialize());
    }
}
