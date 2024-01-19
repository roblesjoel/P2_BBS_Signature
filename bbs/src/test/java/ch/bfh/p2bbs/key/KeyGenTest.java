package ch.bfh.p2bbs.key;

import static org.junit.jupiter.api.Assertions.*;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
class KeyGenTest {

    private final OctetString key_material = OctetString.valueOfHexString("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
    private final OctetString key_info = OctetString.valueOfHexString("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
    private final OctetString key_dst = OctetString.valueOfHexString("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f");
    private final Scalar secretKey = Scalar.of(new BigInteger("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc", 16));
    private final OctetString publicKey = OctetString.valueOfHexString("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");

    @Test
    public void checkKeyPair(){
        var sk = KeyGen.KeyGen(key_material, key_info, key_dst);
        assertTrue(sk.equals(secretKey));
        var pk = KeyGen.SkToPk(sk);
        assertTrue(pk.equals(publicKey));
    }
}