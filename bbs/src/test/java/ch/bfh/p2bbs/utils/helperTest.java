package ch.bfh.p2bbs.utils;

import ch.bfh.p2bbs.Types.G1Point;
import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.openchvote.util.sequence.Vector;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.helper.*;
import static org.junit.jupiter.api.Assertions.*;

class helperTest {

    private final G1Point Q_1 = G1Point.deserialize(OctetString.valueOfHexString("a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be").toBytes());
    private final G1Point H_1 = G1Point.deserialize(OctetString.valueOfHexString("98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4").toBytes());
    private final G1Point H_2 = G1Point.deserialize(OctetString.valueOfHexString("a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a").toBytes());
    private final G1Point H_3 = G1Point.deserialize(OctetString.valueOfHexString("b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62").toBytes());
    private final G1Point H_4 = G1Point.deserialize(OctetString.valueOfHexString("ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035").toBytes());
    private final G1Point H_5 = G1Point.deserialize(OctetString.valueOfHexString("b95d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b596335").toBytes());
    private final G1Point H_6 = G1Point.deserialize(OctetString.valueOfHexString("8f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39").toBytes());
    private final G1Point H_7 = G1Point.deserialize(OctetString.valueOfHexString("abc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1").toBytes());
    private final G1Point H_8 = G1Point.deserialize(OctetString.valueOfHexString("80755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17").toBytes());
    private final G1Point H_9 = G1Point.deserialize(OctetString.valueOfHexString("82701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f").toBytes());
    private final G1Point H_10 = G1Point.deserialize(OctetString.valueOfHexString("a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca").toBytes());

    @Test
    public void hastToScalarTest(){
        var msg = OctetString.valueOfHexString("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
        var dst = OctetString.valueOfHexString("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4d41505f4d53475f544f5f5343414c41525f41535f484153485f");
        var output = Scalar.of(new BigInteger("1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430", 16));
        var hashedMsg = hash_to_scalar(msg,dst);
        assertTrue(hashedMsg.equals(output));
    }

    @Test
    public void checkGenerators(){
        var api_id = OctetString.valueOf("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_", StandardCharsets.US_ASCII);
        var allGenerators = Vector.of(Q_1, H_1, H_2, H_3, H_4, H_5, H_6, H_7, H_8, H_9, H_10);
        var generators = create_generators(11, api_id);
        assertTrue(generators.equals(allGenerators));
    }

}