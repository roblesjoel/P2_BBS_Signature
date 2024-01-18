package ch.bfh.p2bbs.key;

import static ch.bfh.p2bbs.utils.helper.create_generators;
import static ch.bfh.p2bbs.utils.helper.messages_to_scalars;
import static org.junit.jupiter.api.Assertions.*;

import ch.bfh.p2bbs.Types.G1Point;
import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.bfh.p2bbs.signature.Sign;
import ch.bfh.p2bbs.utils.helper;
import ch.openchvote.util.sequence.Vector;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

class KeyGenTest {

    private final OctetString key_material = OctetString.valueOfHexString("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
    private final OctetString key_info = OctetString.valueOfHexString("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
    private final OctetString key_dst = OctetString.valueOfHexString("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f");
    private final Scalar secretKey = Scalar.of(new BigInteger("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc", 16));
    private final OctetString publicKey = OctetString.valueOfHexString("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    private final OctetString dst = OctetString.valueOfHexString("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4d41505f4d53475f544f5f5343414c41525f41535f484153485f");
    private final Scalar msg_scalar_1 = Scalar.of(new BigInteger("1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430", 16));
    private final Scalar msg_scalar_2 = Scalar.of(new BigInteger("154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952", 16));
    private final Scalar msg_scalar_3 = Scalar.of(new BigInteger("0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22", 16));
    private final Scalar msg_scalar_4 = Scalar.of(new BigInteger("4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888", 16));
    private final Scalar msg_scalar_5 = Scalar.of(new BigInteger("34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e", 16));
    private final Scalar msg_scalar_6 = Scalar.of(new BigInteger("4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08", 16));
    private final Scalar msg_scalar_7 = Scalar.of(new BigInteger("064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743", 16));
    private final Scalar msg_scalar_8 = Scalar.of(new BigInteger("34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02", 16));
    private final Scalar msg_scalar_9 = Scalar.of(new BigInteger("57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74", 16));
    private final Scalar msg_scalar_10 = Scalar.of(new BigInteger("08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16", 16));
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
    private final OctetString m_1 = OctetString.valueOfHexString("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
    private final OctetString header = OctetString.valueOfHexString("11223344556677889900aabbccddeeff");
    private final OctetString singleMessageSignature = OctetString.valueOfHexString("88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103");

    @Test
    public void checkKeyPair(){
        var sk = KeyGen.KeyGen(key_material, key_info, key_dst);
        assertTrue(sk.equals(secretKey));
        var pk = KeyGen.SkToPk(sk);
        assertTrue(pk.equals(publicKey));
    }

    @Test
    public void checkSingleMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1);
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        assertTrue(signature.equals(singleMessageSignature));
    }




}