package ch.bfh.evg.signature;

import ch.bfh.evg.Exception.AbortException;
import ch.bfh.evg.Exception.InvalidException;
import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.G2Point;
import ch.bfh.evg.bls12_381.Scalar;
import ch.bfh.evg.group.GroupElement;
import ch.openchvote.util.sequence.ByteArray;
import ch.openchvote.util.sequence.Vector;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static ch.bfh.evg.signature.BBS.*;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BBSTest {

    /**
     * Definitions
     */

    // switch string because big endian

    private static final int Expand_Len = 48;
    private static final BigInteger r = new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static OctetString m_1 = new OctetString(hexStringToByteArray("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")); //"68954167784506593468362446564797910913206407001841014153914480625028501364482");
    private static OctetString m_2 = new OctetString(hexStringToByteArray("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"));
    private static OctetString m_3 = new OctetString(hexStringToByteArray("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"));
    private static OctetString m_4 = new OctetString(hexStringToByteArray("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"));
    private static OctetString m_5 = new OctetString(hexStringToByteArray("496694774c5604ab1b2544eababcf0f53278ff50"));
    private static OctetString m_6 = new OctetString(hexStringToByteArray("515ae153e22aae04ad16f759e07237b4"));
    private static OctetString m_7 = new OctetString(hexStringToByteArray("d183ddc6e2665aa4e2f088af"));
    private static OctetString m_8 = new OctetString(hexStringToByteArray("ac55fb33a75909ed"));
    private static OctetString m_9 = new OctetString(hexStringToByteArray("96012096"));
    private static OctetString m_10 = OctetString.valueOf("");

    public static byte[] hexStringToByteArray(String hex) {
        int l = hex.length();
        byte[] data = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Helper Functions
     */

    /**
     * Generates random scalars
     * @param SEED The Seed for the generation
     * @param DST The domain separation tag
     * @param count How many scalars to generate
     * @return A Vector of the random scalars
     * @throws AbortException Throws this exception if there was an error while generating the scalars
     */
    private static Vector<Scalar> seeded_random_scalars(OctetString SEED, OctetString DST, int count) throws AbortException {
        if(count * Expand_Len > 65535) throw new AbortException("count * Expand_Len exceeds the allowed limit");
        var outLen = Expand_Len * count;
        OctetString v = expand_message_xof(SEED, DST, outLen);
        var builder = new Vector.Builder<Scalar>();
        for (int i = 1; i <= count; i++){
            var start_idx = (i - 1) * Expand_Len;
            var end_idx = i * Expand_Len - 1;
            builder.addValue(Scalar.of(os2ip(v.split(start_idx, end_idx)).toBigInteger().mod(r)));
        }
        return builder.build();
    }

    /**
     * Tests
     */

    @Test // Siganture not working correctly
    public void testKeyGen() throws InvalidException, GroupElement.DeserializationException {
        var otherKey_material = OctetString.valueOfHexString("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579");
        var otherKey_info = OctetString.valueOfHexString("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e");
        var otherKey_dst = OctetString.valueOfHexString("4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f");
        var otherSk = os2ip(OctetString.valueOfHexString("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"));
        var otherPk = new OctetString(HexFormat.of().parseHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"));
        Scalar SK = KeyGen(otherKey_material, otherKey_info, otherKey_dst);
        //Assertions.assertEquals(otherSk, SK);
        var PK = SkToPk(otherSk).reverse();
        Assertions.assertEquals(otherPk.toString(), PK.toString());
    }

    @Test // not working
    public void testMessage_to_scalars() throws AbortException {
        Scalar msg_scalar_1 = Scalar.of(new BigInteger("1e0dea6c9ea8543731d331a0ab5f64954c188542b33c5bbc8ae5b3a830f2d99f", 16));
        Scalar msg_scalar_2 = Scalar.of(new BigInteger("3918a40fb277b4c796805d1371931e08a314a8bf8200a92463c06054d2c56a9f",16));
        Scalar msg_scalar_3 = Scalar.of(new BigInteger("6642b981edf862adf34214d933c5d042bfa8f7ef343165c325131e2ffa32fa94",16));
        Scalar msg_scalar_4 = Scalar.of(new BigInteger("33c021236956a2006f547e22ff8790c9d2d40c11770c18cce6037786c6f23512",16));
        Scalar msg_scalar_5 = Scalar.of(new BigInteger("52b249313abbe323e7d84230550f448d99edfb6529dec8c4e783dbd6dd2a8471",16));
        Scalar msg_scalar_6 = Scalar.of(new BigInteger("2a50bdcbe7299e47e1046100aadffe35b4247bf3f059d525f921537484dd54fc",16));
        Scalar msg_scalar_7 = Scalar.of(new BigInteger("0e92550915e275f8cfd6da5e08e334d8ef46797ee28fa29de40a1ebccd9d95d3",16));
        Scalar msg_scalar_8 = Scalar.of(new BigInteger("4c28f612e6c6f82f51f95e1e4faaf597547f93f6689827a6dcda3cb94971d356",16));
        Scalar msg_scalar_9 = Scalar.of(new BigInteger("1db51bedc825b85efe1dab3e3ab0274fa82bbd39732be3459525faf70f197650",16));
        Scalar msg_scalar_10 = Scalar.of(new BigInteger("27878da72f7775e709bb693d81b819dc4e9fa60711f4ea927740e40073489e78",16));
        Vector<Scalar> otherMsg_scalar = Vector.of(msg_scalar_1, msg_scalar_2, msg_scalar_3, msg_scalar_4, msg_scalar_5, msg_scalar_6, msg_scalar_7, msg_scalar_8, msg_scalar_9, msg_scalar_10);
        OctetString otherDst = new OctetString();
        Vector<Scalar> msgScalar = messages_to_scalars(Vector.of(m_1, m_2, m_3, m_4, m_5, m_6, m_7, m_8, m_9, m_10), otherDst);
        Assertions.assertEquals(otherMsg_scalar, msgScalar);
    }

    @Test // Skipped
    public void TestCreateGenerators() throws AbortException {
        var otherQ1 = OctetString.valueOf("a9d40131066399fd41af51d883f4473b0dcd7d028d3d34ef17f3241d204e28507d7ecae032afa1d5490849b7678ec1f8", Charset.defaultCharset());
        var otherH1 = OctetString.valueOf("903c7ca0b7e78a2017d0baf74103bd00ca8ff9bf429f834f071c75ffe6bfdec6d6dca15417e4ac08ca4ae1e78b7adc0e", Charset.defaultCharset());
        var otherH2 = OctetString.valueOf("84321f5855bfb6b001f0dfcb47ac9b5cc68f1a4edd20f0ec850e0563b27d2accee6edff1a26b357762fb24e8ddbb6fcb", Charset.defaultCharset());
        var otherH3 = OctetString.valueOf("b3060dff0d12a32819e08da00e61810676cc9185fdd750e5ef82b1a9798c7d76d63de3b6225d6c9a479d6c21a7c8bf93", Charset.defaultCharset());
        var otherH4 = OctetString.valueOf("8f1093d1e553cdead3c70ce55b6d664e5d1912cc9edfdd37bf1dad11ca396a0a8bb062092d391ebf8790ea5722413f68", Charset.defaultCharset());
        var otherH5 = OctetString.valueOf("990824e00b48a68c3d9a308e8c52a57b1bc84d1cf5d3c0f8c6fb6b1230e4e5b8eb752fb374da0b1ef687040024868140", Charset.defaultCharset());
        var otherH6 = OctetString.valueOf("b86d1c6ab8ce22bc53f625d1ce9796657f18060fcb1893ce8931156ef992fe56856199f8fa6c998e5d855a354a26b0dd", Charset.defaultCharset());
        var otherH7 = OctetString.valueOf("b4cdd98c5c1e64cb324e0c57954f719d5c5f9e8d991fd8e159b31c8d079c76a67321a30311975c706578d3a0ddc313b7", Charset.defaultCharset());
        var otherH8 = OctetString.valueOf("8311492d43ec9182a5fc44a75419b09547e311251fe38b6864dc1e706e29446cb3ea4d501634eb13327245fd8a574f77", Charset.defaultCharset());
        var otherH9 = OctetString.valueOf("ac00b493f92d17837a28d1f5b07991ca5ab9f370ae40d4f9b9f2711749ca200110ce6517dc28400d4ea25dddc146cacc", Charset.defaultCharset());
        var otherH10 = OctetString.valueOf("965a6c62451d4be6cb175dec39727dc665762673ee42bf0ac13a37a74784fbd61e84e0915277a6f59863b2bb4f5f6005", Charset.defaultCharset());
        Vector<OctetString> otherGenerators = Vector.of(otherQ1, otherH1, otherH2, otherH3, otherH4, otherH5, otherH6, otherH7, otherH8, otherH9,otherH10);
        Vector<G1Point> generators = create_generators(11, new OctetString(), new OctetString());
        for (int i = 1; i < 11; i++){
            Assertions.assertEquals(otherGenerators.getValue(i).toString(), generators.getValue(i).toString());
        }
    }

    @Test // How to set vars in code, G1 does not deserialize
    public void testGenerateSignatureOneMessage() throws InvalidException, GroupElement.DeserializationException {
        var otherSk = Scalar.of(new BigInteger("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079", 16));
        var otherPk = new OctetString(HexFormat.of().parseHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"));
        var otherHeader = new OctetString(HexFormat.of().parseHex("11223344556677889900aabbccddeeff"));
        var otherDomain = new OctetString(HexFormat.of().parseHex("2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9"));
        var otherB = G1Point.deserialize(ByteArray.of(HexFormat.of().parseHex("8bbc8c123d3f128f206dd0d2dae490e82af08b84e8d70af3dc291d32a6e98f635beefcc4533b2599804a164aabe68d7c")));
        OctetString singleSignature = new OctetString(HexFormat.of().parseHex("98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1"));
        Vector<OctetString> otherStrMessages = Vector.of(m_1);
        OctetString signature = Sign(otherSk, otherPk, otherHeader, otherStrMessages);
        Assertions.assertEquals(singleSignature, signature);
    }

    @Test // How to set vars in code, G1 does not deserialize
    public void testGenerateSignatureMultiMessage() throws GroupElement.DeserializationException, InvalidException {
        var otherSk = Scalar.of(new BigInteger("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079", 16));
        var otherPk = new OctetString(HexFormat.of().parseHex("92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"));
        var otherHeader = new OctetString(HexFormat.of().parseHex("11223344556677889900aabbccddeeff"));
        var otherDomain = new OctetString(HexFormat.of().parseHex("6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b"));
        var temp = HexFormat.of().parseHex("ae8d4ebe248b9ad9c933d5661bfb46c56721fba2a1182ddda7e8fb443bda3c0a571ad018ad31d0b6d1f4e8b985e6c58d");
        var otherB = G1Point.deserialize(ByteArray.of(temp));
        OctetString singleSignature = new OctetString(HexFormat.of().parseHex("97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd8 50aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f"));
        Vector<OctetString> otherStrMessages = Vector.of(m_1,m_2,m_3,m_4,m_5,m_6,m_7,m_8,m_9,m_10);
        OctetString signature = Sign(otherSk, otherPk, otherHeader, otherStrMessages);
        Assertions.assertEquals(singleSignature, signature);
    }

    /*private OctetString SEED = new OctetString("332e313431353932363533353839373933323338343632363433333833323739".getBytes(StandardCharsets.UTF_8));

    private OctetString DST = OctetString.valueOf("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_", Charset.defaultCharset());

    @Test
    public void testMocked_calculate_scalars() throws AbortException {
        OctetString random_scalar_1 = OctetString.valueOf("1004262112c3eaa95941b2b0d1311c09c845db0099a50e67eda628ad26b43083", Charset.defaultCharset());
        OctetString random_scalar_2 = OctetString.valueOf("6da7f145a94c1fa7f116b2482d59e4d466fe49c955ae8726e79453065156a9a4", Charset.defaultCharset());
        OctetString random_scalar_3 = OctetString.valueOf("05017919b3607e78c51e8ec34329955d49c8c90e4488079c43e74824e98f1306", Charset.defaultCharset());
        OctetString random_scalar_4 = OctetString.valueOf("4d451dad519b6a226bba79e11b44c441f1a74800eecfec6a2e2d79ea65b9d32d", Charset.defaultCharset());
        OctetString random_scalar_5 = OctetString.valueOf("5e7e4894e6dbe68023bc92ef15c410b01f3828109fc72b3b5ab159fc427b3f51", Charset.defaultCharset());
        OctetString random_scalar_6 = OctetString.valueOf("646e3014f49accb375253d268eb6c7f3289a1510f1e9452b612dd73a06ec5dd4", Charset.defaultCharset());
        OctetString random_scalar_7 = OctetString.valueOf("363ecc4c1f9d6d9144374de8f1f7991405e3345a3ec49dd485a39982753c11a4", Charset.defaultCharset());
        OctetString random_scalar_8 = OctetString.valueOf("12e592fe28d91d7b92a198c29afaa9d5329a4dcfdaf8b08557807412faeb4ac6", Charset.defaultCharset());
        OctetString random_scalar_9 = OctetString.valueOf("513325acdcdec7ea572360587b350a8b095ca19bdd8258c5c69d375e8706141a", Charset.defaultCharset());
        OctetString random_scalar_10 = OctetString.valueOf("6474fceba35e7e17365dde1a0284170180e446ae96c82943290d7baa3a6ed429", Charset.defaultCharset());
        Vector<String> random_scalars = Vector.of(random_scalar_1.toString(), random_scalar_2.toString(), random_scalar_3.toString(), random_scalar_4.toString(), random_scalar_5.toString(), random_scalar_6.toString(), random_scalar_7.toString(), random_scalar_8.toString(), random_scalar_9.toString(), random_scalar_10.toString());
        Vector<Scalar> mocked_scalars = mocked_calculated_scalars(SEED, DST, 10);
        for (int i = 1; i<10; i++){
            Assertions.assertEquals(random_scalars.getValue(i), mocked_scalars.getValue(i).toString());
        }
    }

    /*private String ph = "";
    private int[] disclosed_indexes = {0};
    private static OctetString otherProof = OctetString.valueOf("89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7", Charset.defaultCharset());
    @Test
    public void validSingleMessageProof(){
        byte[] proof = ProofGen(otherPk.toBigInteger().toByteArray(), singleSignature.toBigInteger().toByteArray(), otherHeader.toBytes(), ph, strMessages, disclosed_indexes);
        Assertions.assertEquals(otherProof, proof);
    }*/
}