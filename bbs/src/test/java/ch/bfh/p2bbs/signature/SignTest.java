package ch.bfh.p2bbs.signature;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.openchvote.util.sequence.Vector;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SignTest {

    private final Scalar secretKey = Scalar.of(new BigInteger("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc", 16));
    private final OctetString publicKey = OctetString.valueOfHexString("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    private final OctetString m_1 = OctetString.valueOfHexString("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
    private final OctetString m_2 = OctetString.valueOfHexString("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80");
    private final OctetString m_3 = OctetString.valueOfHexString("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73");
    private final OctetString m_4 = OctetString.valueOfHexString("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c");
    private final OctetString m_5 = OctetString.valueOfHexString("496694774c5604ab1b2544eababcf0f53278ff50");
    private final OctetString m_6 = OctetString.valueOfHexString("515ae153e22aae04ad16f759e07237b4");
    private final OctetString m_7 = OctetString.valueOfHexString("d183ddc6e2665aa4e2f088af");
    private final OctetString m_8 = OctetString.valueOfHexString("ac55fb33a75909ed");
    private final OctetString m_9 = OctetString.valueOfHexString("96012096");
    private final OctetString m_10 = OctetString.valueOfHexString("");
    private final OctetString header = OctetString.valueOfHexString("11223344556677889900aabbccddeeff");
    private final OctetString singleMessageSignature = OctetString.valueOfHexString("88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103");
    private final OctetString multiMessageSignature = OctetString.valueOfHexString("895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e");
    private final OctetString noHeaderSignature = OctetString.valueOfHexString("ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b");

    @Test
    public void checkSingleMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1);
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        assertTrue(signature.equals(singleMessageSignature));
    }

    @Test
    public void checkMultiMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1,m_2,m_3,m_4,m_5,m_6,m_7,m_8,m_9,m_10);
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        assertTrue(signature.equals(multiMessageSignature));
    }

    @Test
    public void noHeaderMultiMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1,m_2,m_3,m_4,m_5,m_6,m_7,m_8,m_9,m_10);
        var header = OctetString.valueOf("", StandardCharsets.US_ASCII);
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        assertTrue(signature.equals(noHeaderSignature));
    }

    @Test
    public void modifiedMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1);
        var modifiedMsg = Vector.of(OctetString.valueOfHexString(""));
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        var signValid = SignVerify.Verify(publicKey, signature, header, modifiedMsg);
        assertFalse(signValid);
    }

    @Test
    public void extraUnsignedMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1);
        var modifiedMsg = Vector.of(m_1, OctetString.valueOfHexString(""));
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        var signValid = SignVerify.Verify(publicKey, signature, header, modifiedMsg);
        assertFalse(signValid);
    }

    @Test
    public void missingMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1,m_2,m_3,m_4,m_5,m_6,m_7,m_8,m_9,m_10);
        var modifiedMsg = Vector.of(m_1, m_2);
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        var signValid = SignVerify.Verify(publicKey, signature, header, modifiedMsg);
        assertFalse(signValid);
    }

    @Test
    public void reorderedMessageSignature(){
        Vector<OctetString> messages = Vector.of(m_1,m_2,m_3,m_4,m_5,m_6,m_7,m_8,m_9,m_10);
        var modifiedMsg = Vector.of(m_10,m_9,m_8,m_7,m_6,m_5,m_4,m_3,m_2,m_1);
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        var signValid = SignVerify.Verify(publicKey, signature, header, modifiedMsg);
        assertFalse(signValid);
    }

    @Test
    public void wrongPublicSignature(){
        Vector<OctetString> messages = Vector.of(m_1,m_2,m_3,m_4,m_5,m_6,m_7,m_8,m_9,m_10);
        var modifiedPublicKey = OctetString.valueOfHexString("b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6");
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        var signValid = SignVerify.Verify(modifiedPublicKey, signature, header, messages);
        assertFalse(signValid);
    }

    @Test
    public void wrongHeaderSignature(){
        Vector<OctetString> messages = Vector.of(m_1,m_2,m_3,m_4,m_5,m_6,m_7,m_8,m_9,m_10);
        var modifiedHeader = OctetString.valueOfHexString("ffeeddccbbaa00998877665544332211");
        var signature = Sign.Sign(secretKey, publicKey, header, messages);
        var signValid = SignVerify.Verify(publicKey, signature, modifiedHeader, messages);
        assertFalse(signValid);
    }

}