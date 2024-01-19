package ch.bfh.p2bbs.proof;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.bfh.p2bbs.excptions.Abort;
import ch.openchvote.util.sequence.Vector;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static ch.bfh.hnr1.util.Hash.expandMessageXMD_SHA_256;
import static ch.bfh.p2bbs.utils.Definitions.Expand_Len;
import static ch.bfh.p2bbs.utils.Definitions.r;
import static ch.bfh.p2bbs.utils.helper.os2ip;
import static org.junit.jupiter.api.Assertions.*;

class ProofGenTest {

    private final OctetString SEED = OctetString.valueOfHexString("332e313431353932363533353839373933323338343632363433333833323739");
    private final OctetString DST = OctetString.valueOf("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_", StandardCharsets.US_ASCII);
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
    private final OctetString publicKey = OctetString.valueOfHexString("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c");
    private final OctetString signature = OctetString.valueOfHexString("88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103");
    private final OctetString header = OctetString.valueOfHexString("11223344556677889900aabbccddeeff");
    private final OctetString presentation_header = OctetString.valueOfHexString("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
    private final OctetString proof = OctetString.valueOfHexString("a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980");
    private final OctetString proofAll = OctetString.valueOfHexString("a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd");
    private final OctetString proofSomeRevealed = OctetString.valueOfHexString("a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481352bb6fce6084eb1867c71caeac2afc4f57f4d26504656b798b3e4009eb227c7fa41b6ae00daae0436d853e86b32b366b0a9929e1570369e9c61b7b177eb70b7ff27326c467c362120dfeacc0692d25ccdd62d733ff6e8614abd16b6b63a7b78d11632cf41bc44856aee370fee6690a637b3b1d8d8525aff01cd3555c39d04f8ee1606964c2da8b988897e3d27cb444b8394acc80876d3916c485c9f36098fed6639f12a6a6e67150a641d7485656408e9ae22b9cb7ec77e477f71c1fe78cab3ee5dd62c34dd595edb15cbce061b29192419dfadcdee179f134dd8feb9323c426c51454168ffacb65021995848e368a5c002314b508299f67d85ad0eaaaac845cb029927191152edee034194cca3ae0d45cbd2f5e5afd1f9b8a3dd903adfa17ae43a191bf3119df57214f19e662c7e01e8cc2eb6b038bc7d707f2f3e13545909e0");
    private final OctetString proofNoHeader = OctetString.valueOfHexString("958783d7d535fe1860a71ad5a7cf42df6527246300e3f3d94d67639c7e8a7dbcf3f082f63e3b1bcc1cdad71e1f6d5f0d821c4c6bb4b2dcdfe945491d4f4a23d10752431d364fcbdd199c753f0beee7ffe02abbad57384244294ef7c2031d9c50ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db36771c74f1feec7f67b30e3805d71c8f893837b455d734d360c80e119b00dc63e2756b81a320d659a9a0f1ee57c41773f304c37c278d169faec5f6720bb9187e9333b793a57ba69f27e4b0c2ea35271276fc0011306d6c909cf4d4a7a50dbc9f6ef35d43e2043046dc3041ac0a9b893dfd2dcd147910d719e818b4189a76f791a3600acd76623573c1796262a3914921ec504d0f727c63e16b432f6256db62b9667016e516e97e2ef0bfa3bd192306564df28e019af18c50ca86a0e1d8d6b08b0641e549accd5e34ada8903d55021780865edfa70f63b85f0ddaf50787f8ced8eee658f2dd61673d2cbeca2aa2a5b649c22501b72cc7ee2d10bc9fe3aa3a7e169dc070d90b37735488cd0c27517ffd634b99c1dc016a4086d24feff6f19f3c92fa11cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652");
    private final OctetString proofNoPH = OctetString.valueOfHexString("a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356d60aa96c9b53ff5c63b3930bbcb3940f2132b7dcd800be4afbffd3325ecedaf033d354de52e12e924b32dd13c2f7cebef3614a4a519ff94d1bcceb7e22562ab4a5729a74cc3746558e25469651d7da37f714951c2ca03fc364a2272d13b2dee53412f97f42dfd6b57ae92fc7cb4859f418d6a912f5c446002cbf96ee6b8f4a849577a43ef303592c33e03608a9ca93066084bdfb3d3974ba322b7523d48fc9b35227e776c994b0e2da1587b496660836a7307a2125eae5912be3ea839bb4db16a21cc394c9a63fce91040d8321b30313677f7cbc4a9119fd0849aacef25fe9336db2dcbd85a2e3fd2ca2efff623c13e6c48b832c9e07dbe4337320dd0264a573f25bb46876e8153db47de2f0176db68cca1f55406a78c89c1a65716c00e9230098c6a9690a190b20720a7662ccd13b392fe08d045b99d5010f625cd74f7e90a");

    private Vector<Scalar> mockedRandomScalars(OctetString SEED, OctetString dst, int count){
        if(count * Expand_Len > 65535) throw new Abort("To many scalars to be mocked");
        var out_len = Expand_Len * count;
        var test = dst.toString();
        var v = new OctetString(expandMessageXMD_SHA_256(SEED.toBytes(), dst.toBytes(), out_len));
        var r_i = new Vector.Builder<Scalar>();
        for (int i = 1; i <= count ; i++) {
            var start_idx = (i-1)* Expand_Len;
            var end_idx = (i * Expand_Len) - 1;
            r_i.addValue(os2ip(v.split(start_idx, end_idx)).mod(r));
        }
        return r_i.build();
    }

    @Test
    public void validSingleMessageProof(){
        Vector<Integer> revealed_indexes = Vector.of(1); //Vector starts with 1 Vector.of(0);
        var messages = Vector.of(m_1);
        var proofRes = ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes);
        assertTrue(proofRes.equals(proof));
    }

    @Test
    public void validMultiMessageProof(){
        Vector<Integer> revealed_indexes = Vector.of(1,2,3,4,5,6,7,8,9,10); //Vector starts with 1 Vector.of(0);
        var messages = Vector.of(m_1, m_2, m_3, m_4, m_5, m_6, m_7, m_8, m_9, m_10);
        var proofRes = ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes);
        assertTrue(proofRes.equals(proofAll));
    }

    @Test
    public void validMultiMessageProofSomeRevealed(){
        Vector<Integer> revealed_indexes = Vector.of(1,3,5,7); //Vector starts with 1 Vector.of(0);
        var messages = Vector.of(m_1, m_2, m_3, m_4, m_5, m_6, m_7, m_8, m_9, m_10);
        var proofRes = ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes);
        assertTrue(proofRes.equals(proofSomeRevealed));
    }

    @Test
    public void noHeaderValidProof(){
        Vector<Integer> revealed_indexes = Vector.of(1,3,5,7); //Vector starts with 1 Vector.of(0);
        var header = OctetString.valueOf("", StandardCharsets.US_ASCII);
        var messages = Vector.of(m_1, m_2, m_3, m_4, m_5, m_6, m_7, m_8, m_9, m_10);
        var proofRes = ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes);
        assertTrue(proofRes.equals(proofNoHeader));
    }

    @Test
    public void noPHValidProof(){
        Vector<Integer> revealed_indexes = Vector.of(1,3,5,7); //Vector starts with 1 Vector.of(0);
        var presentation_header = OctetString.valueOf("", StandardCharsets.US_ASCII);
        var messages = Vector.of(m_1, m_2, m_3, m_4, m_5, m_6, m_7, m_8, m_9, m_10);
        var proofRes = ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes);
        assertTrue(proofRes.equals(proofNoPH));
    }

}