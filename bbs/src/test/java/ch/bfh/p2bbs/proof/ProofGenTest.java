package ch.bfh.p2bbs.proof;

import ch.bfh.p2bbs.Types.*;
import ch.bfh.p2bbs.excptions.Abort;
import ch.openchvote.util.sequence.Vector;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

import static ch.bfh.hnr1.util.Hash.expandMessageXMD_SHA_256;
import static ch.bfh.p2bbs.utils.Definitions.Expand_Len;
import static ch.bfh.p2bbs.utils.Definitions.r;
import static ch.bfh.p2bbs.utils.helper.os2ip;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ProofGenTest {

    private static final OctetString SEED = OctetString.valueOfHexString("332e313431353932363533353839373933323338343632363433333833323739");
    private static final OctetString DST = OctetString.valueOf("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_", StandardCharsets.US_ASCII);
    private static final String fixturePath = "./src/test/java/ch/bfh/p2bbs/fixture_data/bls12-381-sha-256/proof/";

    public static Vector<Scalar> mockedRandomScalars(OctetString SEED, OctetString dst, int count){
        if(count * Expand_Len > 65535) throw new Abort("To many scalars to be mocked");
        var out_len = Expand_Len * count;
        var v = new OctetString(expandMessageXMD_SHA_256(SEED.toBytes(), dst.toBytes(), out_len));
        var r_i = new Vector.Builder<Scalar>();
        for (int i = 1; i <= count; i++) {
            var start_idx = (i-1)* Expand_Len;
            var end_idx = (i * Expand_Len) - 1;
            r_i.addValue(os2ip(v.split(start_idx, end_idx)).mod(r));
        }
        return r_i.build();
    }

    @Test
    public void ProofGen(){
        var fixtures = new String[]{"proof001.json", "proof002.json", "proof003.json", "proof014.json", "proof015.json"};

        for (var fixture : fixtures){
            JSONParser jsonParser = new JSONParser();
            try (FileReader reader = new FileReader(fixturePath + fixture))
            {
                var obj = (JSONObject) jsonParser.parse(reader);
                System.out.println(obj.get("caseName"));
                var publicKey = OctetString.valueOfHexString((String) obj.get("signerPublicKey"));
                var signature = OctetString.valueOfHexString((String) obj.get("signature"));
                var header = OctetString.valueOfHexString((String) obj.get("header"));
                var ph = OctetString.valueOfHexString((String) obj.get("presentationHeader"));
                var messages_base = (JSONArray) obj.get("messages");
                var revealed_indexes_base = (JSONArray) obj.get("disclosedIndexes");
                var proof = OctetString.valueOfHexString((String) obj.get("proof"));

                var builder = new Vector.Builder<Integer>();
                for (var revealed_index: revealed_indexes_base){
                    builder.addValue(Math.toIntExact((Long) revealed_index)+1);
                }

                var messageBuilder = new Vector.Builder<OctetString>();
                for (var message: messages_base){
                    messageBuilder.addValue(OctetString.valueOfHexString((String)message));
                }

                var revealed_indexes = builder.build();
                var messages = messageBuilder.build();
                var random_scalars = mockedRandomScalars(SEED, DST, 5+(messages.getLength()-revealed_indexes.getLength()));

                try (MockedStatic<ProofGen> mocked = Mockito.mockStatic(ProofGen.class)) {
                    mocked.when(() -> ProofGen.calculate_random_scalars(anyInt()))
                            .thenReturn(random_scalars);
                    mocked.when(() -> ProofGen.splitIndexes(any(), anyInt(), anyInt())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.splitScalarVector(any(), anyInt())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.ProofGen(any(), any(), any(), any(), any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.CoreProofGen(any(), any(), any(), any(), any(), any(), any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.ProofInit(any(), any(), any(), any(), any(), any(), any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.ProofFinalize(any(), any(), any(), any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.proof_to_octets(any())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.getIndexedMessages(any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofGen.getIndexedGenerators(any(), any())).thenCallRealMethod();
                    var proofRes = ProofGen.ProofGen(publicKey, signature, header, ph, messages, revealed_indexes);
                    assertTrue(proofRes.equals(proof));
                }

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (org.json.simple.parser.ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Test
    public void ProofVerify(){
        File directoryPath = new File(fixturePath);
        var fixtures = directoryPath.list();

        for (var fixture : fixtures){
            JSONParser jsonParser = new JSONParser();
            try (FileReader reader = new FileReader(fixturePath + fixture))
            {
                var obj = (JSONObject) jsonParser.parse(reader);
                System.out.println(fixture + ": " + obj.get("caseName"));
                var publicKey = OctetString.valueOfHexString((String) obj.get("signerPublicKey"));
                var header = OctetString.valueOfHexString((String) obj.get("header"));
                var ph = OctetString.valueOfHexString((String) obj.get("presentationHeader"));
                var messages_base = (JSONArray) obj.get("messages");
                var revealed_indexes_base = (JSONArray) obj.get("disclosedIndexes");
                var proof = OctetString.valueOfHexString((String) obj.get("proof"));
                var result = ((JSONObject) obj.get("result")).get("valid");

                var builder = new Vector.Builder<Integer>();
                for (var revealed_index: revealed_indexes_base){
                    builder.addValue(Math.toIntExact((Long) revealed_index)+1);
                }
                var revealed_indexes = builder.build();

                var indexArr = new ArrayList<Integer>();

                var revealedBuilder = new Vector.Builder<OctetString>();
                for (int i = 1; i <= revealed_indexes.getLength(); i++){
                    var value = OctetString.valueOfHexString((String) messages_base.get(revealed_indexes.getValue(i)-1));
                    if(!indexArr.contains(revealed_indexes.getValue(i)-1)) {
                        indexArr.add(revealed_indexes.getValue(i)-1);
                        revealedBuilder.addValue(value);
                    }
                }
                var revealedMessages = revealedBuilder.build();

                try (MockedStatic<ProofVerify> mocked = Mockito.mockStatic(ProofVerify.class)) {
                    mocked.when(() -> ProofVerify.splitIndexes(any(), anyInt(), anyInt())).thenCallRealMethod();
                    mocked.when(() -> ProofVerify.ProofVerify(any(), any(), any(), any(), any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofVerify.CoreProofVerify(any(), any(), any(), any(), any(), any(), any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofVerify.ProofVerifyInit(any(), any(), any(), any(), any(), any(), any())).thenCallRealMethod();
                    mocked.when(() -> ProofVerify.getIndexedGenerators(any(), any())).thenCallRealMethod();
                    var valid = ProofVerify.ProofVerify(publicKey, proof, header, ph, revealedMessages, revealed_indexes);
                    assertEquals(result, valid);
                }

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (org.json.simple.parser.ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /*

    @Test
    public void validSingleMessageProof(){
        var revealed_indexes = Vector.of(1); //Vector starts with 1 Vector.of(0);
        var messages = Vector.of(m_1);
        var random_scalars = mockedRandomScalars(SEED, DST, 5+(messages.getLength()-revealed_indexes.getLength()));
        try (MockedStatic<ProofGen> mocked = Mockito.mockStatic(ProofGen.class)) {
            mocked.when(() -> ProofGen.calculate_random_scalars(5))
                    .thenReturn(random_scalars);
            mocked.when(() -> ProofGen.splitIndexes(any(), anyInt(), anyInt())).thenCallRealMethod();
            mocked.when(() -> ProofGen.splitScalarVector(any(), anyInt())).thenCallRealMethod();
            mocked.when(() -> ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes)).thenCallRealMethod();
            mocked.when(() -> ProofGen.CoreProofGen(any(OctetString.class), any(OctetString.class), any(), any(OctetString.class), any(OctetString.class), any(), any(), any(OctetString.class))).thenCallRealMethod();
            mocked.when(() -> ProofGen.ProofInit(any(), any(), any(), any(), any(), any(), any(), any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.ProofFinalize(any(), any(), any(), any(), any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.proof_to_octets(any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.getIndexedMessages(any(), any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.getIndexedGenerators(any(), any())).thenCallRealMethod();
            var proofRes = ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes);
            assertTrue(proofRes.equals(proof));
        }
    }

    @Test
    public void validMultiMessageProof(){
        var revealed_indexes = Vector.of(1,2,3,4,5,6,7,8,9,10); //Vector starts with 1 Vector.of(0);
        var messages = Vector.of(m_1, m_2, m_3, m_4, m_5, m_6, m_7, m_8, m_9, m_10);
        var random_scalars = mockedRandomScalars(SEED, DST, 5+(messages.getLength()-revealed_indexes.getLength()));
        try (MockedStatic<ProofGen> mocked = Mockito.mockStatic(ProofGen.class)) {
            mocked.when(() -> ProofGen.calculate_random_scalars(5))
                    .thenReturn(random_scalars);
            mocked.when(() -> ProofGen.splitIndexes(any(), anyInt(), anyInt())).thenCallRealMethod();
            mocked.when(() -> ProofGen.splitScalarVector(any(), anyInt())).thenCallRealMethod();
            mocked.when(() -> ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes)).thenCallRealMethod();
            mocked.when(() -> ProofGen.CoreProofGen(any(OctetString.class), any(OctetString.class), any(), any(OctetString.class), any(OctetString.class), any(), any(), any(OctetString.class))).thenCallRealMethod();
            mocked.when(() -> ProofGen.ProofInit(any(), any(), any(), any(), any(), any(), any(), any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.ProofFinalize(any(), any(), any(), any(), any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.proof_to_octets(any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.getIndexedMessages(any(), any())).thenCallRealMethod();
            mocked.when(() -> ProofGen.getIndexedGenerators(any(), any())).thenCallRealMethod();
            var proofRes = ProofGen.ProofGen(publicKey, signature, header, presentation_header, messages, revealed_indexes);
            assertTrue(proofRes.equals(proofAll));
        }
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
*/
}