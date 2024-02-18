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

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static ch.bfh.p2bbs.utils.helper.mockedRandomScalars;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ProofGenTest {

    private static final OctetString SEED = OctetString.valueOfHexString("332e313431353932363533353839373933323338343632363433333833323739");
    private static final OctetString DST = OctetString.valueOf("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_", StandardCharsets.US_ASCII);
    private static final String fixturePath = "./src/test/java/ch/bfh/p2bbs/fixture_data/bls12-381-sha-256/proof/";

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
}