package ch.bfh.p2bbs.signature;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.openchvote.util.sequence.Vector;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class SignTest {
    private static final String fixturePath = "./src/test/java/ch/bfh/p2bbs/fixture_data/bls12-381-sha-256/signature/";

    @Test
    public void GenAndVerifySignature(){
        File directoryPath = new File(fixturePath);
        var fixtures = directoryPath.list();
        for (var fixture : fixtures){
            JSONParser jsonParser = new JSONParser();
            try (FileReader reader = new FileReader(fixturePath + fixture))
            {
                var obj = (JSONObject) jsonParser.parse(reader);
                System.out.println(fixture + ": " + obj.get("caseName"));
                var keyPair = (JSONObject) obj.get("signerKeyPair");
                var secretKey = new Scalar(new BigInteger((String) keyPair.get("secretKey"), 16));
                var publicKey = OctetString.valueOfHexString((String) keyPair.get("publicKey"));
                var header = OctetString.valueOfHexString((String) obj.get("header"));
                var signature = OctetString.valueOfHexString((String) obj.get("signature"));
                var messages_base = (JSONArray) obj.get("messages");
                var valid = (Boolean) ((JSONObject) obj.get("result")).get("valid");
                var builder = new Vector.Builder<OctetString>();
                for (var message: messages_base){
                    builder.addValue(OctetString.valueOfHexString((String) message));
                }
                var messages = builder.build();
                if(valid){
                    var res = Sign.Sign(secretKey, publicKey, header, messages);
                    assertTrue(signature.equals(res));
                }
                var res = SignVerify.Verify(publicKey, signature, header, messages);
                assertEquals(valid, res);
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