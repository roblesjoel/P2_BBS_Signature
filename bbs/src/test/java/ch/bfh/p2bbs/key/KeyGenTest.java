package ch.bfh.p2bbs.key;

import static org.junit.jupiter.api.Assertions.*;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
class KeyGenTest {
    private final OctetString key_dst = OctetString.valueOfHexString("");
    private static final String fixturePath = "./src/test/java/ch/bfh/p2bbs/fixture_data/bls12-381-sha-256/keypair.json";

    @Test
    public void checkKeyPair(){
        JSONParser jsonParser = new JSONParser();
        try (FileReader reader = new FileReader(fixturePath)){
            var obj = (JSONObject) jsonParser.parse(reader);
            System.out.println(fixturePath + ": " + obj.get("caseName"));
            var keyMaterial = OctetString.valueOfHexString((String) obj.get("keyMaterial"));
            var keyInfo = OctetString.valueOfHexString((String) obj.get("keyInfo"));
            var keyPair = (JSONObject) obj.get("keyPair");
            var secretKey = new Scalar(new BigInteger((String) keyPair.get("secretKey"), 16));
            var publicKey = OctetString.valueOfHexString((String) keyPair.get("publicKey"));
            var sk = KeyGen.KeyGen(keyMaterial, keyInfo, key_dst);
            assertTrue(sk.equals(secretKey));
            var pk = KeyGen.SkToPk(sk);
            assertTrue(pk.equals(publicKey));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }
}