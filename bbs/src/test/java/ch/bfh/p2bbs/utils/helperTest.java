package ch.bfh.p2bbs.utils;

import ch.bfh.hnr1.bls.BLS;
import ch.bfh.p2bbs.Types.G1Point;
import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.bfh.p2bbs.excptions.Abort;
import ch.bfh.p2bbs.key.KeyGen;
import ch.openchvote.util.sequence.Vector;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static ch.bfh.hnr1.util.Hash.expandMessageXMD_SHA_256;
import static ch.bfh.p2bbs.utils.Definitions.Expand_Len;
import static ch.bfh.p2bbs.utils.Definitions.r;
import static ch.bfh.p2bbs.utils.helper.*;
import static org.junit.jupiter.api.Assertions.*;

class helperTest {

    private static final String fixturePath = "./src/test/java/ch/bfh/p2bbs/fixture_data/bls12-381-sha-256/";

    @Test
    public void hastToScalarTest(){
        JSONParser jsonParser = new JSONParser();
        try (FileReader reader = new FileReader(fixturePath + "h2s.json")){
            var obj = (JSONObject) jsonParser.parse(reader);
            System.out.println(fixturePath + ": " + obj.get("caseName"));
            var message = OctetString.valueOfHexString((String) obj.get("message"));
            var dst = OctetString.valueOfHexString((String) obj.get("dst"));
            var scalar = new Scalar(new BigInteger((String) obj.get("scalar"), 16));
            var hashedMsg = hash_to_scalar(message,dst);
            assertTrue(hashedMsg.equals(scalar));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void checkGenerators(){
        var api_id = OctetString.valueOf("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_", StandardCharsets.US_ASCII);
        JSONParser jsonParser = new JSONParser();
        try (FileReader reader = new FileReader(fixturePath + "generators.json")){
            var obj = (JSONObject) jsonParser.parse(reader);
            System.out.println(fixturePath + ": " + obj.get("caseName"));
            var MsgGenerators = (JSONArray) obj.get("MsgGenerators");
            var Q1 = (G1Point) G1Point.deserialize(OctetString.valueOfHexString((String) obj.get("Q1")).toBytes());
            var builder = new Vector.Builder<G1Point>();
            builder.addValue(Q1);
            for (var generators: MsgGenerators){
                builder.addValue(G1Point.deserialize(OctetString.valueOfHexString((String) generators).toBytes()));
            }
            var allGenerators = builder.build();
            var generators = create_generators(allGenerators.getLength(), api_id);
            assertTrue(generators.equals(allGenerators));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void messageToScalarAsHashTest(){
        JSONParser jsonParser = new JSONParser();
        try (FileReader reader = new FileReader(fixturePath + "MapMessageToScalarAsHash.json")){
            var obj = (JSONObject) jsonParser.parse(reader);
            System.out.println(fixturePath + ": " + obj.get("caseName"));
            var dst = OctetString.valueOfHexString((String) obj.get("dst"));
            var cases = (JSONArray) obj.get("cases");

            for (Object aCase : cases) {
                var msgCase = (JSONObject) aCase;
                var message = OctetString.valueOfHexString((String) msgCase.get("message"));
                var scalar = new Scalar(new BigInteger((String) msgCase.get("scalar"), 16));
                var hashedMsg = hash_to_scalar(message,dst);
                assertTrue(hashedMsg.equals(scalar));
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void mockedRngTest(){
        JSONParser jsonParser = new JSONParser();
        try (FileReader reader = new FileReader(fixturePath + "mockedRng.json")){
            var obj = (JSONObject) jsonParser.parse(reader);
            System.out.println(fixturePath + ": " + obj.get("caseName"));
            var seed = OctetString.valueOfHexString((String) obj.get("seed"));
            var dst = OctetString.valueOfHexString((String) obj.get("dst"));
            var count = Math.toIntExact((Long) obj.get("count"));
            var mockedScalars = (JSONArray) obj.get("mockedScalars");
            var builder = new Vector.Builder<Scalar>();
            for (var generators: mockedScalars){
                builder.addValue(new Scalar(new BigInteger((String) generators, 16)));
            }
            var allScalars = builder.build();
            var result = mockedRandomScalars(seed, dst, count);
            for (int i = 1; i <= result.getLength(); i++) {
                assertTrue(result.getValue(i).equals(allScalars.getValue(i)));
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }
}