package ch.bfh.p2bbs.proof;

import ch.bfh.p2bbs.Types.OctetString;
import ch.openchvote.util.sequence.Vector;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

class ProofVerifyTest {

    private static final String fixturePath = "./src/test/java/ch/bfh/p2bbs/fixture_data/bls12-381-sha-256/proof/";

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

                var valid = ProofVerify.ProofVerify(publicKey, proof, header, ph, revealedMessages, revealed_indexes);
                assertEquals(result, valid);

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