package ch.bfh.p2bbs;

import ch.bfh.p2bbs.key.KeyGen;
import ch.bfh.p2bbs.Types.OctetString;

public class MainBBS {

    public static void main(String[] args){
        OctetString key_material = new OctetString(new byte[256]);
        OctetString key_info = new OctetString(new byte[0]);
        OctetString key_dst = new OctetString(new byte[0]);
        var secretKey = KeyGen.KeyGen(key_material, key_info, key_dst);
        var publicKey = KeyGen.SkToPk(secretKey);
    }


}
