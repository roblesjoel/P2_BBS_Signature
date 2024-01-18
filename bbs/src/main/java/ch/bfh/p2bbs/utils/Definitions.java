package ch.bfh.p2bbs.utils;

import ch.bfh.hnr1.bls.*;
import ch.bfh.p2bbs.Types.G1Point;
import ch.bfh.p2bbs.Types.OctetString;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Definitions {
    public static final OctetString CIPHERSUITE_ID = OctetString.valueOf("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_", StandardCharsets.US_ASCII); // Ciphersuite ID,BLS12-381-SHAKE-256
    public static final SecureRandom SECURE_RANDOM = new SecureRandom(); // Random generator method
    public static final OctetString Octet_Scalar_Length = OctetString.valueOf(32);
    public static final OctetString Octet_Point_Length = OctetString.valueOf(48);
    public static final int Expand_Len = 48;
    public static final BigInteger r = new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    public static final BLS12 BLS12381 = new BLS12(Params.BLS12_381);
    public static final BLS.G1 G1 = BLS12381.G1;
    public static final BLS.G2 G2 = BLS12381.G2;
    public static final BLS12.GT GT = BLS12381.GT;
    public static final G1Point P1 = G1Point.deserialize(OctetString.valueOfHexString("a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9").toBytes());
}
