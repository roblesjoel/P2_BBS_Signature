package ch.bfh.p2bbs.utils;

import ch.bfh.hnr1.bls.*;
import ch.bfh.p2bbs.Types.G1Point;
import ch.bfh.p2bbs.Types.OctetString;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Definitions {
    public static final OctetString CIPHERSUITE_ID = OctetString.valueOf("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_", StandardCharsets.US_ASCII); // Ciphersuite ID,BLS12-381-SHAKE-256
    public static final SecureRandom SECURE_RANDOM = new SecureRandom(); // Random generator method
    public static final OctetString Octet_Scalar_Length = OctetString.valueOf(32);
    public static final OctetString Octet_Point_Length = OctetString.valueOf(48);
    public static final int Expand_Len = 48;
    public static final BigInteger r = new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    public static final BLS12 BLS12381 = new BLS12(Params.BLS12_381);
    public static final BLS.G1 G1 = BLS12381.G1;
    public static final BLS.G2 G2 = BLS12381.G2;
    public static final BLS12.GT GT = BLS12381.GT;
    public static final G1Point P1 = G1Point.GENERATOR;


    // Source: page 18 of https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-02
    private static final String x0 = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    private static final String x1 = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    private static final String y0 = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
    private static final String y1 = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
}
