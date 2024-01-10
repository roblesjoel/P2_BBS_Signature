package ch.bfh.p2bbs.utils;

import ch.bfh.hnr1.bls.BLS;
import ch.bfh.hnr1.element.ECPoint;
import ch.bfh.hnr1.element.Fp2Element;
import ch.bfh.hnr1.element.FpElement;
import ch.bfh.hnr1.elliptic_curve.WeierstrassCurve;
import ch.bfh.hnr1.field.Fp;
import ch.bfh.hnr1.field.Fp12;
import ch.bfh.hnr1.field.Fp2;
import ch.bfh.hnr1.field.Fp6;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Set;

// see Section 8.8 in RFC 9380 "Hashing to Elliptic Curves"
public enum Params {

    // 128 bits security
    BLS12_381(
            12,
            128,
            Set.of(),
            Set.of(16, 48, 57, 60, 62, 63),
            "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
            "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
            "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
            "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_",
            "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_",
            "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_",
            "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_NU_",
            new String[]{
                    "11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7",
                    "17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb",
                    "d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0",
                    "1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861",
                    "e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9",
                    "1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983",
                    "d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84",
                    "17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e",
                    "80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317",
                    "169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e",
                    "10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b",
                    "6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229"},
            new String[]{
                    "8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c",
                    "12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff",
                    "b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19",
                    "3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8",
                    "13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e",
                    "e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5",
                    "772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a",
                    "14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e",
                    "a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641",
                    "95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a",
                    "1"},
            new String[]{
                    "90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33",
                    "134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696",
                    "cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6",
                    "1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb",
                    "8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb",
                    "16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0",
                    "4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2",
                    "987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29",
                    "9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587",
                    "e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30",
                    "19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132",
                    "18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e",
                    "b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8",
                    "245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133",
                    "5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b",
                    "15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604"},
            new String[]{
                    "16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1",
                    "1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d",
                    "58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2",
                    "16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416",
                    "be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d",
                    "8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac",
                    "166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c",
                    "16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9",
                    "1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a",
                    "167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55",
                    "4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8",
                    "accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092",
                    "ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc",
                    "2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7",
                    "e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f",
                    "1"},
            new String[]{
                    "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
                    "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
                    "0",
                    "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a",
                    "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
                    "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d",
                    "171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
                    "0"
            },
            new String[]{
                    "0",
                    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63",
                    "c",
                    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f",
                    "1",
                    "0"
            },
            new String[]{
                    "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
                    "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
                    "0",
                    "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be",
                    "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
                    "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f",
                    "124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
                    "0"
            },
            new String[]{
                    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
                    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
                    "0",
                    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3",
                    "12",
                    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99",
                    "1",
                    "0"
            }),
    // 192 bits security (see "On the Computation of the Optimal Ate Pairing at the 192-bit Security Level")
    BLS12_461( // according to Section 7.1.2 in "Updating key size estimations for pairings"
            12,
            128,
            Set.of(50, 33),
            Set.of(77),
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "",
            "",
            "",
            "",
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{}),
    BLS12_641(
            12,
            192,
            Set.of(84, 19),
            Set.of(107),
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "",
            "",
            "",
            "",
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{},
            new String[]{});

    // BLS12 parameters
    public final int k; // embedding degree
    public final int kappa; // security level
    public final Set<Integer> u_bits_pos;
    public final Set<Integer> u_bits_neg;
    public final BigInteger u;
    public final BigInteger p; // modulo
    public final BigInteger r; // order
    public final BigInteger t; // trace

    // fields
    public final Fp Fp;
    public final Fp2 Fp2;
    public final Fp6 Fp6;
    public final Fp12 Fp12;

    // E1 parameters
    public final BLS.Curve<FpElement, Fp> E1;
    public final FpElement E1_a;
    public final FpElement E1_b;

    // E2 parameters
    public final BLS.Curve<Fp2Element, Fp2> E2;
    public final Fp2Element E2_a;
    public final Fp2Element E2_b;

    // G1 parameters
    public final BigInteger G1_h;
    public final ECPoint<FpElement, Fp> G1_g;
    public final byte[] G1_DST_hash;
    public final byte[] G1_DST_encode;
    public final FpElement G1_Z;
    public final FpElement[] G1_k1;
    public final FpElement[] G1_k2;
    public final FpElement[] G1_k3;
    public final FpElement[] G1_k4;

    // G2 parameters
    public final BigInteger G2_h;
    public final ECPoint<Fp2Element, Fp2> G2_g;
    public final byte[] G2_DST_hash;
    public final byte[] G2_DST_encode;
    public final Fp2Element G2_Z;
    public final Fp2Element[] G2_k1;
    public final Fp2Element[] G2_k2;
    public final Fp2Element[] G2_k3;
    public final Fp2Element[] G2_k4;

    // GT parameters
    public final BigInteger GT_h;

    Params(int k, int kappa, Set<Integer> u_bits_pos, Set<Integer> u_bits_neg, String G1_x, String G1_y, String G2_x0, String G2_x1, String G2_y0, String G2_y1, String G1_DST_hash, String G1_DST_encode, String G2_DST_hash, String G2_DST_encode, String[] G1_k1, String[] G1_k2, String[] G1_k3, String[] G1_k4, String[] G2_k1, String[] G2_k2, String[] G2_k3, String[] G2_k4) {

        // BLS12 parameters
        this.k = k;
        this.kappa = kappa;
        this.u_bits_pos = u_bits_pos;
        this.u_bits_neg = u_bits_neg;
        var u_pos = u_bits_pos.stream().map(BigInteger.TWO::pow).reduce(BigInteger.ZERO, BigInteger::add);
        var u_neg = u_bits_neg.stream().map(BigInteger.TWO::pow).reduce(BigInteger.ZERO, BigInteger::add);
        this.u = u_pos.subtract(u_neg);
        this.r = u.pow(4).subtract(u.pow(2)).add(BigInteger.ONE);
        this.p = u.subtract(BigInteger.ONE).pow(2).multiply(this.r).divide(BigInteger.valueOf(3)).add(u);
        this.t = this.u.add(BigInteger.ONE);

        // fields
        this.Fp = new Fp(this.p, this.kappa);
        this.Fp2 = new Fp2(this.Fp);
        this.Fp6 = new Fp6(this.Fp2);
        this.Fp12 = new Fp12(this.Fp6);

        // auxiliary variables
        var zero = FpElement.getZero(this.p);
        var one = FpElement.getOne(this.p);
        var two = this.Fp.twice(one);
        var eleven = this.Fp.times(one, 11);

        // curve parameters for E'_1 and E'_2, see Section 8.8 in RFC 9380 "Hashing to Elliptic Curves" or Section 4.3 in "Fast and simple constant-time hashing to the BLS12-381 elliptic curve"
        var a1_prime = FpElement.valueOf(this.p, "144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d");
        var b1_prime = FpElement.valueOf(this.p, "12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0");
        var E1_prime = new WeierstrassCurve<>(this.Fp, a1_prime, b1_prime);
        var a2_prime = Fp2Element.valueOf(this.p, BigInteger.ZERO, BigInteger.valueOf(240));
        var b2_prime = Fp2Element.valueOf(this.p, BigInteger.valueOf(1012), BigInteger.valueOf(1012));
        var E2_prime = new WeierstrassCurve<>(this.Fp2, a2_prime, b2_prime);

        // curve parameters for E_1 and E_2
        this.E1_a = zero;
        this.E1_b = FpElement.valueOf(this.p, BigInteger.valueOf(4));
        this.E1 = new BLS.Curve<>(this.E1_b, E1_prime);
        this.E2_a = Fp2Element.valueOf(zero, zero);
        this.E2_b = Fp2Element.valueOf(this.E1_b, this.E1_b);
        this.E2 = new BLS.Curve<>(this.E2_b, E2_prime);

        // group parameters G1
        this.G1_h = this.u.subtract(BigInteger.ONE).pow(2).divide(BigInteger.valueOf(3));
        this.G1_g = ECPoint.valueOf(this.Fp, FpElement.valueOf(this.p, G1_x), FpElement.valueOf(this.p, G1_y));
        // group parameters G2
        this.G2_h = this.u.pow(8) // see https://jinsnotes.com/2021-09-25-bls-12-381-basics
                .subtract(this.u.pow(7).multiply(BigInteger.valueOf(4)))
                .add(this.u.pow(6).multiply(BigInteger.valueOf(5)))
                .subtract(this.u.pow(4).multiply(BigInteger.valueOf(4)))
                .add(this.u.pow(3).multiply(BigInteger.valueOf(6)))
                .subtract(this.u.pow(2).multiply(BigInteger.valueOf(4)))
                .subtract(this.u.multiply(BigInteger.valueOf(4)))
                .add(BigInteger.valueOf(13))
                .divide(BigInteger.valueOf(9));
        this.G2_g = ECPoint.valueOf(this.Fp2, Fp2Element.valueOf(this.p, G2_x0, G2_x1), Fp2Element.valueOf(this.p, G2_y0, G2_y1));

        // group parameters GT
        this.GT_h = this.Fp12.getGroup().getOrder().divide(this.r);

        // hashToCurve parameters G1 (see Section 8.8 in RFC 9380 "Hashing to Elliptic Curves")
        this.G1_DST_hash = this.asciiStringToBytes(G1_DST_hash);
        this.G1_DST_encode = this.asciiStringToBytes(G1_DST_encode);
        this.G1_Z = eleven;
        this.G1_k1 = this.getFpCoefficients(G1_k1);
        this.G1_k2 = this.getFpCoefficients(G1_k2);
        this.G1_k3 = this.getFpCoefficients(G1_k3);
        this.G1_k4 = this.getFpCoefficients(G1_k4);

        // hashToCurve parameters G2 (see Section 8.8 in RFC 9380 "Hashing to Elliptic Curves")
        this.G2_DST_hash = this.asciiStringToBytes(G2_DST_hash);
        this.G2_DST_encode = this.asciiStringToBytes(G2_DST_encode);
        this.G2_Z = this.Fp2.negate(Fp2Element.valueOf(two, one));
        this.G2_k1 = this.getFp2Coefficients(G2_k1);
        this.G2_k2 = this.getFp2Coefficients(G2_k2);
        this.G2_k3 = this.getFp2Coefficients(G2_k3);
        this.G2_k4 = this.getFp2Coefficients(G2_k4);
    }

    private FpElement[] getFpCoefficients(String[] strings) {
        var constants = new FpElement[strings.length];
        for (int i = 0; i < strings.length; i++) {
            constants[i] = FpElement.valueOf(this.p, strings[i]);
        }
        return constants;
    }

    private Fp2Element[] getFp2Coefficients(String[] strings) {
        var constants = new Fp2Element[strings.length / 2];
        for (int i = 0; i < strings.length / 2; i++) {
            constants[i] = Fp2Element.valueOf(this.p, strings[2 * i], strings[2 * i + 1]);
        }
        return constants;
    }

    @Override
    public String toString() {
        var bits = this.p.bitLength();
        return String.format("BLS%d-%d%n", this.k, bits)
                + String.format("  u = %X%n", this.u)
                + String.format("u_w = %X%n", this.u_bits_neg.size() + this.u_bits_pos.size())
                + String.format("  p = %X (%d bits)%n", this.p, this.p.bitLength())
                + String.format("  r = %X (%d bits)%n", this.r, this.r.bitLength())
                + String.format("  t = %X (%d bits)%n", this.t, this.t.bitLength())
                + String.format(" E1 = %s%n", this.E1)
                + String.format(" E1 = %s%n", this.E2)
                + String.format(" h1 = %X (%d bits)%n", this.G1_h, this.G1_h.bitLength())
                + String.format(" h2 = %X (%d bits)%n", this.G2_h, this.G2_h.bitLength())
                + String.format(" hT = %X (%d bits)%n", this.GT_h, this.GT_h.bitLength());
    }

    private byte[] asciiStringToBytes(String str) {
        return str.getBytes(StandardCharsets.US_ASCII);
    }

}
