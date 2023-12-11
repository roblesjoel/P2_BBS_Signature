import java.math.BigInteger;

public class Main {
    public static void main(String[] args) {


        final BigInteger P = new BigInteger("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);

        final BigInteger R = new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

        final BigInteger R_G2 = new BigInteger("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);


        PointG1 gener1 = new PointG1( new BigInteger("017F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB", 16),
                new BigInteger("008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",16));


        PointG2 gener2 = new PointG2(new Polynomial(new BigInteger("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", 16), new BigInteger("013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e", 16)),
                new Polynomial(new BigInteger("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801", 16), new BigInteger("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be", 16)));



        //System.out.println(gener1.scalarMultiply(BigInteger.TWO).toString());

        //System.out.println(gener2.scalarMultiply(R_G2).toString());

        //System.out.println(gener2.scalarMultiply(BigInteger.TWO).toString());
        System.out.println(gener2.doublePoint().toString());

    }
}