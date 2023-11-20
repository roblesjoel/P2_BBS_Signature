package ch.bfh.evg.signature;

import ch.bfh.evg.bls12_381.FrElement;
import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.G2Point;
import ch.bfh.evg.jni.JNI;
import ch.openchvote.util.set.IntSet;
import ch.openchvote.util.sequence.Vector;
import ch.openchvote.util.tuples.*;

import java.security.SecureRandom;
import java.util.stream.IntStream;

public class BBS extends JNI {

    public static final String CIPHERSUITE_ID = "BBS_BLS12381G1"; // hash-to-curve suite ID missing
    private static final G1Point P1 = G1Point.GENERATOR;
    private static final G2Point P2 = G2Point.GENERATOR;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static class Signature extends Triple<G1Point, FrElement, FrElement> {
        public Signature(G1Point A, FrElement e, FrElement s) {
            super(A, e, s);
        }
    }

    public static class Proof extends Nonuple<G1Point, G1Point, G1Point, FrElement, FrElement, FrElement, FrElement, FrElement, Vector<FrElement>> {
        public Proof(G1Point A_prime, G1Point A_bar, G1Point D, FrElement c, FrElement e_hat, FrElement r2_hat, FrElement r3_hat, FrElement s_hat, Vector<FrElement> bold_m_j) {
            super(A_prime, A_bar, D, c, e_hat, r2_hat, r3_hat, s_hat, bold_m_j);
        }
    }

    // SIGNATURE SCHEME METHODS

    public static KeyPair<FrElement, G2Point> generateKeyPair() {
        var sk = FrElement.getRandom();
        var PK = P2.times(sk);
        return new KeyPair<>(sk, PK);
    }

    public static Signature generateSignature(FrElement sk, G2Point PK, String header, Vector<String> strMessages) {
        var messages = strMessages.map(FrElement::hashAndMap);
        // Definitions
        int L = messages.getLength();
        // Precomputations
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Procedure
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var e_s = FrElement.hashAndMap(new Triple<>(sk, domain, messages), 2);
        var e = e_s.getValue(1);
        var s = e_s.getValue(2);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        var A = B.times(sk.add(e).inverse());
        return new Signature(A, e, s);
    }

    public static boolean verifySignature(G2Point PK, Signature signature, String header, Vector<String> strMessages) {
        var messages = strMessages.map(FrElement::hashAndMap);
        // Definitions
        int L = messages.getLength();
        // Precomputations
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Procedure
        var A = signature.getFirst();
        var e = signature.getSecond();
        var s = signature.getThird();
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        return A.pair(PK.add(G2Point.GENERATOR.times(e))).multiply(B.pair(P2.negate())).isOne();
    }

    public static Proof generateProof(G2Point PK, Signature signature, String header, String ph, Vector<String> strMessages, IntSet disclosedIndices) {
        var messages = strMessages.map(FrElement::hashAndMap);
        // Definitions
        int L = messages.getLength();
        int R = (int) disclosedIndices.getSize();
        int U = L - R;
        int prfLen = FrElement.BYTE_LENGTH;
        // Precomputations
        var validIndices = IntSet.range(1, L);
        var undisclosedIndices = validIndices.difference(disclosedIndices); // size = U
        var undisclosedMessages = messages.select(undisclosedIndices);
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Procedure
        var A = signature.getFirst();
        var e = signature.getSecond();
        var s = signature.getThird();
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var scalars = FrElement.hashAndMap(randomBytes(prfLen), 6);
        var r1 = scalars.getValue(1);
        var r2 = scalars.getValue(2);
        var e_tilde = scalars.getValue(3);
        var r2_tilde = scalars.getValue(4);
        var r3_tilde = scalars.getValue(5);
        var s_tilde = scalars.getValue(6);
        var bold_m_tilde = FrElement.hashAndMap(randomBytes(prfLen), U);
        var B = P1.add(Q1.times(s)).add(Q2.times(domain)).add(sumOfProducts(MsgGenerators, messages));
        var r3 = r1.inverse();
        var A_prime = A.times(r1);
        var A_bar = A_prime.times(e.negate()).add(B.times(r1));
        var D = B.times(r1).add(Q1.times(r2));
        var s_prime = r2.multiply(r3).add(s);
        var C1 = A_prime.times(e_tilde).add(Q1.times(r2_tilde));
        var C2 = D.times(r3_tilde.negate()).add(Q1.times(s_tilde)).add(sumOfProducts(MsgGenerators.select(undisclosedIndices), bold_m_tilde));
        var c_array = new Decuple<>(A_prime, A_bar, D, C1, C2, R, disclosedIndices, messages.select(disclosedIndices), domain, ph);
        var c = FrElement.hashAndMap(c_array);
        var e_hat = e.multiply(c).add(e_tilde);
        var r2_hat = r2.multiply(c).add(r2_tilde);
        var r3_hat = r3.multiply(c).add(r3_tilde);
        var s_hat = s_prime.multiply(c).add(s_tilde);
        var bold_m_hat = undisclosedMessages.map(msg -> msg.times(c)).map(bold_m_tilde, FrElement::add);
        return new Proof(A_prime, A_bar, D, c, e_hat, r2_hat, r3_hat, s_hat, bold_m_hat);
    }

    public static boolean verifyProof(G2Point PK, Proof proof, String header, String ph, Vector<String> disclosedStrMessages, IntSet disclosedIndices) {
        var disclosedMessages = disclosedStrMessages.map(FrElement::hashAndMap);
        // Definitions
        int R = (int) disclosedIndices.getSize();
        int U = proof.getNinth().getLength();
        int L = R + U;
        // Precomputations
        var validIndices = IntSet.range(1, L);
        var undisclosedIndices = validIndices.difference(disclosedIndices); // size = U
        var Generators = createGenerators(L + 2);
        var Q1 = Generators.getValue(1);
        var Q2 = Generators.getValue(2);
        var MsgGenerators = Generators.select(IntSet.range(3, L + 2));
        // Preconditions
        if (disclosedStrMessages.getLength() != R) return false;
        if (!validIndices.containsAll(disclosedIndices)) return false;
        // Procedure
        var A_prime = proof.getFirst();
        var A_bar = proof.getSecond();
        var D = proof.getThird();
        var c = proof.getFourth();
        var e_hat = proof.getFifth();
        var r2_hat = proof.getSixth();
        var r3_hat = proof.getSeventh();
        var s_hat = proof.getEighth();
        var bold_m_hat = proof.getNinth();
        var domArray = new Septuple<>(PK, L, Q1, Q2, MsgGenerators, CIPHERSUITE_ID, header);
        var domain = FrElement.hashAndMap(domArray);
        var C1 = A_bar.subtract(D).times(c).add(A_prime.times(e_hat).add(Q1.times(r2_hat)));
        var T = P1.add(Q2.times(domain)).add(sumOfProducts(MsgGenerators.select(disclosedIndices), disclosedMessages));
        var C2 = T.times(c).subtract(D.times(r3_hat)).add(Q1.times(s_hat)).add(sumOfProducts(MsgGenerators.select(undisclosedIndices), bold_m_hat));
        var cv_array = new Decuple<>(A_prime, A_bar, D, C1, C2, R, disclosedIndices, disclosedMessages, domain, ph);
        var cv = FrElement.hashAndMap(cv_array);
        if (!c.equals(cv)) return false;
        if (A_prime.isZero()) return false;
        return A_prime.pair(PK).multiply(A_bar.pair(P2.negate())).isOne();
    }

    // PRIVATE HELPER METHODS

    private static G1Point sumOfProducts(Vector<G1Point> bases, Vector<FrElement> exponents) {
        return bases.map(exponents, G1Point::times).toStream().reduce(G1Point.ZERO, G1Point::add);
    }

    // simplified version for testing
    private static Vector<G1Point> createGenerators(int count) {
        var builder = new Vector.Builder<G1Point>();
        IntStream.rangeClosed(1, count)
                .mapToObj(i -> "Generator-" + i)
                .map(G1Point::hashAndMap)
                .forEach(builder::addValue);
        return builder.build();
    }

    private static byte[] randomBytes(int n) {
        var randomBytes = new byte[n];
        SECURE_RANDOM.nextBytes(randomBytes);
        return randomBytes;
    }

}
