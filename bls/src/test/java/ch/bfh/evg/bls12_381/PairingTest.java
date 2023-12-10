package ch.bfh.evg.bls12_381;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PairingTest {

    static final List<G1Point> g1Points = List.of(G1Point.ZERO, G1Point.GENERATOR, G1Point.GENERATOR.times(Scalar.getRandom()));
    static final List<G2Point> g2Points = List.of(G2Point.ZERO, G2Point.GENERATOR, G2Point.GENERATOR.times(Scalar.getRandom()));
    static final Scalar ZERO = Scalar.of(BigInteger.ZERO);
    static final Scalar ONE = Scalar.of(BigInteger.ONE);
    static final Scalar TWO = Scalar.of(BigInteger.TWO);
    static final Scalar TEN = Scalar.of(BigInteger.TEN);
    static final Scalar RANDOM = Scalar.getRandom();
    static final List<Scalar> exponents = List.of(ZERO, ONE, TWO, TEN, RANDOM);


    @Test
    void testPair() {
        for (var g1Point : g1Points) {
            for (var g2Point : g2Points) {
                var g12 = g1Point.pair(g2Point);
                for (var a : exponents) {
                    for (var b : exponents) {
                        assertEquals(g12.power(a.times(b)), g1Point.times(a).pair(g2Point.times(b)));
                    }
                }
            }
        }

    }

}