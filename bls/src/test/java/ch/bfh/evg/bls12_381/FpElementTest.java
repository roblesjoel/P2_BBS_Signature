package ch.bfh.evg.bls12_381;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class FpElementTest {

    static final FpElement ZERO = FpElement.of(BigInteger.ZERO);
    static final FpElement ONE = FpElement.of(BigInteger.ONE);
    static final FpElement TWO = FpElement.of(BigInteger.TWO);
    static final FpElement TEN = FpElement.of(BigInteger.TEN);
    static final FpElement G1_GEN_X = G1Point.GENERATOR.getX();
    static final FpElement G1_GEN_Y = G1Point.GENERATOR.getY();
    static final Stream<FpElement> fixedElements = Stream.of(ZERO, ONE, TEN, G1_GEN_X, G1_GEN_Y);

    static final int n = 100;
    static final Stream<FpElement> randomElements = Stream.generate(FpElement::getRandom).limit(n);

    static final List<FpElement> testElements = Stream.concat(fixedElements, randomElements).toList();


    @Test
    void testToString() {
        for (FpElement element : testElements) {
            assertEquals(FpElement.BYTE_LENGTH * 2, element.toString().length());
        }
        assertEquals("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", ZERO.toString());
        assertEquals("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", ONE.toString());
        assertEquals("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002", TWO.toString());
        assertEquals("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a", TEN.toString());
        assertEquals("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", G1_GEN_X.toString());
        assertEquals("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", G1_GEN_Y.toString());
    }

    @Test
    void testToBigInteger() {
        assertEquals(BigInteger.ZERO, ZERO.toBigInteger());
        assertEquals(BigInteger.ONE, ONE.toBigInteger());
        assertEquals(BigInteger.TWO, TWO.toBigInteger());
        assertEquals(BigInteger.TEN, TEN.toBigInteger());
    }

    @Test
    void testOf() {
        assertDoesNotThrow(() -> {
            for (FpElement element : testElements) {
                assertEquals(element, FpElement.of(element.toBigInteger()));
            }
        });
    }


    @Test
    void testSerialize() {
        for (FpElement element : testElements) {
            assertEquals(FpElement.BYTE_LENGTH, element.serialize().getLength());
        }
    }

    @Test
    void testDeserialize() {
        assertDoesNotThrow(() -> {
            for (FpElement element : testElements) {
                assertEquals(element, FpElement.deserialize(element.serialize()));
            }
        });
    }

    @Test
    void testAdd() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                var sum = FpElement.of(e1.toBigInteger().add(e2.toBigInteger()).mod(FpElement.MODULUS));
                assertEquals(sum, e1.add(e2));
            }
        }
    }

    @Test
    void testSubtract() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                var diff = FpElement.of(e1.toBigInteger().subtract(e2.toBigInteger()).mod(FpElement.MODULUS));
                assertEquals(diff, e1.subtract(e2));
            }
        }
    }

    @Test
    void testMultiply() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                var prod = FpElement.of(e1.toBigInteger().multiply(e2.toBigInteger()).mod(FpElement.MODULUS));
                assertEquals(prod, e1.multiply(e2));
            }
        }
    }

    @Test
    void testDivide() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                if (!e2.isZero()) {
                    var frac = FpElement.of(e1.toBigInteger().multiply(e2.toBigInteger().modInverse(FpElement.MODULUS)).mod(FpElement.MODULUS));
                    assertEquals(frac, e1.divide(e2));
                }
            }
        }
    }

    @Test
    void testPower() {
        for (var e : testElements) {
            assertEquals(ONE, e.power(ZERO));
            assertEquals(e, e.power(ONE));
            assertEquals(e.multiply(e), e.power(TWO));
            assertEquals(e.multiply(e).multiply(e).multiply(e).multiply(e).multiply(e).multiply(e).multiply(e).multiply(e).multiply(e), e.power(TEN));
        }
    }


    @Test
    void testNegate() {
        for (var e : testElements) {
            if (e.isZero()) {
                assertTrue(e.negate().isZero());
            } else {
                var neg = FpElement.of(FpElement.MODULUS.subtract(e.toBigInteger()));
                assertEquals(neg, e.negate());
            }
        }
    }

    @Test
    void testInverse() {
        for (var e : testElements) {
            if (!e.isZero()) {
                var inv = FpElement.of(e.toBigInteger().modInverse(FpElement.MODULUS));
                assertEquals(inv, e.inverse());
            }
        }
    }

    @Test
    void testIsZero() {
        assertTrue(ZERO.isZero());
        assertFalse(ONE.isZero());
        assertFalse(TWO.isZero());
        assertFalse(TEN.isZero());
        assertFalse(G1_GEN_X.isZero());
        assertFalse(G1_GEN_Y.isZero());
    }

    @Test
    void testIsOne() {
        assertFalse(ZERO.isOne());
        assertTrue(ONE.isOne());
        assertFalse(TWO.isOne());
        assertFalse(TEN.isOne());
        assertFalse(G1_GEN_X.isOne());
        assertFalse(G1_GEN_Y.isOne());
    }
}