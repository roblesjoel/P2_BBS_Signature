package ch.bfh.evg.bls12_381;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class FrElementTest {

    static final FrElement ZERO = FrElement.of(BigInteger.ZERO);
    static final FrElement ONE = FrElement.of(BigInteger.ONE);
    static final FrElement TWO = FrElement.of(BigInteger.TWO);
    static final FrElement TEN = FrElement.of(BigInteger.TEN);
    static final Stream<FrElement> fixedElements = Stream.of(ZERO, ONE, TEN);

    static final int n = 100;
    static final Stream<FrElement> randomElements = Stream.generate(FrElement::getRandom).limit(n);

    static final List<FrElement> testElements = Stream.concat(fixedElements, randomElements).toList();


    @Test
    void testToString() {
        for (FrElement element : testElements) {
            assertEquals(FrElement.BYTE_LENGTH * 2, element.toString().length());
        }
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", ZERO.toString());
        assertEquals("0000000000000000000000000000000000000000000000000000000000000001", ONE.toString());
        assertEquals("0000000000000000000000000000000000000000000000000000000000000002", TWO.toString());
        assertEquals("000000000000000000000000000000000000000000000000000000000000000a", TEN.toString());
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
            for (FrElement element : testElements) {
                assertEquals(element, FrElement.of(element.toBigInteger()));
            }
        });
    }


    @Test
    void testSerialize() {
        for (FrElement element : testElements) {
            assertEquals(FrElement.BYTE_LENGTH, element.serialize().getLength());
        }
    }

    @Test
    void testDeserialize() {
        assertDoesNotThrow(() -> {
            for (FrElement element : testElements) {
                assertEquals(element, FrElement.deserialize(element.serialize()));
            }
        });
    }

    @Test
    void testAdd() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                var sum = FrElement.of(e1.toBigInteger().add(e2.toBigInteger()).mod(FrElement.MODULUS));
                assertEquals(sum, e1.add(e2));
            }
        }
    }

    @Test
    void testSubtract() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                var diff = FrElement.of(e1.toBigInteger().subtract(e2.toBigInteger()).mod(FrElement.MODULUS));
                assertEquals(diff, e1.subtract(e2));
            }
        }
    }

    @Test
    void testMultiply() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                var prod = FrElement.of(e1.toBigInteger().multiply(e2.toBigInteger()).mod(FrElement.MODULUS));
                assertEquals(prod, e1.multiply(e2));
            }
        }
    }

    @Test
    void testDivide() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                if (!e2.isZero()) {
                    var frac = FrElement.of(e1.toBigInteger().multiply(e2.toBigInteger().modInverse(FrElement.MODULUS)).mod(FrElement.MODULUS));
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
                var neg = FrElement.of(FrElement.MODULUS.subtract(e.toBigInteger()));
                assertEquals(neg, e.negate());
            }
        }
    }

    @Test
    void testInverse() {
        for (var e : testElements) {
            if (!e.isZero()) {
                var inv = FrElement.of(e.toBigInteger().modInverse(FrElement.MODULUS));
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
    }

    @Test
    void testIsOne() {
        assertFalse(ZERO.isOne());
        assertTrue(ONE.isOne());
        assertFalse(TWO.isOne());
        assertFalse(TEN.isOne());
    }
}