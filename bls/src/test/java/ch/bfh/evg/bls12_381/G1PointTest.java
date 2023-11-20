package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.ECPoint;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class G1PointTest {

    static final Stream<G1Point> fixedElements = Stream.of(G1Point.ZERO, G1Point.GENERATOR);

    static final int n = 100;
    static final Stream<G1Point> randomElements = Stream.generate(G1Point::getRandom).limit(n);

    static final List<G1Point> testElements = Stream.concat(fixedElements, randomElements).toList();


    @Test
    void testToString() {
        for (G1Point element : testElements) {
            if (!element.isZero()) {
                assertEquals(FpElement.BYTE_LENGTH * 4 + 5, element.toString().length());
            }
        }
        assertEquals(ECPoint.INFINITY, G1Point.ZERO.toString());
        assertEquals("x=17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb y=08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", G1Point.GENERATOR.toString());
    }

    @Test
    void testSerialize() {
        for (G1Point element : testElements) {
            assertEquals(G1Point.BYTE_LENGTH, element.serialize().getLength());
        }
    }

    @Test
    void testDeserialize() {
        assertDoesNotThrow(() -> {
            for (G1Point element : testElements) {
                assertEquals(element, G1Point.deserialize(element.serialize()));
            }
        });
    }

    @Test
    void testAdd() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                assertEquals(e2.add(e1), e1.add(e2));
            }
        }
    }

    @Test
    void testSubtract() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                assertEquals(e2.negate().add(e1), e1.subtract(e2));
            }
        }
    }

    @Test
    void testNegate() {
        for (var e : testElements) {
            if (e.isZero()) {
                assertTrue(e.negate().isZero());
            } else {
                assertEquals(e, e.negate().negate());
                assertEquals(e.getX(), e.negate().getX());
                assertEquals(e.getY(), e.negate().getY().negate());
            }
        }
    }


    @Test
    void testIsZero() {
        assertTrue(G1Point.ZERO.isZero());
        assertFalse(G1Point.GENERATOR.isZero());
    }

}