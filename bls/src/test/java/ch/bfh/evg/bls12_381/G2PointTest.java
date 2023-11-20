package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.ECPoint;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class G2PointTest {

    static final Stream<G2Point> fixedElements = Stream.of(G2Point.ZERO, G2Point.GENERATOR);

    static final int n = 100;
    static final Stream<G2Point> randomElements = Stream.generate(G2Point::getRandom).limit(n);

    static final List<G2Point> testElements = Stream.concat(fixedElements, randomElements).toList();


    @Test
    void testToString() {
        for (G2Point element : testElements) {
            if (!element.isZero()) {
                assertEquals(FpElement.BYTE_LENGTH * 8 + 15, element.toString().length());
            }
        }
        assertEquals(ECPoint.INFINITY, G2Point.ZERO.toString());
        assertEquals("x0=024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 x1=13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e y0=0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 y1=0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be", G2Point.GENERATOR.toString());
    }

    @Test
    void testSerialize() {
        for (G2Point element : testElements) {
            assertEquals(G2Point.BYTE_LENGTH, element.serialize().getLength());
        }
    }

    @Test
    void testDeserialize() {
        assertDoesNotThrow(() -> {
            for (G2Point element : testElements) {
                assertEquals(element, G2Point.deserialize(element.serialize()));
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
            }
        }
    }


    @Test
    void testIsZero() {
        assertTrue(G2Point.ZERO.isZero());
        assertFalse(G2Point.GENERATOR.isZero());
    }

}