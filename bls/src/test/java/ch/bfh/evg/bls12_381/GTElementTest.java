package ch.bfh.evg.bls12_381;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class GTElementTest {

    static final Stream<GTElement> fixedElements = Stream.of(GTElement.ONE, GTElement.GENERATOR);

    static final int n = 100;
    static final Stream<GTElement> randomElements = Stream.generate(GTElement::getRandom).limit(n);

    static final List<GTElement> testElements = Stream.concat(fixedElements, randomElements).toList();


    @Test
    void testToString() {
        for (GTElement element : testElements) {
            if (!element.isOne()) {
                assertEquals(FpElement.BYTE_LENGTH * 24 + 11, element.toString().length());
            }
        }
        assertEquals("0".repeat(FpElement.BYTE_LENGTH * 24), GTElement.ONE.toString().replaceFirst("1", "0").replaceAll("\s", ""));
    }

    @Test
    void testSerialize() {
        for (GTElement element : testElements) {
            assertEquals(GTElement.BYTE_LENGTH, element.serialize().getLength());
        }
    }

    @Test
    void testDeserialize() {
        assertDoesNotThrow(() -> {
            for (GTElement element : testElements) {
                assertEquals(element, GTElement.deserialize(element.serialize()));
            }
        });
    }

    @Test
    void testMultiply() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                assertEquals(e2.multiply(e1), e1.multiply(e2));
            }
        }
    }

    @Test
    void testDivide() {
        for (var e1 : testElements) {
            for (var e2 : testElements) {
                assertEquals(e2.inverse().multiply(e1), e1.divide(e2));
            }
        }
    }

    @Test
    void testNegate() {
        for (var e : testElements) {
            if (e.isOne()) {
                assertTrue(e.inverse().isOne());
            } else {
                assertEquals(e, e.inverse().inverse());
            }
        }
    }


    @Test
    void testIsZero() {
        assertTrue(GTElement.ONE.isOne());
        assertFalse(GTElement.GENERATOR.isOne());
    }

}