package ch.bfh.evg.group;

import ch.openchvote.util.sequence.ByteArray;

public interface GroupElement {

    ByteArray serialize();

    class DeserializationException extends Exception {

        public DeserializationException(ByteArray byteArray, Throwable cause) {
            super("Bad input: " + byteArray + " (" + byteArray.getLength() + ")", cause);
        }
    }

}
