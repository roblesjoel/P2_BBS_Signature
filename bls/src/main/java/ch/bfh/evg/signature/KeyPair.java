package ch.bfh.evg.signature;

import ch.openchvote.util.tuples.Pair;

public class KeyPair<SK, PK> extends Pair<SK, PK> {
    public KeyPair(SK first, PK second) {
        super(first, second);
    }
    public SK getSecretKey() {
        return this.getFirst();
    }

    public PK getPublicKey() {
        return this.getSecond();
    }
}
