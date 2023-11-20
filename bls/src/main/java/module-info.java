module BLS {
    opens ch.bfh.evg.jni;
    exports ch.bfh.evg;
    exports ch.bfh.evg.bls12_381;
    exports ch.bfh.evg.group;
    exports ch.bfh.evg.signature;
    requires ch.openchvote.utilities;
}