module bbs {
    exports ch.bfh.p2bbs;
    exports ch.bfh.p2bbs.signature;
    exports ch.bfh.p2bbs.proof;
    exports ch.bfh.p2bbs.key;
    requires ch.openchvote.utilities;
    requires org.bouncycastle.provider;
    requires ch.bfh.evg.bls;
}