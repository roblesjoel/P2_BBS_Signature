package ch.bfh.p2bbs.excptions;

public class Abort extends RuntimeException{
    public Abort(String message){
        super(message);
    }
}
