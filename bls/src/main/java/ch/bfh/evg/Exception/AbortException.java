package ch.bfh.evg.Exception;

public class AbortException extends Exception{
    public AbortException(String errorMessage){
        super(errorMessage);
    }
}
