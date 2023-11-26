import java.math.BigInteger;
import java.util.Objects;

public class PointG2 {

    public static final BigInteger P = new BigInteger("11", 10);
    private final Polynomial x;
    private final Polynomial y;

    PointG2(Polynomial x, Polynomial y){
        this.x = x;
        this.y = y;
    }

    boolean isInfinity(){

    }


    private static PointG2 add(PointG2 p1){


    }

    private static PointG2 doublePoint(){

    }

    private static PointG2 scalarMultiply(BigInteger k){

    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PointG2 pointG2 = (PointG2) o;
        return Objects.equals(x, pointG2.x) && Objects.equals(y, pointG2.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }
}
