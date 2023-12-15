public class PseudoRandomGenerator {
    private static final long M = (long) (Math.pow(2, 17) - 1);
    private static final long A = (long) Math.pow(4, 3);
    private static final long C = 21;
    private static final long X0 = 256;

    private long previousX;

    public PseudoRandomGenerator() {
        this.previousX = X0;
    }

    public long generateNext() {
        previousX = (A * previousX + C) % M;

        return previousX;
    }
}
