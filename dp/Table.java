import java.util.List;
import java.util.ArrayList;
import java.util.Random;

public class Table {
    private int[] dp;
    private int[] ldp;
    private Random rand;

    public Table(int size) {
        this.dp = new int[size];
        this.ldp = new int[size];

        for (int i = 0; i < size; ++i) {
            this.dp[i] = 0;
            this.ldp[i] = 0;
        }

        this.rand = new Random();
    }

    public void addDP(int n) {
        this.dp[n] += 1;
    }

    public void addLDP(int n) {
        this.ldp[n] += 1;

        List<Integer> list = rr();
        for (int i : list) {
            this.ldp[i] += 1;
        }
    }

    public void applyDP() {
    }

    private List<Integer> rr() {
        List<Integer> list = new ArrayList<>();
        while (rand.nextDouble() >= 0.5) {
            list.add(rand.nextInt(this.ldp.length));
        }

        return list;
    }

    private int[] calMax() {
        int[] max = new int[2];
        max[0] = this.dp[0];
        max[1] = this.ldp[0];

        for (int i = 1; i < this.dp.length; ++i) {
            if (dp[i] > max[0]) max[0] = dp[i];
            if (ldp[i] > max[1]) max[1] = ldp[i];
        }

        return max;
    }

    private int[] calMin() {
        int[] min = new int[2];
        min[0] = this.dp[0];
        min[1] = this.ldp[0];

        for (int n: this.dp) {
            if (n < min[0])
                min[0] = n;
        }

        for (int n: this.ldp) {
            if (n < min[1])
                min[1] = n;
        }

        return min;
    }

    private double[] calAve() {
        double[] ave = new double[2];

        int dp_sum = 0;
        for (int n: this.dp) dp_sum += n;
        ave[0] = (double)dp_sum/this.dp.length;

        int ldp_sum = 0;
        for (int n: this.ldp) ldp_sum += n;
        ave[1] = (double)ldp_sum/this.ldp.length;

        return ave;
    }

    public void printMax() {
        int[] max = calMax();
        System.out.println("Max(DP): " + max[0]);
        System.out.println("Max(LDP): " + max[1]);
    }

    public void printMin() {
        int[] min = calMin();
        System.out.println("Min(DP): " + min[0]);
        System.out.println("Min(LDP): " + min[1]);
    }

    public void printAverage() {
        double[] ave = calAve();
        System.out.println("Average(DP): " + ave[0]);
        System.out.println("Average(LDP): " + ave[1]);
    }

    public String getFrequencyTableDP() {
        StringBuilder sb = new StringBuilder();

        int size = this.dp.length / 100;
        for (int i = 0; i < 100; ++i) {
            int cnt = 0;
            for (int j = i; j < size; ++j) {
                cnt += this.dp[i*size+j];
            }
            sb.append(cnt);
            sb.append("\n");
        }

        return sb.toString();
    }

    public String getFrequencyTableLDP() {
        StringBuilder sb = new StringBuilder();

        int size = this.dp.length / 100;
        for (int i = 0; i < 100; ++i) {
            int cnt = 0;
            for (int j = i; j < size; ++j) {
                cnt += this.ldp[i*size+j];
            }
            sb.append(cnt);
            sb.append("\n");
        }

        return sb.toString();
    }
}
