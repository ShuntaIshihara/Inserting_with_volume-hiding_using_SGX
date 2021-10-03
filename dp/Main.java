import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

public class Main{
    static public void main(String[] args) {
        if (args.length != 3) {
            System.err.println("ファイル名を指定してください");
            return;
        }
        String readfile = args[0];
        String writefile1 = args[1];
        String writefile2 = args[2];

        try {
            File f = new File(readfile);
            BufferedReader br = new BufferedReader(new FileReader(f));

            String line = br.readLine();
            int size = Integer.parseInt(line);

            Table table = new Table(size);

            while ((line = br.readLine()) != null) {
                int n = Integer.parseInt(line);
                
                table.addDP(n);
                table.addLDP(n);
            }

            table.applyDP();

            table.printMax();
            table.printMin();
            table.printAverage();
            

            String ft_dp = table.getFrequencyTableDP();
            String ft_ldp = table.getFrequencyTableLDP();

            File f1 = new File(writefile1);
            File f2 = new File(writefile2);
            FileWriter fw1 = new FileWriter(f1);
            FileWriter fw2 = new FileWriter(f2);

            fw1.write(ft_dp);
            fw2.write(ft_ldp);

            br.close();
            fw1.close();
            fw2.close();

        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
