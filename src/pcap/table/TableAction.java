package pcap.table;

public interface TableAction {

    public static String filePath = "./log.txt";
    public void clean();
    public void dumpToFile();
}
