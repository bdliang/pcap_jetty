package pcap.table;

import java.util.Map;

public abstract class Table<K, V> implements TableAction {

    protected Map<K, V> lastTable;
    protected Map<K, V> currentTable;

    public void tableSwitch() {
        cleanLastTable();
        Map<K, V> tmp = lastTable;
        lastTable = currentTable;
        currentTable = tmp;
    }

    public abstract void cleanLastTable();

}
