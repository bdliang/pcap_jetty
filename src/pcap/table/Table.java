package pcap.table;

import java.util.Map;

/**
 * 
 * 
 * 双标设计： 两个表 + 三个引用(指针)。
 * 一个表记录上一个完整周期的所有记录，由lastTable引用变量引用；一个记录当前的记录，由currentTable引用变量引用
 * 。所有的存储结构都需要实现switch()操作。 还有一个 workingTable引用。
 * 对于表的操作都是对这个表进行的，使用setWorkingTable ()方法来设置具体操作的表，每次对表的操作前都需要设置调用。
 * 
 * switch()操作：[将lastTable表总指标/小指标导出](将来需要)， 清空lastTable所引用的表，两个引用值互换。
 * 
 * 当一个监控周期结束时，相应线程调用表的switch()操作。 操作之后lastTable指向的表就记录上一个完整周期的所有记录
 * ，currentTable指向当前周期的记录表。 实现方式：设计抽象超类Table，2个变量lastTable 和currentTable，
 * 1个抽象方法switch()。所有需要清表操作的表继承Table类。 如果和清表周期相同的周期来请求数据，就能获得所有记录，节省内存，
 * 满足后期数据入库的需求。
 * 
 * 
 * */

public abstract class Table<K, V> implements TableAction {

    protected Map<K, V> lastTable;
    protected Map<K, V> currentTable;
    protected Map<K, V> workingTable;

    public Map<K, V> getWorkingTable() {
        return workingTable;
    }

    /**
     * 对于使用双表设计的表来说，在查找时，需要区分是从哪个表中查找。 每次对于表的操作都需要设置。
     * 
     * @current 设置工作表，即设置操作的表。true, 设置操作的表为currentTable; 否则为 lastTable
     * 
     * */
    protected void setWorkingTable(boolean current) {
        if (current)
            workingTable = currentTable;
        else
            workingTable = lastTable;
    }

    public void tableSwitch() {
        cleanLastTable();
        Map<K, V> tmp = lastTable;
        lastTable = currentTable;
        currentTable = tmp;
    }

    public abstract void cleanLastTable();

}
