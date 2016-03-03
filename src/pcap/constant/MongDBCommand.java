package pcap.constant;

/**
 * 从packetbeat中看到。
 */
public class MongDBCommand {

    public static final String COMMAND_FLAG = ".$cmd";

    public static final String[] commands = {"getLastError", "connPoolSync", "top", "dropIndexes", "explain", "grantRolesToRole",
            "dropRole", "dropAllRolesFromDatabase", "listCommands", "replSetReconfig", "replSetFresh", "writebacklisten", "setParameter",
            "update", "replSetGetStatus", "find", "resync", "appendOplogNote", "revokeRolesFromRole", "compact", "createUser",
            "replSetElect", "getPrevError", "serverStatus", "getShardVersion", "updateRole", "replSetFreeze", "getCmdLineOpts", "applyOps",
            "count", "aggregate", "copydbsaslstart", "distinct", "repairDatabase", "profile", "replSetStepDown", "findAndModify",
            "_transferMods", "filemd5", "forceerror", "getnonce", "saslContinue", "clone", "saslStart", "_getUserCacheGeneration",
            "_recvChunkCommit", "whatsmyuri", "repairCursor", "validate", "dbHash", "planCacheListFilters", "touch", "mergeChunks",
            "cursorInfo", "_recvChunkStart", "unsetSharding", "revokePrivilegesFromRole", "logout", "group", "shardConnPoolStats",
            "listDatabases", "buildInfo", "availableQueryOptions", "_isSelf", "splitVector", "geoSearch", "dbStats", "connectionStatus",
            "currentOpCtx", "copydb", "insert", "reIndex", "moveChunk", "cleanupOrphaned", "driverOIDTest", "isMaster", "getParameter",
            "replSetHeartbeat", "ping", "listIndexes", "dropUser", "dropDatabase", "dataSize", "convertToCapped", "planCacheSetFilter",
            "usersInfo", "grantPrivilegesToRole", "handshake", "_mergeAuthzCollections", "mapreduce.shardedfinish", "_recvChunkAbort",
            "authSchemaUpgrade", "replSetGetConfig", "replSetSyncFrom", "collStats", "replSetMaintenance", "createRole", "copydbgetnonce",
            "cloneCollectionAsCapped", "_migrateClone", "parallelCollectionScan", "connPoolStats", "revokeRolesFromUser", "authenticate",
            "create", "shutdown", "invalidateUserCache", "shardingState", "renameCollection", "replSetGetRBID", "splitChunk",
            "createIndexes", "updateUser", "cloneCollection", "logRotate", "planCacheListPlans", "medianKey", "hostInfo", "geoNear",
            "fsync", "checkShardingIndex", "getShardMap", "planCacheClear", "listCollections", "collMod", "_recvChunkStatus",
            "planCacheListQueryShapes", "delete", "planCacheClearFilters", "mapReduce", "rolesInfo", "eval", "drop", "grantRolesToUser",
            "resetError", "getLog", "dropAllUsersFromDatabase", "diagLogging", "replSetUpdatePosition", "setShardVersion",
            "replSetInitiate"};

    public static final String getMongDBCommand(int index) {
        if (index < 0 || index > commands.length)
            return "";
        return commands[index];
    }

    // OP_REPLY中的标志位，表示CursorNotFound
    public static final int FLAG_CURSOR_NOT_FOUND = 0x01;
    // OP_REPLY中的标志位，表示QueryFailure
    public static final int FLAG_QUERY_FAILURE = 0x02;
    public static final int FLAG_HAVE_ERRORS = FLAG_CURSOR_NOT_FOUND | FLAG_QUERY_FAILURE;
}
