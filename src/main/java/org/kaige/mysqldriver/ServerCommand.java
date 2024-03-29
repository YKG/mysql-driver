package org.kaige.mysqldriver;

public enum ServerCommand {
    /**
     Currently refused by the server. See ::dispatch_command.
     Also used internally to mark the start of a session.
     */
    COM_SLEEP,
    COM_QUIT,       /**< See @ref page_protocol_com_quit */
    COM_INIT_DB,    /**< See @ref page_protocol_com_init_db */
    COM_QUERY,      /**< See @ref page_protocol_com_query */
    COM_FIELD_LIST, /**< Deprecated. See @ref page_protocol_com_field_list */
    COM_CREATE_DB, /**< Currently refused by the server. See ::dispatch_command */
    COM_DROP_DB,   /**< Currently refused by the server. See ::dispatch_command */
    COM_REFRESH,   /**< Deprecated. See @ref page_protocol_com_refresh */
    COM_DEPRECATED_1, /**< Deprecated, used to be COM_SHUTDOWN */
    COM_STATISTICS,   /**< See @ref page_protocol_com_statistics */
    COM_PROCESS_INFO, /**< Deprecated. See @ref page_protocol_com_process_info */
    COM_CONNECT,      /**< Currently refused by the server. */
    COM_PROCESS_KILL, /**< Deprecated. See @ref page_protocol_com_process_kill */
    COM_DEBUG,        /**< See @ref page_protocol_com_debug */
    COM_PING,         /**< See @ref page_protocol_com_ping */
    COM_TIME,         /**< Currently refused by the server. */
    COM_DELAYED_INSERT, /**< Functionality removed. */
    COM_CHANGE_USER,    /**< See @ref page_protocol_com_change_user */
    COM_BINLOG_DUMP,    /**< See @ref page_protocol_com_binlog_dump */
    COM_TABLE_DUMP,
    COM_CONNECT_OUT,
    COM_REGISTER_SLAVE,
    COM_STMT_PREPARE, /**< See @ref page_protocol_com_stmt_prepare */
    COM_STMT_EXECUTE, /**< See @ref page_protocol_com_stmt_execute */
    /** See  @ref page_protocol_com_stmt_send_long_data */
    COM_STMT_SEND_LONG_DATA,
    COM_STMT_CLOSE, /**< See @ref page_protocol_com_stmt_close */
    COM_STMT_RESET, /**< See @ref page_protocol_com_stmt_reset */
    COM_SET_OPTION, /**< See @ref page_protocol_com_set_option */
    COM_STMT_FETCH, /**< See @ref page_protocol_com_stmt_fetch */
    /**
     Currently refused by the server. See ::dispatch_command.
     Also used internally to mark the session as a "daemon",
     i.e. non-client THD. Currently the scheduler and the GTID
     code does use this state.
     These threads won't be killed by `KILL`

     @sa Event_scheduler::start, ::init_thd, ::kill_one_thread,
     ::Find_thd_with_id
     */
    COM_DAEMON,
    COM_BINLOG_DUMP_GTID,
    COM_RESET_CONNECTION, /**< See @ref page_protocol_com_reset_connection */
    COM_CLONE,
    COM_SUBSCRIBE_GROUP_REPLICATION_STREAM,
    /* don't forget to update const char *command_name[] in sql_parse.cc */

    /* Must be last */
    COM_END /**< Not a real command. Refused. */
}
