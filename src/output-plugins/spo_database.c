/*
** spo_database.c
**
** Portions Copyright (C) 2000,2001,2002 Carnegie Mellon University
** Copyright (C) 2001 Jed Pickel <jed@pickel.net>
** Portions Copyright (C) 2001 Andrew R. Baker <andrewb@farm9.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*
 *  Maintainers : The Barnyard2 Team <firnsy@gmail.com> <beenph@gmail.com> 
 *  Past Maintainer: Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
 *  Originally written by Jed Pickel <jed@pickel.net> (2000-2001)
 *
 *  See the doc/README.database file with this distribution
 *  documentation or the snortdb web site for configuration
 *  information
 *
 *    Special thanks to: Rusell Fuleton <russell.fulton@gmail.com> for helping us stress test
 *                       this in production for us.
 *
 */

/******** fatals *******************************************************/


/* these strings deliberately break fatal error messages into
   chunks with lengths < 509 to keep ISO C89 compilers happy
 */

static const char* FATAL_NO_SENSOR_1 =
    " When this plugin starts, a SELECT query is run to find the sensor id for the\n"
    " currently running sensor. If the sensor id is not found, the plugin will run\n"
    " an INSERT query to insert the proper data and generate a new sensor id. Then a\n"
    " SELECT query is run to get the newly allocated sensor id. If that fails then\n"
    " this error message is generated.\n";

static const char* FATAL_NO_SENSOR_2 =
    " Some possible causes for this error are:\n"
    "  * the user does not have proper INSERT or SELECT privileges\n"
    "  * the sensor table does not exist\n"
    "\n"
    " If you are _absolutely_ certain that you have the proper privileges set and\n"
    " that your database structure is built properly please let me know if you\n"
    " continue to get this error. You can contact me at (roman@danyliw.com).\n";

static const char* FATAL_BAD_SCHEMA_1 =
    "database: The underlying database has not been initialized correctly.  This\n"
    "          version of barnyard2 requires version %d of the DB schema.  Your DB\n"
    "          doesn't appear to have any records in the 'schema' table.\n%s";

static const char* FATAL_BAD_SCHEMA_2 =
    "          Please re-run the appropriate DB creation script (e.g. create_mysql,\n"
    "          create_postgresql, create_oracle, create_mssql) located in the\n"
    "          contrib\\ directory.\n\n"
    "          See the database documentation for cursory details (doc/README.database).\n"
    "          and the URL to the most recent database plugin documentation.\n";

static const char* FATAL_OLD_SCHEMA_1 =
    "database: The underlying database seems to be running an older version of\n"
    "          the DB schema (current version=%d, required minimum version= %d).\n\n"
    "          If you have an existing database with events logged by a previous\n"
    "          version of barnyard2, this database must first be upgraded to the latest\n"
    "          schema (see the barnyard2-users mailing list archive or DB plugin\n"
    "          documention for details).\n%s\n";

static const char* FATAL_OLD_SCHEMA_2 =
    "          If migrating old data is not desired, merely create a new instance\n"
    "          of the snort database using the appropriate DB creation script\n"
    "          (e.g. create_mysql, create_postgresql, create_oracle, create_mssql)\n"
    "          located in the contrib\\ directory.\n\n"
    "          See the database documentation for cursory details (doc/README.database).\n"
    "          and the URL to the most recent database plugin documentation.\n";

static const char* FATAL_NO_SUPPORT_1 =
    "If this build of barnyard2 was obtained as a binary distribution (e.g., rpm,\n"
    "or Windows), then check for alternate builds that contains the necessary\n"
    "'%s' support.\n\n"
    "If this build of barnyard2 was compiled by you, then re-run the\n"
    "the ./configure script using the '--with-%s' switch.\n"
    "For non-standard installations of a database, the '--with-%s=DIR'\n%s";

static const char* FATAL_NO_SUPPORT_2 =
    "syntax may need to be used to specify the base directory of the DB install.\n\n"
    "See the database documentation for cursory details (doc/README.database).\n"
    "and the URL to the most recent database plugin documentation.\n";


#include "output-plugins/spo_database.h"

void DatabaseCleanSelect(DatabaseData *data)
{
    
    if( (data != NULL) &&
	(data->SQL_SELECT) != NULL &&
	(data->SQL_SELECT_SIZE > 0))
    {
	memset(data->SQL_SELECT,'\0',data->SQL_SELECT_SIZE);
    }

    return;
}

void DatabaseCleanInsert(DatabaseData *data )
{
    
    if( (data != NULL) &&
	(data->SQL_INSERT) != NULL &&
	(data->SQL_INSERT_SIZE > 0))
    {
	memset(data->SQL_INSERT,'\0',data->SQL_INSERT_SIZE);
    }

    return;
}


/* SQLQueryList Funcs */
u_int32_t SQL_Initialize(DatabaseData *data)
{
    u_int32_t x = 0;

    if(data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    data->SQL.query_total = MAX_SQL_QUERY_OPS;

    if( (data->SQL.query_array =(char **)SnortAlloc( (sizeof(char *) * data->SQL.query_total))) == NULL)
    {
	/* XXX */
	return 1;
    }
    
    
    for(x = 0 ; x < data->SQL.query_total ; x++)
    {
	if( (data->SQL.query_array[x] = SnortAlloc( (sizeof(char) * MAX_QUERY_LENGTH ))) == NULL)
	{
	    /* XXX */
	    return 1;
	}
	
    }
    
    return 0;
}

u_int32_t SQL_Finalize(DatabaseData *data)
{
    u_int32_t x = 0;

    if(data == NULL)
    {
	/* XXX */
	return 1;
    }

    for(x = 0 ; x < data->SQL.query_total ; x++)
    {
	if(data->SQL.query_array[x] != NULL)
	{
	    free(data->SQL.query_array[x]);
	    data->SQL.query_array[x]= NULL;
	}
    }
    
    if( data->SQL.query_array != NULL)
    {
	free(data->SQL.query_array);
	data->SQL.query_array = NULL;
    }
    
    return 0;
}


char *SQL_GetNextQuery(DatabaseData *data)
{
    
    char *ret_query = NULL;

    if(data == NULL)
    {
	/* XXX */
	return NULL;
    }
    
    if( data->SQL.query_count <  data->SQL.query_total)
    {
	ret_query = data->SQL.query_array[data->SQL.query_count];
	data->SQL.query_count++;
	return ret_query;
    }
    
    return NULL;
}

char *SQL_GetQueryByPos(DatabaseData *data,u_int32_t pos)
{
    if( (data == NULL) ||
	pos > data->SQL.query_total)
    {
        /* XXX */
        return NULL;
    }
    
    if(data->SQL.query_array[pos] != NULL)
    {
	return data->SQL.query_array[pos];
    }
    
    return NULL;
}

u_int32_t SQL_GetMaxQuery(DatabaseData *data)
{
    if(data == NULL)
    {
	/* XXX */
	return 0;
    }
    
    return data->SQL.query_count;
}


u_int32_t SQL_Cleanup(DatabaseData *data)
{
    u_int32_t x = 0;
    
    if(data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    if(data->SQL.query_count)
    {
	for(x = 0; x < data->SQL.query_count ; x++)
	{
	    memset(data->SQL.query_array[x],'\0',(sizeof(char) * MAX_QUERY_LENGTH));
	}
	
	data->SQL.query_count = 0;
    }

    return 0;
}

/* SQLQueryList Funcs */




/*******************************************************************************
 * Function: SetupDatabase()
 *
 * Purpose: Registers the output plugin keyword and initialization
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ******************************************************************************/
void DatabaseSetup(void)
{
    /* link the preprocessor keyword to the init function in
       the preproc list */

    /* CHECKME: -elz I think it should also support OUTPUT_TYPE_FLAG__LOG.. */
    RegisterOutputPlugin("database", OUTPUT_TYPE_FLAG__ALERT, DatabaseInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "database(debug): database plugin is registered...\n"););
}


#ifndef DB_CHECK_TABLES
#define DB_CHECK_TABLES 7
#endif /* DB_CHECK_TABLES */

#ifndef DB_TABLE_NAME_LEN
#define DB_TABLE_NAME_LEN 20
#endif /* DB_TABLE_NAME_LEN */

/* 
 * Since it is possible that an error occured and that we could have an event_id out of sync
 * or that a human/automated action could have cleaned the database but missed some old data
 * we query every table where cid for this sid(sensor_id) is present and get the latest (cid) 
 * incident_id possible to start the process.
 */
u_int32_t SynchronizeEventId(DatabaseData *data)
{
    if(data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    u_int32_t c_cid = 0;
    u_int32_t num_tables = 7;
    u_int32_t itr = 0;
    
    char table_array[DB_CHECK_TABLES][DB_TABLE_NAME_LEN] = {"data","event","icmphdr","iphdr","opt","tcphdr","udphdr"};
    
    if( GetLastCid(data, data->sid,(u_int32_t *)&data->cid))
    {
        /* XXX*/
        return 1;
    }
   
    for(itr = 0; itr < num_tables ; itr++)
    {
	c_cid = 0;
	DatabaseCleanSelect(data);	
	if(SnortSnprintf(data->SQL_SELECT,data->SQL_SELECT_SIZE,
			 "SELECT MAX(cid) FROM %s WHERE sid='%u';",
			 table_array[itr],
			 data->sid))
	{
	    LogMessage("database: [%s()], was unable to build query \n",
		       __FUNCTION__);
	    return 1;
	}
	
	
	if(Select(data->SQL_SELECT,data,(u_int32_t *)&c_cid))
	{
	    DEBUG_WRAP(DebugMessage(DB_DEBUG,"database: [%s()]: Problems executing [%s], (there is probably no row in the table for sensor id [%d] \n",
				    __FUNCTION__,
				    data->SQL_SELECT,
			            data->sid););
	}
	
	if(c_cid > data->cid)
	{
	    DEBUG_WRAP(DebugMessage(DB_DEBUG,"INFO database: Table [%s] had a more recent cid [%u], using cid [%u] instead of [%u] \n",
				    table_array[itr],
				    c_cid,
				    c_cid,
				    data->cid););
	    
	    data->cid = c_cid;
	}
    }
    
    data->cid++;


    if( UpdateLastCid(data, data->sid, data->cid) < 0 )
    {
	FatalError("database Unable to construct query - output error or truncation\n");
    }
    
    if( GetLastCid(data, data->sid,(u_int32_t *)&c_cid))
    {
	/* XXX*/
	return 1; 
    }

    if(c_cid != data->cid)
    {
	FatalError("database [%s()]: Something is wrong with the sensor table, you "
		   "might have two process updating it...bailing\n",
		   __FUNCTION__);
    }
    
    return 0;
}


void DatabasePluginPrintData(DatabaseData *data)
{
    /* print out and test the capability of this plugin */
    {
        char database_support_buf[100];
        char database_in_use_buf[100];
	
        database_support_buf[0] = '\0';
        database_in_use_buf[0] = '\0';
	
        /* These strings will not overflow the buffers */
#ifdef ENABLE_MYSQL
        snprintf(database_support_buf, sizeof(database_support_buf),
                 "database: compiled support for (%s)", KEYWORD_MYSQL);
        if (data->dbtype_id == DB_MYSQL)
	    snprintf(database_in_use_buf, sizeof(database_in_use_buf),
		     "database: configured to use %s", KEYWORD_MYSQL);
#endif
#ifdef ENABLE_POSTGRESQL
        snprintf(database_support_buf, sizeof(database_support_buf),
                 "database: compiled support for (%s)", KEYWORD_POSTGRESQL);
        if (data->dbtype_id == DB_POSTGRESQL)
	    snprintf(database_in_use_buf, sizeof(database_in_use_buf),
		     "database: configured to use %s", KEYWORD_POSTGRESQL);
#endif
#ifdef ENABLE_ODBC
        snprintf(database_support_buf, sizeof(database_support_buf),
                 "database: compiled support for (%s)", KEYWORD_ODBC);
        if (data->dbtype_id == DB_ODBC)
	    snprintf(database_in_use_buf, sizeof(database_in_use_buf),
		     "database: configured to use %s", KEYWORD_ODBC);
#endif
#ifdef ENABLE_ORACLE
        snprintf(database_support_buf, sizeof(database_support_buf),
                 "database: compiled support for (%s)", KEYWORD_ORACLE);
        if (data->dbtype_id == DB_ORACLE)
	    snprintf(database_in_use_buf, sizeof(database_in_use_buf),
		     "database: configured to use %s", KEYWORD_ORACLE);
#endif
#ifdef ENABLE_MSSQL
        snprintf(database_support_buf, sizeof(database_support_buf),
                 "database: compiled support for (%s)", KEYWORD_MSSQL);
        if (data->dbtype_id == DB_MSSQL)
	    snprintf(database_in_use_buf, sizeof(database_in_use_buf),
		     "database: configured to use %s", KEYWORD_MSSQL);
#endif
        LogMessage("%s\n", database_support_buf);
        LogMessage("%s\n", database_in_use_buf);
    }
    
    LogMessage("database: schema version = %d\n", data->DBschema_version);
    
    if (data->host != NULL)
	LogMessage("database:           host = %s\n", data->host);
    
    if (data->port != NULL)
	LogMessage("database:           port = %s\n", data->port);
    
    if (data->user != NULL)
	LogMessage("database:           user = %s\n", data->user);
    
    if (data->dbname != NULL)
	LogMessage("database:  database name = %s\n", data->dbname);
    
    if (data->sensor_name != NULL)
	LogMessage("database:    sensor name = %s\n", data->sensor_name);
    
    
    LogMessage("database:      sensor id = %u\n", data->sid);
    
    LogMessage("database:     sensor cid = %u\n", data->cid);
    
    if (data->encoding == ENCODING_HEX)
    {
	LogMessage("database:  data encoding = %s\n", KEYWORD_ENCODING_HEX);
    }
    else if (data->encoding == ENCODING_BASE64)
    {
	LogMessage("database:  data encoding = %s\n", KEYWORD_ENCODING_BASE64);
    }
    else
    {
	LogMessage("database:  data encoding = %s\n", KEYWORD_ENCODING_ASCII);
    }

    if (data->detail == DETAIL_FULL)
    {
	LogMessage("database:   detail level = %s\n", KEYWORD_DETAIL_FULL);
    }
    else
    {
	LogMessage("database:   detail level = %s\n", KEYWORD_DETAIL_FAST);
    }
    
    if (data->ignore_bpf)
    {
	LogMessage("database:     ignore_bpf = %s\n", KEYWORD_IGNOREBPF_YES);
    }
    else
    {
	LogMessage("database:     ignore_bpf = %s\n", KEYWORD_IGNOREBPF_NO);
    }
    
#ifdef ENABLE_MYSQL
    if (data->dbRH[data->dbtype_id].ssl_key != NULL)
	LogMessage("database:        ssl_key = %s\n", data->dbRH[data->dbtype_id].ssl_key);

    if (data->dbRH[data->dbtype_id].ssl_cert != NULL)
	LogMessage("database:       ssl_cert = %s\n", data->dbRH[data->dbtype_id].ssl_cert);

    if (data->dbRH[data->dbtype_id].ssl_ca != NULL)
	LogMessage("database:         ssl_ca = %s\n", data->dbRH[data->dbtype_id].ssl_ca);

    if (data->dbRH[data->dbtype_id].ssl_ca_path != NULL)
	LogMessage("database:    ssl_ca_path = %s\n", data->dbRH[data->dbtype_id].ssl_ca_path);
    
    if (data->dbRH[data->dbtype_id].ssl_cipher != NULL)
	LogMessage("database:     ssl_cipher = %s\n", data->dbRH[data->dbtype_id].ssl_cipher);
#endif /* ENABLE_MYSQL */
    
#ifdef ENABLE_POSTGRESQL
    if (data->dbRH[data->dbtype_id].ssl_mode != NULL)
	LogMessage("database:       ssl_mode = %s\n", data->dbRH[data->dbtype_id].ssl_mode);
#endif /* ENABLE_POSTGRESQL */
    
    if(data->facility != NULL)
    {
	LogMessage("database: using the \"%s\" facility\n",data->facility);
    }
    
    return;
}


/*******************************************************************************
 * Function: DatabaseInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 ******************************************************************************/
void DatabaseInit(char *args)
{
    DatabaseData *data = NULL;
    
    /* parse the argument list from the rules file */
    data = InitDatabaseData(args);
    
    data->tz = GetLocalTimezone();
    
    ParseDatabaseArgs(data);
    
    /* Meanwhile */
    data->dbRH[data->dbtype_id].dbdata = data; 
    /* Meanwhile */
    
    switch(data->dbtype_id)
    {
#ifdef ENABLE_MYSQL	
    case DB_MYSQL:
	data->dbRH[data->dbtype_id].dbConnectionStatus = dbConnectionStatusMYSQL;
	data->dbRH[data->dbtype_id].dbConnectionCount = 0;
	break;
#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL	
    case DB_POSTGRESQL:
	data->dbRH[data->dbtype_id].dbConnectionStatus = dbConnectionStatusPOSTGRESQL;
	data->dbRH[data->dbtype_id].dbConnectionCount = 0;
	break;
#endif /* ENABLE_POSTGRESQL */

#ifdef ENABLE_ODBC
    case DB_ODBC:
	data->dbRH[data->dbtype_id].dbConnectionStatus = dbConnectionStatusODBC;
        data->dbRH[data->dbtype_id].dbConnectionCount = 0;
	break;
#endif 	/* ENABLE ODBC */

#ifdef ENABLE_ORACLE
#ifdef ENABLE_MSSQL	
    case DB_MSSQL:
    case DB_ORACLE:

	FatalError("database The database family you want to use is currently not supported by this build \n");
	break;
#endif 	/* ENABLE MSSQL */
#endif 	/* ENABLE ORACLE */

    default:
	FatalError("database Unknown database type defined: [%lu] \n",data->dbtype_id);
	break;
    }
    
    /* Add the processor function into the function list */
    if (strncasecmp(data->facility, "log", 3) == 0)
    {
        AddFuncToOutputList(Database, OUTPUT_TYPE__LOG, data);
    }
    else
    {
        AddFuncToOutputList(Database, OUTPUT_TYPE__ALERT, data);
    }


    AddFuncToRestartList(SpoDatabaseCleanExitFunction, data); 
    AddFuncToCleanExitList(SpoDatabaseCleanExitFunction, data);
    AddFuncToPostConfigList(DatabaseInitFinalize, data);
    
    
    /* Set the size of the buffers here */
    data->SQL_INSERT_SIZE = (MAX_QUERY_LENGTH * sizeof(char));
    data->SQL_SELECT_SIZE = (MAX_QUERY_LENGTH * sizeof(char));
    
    
    if( (data->SQL_INSERT = malloc(data->SQL_INSERT_SIZE)) == NULL)
    {
	/* XXX */
	FatalError("database [%s()], unable to allocate SQL_INSERT memory, bailing \n",
		   __FUNCTION__);
    }
    
    if ( (data->SQL_SELECT = malloc(data->SQL_SELECT_SIZE)) == NULL)
    {
	/* XXX */
	FatalError("database [%s()], unable to allocate SQL_SELECT memory, bailing \n",
		   __FUNCTION__);
	
    }
    
    DatabaseCleanSelect(data);
    DatabaseCleanInsert(data);
    

    
    return;
}

u_int32_t DatabasePluginInitializeSensor(DatabaseData *data)
{

    u_int32_t retval = 0;
    char * escapedSensorName = NULL;
    char * escapedInterfaceName = NULL;
    char * escapedBPFFilter = NULL;
    
    if(data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    /* find a unique name for sensor if one was not supplied as an option */
    if(!data->sensor_name)
    {
        data->sensor_name = GetUniqueName(PRINT_INTERFACE(barnyard2_conf->interface));
        if ( data->sensor_name )
        {
            if( data->sensor_name[strlen(data->sensor_name)-1] == '\n' )
            {
                data->sensor_name[strlen(data->sensor_name)-1] = '\0';
            }
        }
    }
    
    escapedSensorName    = snort_escape_string(data->sensor_name, data);
    escapedInterfaceName = snort_escape_string(PRINT_INTERFACE(barnyard2_conf->interface), data);
    
    
    if( data->ignore_bpf == 0 )
    {
        if(barnyard2_conf->bpf_filter == NULL)
        {
	    DatabaseCleanInsert(data);
	    if( (SnortSnprintf(data->SQL_INSERT, data->SQL_INSERT_SIZE,
			       "INSERT INTO sensor (hostname, interface, detail, encoding, last_cid) "
			       "VALUES ('%s','%s',%u,%u, 0);",
			       escapedSensorName, escapedInterfaceName,
			       data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		retval = 1;
		goto exit_funct;
	    }
	    
	    DatabaseCleanSelect(data);
            if( (SnortSnprintf(data->SQL_SELECT,data->SQL_SELECT_SIZE,
			       "SELECT sid "
			       "  FROM sensor "
			       " WHERE hostname = '%s' "
			       "   AND interface = '%s' "
			       "   AND detail = %u "
			       "   AND encoding = %u "
			       "   AND filter IS NULL",
			       escapedSensorName, escapedInterfaceName,
			       data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
                retval = 1;
                goto exit_funct;
	    }
        }
        else
        {
            escapedBPFFilter = snort_escape_string(barnyard2_conf->bpf_filter, data);
	    
	    DatabaseCleanInsert(data);
            if( (SnortSnprintf(data->SQL_INSERT, data->SQL_INSERT_SIZE,
			       "INSERT INTO sensor (hostname, interface, filter, detail, encoding, last_cid) "
			       "VALUES ('%s','%s','%s',%u,%u, 0);",
			       escapedSensorName, escapedInterfaceName,
			       escapedBPFFilter, data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
                retval = 1;
                goto exit_funct;
	    }
	    
	    DatabaseCleanSelect(data);
            if( (SnortSnprintf(data->SQL_SELECT,data->SQL_SELECT_SIZE,
			       "SELECT sid "
			       "  FROM sensor "
			       " WHERE hostname = '%s' "
			       "   AND interface = '%s' "
			       "   AND filter ='%s' "
			       "   AND detail = %u "
			       "   AND encoding = %u ",
			       escapedSensorName, escapedInterfaceName,
			       escapedBPFFilter, data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
                retval = 1;
                goto exit_funct;
	    }
	}
    }
    else /* ( data->ignore_bpf == 1 ) */
    {
	if(barnyard2_conf->bpf_filter == NULL)
	{
	    DatabaseCleanInsert(data);
	    if( (SnortSnprintf(data->SQL_INSERT, data->SQL_INSERT_SIZE,
			       "INSERT INTO sensor (hostname, interface, detail, encoding, last_cid) "
			       "VALUES ('%s','%s',%u,%u, 0);",
			       escapedSensorName, escapedInterfaceName,
			       data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
                retval = 1;
                goto exit_funct;
	    }
	    
            DatabaseCleanSelect(data);
            if( (SnortSnprintf(data->SQL_SELECT,data->SQL_SELECT_SIZE,
			       "SELECT sid "
			       "  FROM sensor "
			       " WHERE hostname = '%s' "

			       "   AND interface = '%s' "
			       "   AND detail = %u "
			       "   AND encoding = %u",
			       escapedSensorName, escapedInterfaceName,
			       data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
                retval = 1;
                goto exit_funct;
	    }
	}
	else
	{
	    escapedBPFFilter = snort_escape_string(barnyard2_conf->bpf_filter, data);
	    
	    DatabaseCleanInsert(data);
            if( (SnortSnprintf(data->SQL_INSERT, data->SQL_INSERT_SIZE,
			       "INSERT INTO sensor (hostname, interface, filter, detail, encoding, last_cid) "
			       "VALUES ('%s','%s','%s',%u,%u, 0);",
			       escapedSensorName, escapedInterfaceName,
			       escapedBPFFilter, data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
                retval = 1;
                goto exit_funct;
	    }
	    
	    DatabaseCleanSelect(data);
	    if( (SnortSnprintf(data->SQL_SELECT,data->SQL_SELECT_SIZE,
			       "SELECT sid "
			       "  FROM sensor "
			       " WHERE hostname = '%s' "
			       "   AND interface = '%s' "
			       "   AND detail = %u "
			       "   AND encoding = %u",
			       escapedSensorName, escapedInterfaceName,
			       data->detail, data->encoding)) != SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
                retval = 1;
                goto exit_funct;
	    }
        }
    }
    
        
    /* No check here */
    Select(data->SQL_SELECT,data,(u_int32_t *)&data->sid);
    
    if(data->sid == 0)
      {
         if( BeginTransaction(data) )
         {
	       /* XXX */
	       FatalError("database [%s()]: Failed to Initialize transaction, bailing ... \n",
		   __FUNCTION__);
         }


	if(Insert(data->SQL_INSERT,data,1))
	{
	       /* XXX */
	       FatalError("database Error inserting [%s] \n",data->SQL_INSERT);
	}
	
         if(CommitTransaction(data))
         {
	     /* XXX */
	     ErrorMessage("ERROR database: [%s()]: Error commiting transaction \n",
		     __FUNCTION__);
	     
	     setTransactionCallFail(&data->dbRH[data->dbtype_id]);
	     retval = 1;
	     goto exit_funct;
         }
         else
         {
	    resetTransactionState(&data->dbRH[data->dbtype_id]);
         }


	if( Select(data->SQL_SELECT,data,(u_int32_t *)&data->sid))
	{
	    /* XXX */
	    FatalError("database Error Executing [%s] \n",data->SQL_SELECT);
	}
	
	if(data->sid == 0)
	{
	    ErrorMessage("ERROR database: Problem obtaining SENSOR ID (sid) from %s->sensor\n",
			 data->dbname);
	    FatalError("%s\n%s\n", FATAL_NO_SENSOR_1, FATAL_NO_SENSOR_2);
	}
    }

    
exit_funct:
    if(escapedSensorName != NULL)
    {
	free(escapedSensorName);
	escapedSensorName= NULL;
    }
    if(escapedInterfaceName != NULL)
    {
	free(escapedInterfaceName);
	escapedInterfaceName = NULL;
    }
    
    if( escapedBPFFilter != NULL)
    {
	free(escapedBPFFilter);
	escapedBPFFilter = NULL;
    }
    
    return retval;


}

void DatabaseInitFinalize(int unused, void *arg)
{
    DatabaseData *data = (DatabaseData *)arg;
    
    if ((data == NULL))
    {
        FatalError("database data uninitialized\n");
    }
    
    Connect(data);
    

    if( (ConvertDefaultCache(barnyard2_conf,data)))
    {
	/* XXX */
	FatalError("database [%s()], ConvertDefaultCache() Failed \n",
		   __FUNCTION__);
    }
    
    
    /* Get the versioning information for the DB schema */
    if( (CheckDBVersion(data)))
    {
	/* XXX */
	FatalError("database problems with schema version, bailing...\n");
    }
    
    if( (DatabasePluginInitializeSensor(data)))
    {
	FatalError("database Unable to initialize sensor \n");
    }
    
    
    if(SynchronizeEventId(data))
    {
	FatalError("database Encountered an error while trying to synchronize event_id, this is serious and we can't go any further, please investigate \n");
    }
    

    if(CacheSynchronize(data))
    {
	/* XXX */
	FatalError("database [%s()]: CacheSynchronize() call failed ...\n",
		   __FUNCTION__);
	return;
    }

    DatabasePluginPrintData(data);
    
    SQL_Initialize(data);
    
    return;
}


/*******************************************************************************
 * Function: InitDatabaseData(char *)
 *
 * Purpose: Initialize the data structure for connecting to
 *          this database.
 *
 * Arguments: args => argument list
 *
 * Returns: Pointer to database structure
 *
 ******************************************************************************/
DatabaseData *InitDatabaseData(char *args)
{
    DatabaseData *data;
    
    data = (DatabaseData *)SnortAlloc(sizeof(DatabaseData));
    
    if(args == NULL)
    {
        ErrorMessage("ERROR database: you must supply arguments for database plugin\n");
        DatabasePrintUsage();
        FatalError("");
    }

    data->args = SnortStrdup(args);

    return data;
}

/*******************************************************************************
 * Function: ParseDatabaseArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and
 *          initialize the preprocessor's data struct.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 ******************************************************************************/
void ParseDatabaseArgs(DatabaseData *data)
{
    char *dbarg;
    char *a1;
    char *type;
    char *facility;

    if(data->args == NULL)
    {
        ErrorMessage("ERROR database: you must supply arguments for database plugin\n");
        DatabasePrintUsage();
        FatalError("");
    }

    data->dbtype_id = DB_UNDEFINED;
    data->sensor_name = NULL;
    data->facility = NULL;
    data->encoding = ENCODING_HEX;
    data->detail = DETAIL_FULL;
    data->ignore_bpf = 0;
    data->use_ssl = 0;
    
    
    facility = strtok(data->args, ", ");
    if(facility != NULL)
    {
        if((!strncasecmp(facility,"log",3)) || (!strncasecmp(facility,"alert",5)))
            data->facility = facility;
        else
        {
            ErrorMessage("ERROR database: The first argument needs to be the logging facility\n");
            DatabasePrintUsage();
            FatalError("");
        }
    }
    else
    {
        ErrorMessage("ERROR database: Invalid format for first argment\n");
        DatabasePrintUsage();
        FatalError("");
    }

    type = strtok(NULL, ", ");

    if(type == NULL)
    {
        ErrorMessage("ERROR database: you must enter the database type in configuration "
                     "file as the second argument\n");
        DatabasePrintUsage();
        FatalError("");
    }

#ifdef ENABLE_MYSQL
    if(!strncasecmp(type,KEYWORD_MYSQL,strlen(KEYWORD_MYSQL)))
        data->dbtype_id = DB_MYSQL;
#endif
#ifdef ENABLE_POSTGRESQL
    if(!strncasecmp(type,KEYWORD_POSTGRESQL,strlen(KEYWORD_POSTGRESQL)))
        data->dbtype_id = DB_POSTGRESQL;
#endif
#ifdef ENABLE_ODBC
    if(!strncasecmp(type,KEYWORD_ODBC,strlen(KEYWORD_ODBC)))
        data->dbtype_id = DB_ODBC;
#endif
#ifdef ENABLE_ORACLE
    if(!strncasecmp(type,KEYWORD_ORACLE,strlen(KEYWORD_ORACLE)))
        data->dbtype_id = DB_ORACLE;
#endif
#ifdef ENABLE_MSSQL
    if(!strncasecmp(type,KEYWORD_MSSQL,strlen(KEYWORD_MSSQL)))
        data->dbtype_id = DB_MSSQL;
#endif

    if(data->dbtype_id == 0)
    {
        if ( !strncasecmp(type, KEYWORD_MYSQL, strlen(KEYWORD_MYSQL)) ||
             !strncasecmp(type, KEYWORD_POSTGRESQL, strlen(KEYWORD_POSTGRESQL)) ||
             !strncasecmp(type, KEYWORD_ODBC, strlen(KEYWORD_ODBC)) ||
             !strncasecmp(type, KEYWORD_MSSQL, strlen(KEYWORD_MSSQL))  ||
             !strncasecmp(type, KEYWORD_ORACLE, strlen(KEYWORD_ORACLE)) )
        {
            ErrorMessage("ERROR database: '%s' support is not compiled into this build of barnyard2\n\n", type);
            FatalError(FATAL_NO_SUPPORT_1, type, type, type, FATAL_NO_SUPPORT_2);
        }
        else
        {
           FatalError("database '%s' is an unknown database type.  The supported\n"
                      "          databases include: MySQL (mysql), PostgreSQL (postgresql),\n"
                      "          ODBC (odbc), Oracle (oracle), and Microsoft SQL Server (mssql)\n",
                      type);
        }
    }

    dbarg = strtok(NULL, " =");
    while(dbarg != NULL)
    {
        a1 = NULL;
        a1 = strtok(NULL, ", ");
        if(!strncasecmp(dbarg,KEYWORD_HOST,strlen(KEYWORD_HOST)))
        {
            data->host = a1;
        }
        if(!strncasecmp(dbarg,KEYWORD_PORT,strlen(KEYWORD_PORT)))
        {
            data->port = a1;
        }
        if(!strncasecmp(dbarg,KEYWORD_USER,strlen(KEYWORD_USER)))
        {
            data->user = a1;
        }
        if(!strncasecmp(dbarg,KEYWORD_PASSWORD,strlen(KEYWORD_PASSWORD)))
        {
            data->password = a1;
        }
        if(!strncasecmp(dbarg,KEYWORD_DBNAME,strlen(KEYWORD_DBNAME)))
        {
            data->dbname = a1;
        }
        if(!strncasecmp(dbarg,KEYWORD_SENSORNAME,strlen(KEYWORD_SENSORNAME)))
        {
            data->sensor_name = a1;
        }
        if(!strncasecmp(dbarg,KEYWORD_ENCODING,strlen(KEYWORD_ENCODING)))
        {
            if(!strncasecmp(a1, KEYWORD_ENCODING_HEX, strlen(KEYWORD_ENCODING_HEX)))
            {
                data->encoding = ENCODING_HEX;
            }
            else if(!strncasecmp(a1, KEYWORD_ENCODING_BASE64, strlen(KEYWORD_ENCODING_BASE64)))
            {
                data->encoding = ENCODING_BASE64;
            }
            else if(!strncasecmp(a1, KEYWORD_ENCODING_ASCII, strlen(KEYWORD_ENCODING_ASCII)))
            {
                data->encoding = ENCODING_ASCII;
            }
            else
            {
                FatalError("database unknown  (%s)", a1);
            }
        }
        if(!strncasecmp(dbarg,KEYWORD_DETAIL,strlen(KEYWORD_DETAIL)))
        {
            if(!strncasecmp(a1, KEYWORD_DETAIL_FULL, strlen(KEYWORD_DETAIL_FULL)))
            {
                data->detail = DETAIL_FULL;
            }
            else if(!strncasecmp(a1, KEYWORD_DETAIL_FAST, strlen(KEYWORD_DETAIL_FAST)))
            {
                data->detail = DETAIL_FAST;
            }
            else
            {
                FatalError("database unknown detail level (%s)", a1);
            }
        }
        if(!strncasecmp(dbarg,KEYWORD_IGNOREBPF,strlen(KEYWORD_IGNOREBPF)))
        {
            if(!strncasecmp(a1, KEYWORD_IGNOREBPF_NO, strlen(KEYWORD_IGNOREBPF_NO)) ||
               !strncasecmp(a1, KEYWORD_IGNOREBPF_ZERO, strlen(KEYWORD_IGNOREBPF_ZERO)))
            {
                data->ignore_bpf = 0;
            }
            else if(!strncasecmp(a1, KEYWORD_IGNOREBPF_YES, strlen(KEYWORD_IGNOREBPF_YES)) ||
                    !strncasecmp(a1, KEYWORD_IGNOREBPF_ONE, strlen(KEYWORD_IGNOREBPF_ONE)))
            {
                data->ignore_bpf = 1;
            }
            else
            {
                FatalError("database unknown ignore_bpf argument (%s)", a1);
            }

        }
	if(!strncasecmp(dbarg,KEYWORD_CONNECTION_LIMIT,strlen(KEYWORD_CONNECTION_LIMIT)))
	{
	    data->dbRH[data->dbtype_id].dbConnectionLimit = strtoul(a1,NULL,10);

	    /* Might make a different option for it but for now lets consider
	       the threshold being the same as connectionlimit. */
	    data->dbRH[data->dbtype_id].transactionErrorThreshold = data->dbRH[data->dbtype_id].dbConnectionLimit; 
	    
	}
	if(!strncasecmp(dbarg,KEYWORD_RECONNECT_SLEEP_TIME,strlen(KEYWORD_RECONNECT_SLEEP_TIME)))
	{
	    data->dbRH[data->dbtype_id].dbReconnectSleepTime.tv_sec = strtoul(a1,NULL,10);
	}
	if(!strncasecmp(dbarg,KEYWORD_DISABLE_SIGREFTABLE,strlen(KEYWORD_DISABLE_SIGREFTABLE)))
	{
	    data->dbRH[data->dbtype_id].disablesigref = 1;
	}

#ifdef ENABLE_MYSQL
	/* Option declared here should be forced to dbRH[DB_MYSQL] */

        /* the if/elseif check order is important because the keywords for the */
        /* ca and ca_path are very similar */
        if(!strncasecmp(dbarg, KEYWORD_SSL_KEY, strlen(KEYWORD_SSL_KEY)))
        {
            data->dbRH[DB_MYSQL].ssl_key = a1;
            data->use_ssl = 1;
        }
        else if(!strncasecmp(dbarg, KEYWORD_SSL_CERT, strlen(KEYWORD_SSL_CERT)))
        {
            data->dbRH[DB_MYSQL].ssl_cert = a1;
            data->use_ssl = 1;
        }
        else if(!strncasecmp(dbarg, KEYWORD_SSL_CA_PATH, strlen(KEYWORD_SSL_CA_PATH)))
        {
            data->dbRH[DB_MYSQL].ssl_ca_path = a1;
            data->use_ssl = 1;
        }
        else if(!strncasecmp(dbarg, KEYWORD_SSL_CA, strlen(KEYWORD_SSL_CA)))
        {
            data->dbRH[DB_MYSQL].ssl_ca = a1;
            data->use_ssl = 1;
        }
        else if(!strncasecmp(dbarg, KEYWORD_SSL_CIPHER, strlen(KEYWORD_SSL_CIPHER)))
        {
            data->dbRH[DB_MYSQL].ssl_cipher = a1;
            data->use_ssl = 1;
        }
	else if(!strncasecmp(dbarg, KEYWORD_MYSQL_RECONNECT, strlen(KEYWORD_MYSQL_RECONNECT)))
	{
	    data->dbRH[DB_MYSQL].mysql_reconnect =1;
	}
#endif

#ifdef ENABLE_POSTGRESQL
        if(!strncasecmp(dbarg, KEYWORD_SSL_MODE, strlen(KEYWORD_SSL_MODE)))
        {
            if ( (!strncasecmp(a1, KEYWORD_SSL_MODE_DISABLE, strlen(KEYWORD_SSL_MODE_DISABLE))) ||
                 (!strncasecmp(a1, KEYWORD_SSL_MODE_ALLOW, strlen(KEYWORD_SSL_MODE_ALLOW))) ||
                 (!strncasecmp(a1, KEYWORD_SSL_MODE_PREFER, strlen(KEYWORD_SSL_MODE_PREFER))) ||
                 (!strncasecmp(a1, KEYWORD_SSL_MODE_REQUIRE, strlen(KEYWORD_SSL_MODE_REQUIRE))) )
            {
                data->dbRH[data->dbtype_id].ssl_mode = a1;
                data->use_ssl = 1;
            }
            else
            {
                ErrorMessage("ERROR database: unknown ssl_mode argument (%s)", a1);
            }
        }
#endif
	
        dbarg = strtok(NULL, "=");
    }
    
    if(data->dbtype_id == DB_ODBC)
    {
	/* Print Transaction Warning */
	if(data->dbname == NULL)
	{
	    ErrorMessage("database: no DSN was specified, unable to try to initialize ODBC connection. (use [dbname] parameter, in configuration file to set DSN)\n");
	    FatalError("");
	}
	else
	{
	    LogMessage("database: will use DSN [%s] for ODBC Connection setup \n",
		       data->dbname);
	}
	
	if(data->host != NULL)
	{
	    ErrorMessage("database: [host] [%s] will not be used, we will use infromation from the DSN [%s], make sure your setup is ok. \n",
			 data->host,
			 data->dbname);
	}

	if(data->user != NULL)
	{
	    ErrorMessage("database: [user] [%s] will not be used, we will use infromation from the DSN [%s], make sure your setup is ok. \n",
			 data->user,
			 data->dbname);
	}
	
	if(data->port != NULL)
	{
	    ErrorMessage("database: [port] [%s] will not be used, we will use infromation from the DSN [%s], make sure your setup is ok. \n",
			 data->port,
			 data->dbname);
	}
    }
    else
    {
	if(data->dbname == NULL)
	{
	    ErrorMessage("ERROR database: must enter database name in configuration file\n\n");
	    DatabasePrintUsage();
	    FatalError("");
	}
	else if(data->host == NULL)
	{
	    ErrorMessage("ERROR database: must enter host in configuration file\n\n");
	    DatabasePrintUsage();
	    FatalError("");
	}
    }
    
    if(data->dbRH[data->dbtype_id].dbConnectionLimit == 0)
    {
	LogMessage("INFO database: Defaulting Reconnect/Transaction Error limit to 10 \n");
	data->dbRH[data->dbtype_id].dbConnectionLimit = 10;
	
	/* Might make a different option for it but for now lets consider
	   the threshold being the same as connectionlimit. */
	data->dbRH[data->dbtype_id].transactionErrorThreshold =  data->dbRH[data->dbtype_id].dbConnectionLimit;
    }
    
    if(data->dbRH[data->dbtype_id].dbReconnectSleepTime.tv_sec == 0)
    {
	LogMessage("INFO database: Defaulting Reconnect sleep time to 5 second \n");
	data->dbRH[data->dbtype_id].dbReconnectSleepTime.tv_sec = 5;
    }
    
    return;
}

/*
** This function will either insert a "new" signature, present in file and not in db and update
** the cache information (db_sig_id) or update an existing signature using its db_sig_id.
**
*/
u_int32_t dbSignatureInformationUpdate(DatabaseData *data,cacheSignatureObj *iUpdateSig)
{
    u_int32_t db_sig_id = 0;
    
    if( (data == NULL) ||
	(iUpdateSig == NULL))
    {
	/* XXX */
	return 1;
    }
    
    DatabaseCleanSelect(data);
    DatabaseCleanInsert(data);
    
    
    if( SnortSnprintf(data->SQL_SELECT,data->SQL_SELECT_SIZE,
		      SQL_SELECT_SPECIFIC_SIGNATURE,
		      iUpdateSig->obj.sid,
		      iUpdateSig->obj.gid,
		      iUpdateSig->obj.rev,
		      iUpdateSig->obj.class_id,
		      iUpdateSig->obj.priority_id,
		      iUpdateSig->obj.message))
    {
	/* XXX */
	LogMessage("ERROR database: calling SnortSnprintf() on data->SQL_SELECT in [%s()] \n",
		   __FUNCTION__);
	
	return 1;
    }
    
    if(iUpdateSig->flag & CACHE_BOTH ||
       iUpdateSig->flag & CACHE_DATABASE_ONLY)
    {
	if( SnortSnprintf(data->SQL_INSERT,data->SQL_INSERT_SIZE,
			  SQL_UPDATE_SPECIFIC_SIGNATURE,
			  iUpdateSig->obj.class_id,
			  iUpdateSig->obj.priority_id,
			  iUpdateSig->obj.rev,
			  iUpdateSig->obj.db_id))
	{
	    /* XXX */

	    LogMessage("ERROR database: calling SnortSnprintf() on data->SQL_INSERT in [%s()] \n",
		       __FUNCTION__);
	    
	    return 1;
	}
    }
    else
    {
	if( SnortSnprintf(data->SQL_INSERT,data->SQL_INSERT_SIZE,
			  SQL_INSERT_SIGNATURE,
			  iUpdateSig->obj.sid,
			  iUpdateSig->obj.gid,
			  iUpdateSig->obj.rev,
			  iUpdateSig->obj.class_id,
			  iUpdateSig->obj.priority_id,
			  iUpdateSig->obj.message))
	{
	    /* XXX */
	    LogMessage("ERROR database: calling SnortSnprintf() on data->SQL_INSERT in [%s()] \n",
		       __FUNCTION__);
	    
	    return 1;
	}
    }
    
    
#if DEBUG
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()] Issuing signature update [%s]\n",
			    __FUNCTION__,
			    data->SQL_INSERT));
#endif


    if(Insert(data->SQL_INSERT,data,1))
    {
	/* XXX */
	LogMessage("ERROR database: calling Insert() in [%s()] \n",
		   __FUNCTION__);
	
        return 1;
    }
    
    
    if(Select(data->SQL_SELECT,data,(u_int32_t *)&db_sig_id))
    {
	/* XXX */
	LogMessage("ERROR database: calling Select() in [%s()] \n",
		   __FUNCTION__);
	
        return 1;
    }

    if(iUpdateSig->flag & CACHE_INTERNAL_ONLY)
    {
	iUpdateSig->flag ^=(CACHE_INTERNAL_ONLY | CACHE_BOTH);
	iUpdateSig->obj.db_id = db_sig_id;
	
    }
    else if(iUpdateSig->flag & CACHE_BOTH ||
	    iUpdateSig->flag & CACHE_DATABASE_ONLY)
    {
	if(db_sig_id != iUpdateSig->obj.db_id)
	{
	    /* XXX */
	    LogMessage("ERROR database: Returned signature_id [%u] is not equal to updated signature_id [%u] in [%s()] \n",
		       db_sig_id,
		       iUpdateSig->obj.db_id,
		       __FUNCTION__);
	    
	    return 1;
	}
    }
    
    return 0;
    
}


/* NOTE: -elz this function need to be broken up.. */
int dbProcessSignatureInformation(DatabaseData *data,void *event, u_int32_t event_type, 
				      u_int32_t *psig_id)
{
    cacheSignatureObj unInitSig;
    dbSignatureObj sigInsertObj= {0};
    
    u_int32_t x =0;
    
    u_int32_t db_classification_id = 0;
    u_int32_t sigMatchCount = 0;
    u_int32_t sid = 0;
    u_int32_t gid = 0;
    u_int32_t revision = 0;
    u_int32_t priority = 0;
    u_int32_t classification = 0;
    u_int32_t sigMsgLen = 0;
    u_int8_t reuseSigMsg = 0;

    if( (data == NULL)   ||
        (event == NULL)  ||
        (psig_id == NULL))
    {
        /* XXX */
        return 1;
    }
    
    memset(&unInitSig,'\0',sizeof(cacheSignatureObj));
    
    *psig_id = 0;
    
    sid =  ntohl(((Unified2EventCommon *)event)->signature_id);
    gid =  ntohl(((Unified2EventCommon *)event)->generator_id);    
    revision = ntohl(((Unified2EventCommon *)event)->signature_revision);
    priority = ntohl(((Unified2EventCommon *)event)->priority_id);
    classification = ntohl(((Unified2EventCommon *)event)->classification_id);
    
    /* 
       This is now only needed for backward compatible with old sid-msg.map file.
       new version has gid || sid || revision || msg || etc.. 
    */
    if( BcSidMapVersion() == SIDMAPV1)
    {
	if (gid == 3)
	{
	    gid = 1;
	}
    }
    

    /* NOTE: elz 
       For sanity purpose the sig_class table SHOULD have internal classification id to prevent possible 
       miss classification tagging ... but this is not happening with the old schema.
    */
       
    
#if DEBUG
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()], Classification cachelookup [class_id: %u]\n",
			    __FUNCTION__,
			    classification));
#endif
    
    db_classification_id = cacheEventClassificationLookup(data->mc.cacheClassificationHead,classification);
    
    /* 
       This function comes with a little twist where it return the number of matching couple for 
       gid sid up to a maximum of 255 (arbitrary defined) this is a static buffer  and it is cleaned every call
       from there if its traversed and compared with revision and priority and classification 
       if one or both differs its reported and inserted ....
    */
    
#if DEBUG
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()], Signature cachelookup [gid: %u] [sid: %u]\n",
			    __FUNCTION__,
			    gid,
			    sid));
#endif
    
    if( (sigMatchCount = cacheEventSignatureLookup(data->mc.cacheSignatureHead,
						   data->mc.plgSigCompare,
						   gid,sid)) > 0 )
	for(x = 0 ; x < sigMatchCount ; x++)
	{
	    if( (data->mc.plgSigCompare[x].cacheSigObj->obj.rev == revision) &&
		(data->mc.plgSigCompare[x].cacheSigObj->obj.class_id == db_classification_id) && 
		(data->mc.plgSigCompare[x].cacheSigObj->obj.priority_id == priority))
	    {
		/* Added for bugcheck */
		assert( data->mc.plgSigCompare[x].cacheSigObj->obj.db_id != 0);
		*psig_id = data->mc.plgSigCompare[x].cacheSigObj->obj.db_id;
		return 0;
	    }
	    
	    /* If we have an "uninitialized signature save it */
	    if( ( (data->mc.plgSigCompare[x].cacheSigObj->obj.rev == 0) || 
		  (data->mc.plgSigCompare[x].cacheSigObj->obj.rev < revision)) ||
		
		/* So we have a signature that was inserted, probably a preprocessor signature,
		   but it has probably never been logged before lets set it as a temporary unassigned signature */
		((data->mc.plgSigCompare[x].cacheSigObj->obj.rev == revision) && 
		 ( data->mc.plgSigCompare[x].cacheSigObj->obj.class_id == 0  ||
		   data->mc.plgSigCompare[x].cacheSigObj->obj.priority_id == 0)))
	    {
		memcpy(&unInitSig,data->mc.plgSigCompare[x].cacheSigObj,sizeof(cacheSignatureObj));
		
		/* 
		** We assume that we have the same signature, but with a smaller revision
		** set the unInitSig db_id to 0 for post processing if we do not find a matching 
		** signature, and get the lastest revision
		*/
		if( (data->mc.plgSigCompare[x].cacheSigObj->obj.rev < revision) ||
		    (data->mc.plgSigCompare[x].cacheSigObj->obj.rev > unInitSig.obj.rev))
		{
		    unInitSig.obj.db_id = 0;
		}
	    }
	}
	    
    if(BcSidMapVersion() == SIDMAPV1)
    {
	if(unInitSig.obj.db_id != 0)
	{
#if DEBUG
	    DEBUG_WRAP(DebugMessage(DB_DEBUG,
				    "[%s()], [%u] signatures where found in cache for [gid: %u] [sid: %u] but non matched event criteria.\n" 
				    "Updating database [db_sig_id: %u] FROM  [rev: %u] classification [ %u ] priority [%u] "
				    "                                  TO    [rev: %u] classification [ %u ] priority [%u]\n",
				    __FUNCTION__,
				    sigMatchCount,
				    gid,
				    sid,
				    unInitSig.obj.db_id,
				    unInitSig.obj.rev,unInitSig.obj.class_id,unInitSig.obj.priority_id,
				    revision,db_classification_id,priority));
#endif
	    
	    unInitSig.obj.rev = revision;
	    unInitSig.obj.class_id = db_classification_id;
	    unInitSig.obj.priority_id = priority;
	    
	    if( (dbSignatureInformationUpdate(data,&unInitSig)))
	    {
		
		LogMessage("[%s()] Line[%u], call to dbSignatureInformationUpdate failed for : \n"
			   "[gid :%u] [sid: %u] [upd_rev: %u] [upd class: %u] [upd pri %u]\n",
			   __FUNCTION__,
			   __LINE__,
			   gid,			\
			   sid,
			   revision,
			   db_classification_id,
			   priority);
		return 1;
	    }
	    
	    assert( unInitSig.obj.db_id != 0);
	
	    *psig_id = unInitSig.obj.db_id;
	    return 0;
	}
    }

    /* 
       To avoid possible collision with an older barnyard process or 
       avoid signature insertion race condition we will look in the 
       database if the signature exist, if it does, we will insert it in 
       cache else we will insert in db and cache 
    */
    
    sigInsertObj.sid = sid;
    sigInsertObj.gid = gid;
    sigInsertObj.rev = revision;
    sigInsertObj.class_id = db_classification_id;
    sigInsertObj.priority_id = priority;
    
    if( SignatureLookupDatabase(data,&sigInsertObj))
    {
	if(unInitSig.obj.sid != 0 && unInitSig.obj.gid != 0)
	{
	    sigMsgLen = strlen(unInitSig.obj.message);
	    
	    if( (sigMsgLen > 1) && 
		(sigMsgLen < SIG_MSG_LEN))
	    {
		reuseSigMsg = 1;
	    }
	}
	
	if(reuseSigMsg)
	{
	    /* The signature was not found we will have to insert it */
	    LogMessage("INFO [%s()]: [Event: %u] with [gid: %u] [sid: %u] [rev: %u] [classification: %u] [priority: %u] Signature Message -> \"[%s]\"\n"
		       "\t was not found in barnyard2 signature cache, this could mean its is the first time the signature is processed, and will be inserted\n"
		       "\t in the database with the above information, this message should only be printed once for each signature that is not  present in the database\n"
		       "\t The new inserted signature will not have its information present in the sig_reference table,it should be present on restart\n"
		       "\t if the information is present in the sid-msg.map file. \n"
		       "\t You can always update the message via a SQL query if you want it to be displayed correctly by your favorite interface\n\n",
		       __FUNCTION__,
		       ntohl(((Unified2EventCommon *)event)->event_id),
		       gid,
		       sid,
		       revision,
		       db_classification_id,
		       priority,
		       unInitSig.obj.message);
	    
	    if( SnortSnprintf(sigInsertObj.message,SIG_MSG_LEN,"%s",
			      unInitSig.obj.message))
	    {
		/* XXX */
		return 1;
	    }
	}
    	else
	{
	    /* The signature does not exist we will have to insert it */
	    LogMessage("INFO [%s()]: [Event: %u] with [gid: %u] [sid: %u] [rev: %u] [classification: %u] [priority: %u]\n"
		       "\t was not found in barnyard2 signature cache, this could lead to display inconsistency.\n"
		       "\t To prevent this warning, make sure that your sid-msg.map and gen-msg.map file are up to date with the snort process logging to the spool file.\n"
		       "\t The new inserted signature will not have its information present in the sig_reference table. \n"
		       "\t Note that the message inserted in the signature table will be snort default message \"Snort Alert [gid:sid:revision]\" \n"
		       "\t You can always update the message via a SQL query if you want it to be displayed correctly by your favorite interface\n\n",
		       __FUNCTION__,
		       ntohl(((Unified2EventCommon *)event)->event_id),
		       gid,
		       sid,
		       revision,
		       db_classification_id,
		       priority);
	    
	    
	    if( SnortSnprintf(sigInsertObj.message,SIG_MSG_LEN,"Snort Alert [%u:%u:%u]",
			      gid,sid,revision))
	    {
		/* XXX */
		return 1;
	    }
	}
	
	if( (SignatureCacheInsertObj(&sigInsertObj,&data->mc,0)))
	{
	    /* XXX */
	    LogMessage("[%s()]: ERROR inserting object in the cache list .... \n",
		       __FUNCTION__);
	    goto func_err;
	}
	
	/* 
	   There is some little overhead traversing the list once 
	   the insertion is done on the HEAD so
	   unless you run 1M rules and still there it should 
	   complete in just a few more jiffies, also its better this way
	   than to query the database everytime isin't.
	*/    
	if(SignaturePopulateDatabase(data,data->mc.cacheSignatureHead,1))
	{
	    /* XXX */
	    LogMessage("[%s()]: ERROR inserting new signature \n",
		       __FUNCTION__);
	    goto func_err;
	}
    }
    else
    {
	if( (SignatureCacheInsertObj(&sigInsertObj,&data->mc,1)))
        {
            /* XXX */
            LogMessage("[%s()]: ERROR inserting object in the cache list .... \n",
                       __FUNCTION__);
            goto func_err;
        }
	
    }
    
    /* Added for bugcheck */
    assert( data->mc.cacheSignatureHead->obj.db_id != 0);
    
    *psig_id = data->mc.cacheSignatureHead->obj.db_id;
    return 0;
    
    
func_err:
    return 1;
}


int dbProcessEventInformation(DatabaseData *data,Packet *p,
			      void *event, 
			      u_int32_t event_type,
			      u_int32_t i_sig_id)
{
    char *SQLQueryPtr = NULL;
    int i = 0;    
    
    if( (data == NULL) ||
	(p == NULL) ||
	(event == NULL))
    {
	    /* XXX */
	    /* Mabey move to debug... */
	    LogMessage("[%s()]: Bailing, Invoked with DatabaseData *[0x%x] Packet *[0x%x] Event(void) *[0x%x] \n",
		       __FUNCTION__,
		       data,
		       p,
		       event);
	    return 1;
    }
    
    
    /* 
       CHECKME: -elz We need to get this logic sorted out since event shouldn't be null
       theorically and event time should be priorized 
    */
    /* Generate a default-formatted timestamp now */
    memset(data->timestampHolder,'\0',SMALLBUFFER);
    
    if(event != NULL)
    {
	if( (GetTimestampByComponent_STATIC(
		 ntohl(((Unified2EventCommon *)event)->event_second),
		 ntohl(((Unified2EventCommon *)event)->event_microsecond),
		 data->tz,data->timestampHolder)))
	{
	    /* XXX */
	    return 1;
	}
    }
    else if(p != NULL)
    {
	if( (GetTimestampByStruct_STATIC((struct timeval *) &p->pkth->ts, 
					 data->tz,data->timestampHolder)))
	{
	    /* XXX */
	    return 1;
	}
    }
    else
    {
	if(GetCurrentTimestamp_STATIC(data->timestampHolder))
	{
	    /* XXX */
	    return 1;
	}
    }
    

/* Some timestring comments comments */
    /* SQL Server uses a date format which is slightly
     * different from the ISO-8601 standard generated
     * by GetTimestamp() and GetCurrentTimestamp().  We
     * need to convert from the ISO-8601 format of:
     *   "1998-01-25 23:59:59+14316557"
     * to the SQL Server format of:
     *   "1998-01-25 23:59:59.143"
     */

    /* Oracle (everything before 9i) does not support
     * date information smaller than 1 second.
     * To go along with the TO_DATE() Oracle function
     * below, this was written to strip out all the
     * excess information. (everything beyond a second)
     * Use the Oracle format of:
     *   "1998-01-25 23:59:59"
     */
    /* MySql does not support date information smaller than
     * 1 second.  This was written to strip out all the
     * excess information. (everything beyond a second)
     * Use the MySql format of:
     *   "2005-12-23 22:37:16"
     */
    /* ODBC defines escape sequences for date data.
     * These escape sequences are of the format:
     *   {literal-type 'value'}
     * The Timestamp (ts) escape sequence handles
     * date/time values of the format:
     *   yyyy-mm-dd hh:mm:ss[.f...]
     * where the number of digits to the right of the
     * decimal point in a time or timestamp interval
     * literal containing a seconds component is
     * dependent on the seconds precision, as contained
     * in the SQL_DESC_PRECISION descriptor field. (For
     * more information, see function SQLSetDescField.)
     *
     * The number of decimal places within the fraction
     * of a second is database dependant.  I wasn't able
     * to easily determine the granularity of this
     * value using SQL_DESC_PRECISION, so choosing to
     * simply discard the fractional part.
     */
    /* From Posgres Documentation
     * For timestamp with time zone, the internally stored
     * value is always in UTC (GMT). An input value that has
     * an explicit time zone specified is converted to UTC
     * using the appropriate offset for that time zone. If no
     * time zone is stated in the input string, then it is assumed
     * to be in the time zone indicated by the system's TimeZone
     * parameter, and is converted to UTC using the offset for
     * the TimeZone zone
     */
/* Some timestring comments comments */

/* 
   COMMENT: -elz
   The new schema will log timestamp in UTC, 
   no need for resolve time to be logged as a string literal, 
   this should be handled by UI's. 
*/
    if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
    {
	goto bad_query;
    }

    switch(data->dbtype_id)
    {
	
    case DB_MSSQL:
    case DB_MYSQL:
    case DB_ORACLE:
    case DB_ODBC:
	if(strlen(data->timestampHolder) > 20)
	{
	    data->timestampHolder[19] = '\0';
	}
	break;
	
    case DB_POSTGRESQL:
    default:
	
	if(strlen(data->timestampHolder) > 24)
	{
	    data->timestampHolder[23] = '\0';
	}

	break;
    }
    
    switch(data->dbtype_id)
    {
	
    case  DB_ORACLE:
	
	if((data->DBschema_version >= 105) )
	{
	    if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
			       "INSERT INTO "
			       "event (sid,cid,signature,timestamp) "
			       "VALUES (%u, %u, %u, TO_DATE('%s', 'YYYY-MM-DD HH24:MI:SS'));",
			       data->sid, 
			       data->cid, 
			       i_sig_id, 
			       data->timestampHolder)) != SNORT_SNPRINTF_SUCCESS)
	    {
		goto bad_query;
	    }
	}
	else
	{
	    /* 
	       COMMENT: -elz
	       I just hate useless duplication and this
	       dosent break anything so just go down please
	    */
	    goto GenericEVENTQUERYJMP;
	    
	}
	
	break;
	

/* -elz: ODBC with {ts ....} string for timestamp!? nha...
  if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
			   "INSERT INTO "
			   "event (sid,cid,signature,timestamp) "
			   "VALUES (%u, %u, %u, {ts '%s'})",
			   data->sid, 
			   data->cid, 
			   i_sig_id, 
			   data->timestampHolder)) != SNORT_SNPRINTF_SUCCESS)
	{
	    goto bad_query;
	}
	break;
*/
	
    case DB_MSSQL:
    case DB_MYSQL:
    case DB_POSTGRESQL:
    case DB_ODBC:
    default:
	
    GenericEVENTQUERYJMP:
	if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
			   "INSERT INTO "
			   "event (sid,cid,signature,timestamp) "
			   "VALUES (%u, %u, %u, '%s');",
			   data->sid, 
			   data->cid, 
			   i_sig_id, 
			   data->timestampHolder)) != SNORT_SNPRINTF_SUCCESS)
	{
	    goto bad_query;
	}
	
	break;
    }
    
    
    /* We do not log fragments! They are assumed to be handled
       by the fragment reassembly pre-processor */
    
    if(p != NULL)
    {
	if((!p->frag_flag) && (IPH_IS_VALID(p)))
	{

	    
	    switch(GET_IPH_PROTO(p))
	    {
		
	    case IPPROTO_ICMP:

		/* IPPROTO_ICMP */
		if(p->icmph)
		{
		    if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
		    {
			goto bad_query;
		    }
		    
		    /*** Build a query for the ICMP Header ***/
		    if(data->detail)
		    {
			if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					   "INSERT INTO "
					   "icmphdr (sid, cid, icmp_type, icmp_code, icmp_csum, icmp_id, icmp_seq) "
					   "VALUES (%u,%u,%u,%u,%u,%u,%u);",
					   data->sid, 
					   data->cid, 
					   p->icmph->type,
					   p->icmph->code, 
					   ntohs(p->icmph->csum),
					   ntohs(p->icmph->s_icmp_id), 
					   ntohs(p->icmph->s_icmp_seq))) != SNORT_SNPRINTF_SUCCESS)
			{
			    goto bad_query;
			}
		    }
		    else
		    {
			if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					   "INSERT INTO "
					   "icmphdr (sid, cid, icmp_type, icmp_code) "
					       "VALUES (%u,%u,%u,%u);",
					   data->sid, 
					   data->cid,
					   p->icmph->type, 
					   p->icmph->code)) != SNORT_SNPRINTF_SUCCESS)
			{
			    goto bad_query;
			}
		    }
		    
		}
		else
		{

		    DEBUG_WRAP(DebugMessage(DB_DEBUG,
					    "[%s()], unable to build query, IP header tell's us its an ICMP packet but "
					    "there is not ICMP header in the decoded packet ... \n",
					    __FUNCTION__));
		}
		break;
		/* IPPROTO_ICMP */


		/* IPPROTO_TCP */
	    case IPPROTO_TCP:

		if(p->tcph)
		{
		    if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
		    {
			goto bad_query;
		    }
		    
		    /*** Build a query for the TCP Header ***/
		    if(data->detail)
		    {
			if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					   "INSERT INTO "
					   "tcphdr (sid, cid, tcp_sport, tcp_dport, "
					   "tcp_seq, tcp_ack, tcp_off, tcp_res, "
					   "tcp_flags, tcp_win, tcp_csum, tcp_urp) "
					   "VALUES (%u,%u,%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u);",
					   data->sid,
					   data->cid,
					   ntohs(p->tcph->th_sport),
					   ntohs(p->tcph->th_dport),
					   (u_long)ntohl(p->tcph->th_seq),
					   (u_long)ntohl(p->tcph->th_ack),
					   TCP_OFFSET(p->tcph),
					   TCP_X2(p->tcph),
					   p->tcph->th_flags,
					   ntohs(p->tcph->th_win),
					   ntohs(p->tcph->th_sum),
					   ntohs(p->tcph->th_urp))) != SNORT_SNPRINTF_SUCCESS)
			{
			    goto bad_query;
			}
		    }
		    else
		    {
			if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					   "INSERT INTO "
					   "tcphdr (sid,cid,tcp_sport,tcp_dport,tcp_flags) "
					   "VALUES (%u,%u,%u,%u,%u);",
					   data->sid,
					   data->cid,
					   ntohs(p->tcph->th_sport),
					   ntohs(p->tcph->th_dport),
					   p->tcph->th_flags))  != SNORT_SNPRINTF_SUCCESS)
			{
			    goto bad_query;
			}
		    }
		    
		    if(data->detail)
		    {
                    /*** Build the query for TCP Options ***/
			for(i=0; i < (int)(p->tcp_option_count); i++)
			{

			    if( (&p->tcp_options[i]) &&
				(p->tcp_options[i].len > 0))
			    {
				if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
				{
				    goto bad_query;
				}
				
				if((data->encoding == ENCODING_HEX) || (data->encoding == ENCODING_ASCII))
				{
				    //packet_data = fasthex(p->tcp_options[i].data, p->tcp_options[i].len);
				    if( fasthex_STATIC(p->tcp_options[i].data, p->tcp_options[i].len,data->PacketData))
				    {
				    /* XXX */
					goto bad_query;
				    }
				}
				else
				{
				    //packet_data = base64(p->tcp_options[i].data, p->tcp_options[i].len);
				    if( base64_STATIC(p->tcp_options[i].data, p->tcp_options[i].len,data->PacketData))
				    {
				    /* XXX */
					goto bad_query;
				    }
			    }
				
				
				if(data->dbtype_id == DB_ORACLE)
				{
				    /* Oracle field BLOB type case. We append unescaped
				     * opt_data data after query, which later in Insert()
				     * will be cut off and uploaded with OCIBindByPos().
				     */
				    if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
						       "INSERT INTO "
						       "opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
						       "VALUES (%u,%u,%u,%u,%u,%u,:1);|%s",
						       data->sid,
						       data->cid,
						       i,
						       6,
						       p->tcp_options[i].code,
						       p->tcp_options[i].len,
						       //packet_data))  != SNORT_SNPRINTF_SUCCESS)
						       data->PacketData))  != SNORT_SNPRINTF_SUCCESS)
				    {
					goto bad_query;
				    }
				}
				else
				{
				    if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
						       "INSERT INTO "
						       "opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
						       "VALUES (%u,%u,%u,%u,%u,%u,'%s');",
						       data->sid,
						       data->cid,
						       i,
						       6,
						       p->tcp_options[i].code,
						       p->tcp_options[i].len,
						       //packet_data))  != SNORT_SNPRINTF_SUCCESS)
						       data->PacketData))  != SNORT_SNPRINTF_SUCCESS)
				    {
					goto bad_query;
				    }
				}
			    }
			}
		    }
		}
		else
                {
                    DEBUG_WRAP(DebugMessage(DB_DEBUG,
                                            "[%s()], unable to build query, IP header tell's us its an TCP  packet but "
					    "there is not TCP header in the decoded packet ... \n",
					    __FUNCTION__));
		}
		
		break;		
		/* IPPROTO_TCP */

		
		/* IPPROTO_UDP */
	    case IPPROTO_UDP:

		if(p->udph)
		{
		    /*** Build the query for the UDP Header ***/
		    if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
		    {
			goto bad_query;
		    }
		    
		    if(data->detail)
		    {
			if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					   "INSERT INTO "
					   "udphdr (sid, cid, udp_sport, udp_dport, udp_len, udp_csum) "
					   "VALUES (%u, %u, %u, %u, %u, %u);",
					   data->sid,
					   data->cid,
					   ntohs(p->udph->uh_sport),
					   ntohs(p->udph->uh_dport),
					   ntohs(p->udph->uh_len),
					   ntohs(p->udph->uh_chk)))  != SNORT_SNPRINTF_SUCCESS)
			{
			    goto bad_query;
			}
		    }
		    else
		    {
			if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					   "INSERT INTO "
					   "udphdr (sid, cid, udp_sport, udp_dport) "
					   "VALUES (%u, %u, %u, %u);",
					   data->sid,
					   data->cid,
					   ntohs(p->udph->uh_sport),
					   ntohs(p->udph->uh_dport)))  != SNORT_SNPRINTF_SUCCESS)
			{
			    goto bad_query;
			}
		    }
		}
		else
		{
		    DEBUG_WRAP(DebugMessage(DB_DEBUG,
					    "[%s()], unable to build query, IP header tell's us its an UDP packet but "
					    "there is not UDP header in the decoded packet ... \n",
					    __FUNCTION__));
		}
		break;
		/* IPPROTO_UDP */
		    
		
		/* DEFAULT */
	    default:
		/* Do nothing ... */
		break;
		/* DEFAULT */
	    }
                
	    /*** Build the query for the IP Header ***/
	    if(p->iph)
	    {

		if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
		{
		    goto bad_query;
		}
		
		if(data->detail)
		{
		    if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					"INSERT INTO "
					"iphdr (sid, cid, ip_src, ip_dst, ip_ver, ip_hlen, "
					"ip_tos, ip_len, ip_id, ip_flags, ip_off,"
					"ip_ttl, ip_proto, ip_csum) "
					"VALUES (%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u);",
					data->sid,
					data->cid,
					(u_long)ntohl(p->iph->ip_src.s_addr),
					(u_long)ntohl(p->iph->ip_dst.s_addr),
					IP_VER(p->iph),
					IP_HLEN(p->iph),
					p->iph->ip_tos,
					ntohs(p->iph->ip_len),
					ntohs(p->iph->ip_id),
					p->frag_flag,
					ntohs(p->frag_offset),
					p->iph->ip_ttl,
					p->iph->ip_proto,
				       ntohs(p->iph->ip_csum))) != SNORT_SNPRINTF_SUCCESS)
		    {
			goto bad_query;
		    }
		}
		else
		{
		    if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					"INSERT INTO "
					"iphdr (sid, cid, ip_src, ip_dst, ip_proto) "
					"VALUES (%u,%u,%lu,%lu,%u);",
					data->sid,
					data->cid,
					(u_long)ntohl(p->iph->ip_src.s_addr),
					(u_long)ntohl(p->iph->ip_dst.s_addr),
				       GET_IPH_PROTO(p))) != SNORT_SNPRINTF_SUCCESS)
		    {
			goto bad_query;
		    }
		}
	    
		
		/*** Build querys for the IP Options ***/
		if(data->detail)
		{
		    for(i=0 ; i < (int)(p->ip_option_count); i++)
		    {
			if( (&p->ip_options[i]) &&
			    (p->ip_options[i].len > 0))
			{
			    if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
			    {
				goto bad_query;
			    }
			    
			    if((data->encoding == ENCODING_HEX) || 
			       (data->encoding == ENCODING_ASCII))
			    {
				//packet_data = fasthex(p->ip_options[i].data, p->ip_options[i].len);
				if( fasthex_STATIC(p->ip_options[i].data, p->ip_options[i].len,data->PacketData))
				{
				    /* XXX */
				    goto bad_query;
				}
			    }
			    else
			    {
				//packet_data = base64(p->ip_options[i].data, p->ip_options[i].len);
				if( base64_STATIC(p->ip_options[i].data, p->ip_options[i].len,data->PacketData))
				{
				    /* XXX */
				    goto bad_query;
				}

			    }
			    
			    if(data->dbtype_id == DB_ORACLE)
			    {
				/* Oracle field BLOB type case. We append unescaped
				 * opt_data data after query, which later in Insert()
				 * will be cut off and uploaded with OCIBindByPos().
				 */
				if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
						   "INSERT INTO "
						   "opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
						   "VALUES (%u,%u,%u,%u,%u,%u,:1);|%s",
						   data->sid,
						   data->cid,
						   i,
						   0,
						   p->ip_options[i].code,
						   p->ip_options[i].len,
						   //packet_data))  != SNORT_SNPRINTF_SUCCESS)
						   data->PacketData))  != SNORT_SNPRINTF_SUCCESS)
				{
				    goto bad_query;
				}
			    }
			    else
			    {
				if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
						   "INSERT INTO "
						    "opt (sid,cid,optid,opt_proto,opt_code,opt_len,opt_data) "
						   "VALUES (%u,%u,%u,%u,%u,%u,'%s');",
						   data->sid,
						   data->cid,
						   i,
						   0,
						   p->ip_options[i].code,
						   p->ip_options[i].len,
						   //packet_data))  != SNORT_SNPRINTF_SUCCESS)
						   data->PacketData))  != SNORT_SNPRINTF_SUCCESS)
				{
				    goto bad_query;
				}
			    }
			}
		    }
		}
	    }
	    
	    
	    /*** Build query for the payload ***/
	    if ( p->data )
	    {
		if(data->detail)
		{
		    if(p->dsize)
		    {
			if( (SQLQueryPtr=SQL_GetNextQuery(data)) == NULL)
			{
			    goto bad_query;
			}
			
			if(data->encoding == ENCODING_BASE64)
			{
			    //packet_data_not_escaped = base64(p->data, p->dsize);
			    if(base64_STATIC(p->data,p->dsize,data->PacketDataNotEscaped))
			    {
				/* XXX */
				goto bad_query;
			    }
			}
			else if(data->encoding == ENCODING_ASCII)
			{
			    //packet_data_not_escaped = ascii(p->data, p->dsize);
			    if(ascii_STATIC(p->data, p->dsize,data->PacketDataNotEscaped))
			    {
				/* XXX */
				goto bad_query;
			    }
			    
			}
			else
			{
			    //packet_data_not_escaped = fasthex(p->data, p->dsize);
			    if( (fasthex_STATIC(p->data, p->dsize,data->PacketDataNotEscaped)))
			    {
				/* XXX */
                                goto bad_query;
			    }
			    
			}
			
			//packet_data = snort_escape_string(packet_data_not_escaped, data);
			if( snort_escape_string_STATIC(data->PacketDataNotEscaped,strlen(data->PacketDataNotEscaped)+1,data))
			{
			    /* XXX */
			    goto bad_query;
			}
			
			
			switch(data->dbtype_id)
			{
			    
			case DB_ORACLE:
			    
			    /* Oracle field BLOB type case. We append unescaped
			     * packet_payload data after query, which later in Insert()
			     * will be cut off and uploaded with OCIBindByPos().
			     */
			    if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					       "INSERT INTO "
					       "data (sid,cid,data_payload) "
					       "VALUES (%u,%u,:1);|%s",
					       data->sid,
					       data->cid,
					       //packet_data_not_escaped))  != SNORT_SNPRINTF_SUCCESS)
					       data->PacketDataNotEscaped)) != SNORT_SNPRINTF_SUCCESS)
			    {
				goto bad_query;
			    }
			    break;
			    
			default:
			    if( (SnortSnprintf(SQLQueryPtr, MAX_QUERY_LENGTH,
					       "INSERT INTO "
					       "data (sid,cid,data_payload) "
					       "VALUES (%u,%u,'%s');",
					       data->sid,
					       data->cid,
					       //packet_data))  != SNORT_SNPRINTF_SUCCESS)
					       data->sanitize_buffer)) != SNORT_SNPRINTF_SUCCESS)
			    {
				goto bad_query;
			    }
			    break;
			}
		    }
		}
	    }
	}
    }
    
    return 0;
    
    
bad_query:
    
    setTransactionCallFail(&data->dbRH[data->dbtype_id]);
    return 1;
    
}
    


/*******************************************************************************
 * Function: Database(Packet *p, void *event, uint32_t event_type, void *arg)
 *
 * Purpose: Insert data into the database
 *
 * Arguments: p   => pointer to the current packet data struct
 *            msg => pointer to the signature message
 *
 * Returns: void function
 *
 ******************************************************************************/
void Database(Packet *p, void *event, uint32_t event_type, void *arg)
{
    DatabaseData *data = (DatabaseData *)arg;

    char *CurrentQuery = NULL;

    u_int32_t sig_id = 0;
    u_int32_t itr = 0;
    u_int32_t SQLMaxQuery = 0;
    
    if(data == NULL)
    {
	FatalError("database [%s()]: Called with a NULL DatabaseData Argument, can't process \n",
		   __FUNCTION__);
    }
    
    if( event == NULL || p == NULL)
    {
	LogMessage("WARNING database [%s()]: Called with Event[0x%x] Event Type [%u] (P)acket [0x%x], information has not been outputted. \n",
		   __FUNCTION__,
		   event,
		   event_type,
		   p);
	return;
    }
    
    
    /* 
       Check for invalid revision eg: rev==0 when people write their own testing signature and 
       do not set a revision, in our context we will not log it to the database
       and print a informative messsage 
    */
    u_int32_t sid = 0;
    u_int32_t gid = 0;
    u_int32_t revision = 0;
    u_int32_t event_id = 0;
    u_int32_t event_second = 0;
    u_int32_t event_microsecond = 0;
    
    sid =  ntohl(((Unified2EventCommon *)event)->signature_id);    
    gid =  ntohl(((Unified2EventCommon *)event)->generator_id);
    revision = ntohl(((Unified2EventCommon *)event)->signature_revision);
    event_id = ntohl(((Unified2EventCommon *)event)->event_id);
    event_second = ntohl(((Unified2EventCommon *)event)->event_second);
    event_microsecond =  ntohl(((Unified2EventCommon *)event)->event_microsecond);
    
    if( (gid == 1) &&
	(revision == 0))
    {
	LogMessage("INFO: Current event with event_id [%u] Event Second:Microsecond [%u:%u] and signature id of [%u] was logged with a revision of [%u]\n"
		   "      Make sure you verify your triggering  rule body so it include the snort keyword \"rev:xxx;\" Where xxx is greater than 0 \n"
		   ">>>>>>The event has not been logged to the database<<<<<<\n",
		   event_id,
		   event_second,
		   event_microsecond,
		   sid,
		   revision);
	return;
    }

/*
  This has been refactored to simplify the workflow of the function 
  We separate the legacy signature entry code and the event entry code
*/
    
/* Point where transaction rollback */
TransacRollback: 
    if(checkTransactionState(&data->dbRH[data->dbtype_id]) && 
       checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
	if(RollbackTransaction(data))
	{
	    /* XXX */
	    FatalError("database Unable to rollback transaction in [%s()]\n",
		       __FUNCTION__);
	}
	
	resetTransactionState(&data->dbRH[data->dbtype_id]);
    }
    
    if( BeginTransaction(data) )
    {
	/* XXX */
	FatalError("database [%s()]: Failed to Initialize transaction, bailing ... \n",
		   __FUNCTION__);
    }
    
    if( dbProcessSignatureInformation(data,event,event_type,&sig_id))
    {
	/* XXX */
	setTransactionCallFail(&data->dbRH[data->dbtype_id]);
	FatalError("[dbProcessSignatureInformation()]: Failed, stopping processing \n");
    }
    
    if( dbProcessEventInformation(data,p,event,event_type,sig_id))
    {
	/* XXX */
	setTransactionCallFail(&data->dbRH[data->dbtype_id]);
	FatalError("[dbProcessEventInformation()]: Failed, stopping processing \n");
    }
    
    
    if( (SQLMaxQuery = SQL_GetMaxQuery(data)))
    {
	itr = 0;
	for(itr = 0 ; itr < SQLMaxQuery; itr++)
	{
	    CurrentQuery = NULL;
	    if( (CurrentQuery = SQL_GetQueryByPos(data,itr)) == NULL)
	    {
		/* XXX */
		goto bad_query;
	    }
		    
	    if (Insert(CurrentQuery,data,1))
	    {
		setTransactionCallFail(&data->dbRH[data->dbtype_id]);
		ErrorMessage("[%s()]: Insertion of Query [%s] failed\n",
			     __FUNCTION__,
			     CurrentQuery);
		goto bad_query;
		break;
	    }
	}
    }
    
    if(CommitTransaction(data))
    {
	/* XXX */
	ErrorMessage("ERROR database: [%s()]: Error commiting transaction \n",
		     __FUNCTION__);
	
	setTransactionCallFail(&data->dbRH[data->dbtype_id]);
	goto bad_query;
    }
    else
    {
	resetTransactionState(&data->dbRH[data->dbtype_id]);
    }
    
    
    /* Clean the query */
    SQL_Cleanup(data);
    
    /* Increment the cid*/
    data->cid++;
    //LogMessage("Inserted a new event \n");
    /* Normal Exit Path */

    return;
    
bad_query:
    if( (SQLMaxQuery = SQL_GetMaxQuery(data)))
    {
	LogMessage("WARNING database: [%s()] Failed transaction with current query transaction \n ",
		   __FUNCTION__);
	
        itr = 0;
        for(itr = 0 ; itr < SQLMaxQuery; itr++)
        {
            CurrentQuery = NULL;
            if( (CurrentQuery = SQL_GetQueryByPos(data,itr)) == NULL)
            {
                /* XXX */
		FatalError("database [%s()]: Failed to execute SQL_GetQueryByPos() in bad_query state, exiting \n",
			   __FUNCTION__);
            }
	    
	    LogMessage("WARNING database: Failed Query Position [%d] Failed Query Body [%s] \n",
		       itr+1,
		       CurrentQuery);
        }
	
	LogMessage("WARNING database [%s()]: End of failed transaction block \n",
		   __FUNCTION__);
    }
    
    SQL_Cleanup(data);
    
    
    if( checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
	goto TransacRollback;
    }

    return;
}



/* Some of the code in this function is from the
   mysql_real_escape_string() function distributed with mysql.

   Those portions of this function remain
   Copyright (C) 2000 MySQL AB & MySQL Finland AB & TCX DataKonsult AB

   We needed a more general case that was not MySQL specific so there
   were small modifications made to the mysql_real_escape_string()
   function. */

char * snort_escape_string(char * from, DatabaseData * data)
{
    char * to;
    char * to_start;
    char * end;
    int from_length;

    from_length = (int)strlen(from);

    to = (char *)SnortAlloc(strlen(from) * 2 + 1);
    to_start = to;
#ifdef ENABLE_ORACLE
    if (data->dbtype_id == DB_ORACLE)
    {
	for (end=from+from_length; from != end; from++)
      {
        switch(*from)
        {
          case '\'':           /*  '  -->  '' */
            *to++= '\'';
            *to++= '\'';
            break;
          case '\032':         /* Ctrl-Z (Win32 EOF)  -->  \\Z */
            *to++= '\\';       /* This gives problems on Win32 */
            *to++= 'Z';
            break;
          default:             /* copy character directly */
            *to++= *from;
        }
      }
    }
    else
#endif
#ifdef ENABLE_MSSQL
    if (data->dbtype_id == DB_MSSQL)
    {
      for (end=from+from_length; from != end; from++)
      {
        switch(*from)
        {
          case '\'':           /*  '  -->  '' */
            *to++= '\'';
            *to++= '\'';
            break;
          default:             /* copy character directly */
            *to++= *from;
        }
      }
    }
    else
#endif
/* Historically these were together in a common "else".
 * Keeping it that way until somebody complains...
 */
#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
    if (data->dbtype_id == DB_MYSQL ||
        data->dbtype_id == DB_POSTGRESQL)
    {
      for(end=from+from_length; from != end; from++)
      {
        switch(*from)
        {
          /*
           * Only need to escape '%' and '_' characters
           * when querying a SELECT...LIKE, which never
           * occurs in Snort.  Excluding these checks
           * for that reason.
          case '%':            ** %  -->  \% **
            *to++= '\\';
            *to++= '%';
            break;
          case '_':            ** _  -->  \_ **
            *to++= '\\';
            *to++= '_';
            break;
           */

	case 0:              /* NULL  -->  \\0  (probably never encountered due to strlen() above) */
	    *to++= '\\';       /* Must be escaped for 'mysql' */
            *to++= '0';
            break;
	case '\n':           /* \n  -->  \\n */
            *to++= '\\';       /* Must be escaped for logs */
            *to++= 'n';
            break;
	case '\r':           /* \r  -->  \\r */
            *to++= '\\';
            *to++= 'r';
            break;
	case '\t':           /* \t  -->  \\t */
	    *to++= '\\';
            *to++= 't';
            break;
	case '\\':           /* \  -->  \\ */
	    *to++= '\\';
            *to++= '\\';
            break;
	case '\'':           /* '  -->  \' */
	    *to++= '\\';
	    *to++= '\'';
            break;
	case '"':            /* "  -->  \" */
            *to++= '\\';       /* Better safe than sorry */
            *to++= '"';
            break;
	case '\032':         /* Ctrl-Z (Win32 EOF)  -->  \\Z */
            if (data->dbtype_id == DB_MYSQL)
            {
		*to++= '\\';       /* This gives problems on Win32 */
		*to++= 'Z';
            }
            else
            {
		*to++= *from;
            }
            break;
	default:             /* copy character directly */
            *to++= *from;
        }
      }
    }
    else
#endif
    {
	for (end=from+from_length; from != end; from++)
	{
	    switch(*from)
	    {
	    case '\'':           /*  '  -->  '' */
            *to++= '\'';
            *to++= '\'';
            break;
	    default:             /* copy character directly */
		*to++= *from;
	    }
	}
    }
    *to=0;
    return(char *)to_start;
}

/* 
  Same function as above but will work on a static buffer, slightly different arguments...
*/
u_int32_t snort_escape_string_STATIC(char *from, u_int32_t buffer_max_len ,DatabaseData *data)
{



#if defined(ENABLE_POSTGRESQL)   
    int error = 0;
    size_t write_len = 0;
#endif /* defined(ENABLE_POSRGRESQL) */

    char * to = NULL;
    char * to_start = NULL;
    char * end = NULL;
    char * from_start = NULL;
    int from_length = 0;
    
    if( (from == NULL) ||
	(data == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (buffer_max_len > (DATABASE_MAX_ESCAPE_STATIC_BUFFER_LEN - 1)) ||
	( (strlen(from) + 1 ) > buffer_max_len) ||
	(buffer_max_len == 0))
    {
	/* XXX */
	FatalError("database [%s()]: Edit source code and change the value of the #define  DATABASE_MAX_ESCAPE_STATIC_BUFFER_LEN in spo_database.h to something greater than [%u] \n",
		   __FUNCTION__,
		   buffer_max_len);
    }
    
    memset(data->sanitize_buffer,'\0',DATABASE_MAX_ESCAPE_STATIC_BUFFER_LEN);
    
    if( (from_length = strlen(from)) == 1)
    {
	/* Nothing to escape */
	return 0;
    }
    
    from_start = from;    
    to = data->sanitize_buffer;
    to_start = to;
    
    switch(data->dbtype_id)
    {
#ifdef ENABLE_ORACLE
    case DB_ORACLE:
	for (end=from+from_length; from != end; from++)
	{
	    switch(*from)
	    {
	    case '\'':           /*  '  -->  '' */
		*to++= '\'';
		*to++= '\'';
		break;
	    case '\032':         /* Ctrl-Z (Win32 EOF)  -->  \\Z */
		*to++= '\\';       /* This gives problems on Win32 */
		*to++= 'Z';
		break;
	    default:             /* copy character directly */
		*to++= *from;
	    }
	}
	break;
#endif

#ifdef ENABLE_MSSQL
    case DB_MSSQL:

	for (end=from+from_length; from != end; from++)
	{
	    switch(*from)
	    {
	    case '\'':           /*  '  -->  '' */
		*to++= '\'';
		*to++= '\'';
		break;
	    default:             /* copy character directly */
		*to++= *from;
	    }
	}
	break;
#endif
/* Historically these were together in a common "else".
 * Keeping it that way until somebody complains...
 */

#if  defined( ENABLE_MYSQL ) || defined (ENABLE_ODBC)
//#ifdef ENABLE_MYSQL
    case DB_ODBC:
    case DB_MYSQL:
	for(end=from+from_length; from != end; from++)
	{
	    switch(*from)
	    {
		/*
		 * Only need to escape '%' and '_' characters
		 * when querying a SELECT...LIKE, which never
		 * occurs in Snort.  Excluding these checks
		 * for that reason.
		 */
		/*
		  case '%':            * %  -->  \% *
		  *to++= '\\';
		  *to++= '%';
		  break;
		  case '_':            * _  -->  \_  *
		  *to++= '\\';
		  *to++= '_';
		  break;
		*/
		
	    case 0:              /* NULL  -->  \\0  (probably never encountered due to strlen() above) */
		*to++= '\\';       /* Must be escaped for 'mysql' */
		*to++= '0';
		break;
	    case '\n':           /* \n  -->  \\n */
		*to++= '\\';       /* Must be escaped for logs */
		*to++= 'n';
		break;
	    case '\r':           /* \r  -->  \\r */
		*to++= '\\';
		*to++= 'r';
		break;
	    case '\t':           /* \t  -->  \\t */
		*to++= '\\';
		*to++= 't';
		break;
	    case '\\':           /* \  -->  \\ */
		*to++= '\\';
		*to++= '\\';
		break;
	    case '/':
		*to++= '\\';      /* / --> \/ */
		*to++= '/';
		break;
	    case '\'':           /* '  -->  \' */
		*to++= '\\';
		*to++= '\'';
		break;
	    case '"':            /* "  -->  \" */
		*to++= '\\';       /* Better safe than sorry */
		*to++= '"';
		break;
	    case '\032':         /* Ctrl-Z (Win32 EOF)  -->  \\Z */
		if (data->dbtype_id == DB_MYSQL)
		{
		    *to++= '\\';       /* This gives problems on Win32 */
		    *to++= 'Z';
		}
		else
		{
		    *to++= *from;
		}
		break;
	    default:             /* copy character directly */
		*to++= *from;
	    }
	}
    	break;
#endif /* defined( ENABLE_MYSQL ) || defined (ENABLE_ODBC) */
	
#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:
	
	if( (write_len = PQescapeStringConn(data->p_connection,
					    data->sanitize_buffer,
					    from,
					    buffer_max_len,&error)) == 0)
	{
	    /* XXX */
	    return 1;
	}
	
	if(error != 1)
	{
	    memcpy(from_start,data->sanitize_buffer,write_len+1);
	}
	else
	{
	    /* XXX */
	    return 1;
	}
	
	return 0;
	break;
#endif /* ENABLE_POSTGRESQL*/	
    default:
	for (end=from+from_length; from != end; from++)
	{
	    switch(*from)
	    {
	    case '\'':           /*  '  -->  '' */
		*to++= '\'';
		*to++= '\'';
		break;
	    case '\\':           /* \  -->  \\ */
                *to++= '\\';
                *to++= '\\';
                break;
	    default:             /* copy character directly */
		*to++= *from;
	    }
	}
	break;
    }
    
    *to='\0';
 
    if(strlen(to_start) > buffer_max_len)
    {
	/* XXX */
	return 1;
    }
    

    memcpy(from_start,to_start,strlen(to_start));
    return 0;
}


/*******************************************************************************
 * Function: UpdateLastCid(DatabaseData * data, int sid, int cid)
 *
 * Purpose: Sets the last cid used for a given a sensor ID (sid),
 *
 * Arguments: data  : database information
 *            sid   : sensor ID
 *            cid   : event ID
 *
 * Returns: status of the update
 *
 ******************************************************************************/
int UpdateLastCid(DatabaseData *data, int sid, int cid)
{
    
    DatabaseCleanInsert(data);

    if( BeginTransaction(data) )
    {
        /* XXX */
        FatalError("database [%s()]: Failed to Initialize transaction, bailing ... \n",
                   __FUNCTION__);
    }
    
    if( (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
		       "UPDATE sensor "
		       "SET last_cid = %u "
		       "WHERE sid = %u;",
		       cid, sid)) != SNORT_SNPRINTF_SUCCESS)
    {
	/* XXX */
	return 1;
    }
    
    if(Insert(data->SQL_INSERT, data,0))
    {
	/* XXX */
	return 1;
    }
    
    if(CommitTransaction(data))
    {
        /* XXX */
        ErrorMessage("ERROR database: [%s()]: Error commiting transaction \n",
                     __FUNCTION__);
	
        setTransactionCallFail(&data->dbRH[data->dbtype_id]);
	return 1;
    }
    else
    {
	resetTransactionState(&data->dbRH[data->dbtype_id]);
    }
    
    return 0;
}
    
/*******************************************************************************
 * Function: GetLastCid(DatabaseData * data, int sid)
 *
 * Purpose: Returns the last cid used for a given a sensor ID (sid),
 *
 * Arguments: data  : database information
 *            sid   : sensor ID
 *
 * Returns: last cid for a given sensor ID (sid)
 *
 ******************************************************************************/
int GetLastCid(DatabaseData *data, int sid,u_int32_t *r_cid)
{

    if(r_cid == NULL)
    {
	/* XXX */
	return 1;
    }
    
    
    DatabaseCleanSelect(data);
    
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                        "SELECT last_cid "
                        "  FROM sensor "
		       " WHERE sid = %u", sid)) != SNORT_SNPRINTF_SUCCESS)
    {
	*r_cid = 0;
        return 1;
    }
    
    if( Select(data->SQL_SELECT,data,(u_int32_t *)r_cid))
    {
	/* XXX */
        ErrorMessage("ERROR database: executing Select() with Query [%s] \n",data->SQL_SELECT);
	*r_cid = 0;
	
	return 1;
    }
    
    
    return 0;
}

/*******************************************************************************
 * Function: CheckDBVersion(DatabaseData * data)
 *
 * Purpose: To determine the version number of the underlying DB schema
 *
 * Arguments: database information
 *
 * Returns: version number of the schema
 *
 ******************************************************************************/
int CheckDBVersion(DatabaseData * data)
{
    if(data == NULL)
    {
	/* XXX */
	return 1;
    }

   DatabaseCleanSelect(data);

#if defined(ENABLE_MSSQL) || defined(ENABLE_ODBC)
//   if ( data->dbtype_id == DB_MSSQL ||
   //      (data->dbtype_id==DB_ODBC && data->u_underlying_dbtype_id==DB_MSSQL) )
   if(data->dbtype_id == DB_ODBC)
   {
      /* "schema" is a keyword in SQL Server, so use square brackets
       *  to indicate that we are referring to the table
       */
       if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                          "SELECT vseq FROM [schema]")) != SNORT_SNPRINTF_SUCCESS)
       {
	   return 1;
       }
   }
   else
#endif
   {
#if defined(ENABLE_MYSQL)
      if (data->dbtype_id == DB_MYSQL)
      {
	  /* "schema" is a keyword in MYSQL, so use `schema`
	   *  to indicate that we are referring to the table
          */
	  
	  if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                             "SELECT vseq FROM `schema`")) != SNORT_SNPRINTF_SUCCESS)
	  {
	      return 1;
	  }
      }
      else
#endif
      {
	  if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                             "SELECT vseq FROM schema")) != SNORT_SNPRINTF_SUCCESS)
	  {
	      return 1;
	  }
      }
   }
   
   if( Select(data->SQL_SELECT,data,(u_int32_t *)&data->DBschema_version))
   {
       /* XXX */
       ErrorMessage("ERROR database: executing Select() with Query [%s] \n",data->SQL_SELECT);
       return 1;
   }
   
   
   if (data->DBschema_version == -1)
       FatalError("database Unable to construct query - output error or truncation\n");
   
   if ( data->DBschema_version == 0 )
   {
       FatalError(FATAL_BAD_SCHEMA_1, LATEST_DB_SCHEMA_VERSION, FATAL_BAD_SCHEMA_2);
   }
   if ( data->DBschema_version < LATEST_DB_SCHEMA_VERSION )
   {
       FatalError(FATAL_OLD_SCHEMA_1, data->DBschema_version, LATEST_DB_SCHEMA_VERSION, FATAL_OLD_SCHEMA_2);
   }
   
   return 0;
}

/*******************************************************************************
 * Function: BeginTransaction(DatabaseData * data)
 *
 * Purpose: Database independent SQL to start a transaction
 *
 ******************************************************************************/
u_int32_t BeginTransaction(DatabaseData * data)
{
    
    if(data == NULL)
    {
	/* XXX */
	FatalError("database [%s()], Invoked with NULL DatabaseData \n",
		   __FUNCTION__);
    }

    
    if(checkTransactionState(&data->dbRH[data->dbtype_id]))
    {
	/* We already are in a transaction, possible nested call do not sub BEGIN..*/
	return 0;
    }


    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_ODBC
    case DB_ODBC:
	setTransactionState(&data->dbRH[data->dbtype_id]);
	return 0;
	break;
#endif

	
#ifdef ENABLE_MSSQL
    case DB_MSSQL:
	setTransactionState(&data->dbRH[data->dbtype_id]);
	if( Insert("BEGIN TRANSACTION", data,0))
	{
	    /*XXX */ 
	    return 1;
	}
	return 0;
	
	break;
#endif
#ifdef ENABLE_ORACLE
    case DB_ORACLE:
	
	/* Do nothing.  Oracle will implicitly create a transaction. */
	/* CHECK -elz i will have to check on that */
	return 0;
	break;
	
#endif


    default:
	setTransactionState(&data->dbRH[data->dbtype_id]);
	if( Insert("BEGIN;", data,0))
	{
	    /*XXX */
	    return 1;
	}
	
	return 0;
	break;
    }
    
    
    /* XXX */
    return 1;
}

/*******************************************************************************
 * Function: CommitTransaction(DatabaseData * data)
 *
 * Purpose: Database independent SQL to commit a transaction
 *
 ******************************************************************************/
u_int32_t  CommitTransaction(DatabaseData * data)
{

    if(data == NULL)
    {
        /* XXX */
        FatalError("database [%s()], Invoked with NULL DatabaseData \n",
                   __FUNCTION__);
    }
    
    if((checkTransactionState(&data->dbRH[data->dbtype_id])) == 0)
    {
	/* We are not in a transaction, effect of some possible nested call
	   be quiet */
	return 0;
    }

    switch(data->dbtype_id)
    {
#ifdef ENABLE_ODBC
    case DB_ODBC:

	//if( SQLEndTran(SQL_HANDLE_DBC, data->u_connection, SQL_COMMIT) != SQL_SUCCESS )
	//{
	//ODBCPrintError(data,SQL_HANDLE_DBC);
	//}
	goto transaction_success;
	break;

#endif
#ifdef ENABLE_MSSQL

    case DB_MSSQL:
    
	if( Insert("COMMIT TRANSACTION", data,1))
	{
	    /* XXX */ 
	    return 1;
	}
	
	goto transaction_success;
	break;
#endif
#ifdef ENABLE_ORACLE
    case DB_ORACLE:
	
	return Insert("COMMIT WORK", data,1);
	break;
#endif

    default:
	
	if( Insert("COMMIT;", data,1))
	{
	    /*XXX */
	    return 1;
	}
	
	goto transaction_success;
	
	break;
    }
    
    /* XXX */
    return 1;
    
transaction_success:
    /* Reset the transaction error count */
    resetTransactionState(&data->dbRH[data->dbtype_id]);
    return 0;

}

/*******************************************************************************
 * Function: RollbackTransaction(DatabaseData * data)
 *
 * Purpose: Database independent SQL to rollback a transaction
 *
 ******************************************************************************/
u_int32_t RollbackTransaction(DatabaseData * data)
{
    if(data == NULL)
    {
        /* XXX */
        FatalError("database [%s()], Invoked with NULL DatabaseData \n",
                   __FUNCTION__);
    }

    if(data->dbRH[data->dbtype_id].transactionErrorCount > data->dbRH[data->dbtype_id].transactionErrorThreshold)
    {
	/* XXX */
	LogMessage("[%s(): Call failed, we reached the maximum number of transaction error [%u] \n",
		   __FUNCTION__,
		   data->dbRH[data->dbtype_id].transactionErrorThreshold);
	return 1;
    }

    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        LogMessage("[%s()] Call failed check to dbConnectionStatus()\n",
		   __FUNCTION__);
        return 1;
    }
    
    if((checkTransactionState(&data->dbRH[data->dbtype_id])) == 0)
    {
	/* We reached a rollback when not in transaction state announce it */
	LogMessage("[%s()] : called while not in transaction \n",
		   __FUNCTION__);
	return 1;
    }

    if(getReconnectState(&data->dbRH[data->dbtype_id]))
    {
	/* Since We could get called from different places we are gown up and reset out self. */
	resetTransactionState(&data->dbRH[data->dbtype_id]);
	
	/* We reconnected, transaction call failed , we can't call "ROLLBACK" since the transaction should have aborted  */
	/* We reset state */
	setReconnectState(&data->dbRH[data->dbtype_id],0);
	return 0;
    }

    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_ODBC
  case DB_ODBC:
  
//  if( SQLEndTran(SQL_HANDLE_DBC, data->u_connection, SQL_ROLLBACK) != SQL_SUCCESS )
//  {
//  ODBCPrintError(data,SQL_HANDLE_DBC);
//  return 1;
//    }
      return 0;
      break;
#endif
  
	

#ifdef ENABLE_MSSQL
    case DB_MSSQL:
	return 	Insert("ROLLBACK TRANSACTION;", data,0);
	break;
#endif
#ifdef ENABLE_ORACLE
	
    case DB_ORACLE:
	return Insert("ROLLBACK WORK;", data,0);
	break;
#endif
    default:
	return Insert("ROLLBACK;", data,0);
    }
    
    /* XXX */
    return 1;
}

/*******************************************************************************
 * Function: Insert(char * query, DatabaseData * data)
 *
 * Purpose: Database independent function for SQL inserts
 *
 * Arguments: query (An SQL insert)
 *
 * Returns: 
 * 0 OK
 * 1 Error
 ******************************************************************************/
int Insert(char * query, DatabaseData * data,u_int32_t inTransac)
{

#ifdef ENABLE_ODBC
    long fRes = 0;
#endif


#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
    int result = 0;
#endif /* defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) */

    
    if( (query == NULL) ||
	(data == NULL) || 
        checkDatabaseType(data))
    {
	/* XXX */
	return 1;
    }
    
    /* This mainly has been set for Rollback */
    if(inTransac == 1)
    {
	if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
	{
	    /* A This shouldn't happen since we are in failed transaction state */
	    /* XXX */
	    return 1;
	}
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
	/* XXX */
	LogMessage("Insert Query[%s] failed check to dbConnectionStatus()\n",query);
	return 1;
    }
    
#ifdef ENABLE_POSTGRESQL
    if( data->dbtype_id == DB_POSTGRESQL )
    {
        data->p_result = PQexec(data->p_connection,query);
        if(!(PQresultStatus(data->p_result) != PGRES_COMMAND_OK))
        {
            result = 0;
        }
        else
        {
            if(PQerrorMessage(data->p_connection)[0] != '\0')
            {
                ErrorMessage("ERROR database: database: postgresql_error: %s\n",
                             PQerrorMessage(data->p_connection));
		return 1;
            }
        }
        PQclear(data->p_result);
	data->p_result = NULL;
	return 0;
    }
#endif
    
#ifdef ENABLE_MYSQL
    if(data->dbtype_id == DB_MYSQL)
    {
	result = mysql_query(data->m_sock,query);
	
	switch (result)
	{
	    
	case 0:
	    return 0;
	    break;
	    
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_SERVER_GONE_ERROR:
	case CR_UNKNOWN_ERROR:
	default:
	    /* XXX */
	    /* Could lead to some corruption lets exit nicely .. */
	    /* Since this model of the database incluse alot of atomic queries .....*/
	    if( (mysql_errno(data->m_sock)))
	    {
		
		FatalError("database mysql_error: %s\n\tSQL=[%s]\n",
			   mysql_error(data->m_sock),query);
		
	    }
	    else
	    {
		/* XXX */
		return 1;
	    }
	    break;
	}
	
    }
#endif
    
#ifdef ENABLE_ODBC
    if(data->dbtype_id == DB_ODBC)
    {
        if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
        {
	    fRes = SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)query, SQL_NTS);
	    
	    if( (fRes != SQL_SUCCESS) || 
		(fRes != SQL_SUCCESS_WITH_INFO))
	    {
		result = 0;
		SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
		return 0;
	    }
	    else
	    {
		LogMessage("execdirect failed \n");
	    }
	}
	else
	{
	    LogMessage("stmtalloc failed \n");
	}
	
	LogMessage("[%s()], failed insert [%s], \n",
		   __FUNCTION__,
		   query);
	ODBCPrintError(data,SQL_HANDLE_STMT);
	SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
    }
#endif

#ifdef ENABLE_ORACLE
    if(data->dbtype_id == DB_ORACLE)
    {
        char *blob = NULL;
	
        /* If BLOB type - split query to actual SQL and blob to BLOB data */
        if(strncasecmp(query,"INSERT INTO data",16)==0 || strncasecmp(query,"INSERT INTO opt",15)==0)
        {
            if((blob=strchr(query,'|')) != NULL)
            {
                *blob='\0'; blob++;
            }
        }

        if(OCI_SUCCESS == OCIStmtPrepare(data->o_statement
                                       , data->o_error
                                       , query
                                       , strlen(query)
                                       , OCI_NTV_SYNTAX
                                       , OCI_DEFAULT))
        {
            if( blob != NULL )
            {
                OCIBindByPos(data->o_statement
                           , &data->o_bind
                           , data->o_error
                           , 1
                           , (dvoid *)blob
                           , strlen(blob)
                           , SQLT_BIN
                           , 0
                           , 0
                           , 0
                           , 0
                           , 0
                           , OCI_DEFAULT);
            }

            if(OCI_SUCCESS == OCIStmtExecute(data->o_servicecontext
                                           , data->o_statement
                                           , data->o_error
                                           , 1
                                           , 0
                                           , NULL
                                           , NULL
                                           , OCI_COMMIT_ON_SUCCESS))
            {
                result = 0;
            }
        }

        if( result != 1 )
        {
            OCIErrorGet(data->o_error
                      , 1
                      , NULL
                      , &data->o_errorcode
                      , data->o_errormsg
                      , sizeof(data->o_errormsg)
                      , OCI_HTYPE_ERROR);
            ErrorMessage("ERROR database: database: oracle_error: %s\n", data->o_errormsg);
            ErrorMessage("        : query: %s\n", query);
        }
    }
#endif

#ifdef ENABLE_MSSQL
    if(data->dbtype_id == DB_MSSQL)
    {
        SAVESTATEMENT(query);
        dbfreebuf(data->ms_dbproc);
        if( dbcmd(data->ms_dbproc, query) == SUCCEED )
            if( dbsqlexec(data->ms_dbproc) == SUCCEED )
                if( dbresults(data->ms_dbproc) == SUCCEED )
                {
                    while (dbnextrow(data->ms_dbproc) != NO_MORE_ROWS)
                    {
                        result = (int)data->ms_col;
                    }
                    result = 0;
                }
        CLEARSTATEMENT();
    }
#endif

    
    return 1;
}


/*******************************************************************************
 * Function: Select(char * query, DatabaeData * data, u_int32_t *rval)
 *
 *
 *
 * Returns: 
 * 0 OK
 * 1 ERROR
 ******************************************************************************/
int Select(char * query, DatabaseData * data,u_int32_t *rval)
{

#if defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)
    int result = 0;
#endif /* defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL) */
    
    if( (query == NULL) || 
	(data == NULL) ||
	(rval == NULL))
    {
	/* XXX */
	FatalError("database [%s()] Invoked with a NULL argument Query [0x%x] Data [0x%x] rval [0x%x] \n",
		   __FUNCTION__,
		   query,
		   data,
		   rval);
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
#if defined(ENABLE_MYSQL)
Select_reconnect:
#endif /* defined(ENABLE_MYSQL) */

    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
	/* XXX */
	FatalError("database Select Query[%s] failed check to dbConnectionStatus()\n",query);
    }
    
    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:
	
        data->p_result = PQexec(data->p_connection,query);
        if((PQresultStatus(data->p_result) == PGRES_TUPLES_OK))
        {
            if(PQntuples(data->p_result))
            {
                if((PQntuples(data->p_result)) > 1)
                {
                    ErrorMessage("ERROR database: Query [%s] returned more than one result\n",
                                 query);
                    result = 0;
		    PQclear(data->p_result);
		    data->p_result = NULL;
		    return 1;
                }
                else
                {
                    *rval = atoi(PQgetvalue(data->p_result,0,0));
                }
            }
	    else
	    {
		PQclear(data->p_result);
		data->p_result = NULL;
		return 1;
	    }
        }

        if(!result)
        {
            if(PQerrorMessage(data->p_connection)[0] != '\0')
            {
                ErrorMessage("ERROR database: postgresql_error: %s\n",
                             PQerrorMessage(data->p_connection));
		return 1;
            }
        }

        PQclear(data->p_result);
	data->p_result = NULL;
	break;
#endif
	
#ifdef ENABLE_MYSQL
    case DB_MYSQL:
	
	result = mysql_query(data->m_sock,query);
	
	switch(result)
	{
	case 0:
	    if( (data->m_result = mysql_use_result(data->m_sock)) == NULL)
	    {
		/* XXX */
		*rval = 0;
		return 1;
	    }
	    else
	    {
		if( (data->m_row = mysql_fetch_row(data->m_result)) == NULL)
		{
		    /* XXX */
		    *rval = 0;
		    mysql_free_result(data->m_result);
		    data->m_result = NULL;
		    return 1;
		}
		else
		{
		    if(data->m_row[0] != NULL)
		    {
			*rval = atoi(data->m_row[0]);
		    }
		    else
		    {
			/* XXX */
			*rval = 0;
			mysql_free_result(data->m_result);
			data->m_result = NULL;
			return 1;
		    }
		    
		}
		mysql_free_result(data->m_result);
		data->m_result = NULL;
		return 0;
	    }
	    break;
	    
	    
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_SERVER_GONE_ERROR:
	    case CR_UNKNOWN_ERROR:
	default:
	    
	    if(checkTransactionState(data->dbRH))
	    {
		LogMessage("[%s()]: Failed executing with error [%s], in transaction will Abort. \n"
			   "\t Failed QUERY: [%s] \n",
			   __FUNCTION__,
			   mysql_error(data->m_sock),
			   query);
		return 1;
	    }
	    
	    LogMessage("[%s()]: Failed to execute  query [%s] , will retry \n",
                       __FUNCTION__,
		       query);
	    
	    
	    goto Select_reconnect;
	    break;
	    
	}
	
	/* XXX */
	*rval = 0;
	return 1;
	
    break;

#endif

#ifdef ENABLE_ODBC
    case DB_ODBC:
	
	if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
	{
            //if(SQLPrepare(data->u_statement, (ODBC_SQLCHAR *)query, SQL_NTS) == SQL_SUCCESS)
	    //{
                //if(SQLExecute(data->u_statement) == SQL_SUCCESS)
		if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)query, SQL_NTS) == SQL_SUCCESS)
		{
		    if(SQLRowCount(data->u_statement, &data->u_rows) == SQL_SUCCESS)
		    {
                        if(data->u_rows)
                        {
                            if(data->u_rows > 1)
                            {
				SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
                                ErrorMessage("ERROR database: Query [%s] returned more than one result\n", query);
                                result = 0;
				return 1;
                            }
                            else
                            {
                                if(SQLFetch(data->u_statement) == SQL_SUCCESS)
				{
                                    if(SQLGetData(data->u_statement,1,SQL_INTEGER,
						  &data->u_col,
                                                  sizeof(data->u_col), NULL) == SQL_SUCCESS)
				    {
                                        *rval = (int)data->u_col;
					SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);


				    }
				}
				else
				{
				    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
				    return 1;
				}
			    }
			}
			else
			{
			    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
			    return 1;
			}
		    }
		}
	}
	break;
#endif
	    
#ifdef ENABLE_ORACLE
    case  DB_ORACLE:

        int success = 0;  /* assume it will fail */
        if(OCI_SUCCESS == OCIStmtPrepare(data->o_statement
                                       , data->o_error
                                       , query
                                       , strlen(query)
                                       , OCI_NTV_SYNTAX
                                       , OCI_DEFAULT))
        {
            if(OCI_SUCCESS == OCIDefineByPos(data->o_statement
                                           , &data->o_define
                                           , data->o_error
                                           , 1
                                           , &result
                                           , sizeof(result)
                                           , SQLT_INT
                                           , 0
                                           , 0
                                           , 0
                                           , OCI_DEFAULT))
            {
                sword status;
                status = OCIStmtExecute(data->o_servicecontext
                                               , data->o_statement
                                               , data->o_error
                                               , 1  /*0*/
                                               , 0
                                               , NULL
                                               , NULL
                                               , OCI_DEFAULT);
                if( status==OCI_SUCCESS || status==OCI_NO_DATA )
                {
                    success = 1;
                }
            }
        }

        if( ! success )
        {
            OCIErrorGet(data->o_error
                      , 1
                      , NULL
                      , &data->o_errorcode
                      , data->o_errormsg
                      , sizeof(data->o_errormsg)
                      , OCI_HTYPE_ERROR);
            ErrorMessage("ERROR database: database: oracle_error: %s\n", data->o_errormsg);
            ErrorMessage("        : query: %s\n", query);
        }
	
	break;
#endif

#ifdef ENABLE_MSSQL
    case DB_MSSQL:
	
        SAVESTATEMENT(query);
        dbfreebuf(data->ms_dbproc);
        if( dbcmd(data->ms_dbproc, query) == SUCCEED )
            if( dbsqlexec(data->ms_dbproc) == SUCCEED )
                if( dbresults(data->ms_dbproc) == SUCCEED )
                    if( dbbind(data->ms_dbproc, 1, INTBIND, (DBINT) 0, (BYTE *) &data->ms_col) == SUCCEED )
                        while (dbnextrow(data->ms_dbproc) != NO_MORE_ROWS)
                        {
                            result = (int)data->ms_col;
                        }
        CLEARSTATEMENT();

	break;

#endif
	
    default:
	FatalError("database [%s()]: Invoked with unknown database type [%u] \n",
		   __FUNCTION__,
		   data->dbtype_id);
    }
    
    return 0;
}


/*******************************************************************************
 * Function: Connect(DatabaseData * data)
 *
 * Purpose: Database independent function to initiate a database
 *          connection
 *
 ******************************************************************************/
void Connect(DatabaseData * data)
{

#ifdef ENABLE_ODBC
    ODBC_SQLRETURN ret;
#endif /* ENABLE_ODBC */

    if(data == NULL)
    {
	/* XXX */
	FatalError("database [%s()]: Invoked with NULL DatabaseData argument \n",
		   __FUNCTION__);
    }
    
    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:

#ifdef HAVE_PQPING
	/* Set PQPing String */
	memset(data->p_pingString,'\0',1024);
	if(SnortSnprintf(data->p_pingString,1024,"host='%s' port='%s' user='%s' dbname='%s'",
			 data->host,
			 data->port == NULL ? "5432" : data->port,
			 data->user,
			 data->dbname))
	{
	    /* XXX */
	    FatalError("[%s()],unable to create PQPing connection string.. bailing \n",
		       __FUNCTION__);
	}
#endif
	
        if (data->use_ssl == 1)
        {
            data->p_connection =
                PQsetdbLogin(data->host,
                             data->port,
                             data->dbRH[data->dbtype_id].ssl_mode,
                             NULL,
                             data->dbname,
                             data->user,
                             data->password);
        }
        else
        {
            data->p_connection =
                PQsetdbLogin(data->host,
                             data->port,
                             NULL,
                             NULL,
                             data->dbname,
                             data->user,
                             data->password);
        }
	
	
        if(PQstatus(data->p_connection) == CONNECTION_BAD)
        {
            PQfinish(data->p_connection);
	    data->p_connection = NULL;
            FatalError("database Connection to database '%s' failed\n", data->dbname);
        }
	break;
#endif
	
#ifdef ENABLE_MYSQL
    case DB_MYSQL:
	
        data->m_sock = mysql_init(NULL);
        if(data->m_sock == NULL)
        {
            FatalError("database Connection to database '%s' failed\n", data->dbname);
        }
	
        /* check if we want to connect with ssl options */
        if (data->use_ssl == 1)
        {
            mysql_ssl_set(data->m_sock, 
			  data->dbRH[data->dbtype_id].ssl_key,
                          data->dbRH[data->dbtype_id].ssl_cert, 
			  data->dbRH[data->dbtype_id].ssl_ca,
                          data->dbRH[data->dbtype_id].ssl_ca_path, 
			  data->dbRH[data->dbtype_id].ssl_cipher);
        }

        if(mysql_real_connect(data->m_sock, 
			      data->host, 
			      data->user,
                              data->password, 
			      data->dbname,
                              data->port == NULL ? 0 : atoi(data->port), NULL, 0) == NULL)
        {
            if(mysql_errno(data->m_sock))
	    {
                LogMessage("database mysql_error: %s\n", mysql_error(data->m_sock));
		mysql_close(data->m_sock);
		data->m_sock = NULL;
		CleanExit(1);
	    }
	    
            LogMessage("database Failed to logon to database '%s'\n", data->dbname);
	    mysql_close(data->m_sock);
	    data->m_sock = NULL;
	    CleanExit(1);
        }
	
	if(mysql_autocommit(data->m_sock,0))
	{
	    /* XXX */
	    mysql_close(data->m_sock);
	    data->m_sock = NULL;
	    LogMessage("WARNING database: unable to unset autocommit\n");
	    return;
	}

	data->dbRH[data->dbtype_id].pThreadID = mysql_thread_id(data->m_sock);
	
	break;
#endif  /* ENABLE_MYSQL */
	
#ifdef ENABLE_ODBC
	
    case DB_ODBC:
        data->u_underlying_dbtype_id = DB_UNDEFINED;
	
        if(!(SQLAllocEnv(&data->u_handle) == SQL_SUCCESS))
        {
            FatalError("database unable to allocate ODBC environment\n");
        }
        if(!(SQLAllocConnect(data->u_handle, &data->u_connection) == SQL_SUCCESS))
        {
            FatalError("database unable to allocate ODBC connection handle\n");
        }

        /* The SQL Server ODBC driver always returns SQL_SUCCESS_WITH_INFO
         * on a successful SQLConnect, SQLDriverConnect, or SQLBrowseConnect.
         * When an ODBC application calls SQLGetDiagRec after getting
         * SQL_SUCCESS_WITH_INFO, it can receive the following messages:
         * 5701 - Indicates that SQL Server put the user's context into the
         *        default database defined in the data source, or into the
         *        default database defined for the login ID used in the
         *        connection if the data source did not have a default database.
         * 5703 - Indicates the language being used on the server.
         * You can ignore messages 5701 and 5703; they are only informational.
         */
        ret = SQLConnect( data->u_connection
			  , (ODBC_SQLCHAR *)data->dbname
			  , SQL_NTS
			  , (ODBC_SQLCHAR *)data->user
			  , SQL_NTS
			  , (ODBC_SQLCHAR *)data->password
			  , SQL_NTS);
	
        if( (ret != SQL_SUCCESS)  && 
	    (ret != SQL_SUCCESS_WITH_INFO))
        {
	    ODBCPrintError(data,SQL_HANDLE_DBC);
	    FatalError("database ODBC unable to connect.\n");
	}

/* NOTE: -elz
   The code below was commented for review, since we want to streamline the api and remove
   all SQLGetDiagRec call's.
   
*/
	//int  encounteredFailure = 1;  /* assume there is an error */
        /*  
	    char odbcError[2000];
            odbcError[0] = '\0';
	    
            if( ret == SQL_SUCCESS_WITH_INFO )
            {
	    
	    ODBC_SQLCHAR   sqlState[6];
	    ODBC_SQLCHAR   msg[SQL_MAX_MESSAGE_LENGTH];
	    SQLINTEGER     nativeError;
	    SQLSMALLINT    errorIndex = 1;
	    SQLSMALLINT    msgLen;
	*/
	/* assume no error unless nativeError tells us otherwise */
	//encounteredFailure = 0;
/*
  while ((ret = SQLGetDiagRec( SQL_HANDLE_DBC
  , data->u_connection
  , errorIndex
  , sqlState
  , &nativeError
  , msg
  , SQL_MAX_MESSAGE_LENGTH
  , &msgLen)) != SQL_NO_DATA)
  {
  if( strstr((const char *)msg, "SQL Server") != NULL )
  {
  data->u_underlying_dbtype_id = DB_MSSQL;
  }
  
  if( nativeError!=5701 && nativeError!=5703 )
  {
  encounteredFailure = 1;
  strncat(odbcError, (const char *)msg, sizeof(odbcError));
  }
  errorIndex++;
  }
  }
  if( encounteredFailure )
  {
  
  }
*/
	
	break;
#endif

#ifdef ENABLE_ORACLE
	
    case DB_ORACLE:

    #define PRINT_ORACLE_ERR(func_name) \
     { \
         OCIErrorGet(data->o_error, 1, NULL, &data->o_errorcode, \
                     data->o_errormsg, sizeof(data->o_errormsg), OCI_HTYPE_ERROR); \
         ErrorMessage("ERROR database: Oracle_error: %s\n", data->o_errormsg); \
         FatalError("database  %s : Connection to database '%s' failed\n", \
                    func_name, data->dbRH[data->dbtype_id]->dbname); \
     }
    
    if (!getenv("ORACLE_HOME"))
      {
         ErrorMessage("ERROR database: ORACLE_HOME environment variable not set\n");
      }

      if (!data->user || !data->password || !data->dbRH[data->dbtype_id]->dbname)
      {
         ErrorMessage("ERROR database: user, password and dbname required for Oracle\n");
         ErrorMessage("ERROR database: dbname must also be in tnsnames.ora\n");
      }

      if (data->host)
      {
         ErrorMessage("ERROR database: hostname not required for Oracle, use dbname\n");
         ErrorMessage("ERROR database: dbname  must be in tnsnames.ora\n");
      }

      if (OCIInitialize(OCI_DEFAULT, NULL, NULL, NULL, NULL))
         PRINT_ORACLE_ERR("OCIInitialize");

      if (OCIEnvInit(&data->o_environment, OCI_DEFAULT, 0, NULL))
         PRINT_ORACLE_ERR("OCIEnvInit");

      if (OCIEnvInit(&data->o_environment, OCI_DEFAULT, 0, NULL))
         PRINT_ORACLE_ERR("OCIEnvInit (2)");

      if (OCIHandleAlloc(data->o_environment, (dvoid **)&data->o_error, OCI_HTYPE_ERROR, (size_t) 0, NULL))
         PRINT_ORACLE_ERR("OCIHandleAlloc");

      if (OCILogon(data->o_environment, data->o_error, &data->o_servicecontext,
                   data->user, strlen(data->user), data->password, strlen(data->password),
                   data->dbRH[data->dbtype_id]->dbname, strlen(data->dbRH[data->dbtype_id]->dbname)))
      {
         OCIErrorGet(data->o_error, 1, NULL, &data->o_errorcode, data->o_errormsg, sizeof(data->o_errormsg), OCI_HTYPE_ERROR);
         ErrorMessage("ERROR database: oracle_error: %s\n", data->o_errormsg);
         ErrorMessage("ERROR database: Checklist: check database is listed in tnsnames.ora\n");
         ErrorMessage("ERROR database:            check tnsnames.ora readable\n");
         ErrorMessage("ERROR database:            check database accessible with sqlplus\n");
         FatalError("database OCILogon : Connection to database '%s' failed\n", data->dbRH[data->dbtype_id]->dbname);
      }

      if (OCIHandleAlloc(data->o_environment, (dvoid **)&data->o_statement, OCI_HTYPE_STMT, 0, NULL))
         PRINT_ORACLE_ERR("OCIHandleAlloc (2)");
      break;
#endif

#ifdef ENABLE_MSSQL
      
    case DB_MSSQL:
	
        CLEARSTATEMENT();
        dberrhandle(mssql_err_handler);
        dbmsghandle(mssql_msg_handler);

        if( dbinit() != NULL )
        {
            data->ms_login = dblogin();
            if( data->ms_login == NULL )
            {
                FatalError("database Failed to allocate login structure\n");
            }
            /* Set up some informational values which are stored with the connection */
            DBSETLUSER (data->ms_login, data->user);
            DBSETLPWD  (data->ms_login, data->password);
            DBSETLAPP  (data->ms_login, "snort");

            data->ms_dbproc = dbopen(data->ms_login, data->host);
            if( data->ms_dbproc == NULL )
            {
                FatalError("database Failed to logon to host '%s'\n", data->host);
            }
            else
            {
                if( dbuse( data->ms_dbproc, data->dbRH[data->dbtype_id]->dbname ) != SUCCEED )
                {
                    FatalError("database Unable to change context to database '%s'\n", data->dbRH[data->dbtype_id]->dbname);
                }
            }
        }
        else
        {
            FatalError("database Connection to database '%s' failed\n", data->dbRH[data->dbtype_id]->dbname);
        }
        CLEARSTATEMENT();
	break;
#endif
	
    default:
	FatalError("database [%s()]: Invoked with unknown database type [%u] \n",
		   __FUNCTION__,
		   data->dbtype_id);
	
	break;
	
    }

    
    return;

}



/*******************************************************************************
 * Function: Disconnect(DatabaseData * data)
 *
 * Purpose: Database independent function to close a connection
 *
 ******************************************************************************/
void Disconnect(DatabaseData * data)
{

    if(data == NULL)
    {
	FatalError("database [%s()]: Invoked with NULL data \n",
		   __FUNCTION__);
    }
    
    
    
    LogMessage("database: Closing connection to database \"%s\"\n",
               data->dbname);
    
    switch(data->dbtype_id)
    {
#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:
	
	if(data->p_result)
	{
	    PQclear(data->p_result);
	    data->p_result = NULL;
	}
	
	if(data->p_connection)
 	{
	    PQfinish(data->p_connection);
	    data->p_connection = NULL;
	}
    break;
    
#endif

#ifdef ENABLE_MYSQL
    case DB_MYSQL:
	
	if(data->m_result)
	{
	    mysql_free_result(data->m_result);	    
	    data->m_result = NULL;
	}
	
	
	if(data->m_sock)
	{
	    mysql_close(data->m_sock);
	    data->m_sock = NULL;
	}


	break;
#endif

#ifdef ENABLE_ODBC
        
    case DB_ODBC:

	if(data->u_handle)
	{
	    SQLDisconnect(data->u_connection);
	    SQLFreeHandle(SQL_HANDLE_ENV, data->u_handle);
	}
	break;
#endif

#ifdef ENABLE_ORACLE
    case DB_ORACLE:

	if(data->o_servicecontext)
            {
                OCILogoff(data->o_servicecontext, data->o_error);
                if(data->o_error)
                {
                    OCIHandleFree((dvoid *)data->o_error, OCI_HTYPE_ERROR);
                }
                if(data->o_statement)
                {
                    OCIHandleFree((dvoid *)data->o_statement, OCI_HTYPE_STMT);
                }
            }
        break;
#endif

#ifdef ENABLE_MSSQL
        
    case DB_MSSQL:
	
            CLEARSTATEMENT();
            if( data->ms_dbproc != NULL )
            {
                dbfreelogin(data->ms_login);
                data->ms_login = NULL;
                dbclose(data->ms_dbproc);
                data->ms_dbproc = NULL;
            }
	    break;
#endif
	    
    default:
	FatalError("database [%s()]: Invoked with unknown database type [%u] \n",
                   __FUNCTION__,
                   data->dbtype_id);
	break;

    }

    return;
}


void DatabasePrintUsage(void)
{
    puts("\nUSAGE: database plugin\n");

    puts(" output database: [log | alert], [type of database], [parameter list]\n");
    puts(" [log | alert] selects whether the plugin will use the alert or");
    puts(" log facility.\n");

    puts(" For the first argument, you must supply the type of database.");
    puts(" The possible values are mysql, postgresql, odbc, oracle and");
    puts(" mssql ");

    puts(" The parameter list consists of key value pairs. The proper");
    puts(" format is a list of key=value pairs each separated a space.\n");

    puts(" The only parameter that is absolutely necessary is \"dbname\".");
    puts(" All other parameters are optional but may be necessary");
    puts(" depending on how you have configured your RDBMS.\n");

    puts(" dbname - the name of the database you are connecting to\n");

    puts(" host - the host the RDBMS is on\n");

    puts(" port - the port number the RDBMS is listening on\n");

    puts(" user - connect to the database as this user\n");

    puts(" password - the password for given user\n");

    puts(" sensor_name - specify your own name for this barnyard2 sensor. If you");
    puts("        do not specify a name one will be generated automatically\n");

    puts(" encoding - specify a data encoding type (hex, base64, or ascii)\n");

    puts(" detail - specify a detail level (full or fast)\n");

    puts(" ignore_bpf - specify if you want to ignore the BPF part for a sensor\n");
    puts("              definition (yes or no, no is default)\n");

    puts(" FOR EXAMPLE:");
    puts(" The configuration I am currently using is MySQL with the database");
    puts(" name of \"snort\". The user \"snortusr@localhost\" has INSERT and SELECT");
    puts(" privileges on the \"snort\" database and does not require a password.");
    puts(" The following line enables barnyard2 to log to this database.\n");

    puts(" output database: log, mysql, dbname=snort user=snortusr host=localhost\n");
}


/* CHECKME: -elz This function is not complete ...alot of leaks could happen here! */
void SpoDatabaseCleanExitFunction(int signal, void *arg)
{
    DatabaseData *data = (DatabaseData *)arg;
    
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"database(debug): entered SpoDatabaseCleanExitFunction\n"););
    
    if(data != NULL)
    {
	if(checkTransactionState(&data->dbRH[data->dbtype_id]))
	{
	    if( RollbackTransaction(data))
	    {
		DEBUG_WRAP(DebugMessage(DB_DEBUG,"database: RollbackTransaction failed in [%s()] \n",
					__FUNCTION__));
	    }
	    
	}
	
	resetTransactionState(&data->dbRH[data->dbtype_id]);
	
	MasterCacheFlush(data,CACHE_FLUSH_ALL);    
	
	SQL_Finalize(data);
	
	if( !(data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
	{
	    UpdateLastCid(data, data->sid, ((data->cid)-1));
	}
	
	Disconnect(data);

	if(data->SQL_INSERT != NULL)
	{
	    free(data->SQL_INSERT);
	    data->SQL_INSERT = NULL;
	}
	
	if(data->SQL_SELECT != NULL)
	{
	    free(data->SQL_SELECT);
	    data->SQL_SELECT = NULL;
	}
	
	free(data->args);
	free(data);
	data = NULL;
    }

    return;
}


/* CHECKME: -elz This function is not complete ...alot of leaks could happen here! */
void SpoDatabaseRestartFunction(int signal, void *arg)
{
    DatabaseData *data = (DatabaseData *)arg;

    DEBUG_WRAP(DebugMessage(DB_DEBUG,"database(debug): entered SpoDatabaseRestartFunction\n"););

    if(data != NULL)
    {
	MasterCacheFlush(data,CACHE_FLUSH_ALL);    

	resetTransactionState(&data->dbRH[data->dbtype_id]);
	
	UpdateLastCid(data,
		      data->sid, 
		      (data->cid)-1);
	
	Disconnect(data);
	free(data->args);
	free(data);
	data = NULL;
    }
    
    return;
}


/* CHECKME: -elz , compilation with MSSQL will have to be worked out ... */
#ifdef ENABLE_MSSQL
/*
 * The functions mssql_err_handler() and mssql_msg_handler() are callbacks that are registered
 * when we connect to SQL Server.  They get called whenever SQL Server issues errors or messages.
 * This should only occur whenever an error has occurred, or when the connection switches to
 * a different database within the server.
 */
static int mssql_err_handler(PDBPROCESS dbproc, int severity, int dberr, int oserr,
                             LPCSTR dberrstr, LPCSTR oserrstr)
{
    int retval;
    ErrorMessage("ERROR database: DB-Library error:\n\t%s\n", dberrstr);

    if ( severity == EXCOMM && (oserr != DBNOERR || oserrstr) )
        ErrorMessage("ERROR database: Net-Lib error %d:  %s\n", oserr, oserrstr);
    if ( oserr != DBNOERR )
        ErrorMessage("ERROR database: Operating-system error:\n\t%s\n", oserrstr);
#ifdef ENABLE_MSSQL_DEBUG
    if( strlen(g_CurrentStatement) > 0 )
        ErrorMessage("ERROR database:  The above error was caused by the following statement:\n%s\n", g_CurrentStatement);
#endif
    if ( (dbproc == NULL) || DBDEAD(dbproc) )
        retval = INT_EXIT;
    else
        retval = INT_CANCEL;
    return(retval);
}


static int mssql_msg_handler(PDBPROCESS dbproc, DBINT msgno, int msgstate, int severity,
                             LPCSTR msgtext, LPCSTR srvname, LPCSTR procname, DBUSMALLINT line)
{
    ErrorMessage("ERROR database: SQL Server message %ld, state %d, severity %d: \n\t%s\n",
                 msgno, msgstate, severity, msgtext);
    if ( (srvname!=NULL) && strlen(srvname)!=0 )
        ErrorMessage("Server '%s', ", srvname);
    if ( (procname!=NULL) && strlen(procname)!=0 )
        ErrorMessage("Procedure '%s', ", procname);
    if (line !=0)
        ErrorMessage("Line %d", line);
    ErrorMessage("\n");
#ifdef ENABLE_MSSQL_DEBUG
    if( strlen(g_CurrentStatement) > 0 )
        ErrorMessage("ERROR database:  The above error was caused by the following statement:\n%s\n", g_CurrentStatement);
#endif

    return(0);
}
#endif


/* Database Reliability */

/* Ensure that we do not get some wierd poker's */
u_int32_t checkDatabaseType(DatabaseData *data)
{
    if(data == NULL)
    {
	/* XXX */
	return 1;
    }

    if(data->dbtype_id <= DB_ENUM_MIN_VAL ||
       data->dbtype_id > DB_ENUM_MAX_VAL)
    {
	/* XXX */
	return 1;
    }
    
    return 0;
}

void resetTransactionState(dbReliabilityHandle *pdbRH)
{
    if(pdbRH == NULL)
    {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",__FUNCTION__);
    }
    
    pdbRH->checkTransaction = 0;
    pdbRH->transactionCallFail = 0;

    /* seem'ed to cause loop */
    //pdbRH->transactionErrorCount = 0;

    return;
}

void setTransactionState(dbReliabilityHandle *pdbRH)
{
    if(pdbRH == NULL)
    {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",__FUNCTION__);
    }
    
    pdbRH->checkTransaction = 1;

    return;
}

void setTransactionCallFail(dbReliabilityHandle *pdbRH)
{
    if(pdbRH == NULL)
    {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",__FUNCTION__);
    }
    
    if(pdbRH->checkTransaction)
    {
	pdbRH->transactionCallFail=1;
	pdbRH->transactionErrorCount++;
    }
    
    return;
}


u_int32_t getReconnectState(dbReliabilityHandle *pdbRH)
{
    if(pdbRH == NULL)
    {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",__FUNCTION__);
    }
    
    return  pdbRH->dbReconnectedInTransaction;
}


void setReconnectState(dbReliabilityHandle *pdbRH,u_int32_t reconnection_state)
{
    if(pdbRH == NULL)
    {
        /* XXX */
	FatalError("database [%s()] called with a null dbReliabilityHandle",__FUNCTION__);
    }
    
    pdbRH->dbReconnectedInTransaction = reconnection_state;
    return;
}

u_int32_t checkTransactionState(dbReliabilityHandle *pdbRH)
{
    
    if(pdbRH == NULL)
    {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",__FUNCTION__);
    }
    
    return pdbRH->checkTransaction;
    
}

u_int32_t checkTransactionCall(dbReliabilityHandle *pdbRH)
{
    if(pdbRH == NULL)
    {
        /* XXX */
        FatalError("database [%s()] called with a null dbReliabilityHandle",__FUNCTION__);
    }
    
    if(checkTransactionState(pdbRH))
    {
	return pdbRH->transactionCallFail;
    }
    
    return 0;
}

u_int32_t  dbReconnectSetCounters(dbReliabilityHandle *pdbRH)
{
    struct timespec sleepRet = {0};

    if(pdbRH == NULL)
    {
	/* XXX */
	return 1;
    }

    if( pdbRH->dbConnectionCount < pdbRH->dbConnectionLimit)
    {
	pdbRH->dbConnectionCount++; /* Database Reconnected it seem... */
	
	if(nanosleep(&pdbRH->dbReconnectSleepTime,&sleepRet) <0)
	{
	    perror("dbReconnectSetCounter():");
	    LogMessage("[%s() ]Call to nanosleep(): Failed with [%u] seconds left and [%u] microsecond left \n",
		       __FUNCTION__,
		       sleepRet.tv_sec,
		       sleepRet.tv_nsec);
	    return 1;
	}
	return 0;
    }

    return 1;
}

#ifdef ENABLE_MYSQL
u_int32_t MYSQL_ManualConnect(DatabaseData *dbdata)
{
    if(dbdata == NULL)
    {
	/* XXX */
	return 1;
    }
    
    if(dbdata->m_sock != NULL)
    {
	mysql_close(dbdata->m_sock);
	dbdata->m_sock = NULL;	
    }
    
    dbdata->m_sock = mysql_init(NULL);
    
    if(dbdata->m_sock == NULL)
    {
	FatalError("database Connection to database '%s' failed\n", 
		   dbdata->dbname);
    }
    
    /* check if we want to connect with ssl options */
    if (dbdata->use_ssl == 1)
    {
	mysql_ssl_set(dbdata->m_sock, 
		      dbdata->dbRH[dbdata->dbtype_id].ssl_key,
		      dbdata->dbRH[dbdata->dbtype_id].ssl_cert, 
		      dbdata->dbRH[dbdata->dbtype_id].ssl_ca,
		      dbdata->dbRH[dbdata->dbtype_id].ssl_ca_path, 
		      dbdata->dbRH[dbdata->dbtype_id].ssl_cipher);
    }
    
    if(mysql_real_connect(dbdata->m_sock, 
			  dbdata->host, 
			  dbdata->user,
			  dbdata->password, 
			  dbdata->dbname,
			  dbdata->port == NULL ? 0 : atoi(dbdata->port), NULL, 0) == NULL)
    {
	if(mysql_errno(dbdata->m_sock))
	    LogMessage("database: mysql_error: %s\n", mysql_error(dbdata->m_sock));
	
	LogMessage("database: Failed to logon to database '%s'\n", dbdata->dbname);
	
	mysql_close(dbdata->m_sock);
	dbdata->m_sock = NULL;
	return 1;
    }

    
    if(mysql_autocommit(dbdata->m_sock,0))
    {
	/* XXX */
	LogMessage("database Can't set autocommit off \n");
	mysql_close(dbdata->m_sock);
	dbdata->m_sock = NULL;
	return 1;
    }
    
    /* We are in manual connect mode */
    if (mysql_options(dbdata->m_sock, MYSQL_OPT_RECONNECT, &dbdata->dbRH[dbdata->dbtype_id].mysql_reconnect) != 0)
    {
	LogMessage("database: Failed to set reconnect option: %s\n", mysql_error(dbdata->m_sock));
	mysql_close(dbdata->m_sock);
	dbdata->m_sock = NULL;
	return 1;
    }
    
    /* Get the new thread id */
    dbdata->dbRH[dbdata->dbtype_id].pThreadID = mysql_thread_id(dbdata->m_sock);
    
    return 0;
}

u_int32_t dbConnectionStatusMYSQL(dbReliabilityHandle *pdbRH)
{
    unsigned long aThreadID = 0; /* after  mysql_ping call thread_id */
    int ping_ret = 0;

    DatabaseData *dbdata = NULL;
    
    if( (pdbRH == NULL) ||
	(pdbRH->dbdata == NULL))
    {
	/* XXX */
	return 1;
    }
    
    dbdata = pdbRH->dbdata;
    
    if(dbdata->m_sock == NULL)
	return 1;
    
MYSQL_RetryConnection:    
    /* mysql_ping() could reconnect and we wouldn't know */
    
    aThreadID = mysql_thread_id(pdbRH->dbdata->m_sock);    
    
    ping_ret = mysql_ping(pdbRH->dbdata->m_sock);
    
    /* We might try to recover from this */
    if (pdbRH->mysql_reconnect)
    {
	switch(ping_ret)
	{
	    
	case 0:
	    if( aThreadID != pdbRH->pThreadID )
	    {
		/* mysql ping reconnected, 
		   we need to check if we are in a transaction
		   and if we are we bail, since the resulting issued commands would obviously fail
		*/
		if( dbReconnectSetCounters(pdbRH))
		{
		    /* XXX */
		    FatalError("database [%s()]: Call failed, the process will need to be restarted \n",__FUNCTION__);
		}
		
		if(checkTransactionState(pdbRH))
		{
		    /* ResetState for the caller */
		    setReconnectState(pdbRH,1);
		    setTransactionCallFail(pdbRH);
		    setTransactionState(pdbRH);
		}
		
		pdbRH->pThreadID = aThreadID;
		
		/* make sure are are off auto_commit */
		if(mysql_autocommit(pdbRH->dbdata->m_sock,0))
		{
		    /* XXX */
		    LogMessage("database Can't set autocommit off \n");
		    return 1;
		}
		
		/* make shure we keep the option on ..*/
		if (mysql_options(dbdata->m_sock, 
				  MYSQL_OPT_RECONNECT, 
				  &pdbRH->mysql_reconnect) != 0)
		{
		    LogMessage("database: Failed to set reconnect option: %s\n", mysql_error(dbdata->m_sock));
		    return 1;
		}
		
		LogMessage("Warning: {MYSQL} The database connection has reconnected it self to the database server, via a call to mysql_ping() new thread id is [%u] \n",
			   pdbRH->pThreadID);
		return 0;
	    }
	    else
	    {
		/* Safety */
		pdbRH->pThreadID = aThreadID;
		
		/*
		  make sure are are off auto_commit, since we are in auto_commit and mysql doc is not clear if 
		  by using automatic reconnect we keep connection attribute, i just force them, since we do not call
		  MYSQL_ManualConnect
		*/
		
		if(mysql_autocommit(pdbRH->dbdata->m_sock,0))
		{
		    /* XXX */
		    LogMessage("database Can't set autocommit off \n");
		    return 1;
		}
		
		/* make shure we keep the option on ..*/
		if (mysql_options(dbdata->m_sock,
				  MYSQL_OPT_RECONNECT,
				  &pdbRH->mysql_reconnect) != 0)
		{
		    LogMessage("database: Failed to set reconnect option: %s\n", mysql_error(dbdata->m_sock));
		    return 1;
		}
		return 0;
	    }
	    break;
	    
	case CR_COMMANDS_OUT_OF_SYNC:	    
	case CR_SERVER_GONE_ERROR:
	case CR_UNKNOWN_ERROR:	    
	default:
	    
	    if(checkTransactionState(pdbRH))
	    {
		/* ResetState for the caller */
		setReconnectState(pdbRH,1);
		setTransactionCallFail(pdbRH);
		setTransactionState(pdbRH);
	    }
	    
	    if( dbReconnectSetCounters(pdbRH))
	    {
		/* XXX */
		FatalError("database [%s()]: Call failed, the process will need to be restarted \n",__FUNCTION__);
	    }
	    
	    goto MYSQL_RetryConnection;
	    break;
	    
	}
    }
    else     /* Manual Reconnect mode */
    {	
	switch(ping_ret)
	{
	    
	case 0 :
	    if( aThreadID != pdbRH->pThreadID)
	    {
		FatalError("database We are in {MYSQL} \"manual reconnect\" mode and a call to mysql_ping() changed the mysql_thread_id, this shouldn't happen the process will terminate \n");
	    }
	    return 0;
	    
	    break;
	    
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_SERVER_GONE_ERROR:
	case CR_UNKNOWN_ERROR:	    
	default:
	    
	    if(checkTransactionState(pdbRH))
            {
		/* ResetState for the caller */
		setReconnectState(pdbRH,1);
		setTransactionCallFail(pdbRH);
		setTransactionState(pdbRH);
	    }
	    
	    if(dbReconnectSetCounters(pdbRH))
	    {
		/* XXX */
		FatalError("database [%s()]: Call failed, the process will need to be restarted \n",__FUNCTION__);
	    }
	    
	    if((MYSQL_ManualConnect(pdbRH->dbdata)))
	    {
		goto MYSQL_RetryConnection;
	    }
	}
	return 0; 
    }
    
    /* XXX */
    LogMessage("[%s()], Reached a point of no return ...it shouldn't happen \n",
	       __FUNCTION__);
    
    return 1;
}
#endif
    
#ifdef ENABLE_ODBC
u_int32_t dbConnectionStatusODBC(dbReliabilityHandle *pdbRH)
{
    DatabaseData *data = NULL;
    u_int32_t StateFail = 0;
    ODBC_SQLRETURN  ret;    
    ODBC_SQLCHAR    sqlState[6];
    ODBC_SQLCHAR    msg[SQL_MAX_MESSAGE_LENGTH] = {0};
    SQLINTEGER      nativeError;
    SQLSMALLINT     errorIndex = 1;
    SQLSMALLINT     msgLen;

    //DEBUGGGGGGGGGGGGGGGGGGG
    return 0;
    //DEBUGGGGGGGGGGGGGGGGGGG

    if( (pdbRH == NULL) ||
        (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }
    data =  pdbRH->dbdata;
    
    if(data->u_connection != NULL)
    {
	while ( (ret = SQLGetDiagRec(  SQL_HANDLE_DBC
				       , data->u_connection
				       , errorIndex
				       , sqlState
				       , &nativeError
				       , msg
				       , SQL_MAX_MESSAGE_LENGTH
				       , &msgLen)) == SQL_SUCCESS)
	{
	    if(StateFail == 0)
	    {
		/* Destroy the statement handle */
		if(data->u_statement != NULL)
		{
		    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
		}
		
		if(data->u_connection != NULL)
		{
		    SQLFreeHandle(SQL_HANDLE_DBC,data->u_connection);
		}
	
		if(data->u_handle != NULL)
		{
		    SQLFreeHandle(SQL_HANDLE_ENV,data->u_statement);
		}
	
		if(checkTransactionState(pdbRH))
		{
		    /* ResetState for the caller */
		    setReconnectState(pdbRH,1);
		    setTransactionCallFail(pdbRH);
		    setTransactionState(pdbRH);
		}
		StateFail = 1;
	    
		if(!(SQLAllocEnv(&data->u_handle) == SQL_SUCCESS))
		{
		    FatalError("database unable to allocate ODBC environment\n");
		}
		
		if(!(SQLAllocConnect(data->u_handle, &data->u_connection) == SQL_SUCCESS))
		{
		    FatalError("database unable to allocate ODBC connection handle\n");
		}
		
		/* The SQL Server ODBC driver always returns SQL_SUCCESS_WITH_INFO
		 * on a successful SQLConnect, SQLDriverConnect, or SQLBrowseConnect.
		 * When an ODBC application calls SQLGetDiagRec after getting
		 * SQL_SUCCESS_WITH_INFO, it can receive the following messages:
		 * 5701 - Indicates that SQL Server put the user's context into the
		 *        default database defined in the data source, or into the
		 *        default database defined for the login ID used in the
		 *        connection if the data source did not have a default database.
		 * 5703 - Indicates the language being used on the server.
		 * You can ignore messages 5701 and 5703; they are only informational.
		 */
		ret = SQLConnect( data->u_connection
				  , (ODBC_SQLCHAR *)data->dbname
				  , SQL_NTS
				  , (ODBC_SQLCHAR *)data->user
				  , SQL_NTS
				  , (ODBC_SQLCHAR *)data->password
				  , SQL_NTS);
		
		if( (ret != SQL_SUCCESS)  &&
		    (ret != SQL_SUCCESS_WITH_INFO))
		{
		    ODBCPrintError(data,SQL_HANDLE_DBC);
		    FatalError("database ODBC unable to connect.\n");
		}
	    }
	}
    }
    
    return 0;

}
#endif  /* ENABLE_ODBC */

#ifdef ENABLE_POSTGRESQL
u_int32_t dbConnectionStatusPOSTGRESQL(dbReliabilityHandle *pdbRH)
{
    DatabaseData *data = NULL;
    
    int PQpingRet = 0;
    
    if( (pdbRH == NULL) ||
        (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }
    
    data = pdbRH->dbdata;
    
conn_test:
    if(data->p_connection != NULL)
    {
	
#ifdef HAVE_PQPING
	switch( (PQpingRet = PQping(data->p_pingString)))
        {
        case PQPING_OK:
            break;

        case PQPING_NO_ATTEMPT:
	    LogMessage("[%s()], PQPing call assumed [PQPING_NO_ATTEMPT] using connection string [%s], continuing \n",
		       __FUNCTION__,
		       data->p_pingString);
	    break;

        case PQPING_REJECT:
        case PQPING_NO_RESPONSE:
        default:

            LogMessage("[%s()], PQPing call retval[%d] seem's to indicate unreacheable server, assuming connection is dead \n",
                       __FUNCTION__,
		       PQpingRet);

            if(checkTransactionState(pdbRH))
            {
                /* ResetState for the caller */
                setReconnectState(pdbRH,1);
                setTransactionCallFail(pdbRH);
                setTransactionState(pdbRH);
            }

	    if(data->p_connection)
	    {
		PQfinish(data->p_connection);
		data->p_connection = NULL;
	    }
            break;
        }
#endif
	
	switch(PQstatus(data->p_connection))
	{
	case CONNECTION_OK:
	    return 0;
	    break;
	    
	case CONNECTION_BAD:
	default:

	    if(checkTransactionState(pdbRH))
	    {
		/* ResetState for the caller */
		setReconnectState(pdbRH,1);
		setTransactionCallFail(pdbRH);
		setTransactionState(pdbRH);
	    }
	    
	failed_pqcon:	    
	    if(dbReconnectSetCounters(pdbRH))
	    {
		/* XXX */
		FatalError("database [%s()]: Call failed, the process will need to be restarted \n",__FUNCTION__);
	    }

	    /* Changed PQreset by call to PQfinish and PQdbLogin */
	    if(data->p_connection)
	    {
		PQfinish(data->p_connection);
		data->p_connection = NULL;
	    }

	    if (data->use_ssl == 1)
	    {
		if( (data->p_connection =
		     PQsetdbLogin(data->host,
				  data->port,
				  data->dbRH[data->dbtype_id].ssl_mode,
				  NULL,
				  data->dbname,
				  data->user,
				  data->password)) == NULL)
		{
		    goto failed_pqcon;
		}
	    }
	    else
	    {
		if( (data->p_connection =
		     PQsetdbLogin(data->host,
				  data->port,
				  NULL,
				  NULL,
				  data->dbname,
				  data->user,
				  data->password)) == NULL)
		{
		    goto failed_pqcon;
		}
	    }
	
	    goto conn_test;
	    break;
	}
	
    }
    else
    {
	/* XXX */
	setTransactionCallFail(pdbRH);
	setTransactionState(pdbRH);
	return 1;
    }
    
    return 0;
}
#endif

#ifdef ENABLE_ORACLE
u_int32_t dbConnectionStatusORACLE(dbReliabilityHandle *pdbRH)
{
    if( (pdbRH == NULL) ||
        (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }

    return 0;
}
#endif

#ifdef ENABLE_MSSQL
u_int32_t dbConnectionStatusMSSQL(struct  dbReliabilityHandle *pdbRH);
{
    if( (pdbRH == NULL) ||
        (pdbRH->dbdata == NULL))
    {
        /* XXX */
        return 1;
    }

    return 0;
}
#endif

#ifdef ENABLE_ODBC
void ODBCPrintError(DatabaseData *data,SQLSMALLINT iHandleType)
{
    ODBC_SQLRETURN  ret;
    ODBC_SQLCHAR    sqlState[6];
    ODBC_SQLCHAR    msg[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER      nativeError;
    SQLSMALLINT     errorIndex = 1;
    SQLSMALLINT     msgLen;
    
    void * selected_handle;

    if(data == NULL)
    {
	/* XXX */
	return;
    }    
    
    switch(iHandleType)
    {
	
    case SQL_HANDLE_DBC:
	selected_handle = data->u_connection;
	break;
	
    case SQL_HANDLE_STMT:
	selected_handle = data->u_statement;
	break;
	
    default:
	LogMessage("Database [%s()]: Unknown statement type [%u] \n",
		   __FUNCTION__,
		   iHandleType);
	return;
	break;
    }
    
    /* assume no errror unless nativeError tells us otherwise */
    while ( (ret = SQLGetDiagRec(  iHandleType
				   , selected_handle
				   , errorIndex
				   , sqlState
				   , &nativeError
				   , msg
				   , SQL_MAX_MESSAGE_LENGTH
				   , &msgLen)) == SQL_SUCCESS)
    {
	ErrorMessage("[%s()]: Error Index [%u] Error Message [%s] \n",
		     __FUNCTION__,
		     errorIndex,
		     msg);
		     
	DEBUG_WRAP(LogMessage("database: %s\n", msg););
	errorIndex++;
    }


    return;
}
#endif /* ENABLE_ODBC */



/* Database Reliability */
