/*
 Copyright (c) 2012, 2014, Oracle and/or its affiliates. All rights
 reserved.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; version 2 of
 the License.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA
*/

/*global unified_debug, exports, api_dir, path */

"use strict";

/* Requires version 2.0 of Felix Geisendoerfer's MySQL client */

var stats = {
  "created"             : 0,
  "list_tables"         : 0,
  "get_table_metadata"  : 0,
  "connections"         : { "successful" : 0, "failed" : 0 }	
};

var mysql = require("mysql");
var mysqlConnection = require("./MySQLConnection.js");
var mysqlDictionary = require("./MySQLDictionary.js");
var udebug = unified_debug.getLogger("MySQLConnectionPool.js");
var util = require('util');
var stats_module = require(path.join(api_dir, "stats.js"));
var MySQLTime = require("../common/MySQLTime.js");

stats_module.register(stats, "spi","mysql","DBConnectionPool");

/* Translate our properties to the driver's */
function getDriverProperties(props) {
  var driver = {};

  if(props.mysql_socket) {
    driver.SocketPath = props.mysql_socket;
  }
  else {
    driver.host = props.mysql_host;
    driver.port = props.mysql_port;
  }

  if(props.mysql_user) {
    driver.user = props.mysql_user;
  }
  if(props.mysql_password) {
    driver.password = props.mysql_password;
  }
  driver.database = props.database;
  driver.debug = props.mysql_debug;
  driver.trace = props.mysql_trace;

  if (props.mysql_charset) {
    driver.charset = props.mysql_charset;
  } else {
    // by default, use utf-8 multibyte for character encoding
    driver.charset = 'UTF8MB4';
  }

  if (typeof props.mysql_sql_mode !== 'undefined') {
    driver.sql_mode = props.mysql_sql_mode;
  } else {
    // default to STRICT_ALL_TABLES
    driver.sql_mode = 'STRICT_ALL_TABLES';
  }

  // allow multiple statements in one query (used to set character set)
  driver.multipleStatements = true;
  return driver;
}

/** Default domain type converter for timestamp and datetime objects. The domain type is Date
 * and the intermediate type is MySQLTime. MySQLTime provides a lossless conversion from
 * database DATETIME and TIMESTAMP with fractional microseconds. The default domain type converter
 * to javascript Date is lossy: javascript Date does not support microseconds. Users might supply
 * their own domain type with a converter that supports microseconds.
 */
var DomainTypeConverterDateTime = function() {
  // just a bit of documentation for debugging
  this.converter = 'DomainTypeConverterDateTime';
};

DomainTypeConverterDateTime.prototype.toDB = function toDB(userDate) {
  if (userDate === null || userDate === undefined) {
    return userDate;
  }
  // convert to the string form of the mySQLTime object
  var mysqlTime = new MySQLTime();
  mysqlTime.fsp = 6;
  mysqlTime.initializeFromJsDateLocal(userDate);
  return mysqlTime;
};
  
DomainTypeConverterDateTime.prototype.fromDB =  function fromDB(mysqlTime) {
  if (mysqlTime === null || mysqlTime === undefined) {
    return mysqlTime;
  }
  var jsDate = mysqlTime.toJsDateLocal();
  return jsDate;
};

/** Default database type converter for timestamp and datetime objects. The database type is string
 * and the intermediate type is MySQLTime. MySQLTime provides a lossless conversion from
 * database DATETIME and TIMESTAMP with fractional microseconds.
 */
var DatabaseTypeConverterDateTime = function() {
  // just a bit of documentation for debugging
  this.converter = 'DatabaseTypeConverterDateTime';
};

DatabaseTypeConverterDateTime.prototype.toDB = function toDB(mysqlTime) {
  if (mysqlTime === null || mysqlTime === undefined) {
    return mysqlTime;
  }
  // convert to the string form of the mySQLTime object
  var dbDateTime = mysqlTime.toDateTimeString();
  return dbDateTime;
};
  
DatabaseTypeConverterDateTime.prototype.fromDB =  function fromDB(dbDateTime) {
  if (dbDateTime === null || dbDateTime === undefined) {
    return dbDateTime;
  }
  var mysqlTime = new MySQLTime();
  mysqlTime.initializeFromDateTimeString(dbDateTime);
  return mysqlTime;
};



/* Constructor saves properties but doesn't actually do anything with them.
*/
exports.DBConnectionPool = function(props) {
  this.driverproperties = getDriverProperties(props);
  udebug.log('MySQLConnectionPool constructor with driverproperties: ' + util.inspect(this.driverproperties));
  // connections not being used at the moment
  this.pooledConnections = [];
  // connections that are being used (wrapped by DBSession)
  this.openConnections = [];
  this.is_connected = false;
  // create database type converter map
  this.databaseTypeConverterMap = {};
  this.databaseTypeConverterMap.TIMESTAMP = new DatabaseTypeConverterDateTime();
  this.databaseTypeConverterMap.DATETIME = new DatabaseTypeConverterDateTime();
  // create domain type converter map
  this.domainTypeConverterMap = {};
  this.domainTypeConverterMap.TIMESTAMP = new DomainTypeConverterDateTime();
  this.domainTypeConverterMap.DATETIME = new DomainTypeConverterDateTime();
  stats.created++;
};

/** Register a user-specified domain type converter for this connection pool.
 * Called by SessionFactory.registerTypeConverter.
 */
exports.DBConnectionPool.prototype.registerTypeConverter = function(typeName, converterObject) {
  if (converterObject) {
    this.domainTypeConverterMap[typeName] = converterObject;
  } else {
    this.domainTypeConverterMap[typeName] = undefined;
  }
};

/** Get the database type converter for the parameter type name.
 * Called when creating the DBTableHandler for a constructor.
 */
exports.DBConnectionPool.prototype.getDatabaseTypeConverter = function(typeName) {
  return this.databaseTypeConverterMap[typeName];
};

/** Get the domain type converter for the parameter type name.
 * Called when creating the DBTableHandler for a constructor.
 */
exports.DBConnectionPool.prototype.getDomainTypeConverter = function(typeName) {
  return this.domainTypeConverterMap[typeName];
};

/** Get a connection. If pooling via felix, get a connection from the pool.
 * If not, create a connection. This api does not manage the list of open connections.
 * 
 * @param callback (err, connection)
 */
exports.DBConnectionPool.prototype.getConnection = function(callback) {
  var connectionPool = this;
  var connection, error;

  function getConnectionOnConnection(err, c) {
    if (err) {
      stats.connections.failed++;
      // create a new Error with a message and this stack
      error = new Error('Connection failed.');
      // add cause to the error
      error.cause = err;
      // add sqlstate to error
      error.sqlstate = '08000';
      callback(error);      
    } else {
      stats.connections.successful++;
      callback(null, c);
    }
  }

  // getConnection starts here
  if (connectionPool.is_connected) {
    connection = mysql.createConnection(connectionPool.driverproperties);
    connection.connect(getConnectionOnConnection);
  } else {
    callback(new Error('GetConnection called before connect.'));
  }
};

/** Release a connection (synchronous). If pooling via felix, return the connection to the pool.
 * If not, end the connection. No errors are reported to the user.
 */
exports.DBConnectionPool.prototype.releaseConnection = function(connection) {
  var connectionPool = this;
  connection.end();
};

exports.DBConnectionPool.prototype.connect = function(user_callback) {
  var callback = user_callback;
  var connectionPool = this;
  var pooledConnection;
  var error;
  
  if (this.is_connected) {
    udebug.log('MySQLConnectionPool.connect is already connected');
    callback(null, this);
  } else {
    pooledConnection = mysql.createConnection(this.driverproperties);
    pooledConnection.connect(function(err) {
    if (err) {
      stats.connections.failed++;
      // create a new Error with a message and this stack
      error = new Error('Connection failed.');
      // add cause to the error
      error.cause = err;
      // add sqlstate to error
      error.sqlstate = '08000';
      callback(error);
    } else {
      stats.connections.successful++;
      connectionPool.pooledConnections[0] = pooledConnection;
      connectionPool.is_connected = true;
      callback(null, connectionPool);
    }
  });
  }
};

exports.DBConnectionPool.prototype.close = function(user_callback) {
  udebug.log('close');
  var i;
  for (i = 0; i < this.pooledConnections.length; ++i) {
    var pooledConnection = this.pooledConnections[i];
    udebug.log('close ending pooled connection', i);
    if (pooledConnection && pooledConnection._connectCalled) {
      pooledConnection.end();
    }
  }
  this.pooledConnections = [];
  for (i = 0; i < this.openConnections.length; ++i) {
    var openConnection = this.openConnections[i];
    udebug.log('close ending open connection', i);
    if (openConnection && openConnection._connectCalled) {
      openConnection.end();
    }
  }
  this.openConnections = [];
  this.is_connected = false;

  user_callback();
};

exports.DBConnectionPool.prototype.destroy = function() { 
};

exports.DBConnectionPool.prototype.isConnected = function() {
  return this.is_connected;
};

var countOpenConnections = function(connectionPool) {
  var i, count = 0;
  for (i = 0; i < connectionPool.openConnections.length; ++i) {
    if (connectionPool.openConnections[i] !== null) {
      count++;
    }
  }
  return count;
};

exports.DBConnectionPool.prototype.getDBSession = function(index, callback) {
  // get a connection from the pool
  var pooledConnection = null;
  var connectionPool = this;
  var newDBSession = null;
  var charset = connectionPool.driverproperties.charset;
  var charsetQuery = 
       'SET character_set_client=\'' + charset +
    '\';SET character_set_connection=\'' + charset +
    '\';SET character_set_results=\'' + charset + 
    '\';';
  var sqlModeQuery = '';
  // set SQL_MODE if specified in driverproperties
  if (typeof connectionPool.driverproperties.sql_mode !== 'undefined') {
    sqlModeQuery = 'SET SQL_MODE = \'' + connectionPool.driverproperties.sql_mode + '\';';
  }
  udebug.log(sqlModeQuery);
  function charsetComplete(err) {
    callback(err, newDBSession);
  }
  if (this.pooledConnections.length > 0) {
    udebug.log_detail('MySQLConnectionPool.getDBSession before found a pooledConnection for index ' + index + ' in connectionPool; ', 
        ' pooledConnections:', connectionPool.pooledConnections.length,
        ' openConnections: ', countOpenConnections(connectionPool));
    // pop a connection from the pool
    pooledConnection = connectionPool.pooledConnections.pop();
    newDBSession = new mysqlConnection.DBSession(pooledConnection, connectionPool, index);
    connectionPool.openConnections[index] = pooledConnection;
    udebug.log_detail('MySQLConnectionPool.getDBSession after found a pooledConnection for index ' + index + ' in connectionPool; ', 
        ' pooledConnections:', connectionPool.pooledConnections.length,
        ' openConnections: ', countOpenConnections(connectionPool));
    callback(null, newDBSession);
  } else {
    // create a new pooled connection
    var connected_callback = function(err) {
      if (err) {
        callback(err);
        return;
      }
      newDBSession = new mysqlConnection.DBSession(pooledConnection, connectionPool, index);
      connectionPool.openConnections[index] = pooledConnection;
      udebug.log_detail('MySQLConnectionPool.getDBSession created a new pooledConnection for index ' + index + ' ; ', 
          ' pooledConnections:', connectionPool.pooledConnections.length,
          ' openConnections: ', countOpenConnections(connectionPool));
      // set character set server variables      
      pooledConnection.query(charsetQuery + sqlModeQuery, charsetComplete);
    };
    // create a new connection
    pooledConnection = mysql.createConnection(this.driverproperties);
    pooledConnection.connect(connected_callback);
  }
};

/** Close the connection being used by the dbSession.
 * @param dbSession contains index the index into the openConnections array
 *                           pooledConnection the connection being used
 * @param callback when the connection is closed call the user
 */
exports.DBConnectionPool.prototype.closeConnection = function(dbSession, callback) {
  var connectionPool = this;
  if (dbSession.pooledConnection) {
    dbSession.pooledConnection.end(function(err) {
      udebug.log('close dbSession', dbSession);
    });
  }
  connectionPool.openConnections[dbSession.index] = null;
  if (typeof(callback) === 'function') {
    callback(null);
  }
};

exports.DBConnectionPool.prototype.getTableMetadata = function(databaseName, tableName, dbSession, user_callback) {
  var connectionPool = this;
  var connection, dictionary;
  stats.get_table_metadata++;

  function getTableMetadataOnMetadata(err, metadata) {
    if (!dbSession) {
      connectionPool.releaseConnection(connection);
    }
    user_callback(err, metadata);
  }

  function getTableMetadataOnConnection(err, c) {
    if (err) {
      user_callback(err);
    } else {
      connection = c;
      dictionary = new mysqlDictionary.DataDictionary(connection, connectionPool);
      udebug.log_detail('MySQLConnectionPool.getTableMetadata calling dictionary.getTableMetadata for',
          databaseName, tableName);
      dictionary.getTableMetadata(databaseName, tableName, getTableMetadataOnMetadata);
    }
  }

  // getTableMetadata starts here

  if (dbSession) {
    // dbSession exists; use the connection in the db session
    getTableMetadataOnConnection(null, dbSession.pooledConnection);
  } else {
    // dbSession does not exist; get a connection for the call
    connectionPool.getConnection(getTableMetadataOnConnection);
  }

};

exports.DBConnectionPool.prototype.listTables = function(databaseName, dbSession, user_callback) {

  var connectionPool = this;
  var connection, dictionary;
  stats.list_tables++;

  function listTablesOnTableList(err, list) {
    if (!dbSession) {
      // return the connection we got just for this call
      connectionPool.releaseConnection(connection);
    }
    // return the list to the user
    user_callback(err, list);
  }

  function listTablesOnConnection(err, c) {
    if (err) {
      user_callback(err);
    } else {
      connection = c;
      dictionary = new mysqlDictionary.DataDictionary(connection);
      dictionary.listTables(databaseName, listTablesOnTableList);
    }
  }

  // listTables starts here
  
  if (dbSession) {
    listTablesOnConnection(null, dbSession.pooledConnection);
  } else {
    // dbSession does not exist; get a connection for the call
    connectionPool.getConnection(listTablesOnConnection);
  }
};
