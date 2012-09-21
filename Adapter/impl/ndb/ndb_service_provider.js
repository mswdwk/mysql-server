/*
 Copyright (c) 2012, Oracle and/or its affiliates. All rights
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

/*global unified_debug, path */

"use strict";

try {
  var ndbconnection = require("./NdbConnectionPool.js");
}
catch(e) {
  /* Let unmet module dependencies be caught by loadRequiredModules() */
}

var udebug  = unified_debug.getLogger("ndb_service_provider.js");


exports.loadRequiredModules = function() {
  var err, ldp, module, msg;
  module = path.join(build_dir, "ndb_adapter.node");
  try {
    require(module);
    return true;
  }
  catch(e) {
    ldp = process.platform === 'darwin' ? 'DYLD_LIBRARY_PATH' : 'LD_LIBRARY_PATH';
    msg = "\n\n" +
      "  The ndb adapter cannot load the native code module ndb_adapter.node.\n";
    if(path.existsSync(module)) {
      msg += 
      "  This module has been built, but was not succesfully loaded.  Perhaps \n" +
      "  setting " + ldp + " to the mysql lib directory (containing \n" +
      "  libndbclient) will resolve the problem.\n";
    }
    else {
      msg += 
      "  For help building the module, run " + 
      "\"setup/build.sh\" or \"npm install .\"\n";
    }
    err = new Error(msg);
    err.cause = e;
    throw err;
  }
};


var NdbDefaultConnectionProperties = {  
  "implementation" : "ndb",
  "database" : "test",
  
  "ndb_connectstring" : "localhost:1186",
  "ndb_connect_retries" : 4, 
  "ndb_connect_delay" : 5,
  "ndb_connect_verbose" : 0,
  "ndb_connect_timeout_before" : 30,
  "ndb_connect_timeout_after" : 20
};


exports.getDefaultConnectionProperties = function() {
  return NdbDefaultConnectionProperties;
};


exports.connectSync = function(properties) {
  udebug.log("connectSync");
  var dbconn = new ndbconnection.DBConnectionPool(properties);
  dbconn.connectSync();
  return dbconn;
};


exports.connect = function(properties, user_callback) {
  udebug.log("connect");
  var dbconn = new ndbconnection.DBConnectionPool(properties);
  dbconn.connect(user_callback);
};


exports.getFactoryKey = function(properties) {
  udebug.log("getFactoryKey");
  var key = properties.implementation + "://" + properties.ndb_connectstring;
  return key;
};
