cmake -DCMAKE_INSTALL_PREFIX=/home/mysql/sm3 -DMYSQL_DATADIR=/home/mysql/sm3/data -DDOWNLOAD_BOOST=1 -DWITH_BOOST=/var/lib/boost_1_59_0 -DSYSCONFDIR=/home/mysql/sm3/etc -DWITH_INNOBASE_STORAGE_ENGINE=1 -DWITH_PARTITION_STORAGE_ENGINE=1 -DWITH_FEDERATED_STORAGE_ENGINE=1 -DWITH_BLACKHOLE_STORAGE_ENGINE=1 -DWITH_MYISAM_STORAGE_ENGINE=1 -DENABLED_LOCAL_INFILE=1 -DENABLE_DTRACE=0 -DDEFAULT_CHARSET=utf8 -DDEFAULT_COLLATION=utf8_general_ci -DWITH_EMBEDDED_SERVER=1 -DWITH_DEBUG=1

