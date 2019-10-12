/*  Copyright (c) 2010, 2016, Oracle and/or its affiliates. All rights reserved.
    
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; version 2 of the
    License.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA */

#include <my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/client_plugin.h>
#include <mysql/service_locking.h>
#include <mysql/service_my_plugin_log.h>
#include <sql_class.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mysql_com.h>
#include <crypt_genhash_impl.h> // generate_user_salt
#include <errmsg.h>
#include <my_sys.h>
#include <sha1.h>

//#include <plugin_auth_common.h>
/*
 #define _HAS_SQL_AUTHENTICATION_H
#ifdef _HAS_SQL_AUTHENTICATION_H
  #include <sql_connect.h>
  #include <sql_auth_cache.h>
  #include <sql_authentication.h>
#endif
*/
#include "sm3.h"
#define PVERSION41_CHAR '*'
#define SM3_SCRAMBLE_LENGTH SM3_HASH_SIZE
#define SM3_SCRAMBLED_PASSWORD_CHAR_LENGTH (SM3_SCRAMBLE_LENGTH*2+1)

static void
my_crypt(char *to, const uchar *s1, const uchar *s2, uint len)
{
  const uint8 *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
}

void test_generate_user_salt(char* scramble,int len) {
    int i = 0;
    for (i=0;i<len-1;i++) {
            *scramble=0x32;
            scramble++;
    };
    *scramble = '\0';
}

inline static
void compute_two_stage_sm3_hash(const char *password, size_t pass_len,
                                 uint8 *hash_stage1, uint8 *hash_stage2)
{
  /* Stage 1: hash password */
  compute_sm3_hash(hash_stage1, (unsigned char*)password, pass_len);

  /* Stage 2 : hash first stage's output. */
  compute_sm3_hash(hash_stage2, (unsigned char *) hash_stage1, SM3_HASH_SIZE);
}

 void
scramble_sm3(char *to, const char *message, const char *password)
{
  uint8 hash_stage1[SM3_HASH_SIZE];
  uint8 hash_stage2[SM3_HASH_SIZE];

  /* Two stage SM3 hash of the password. */
  compute_two_stage_sm3_hash(password, strlen(password), hash_stage1,
                              hash_stage2);
    
  /* create crypt string as sm3(message, hash_stage2) */;
  compute_sm3_hash_multi((uint8 *) to,(unsigned char*) message, SM3_SCRAMBLE_LENGTH,
                           hash_stage2, SM3_HASH_SIZE);
  my_crypt(to, (const uchar *) to, hash_stage1, SM3_SCRAMBLE_LENGTH);
}

/********************* CLIENT SIDE ***************************************/
/*
  client plugin used for testing the plugin API
*/
#include <mysql.h>

/* this is a "superset" of MYSQL_PLUGIN_VIO, in C++ I use inheritance */
typedef struct st_mysql_client_plugin_AUTHENTICATION auth_plugin_t;

typedef struct {
  int (*read_packet)(struct st_plugin_vio *vio, uchar **buf);
  int (*write_packet)(struct st_plugin_vio *vio, const uchar *pkt, int pkt_len);
  void (*info)(struct st_plugin_vio *vio, struct st_plugin_vio_info *info);
  /* -= end of MYSQL_PLUGIN_VIO =- */
  MYSQL *mysql;
  auth_plugin_t *plugin;            /**< what plugin we're under */
  const char *db;
  struct {
    uchar *pkt;                     /**< pointer into NET::buff */
    uint pkt_len;
  } cached_server_reply;
  int packets_read, packets_written; /**< counters for send/received packets */
  int mysql_change_user;            /**< if it's mysql_change_user() */
  int last_read_packet_len;         /**< the length of the last *read* packet */
} MCPVIO_EXT;

static int sm3_password_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  int pkt_len;
  uchar *pkt,scramble[SM3_SCRAMBLE_LENGTH+1];

  //DBUG_ENTER("sm3_password_auth_client");

  if (((MCPVIO_EXT *)vio)->mysql_change_user)
  {
    /*
      in mysql_change_user() the client sends the first packet.
      we use the old scramble.
    */
    //pkt= (uchar*)mysql->scramble;
   // generate_user_salt((char*)scramble, SM3_SCRAMBLE_LENGTH + 1);
    test_generate_user_salt((char*)scramble, SM3_SCRAMBLE_LENGTH + 1);
    pkt = scramble;
    pkt_len= SM3_SCRAMBLE_LENGTH + 1;
  }
  else
  {
    /* read the scramble */
    if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
      return (CR_ERROR);

    if (pkt_len != SM3_SCRAMBLE_LENGTH + 1)
      return (CR_SERVER_HANDSHAKE_ERR);

    /* save it in MYSQL */
    // TODO
  //  memcpy(mysql->scramble, pkt, SM3_SCRAMBLE_LENGTH);
  //  mysql->scramble[SM3_SCRAMBLE_LENGTH] = 0;
  }

  if (mysql->passwd[0])
  {
    char scrambled[SM3_SCRAMBLE_LENGTH + 1];
    // my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL, "sending scramble");
    scramble_sm3(scrambled, (char*)pkt, mysql->passwd);
    if (vio->write_packet(vio, (uchar*)scrambled, SM3_SCRAMBLE_LENGTH))
      return (CR_ERROR);
  }
  else
  {
    //my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL, ("no password"));
    if (vio->write_packet(vio, 0, 0)) /* no password */
      return (CR_ERROR);
  }

  return (CR_OK);
}

mysql_declare_client_plugin(AUTHENTICATION)
  sm3_password_plugin_name_client,
  "Georgi Kodinov",
  "Dialog Client Authentication Plugin",
  {0,1,0},
  "GPL",
  NULL,
  NULL,
  NULL,
  NULL,
  sm3_password_auth_client
mysql_end_client_plugin;

