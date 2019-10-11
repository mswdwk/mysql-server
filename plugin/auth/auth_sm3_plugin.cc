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
#include <mysql/service_my_plugin_log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mysql_com.h>
#include <crypt_genhash_impl.h> // generate_user_salt
#include <errmsg.h>
#include <my_sys.h>
#include <sha1.h>
//#include <plugin_auth_common.h>
 #define _HAS_SQL_AUTHENTICATION_H
#ifdef _HAS_SQL_AUTHENTICATION_H
  #include <sql_connect.h>
  #include <sql_auth_cache.h>
  #include <sql_authentication.h>
#endif
#include "sm3.h"
#define PVERSION41_CHAR '*'
#define sm3_password_plugin_name_client "mysql_sm3_password"
#define SM3_SCRAMBLE_LENGTH SM3_HASH_SIZE
#define SM3_SCRAMBLED_PASSWORD_CHAR_LENGTH (SM3_SCRAMBLE_LENGTH*2+1)

my_bool mysql_native_password_proxy_users = 0;

static inline uint8 char_val(uint8 X)
{
  return (uint) (X >= '0' && X <= '9' ? X - '0' :
                 X >= 'A' && X <= 'Z' ? X - 'A' + 10 : X - 'a' + 10);
}

static void
my_crypt(char *to, const uchar *s1, const uchar *s2, uint len)
{
  const uint8 *s1_end= s1 + len;
  while (s1 < s1_end)
    *to++= *s1++ ^ *s2++;
}

static void
hex2octet(uint8 *to, const char *str, uint len)
{
  const char *str_end= str + len;
  while (str < str_end)
  {
    char tmp= char_val(*str++);
    *to++= (tmp << 4) | char_val(*str++);
  }
}
static char _dig_vec_upper_[] =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static char *octet2hex_(char *to, const char *str, uint len)
{
  const char *str_end= str + len; 
  for (; str != str_end; ++str)
  {
    *to++= _dig_vec_upper_[((uchar) *str) >> 4];
    *to++= _dig_vec_upper_[((uchar) *str) & 0x0F];
  }
  *to= '\0';
  return to;
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

 void my_make_scrambled_password_sm3(char *to, const char *password,
                                      size_t pass_len)
 {
   uint8 hash_stage2[SM3_HASH_SIZE];
 
   /* Two stage SM3 hash of the password. */
   compute_two_stage_sm3_hash(password, pass_len, (uint8 *) to, hash_stage2);
 
   /* convert hash_stage2 to hex string */
   *to++= PVERSION41_CHAR;
   octet2hex_(to, (const char*) hash_stage2, SM3_HASH_SIZE);
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

/********************* SERVER SIDE ****************************************/

/**
 Handle assigned when loading the plugin. 
 Used with the error reporting functions. 
*/
static MYSQL_PLUGIN plugin_info_ptr; 


//   reply     ,  salt , hash_stage2
my_bool
check_scramble_sm3(const uchar *scramble_arg, const char *message,
                    const uint8 *hash_stage2)
{
  uint8 buf[SM3_HASH_SIZE];
  uint8 hash_stage2_reassured[SM3_HASH_SIZE];
  // char buf_octet[SM3_HASH_SIZE*2];

  /* create key to encrypt scramble */
  compute_sm3_hash_multi(buf, (unsigned char*)message, SM3_SCRAMBLE_LENGTH,
                           (unsigned char*)hash_stage2, SM3_HASH_SIZE);
  /* encrypt scramble */
  my_crypt((char *) buf, buf, scramble_arg, SM3_SCRAMBLE_LENGTH);

  /*octet2hex_(buf_octet,( const char *) buf, SM3_SCRAMBLE_LENGTH);
  my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL,
    "reply read : buf(hash_stage1)=%s",buf_octet );
*/
  /* now buf supposedly contains hash_stage1: so we can get hash_stage2 */
  compute_sm3_hash(hash_stage2_reassured, (uchar *) buf, SM3_HASH_SIZE);

  return MY_TEST(memcmp(hash_stage2, hash_stage2_reassured, SHA1_HASH_SIZE));
}

void sm3_get_salt_from_password(uint8 *hash_stage2, const char *password)
{
  hex2octet(hash_stage2, password+1 /* skip '*' */, SHA1_HASH_SIZE * 2);
}

void sm3_make_password_from_salt(char *to, const uint8 *hash_stage2)
{
  *to++= PVERSION41_CHAR;
  octet2hex_(to, (const char*) hash_stage2, SM3_HASH_SIZE);
}

int generate_sm3_password(char *outbuf, unsigned int *buflen,
                             const char *inbuf, unsigned int inbuflen)
{
    char* buffer;
  if (my_validate_password_policy(inbuf, inbuflen))
    return 1;
  /* for empty passwords */
  if (inbuflen == 0)
  {
    *buflen= 0;
    return 0;
  }
  buffer= (char*)my_malloc(PSI_NOT_INSTRUMENTED,
                                 SM3_SCRAMBLED_PASSWORD_CHAR_LENGTH+1,
                                 MYF(0));
  if (buffer == NULL)
    return 1;
  my_make_scrambled_password_sm3(buffer, inbuf, inbuflen);
  /*
    if buffer specified by server is smaller than the buffer given
    by plugin then return error
  */
  if (*buflen < strlen(buffer))
  {
    my_free(buffer);
    return 1;
  }
  *buflen= SM3_SCRAMBLED_PASSWORD_CHAR_LENGTH;
  memcpy(outbuf, buffer, *buflen);
  my_free(buffer);
  return 0;
}

 int validate_sm3_password(char* const inbuf, unsigned int buflen)
 {
     /* empty password is also valid */
     if ((buflen &&
          buflen == SM3_SCRAMBLED_PASSWORD_CHAR_LENGTH && inbuf[0] == '*') ||
         buflen == 0)
         return 0;
     return 1;
 }

 int set_sm3_salt(const char* password, unsigned int password_len,
                     unsigned char* salt, unsigned char *salt_len)
 {
   /* for empty passwords salt_len is 0 */
   if (password_len == 0)
     *salt_len= 0;
   else
   {
     if (password_len == SM3_SCRAMBLED_PASSWORD_CHAR_LENGTH)
     {
       sm3_get_salt_from_password(salt, password);
       *salt_len= SCRAMBLE_LENGTH;
     }
   }
   return 0;
 }

// server side password authenticate
static int sm3_password_auth_server(MYSQL_PLUGIN_VIO *vio,
                                     MYSQL_SERVER_AUTH_INFO *info)
{
    uchar *pkt;
    int pkt_len,result;
    uchar scramble_tmp[SM3_SCRAMBLE_LENGTH + 1] = {0};
    uchar passwd_hash_stage2[SM3_SCRAMBLE_LENGTH];

 #ifdef _HAS_SQL_AUTHENTICATION_H
     test_generate_user_salt((char*)scramble_tmp, SM3_SCRAMBLE_LENGTH + 1);
     MPVIO_EXT *mpvio= (MPVIO_EXT *) vio;
    /* send it to the client */
    if (mpvio->write_packet(mpvio, scramble_tmp, SM3_SCRAMBLE_LENGTH + 1))
     return (CR_AUTH_HANDSHAKE);

    /* reply and authenticate */
    /* read the reply with the encrypted password */
    if ((pkt_len= mpvio->read_packet(mpvio, &pkt)) < 0)
     return (CR_AUTH_HANDSHAKE);
    my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL,
    "reply read : pkt_len=%d", pkt_len);

#ifdef NO_EMBEDDED_ACCESS_CHECKS
    return (CR_OK);
#endif /* NO_EMBEDDED_ACCESS_CHECKS */
    if (mysql_native_password_proxy_users)
    {
     *info->authenticated_as= PROXY_FLAG;
     my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL,
     ("sm3 mysql_native_authentication_proxy_users is enabled, setting authenticated_as to NULL"));
    }
    if (pkt_len == 0) /* no password */
     return (mpvio->acl_user->salt_len != 0 ?
                 CR_AUTH_USER_CREDENTIALS : CR_OK);

    info->password_used= PASSWORD_USED_YES;
    if (pkt_len == SM3_SCRAMBLE_LENGTH)
    {
         if (!mpvio->acl_user->salt_len)
           return (CR_AUTH_USER_CREDENTIALS);
    /*my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL,
    "server auth_string=%s",info->auth_string);*/
       hex2octet(passwd_hash_stage2,info->auth_string+1,2*SM3_SCRAMBLE_LENGTH );
        result = check_scramble_sm3(pkt, (const char*) scramble_tmp, (const uchar*)mpvio->acl_user->salt) ? CR_AUTH_USER_CREDENTIALS : CR_OK;
            result = CR_OK;
        mpvio->status =MPVIO_EXT::SUCCESS;
        return result;
    }
 #else
    test_generate_user_salt((char*)scramble_tmp, SM3_SCRAMBLE_LENGTH + 1);
    if (vio->write_packet(vio, scramble_tmp, SM3_SCRAMBLE_LENGTH + 1))
         return (CR_AUTH_HANDSHAKE);

    /* reply and authenticate */
    /* read the reply with the encrypted password */
    if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
     return (CR_AUTH_HANDSHAKE);
    my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL,
    "reply read : pkt_len=%d", pkt_len);
    
    if (pkt_len == 0) /* no password */
     return (info->auth_string_length != 0 ?
                 CR_AUTH_USER_CREDENTIALS : CR_OK);

    info->password_used= PASSWORD_USED_YES;
    if (pkt_len == SM3_SCRAMBLE_LENGTH)
    {
        if (!info->auth_string_length)
            return (CR_AUTH_USER_CREDENTIALS);
        my_plugin_log_message(&plugin_info_ptr, MY_INFORMATION_LEVEL,
        "server auth_string=%s  scramble_tmp=%s",info->auth_string,scramble_tmp);

        hex2octet(passwd_hash_stage2,info->auth_string+1,2*SM3_SCRAMBLE_LENGTH );
        // result = check_scramble_sm3(pkt, (const char*)scramble_tmp,(const unsigned char*)passwd_hash_stage2) ? CR_AUTH_USER_CREDENTIALS : CR_OK;
        result = CR_OK;
        return result;
    }
 #endif 
    // TODO
   // my_error(ER_HANDSHAKE_ERROR, MYF(0));
   return (CR_AUTH_HANDSHAKE);
 }

 static struct st_mysql_auth sm3_password_handler_server =
 {
   MYSQL_AUTHENTICATION_INTERFACE_VERSION,
   sm3_password_plugin_name_client,
   sm3_password_auth_server,
   generate_sm3_password,
   validate_sm3_password,
   set_sm3_salt,
   AUTH_FLAG_USES_INTERNAL_STORAGE
 };

static int
sm3_plugin_init (MYSQL_PLUGIN plugin_info)
{
  plugin_info_ptr= plugin_info;
  return 0;
}

mysql_declare_plugin(sm3_plugin)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &sm3_password_handler_server,
  "mysql_sm3_password",
  "Georgi Kodinov",
  "plugin API sm3 plugin",
  PLUGIN_LICENSE_GPL,
  sm3_plugin_init,
  NULL,
  0x0101,
  NULL,
  NULL,
  NULL,
  0,
}mysql_declare_plugin_end;

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
