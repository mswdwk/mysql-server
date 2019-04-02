/*
   Copyright (c) 2017, 2018, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include "sha256_scramble_generator.h"

#include <cstring>

#include "my_config.h"

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#include <openssl/evp.h>

#include "my_dbug.h"     /* DBUG instrumentation */
#include "my_inttypes.h" /* typedefs */

namespace xcl {
namespace sha256_password {

/**
  SHA256 digest generator constructor

  Initializes digest context and sets
  status of initialization.

  If m_ok is set to false at the end,
  it indicates a problem in initialization.
*/
SHA256_digest::SHA256_digest() : m_ok(false) { init(); }

/**
  Release acquired memory
*/
SHA256_digest::~SHA256_digest() { deinit(); }

/**
  Update digest with plaintext

  @param [in] src    Plaintext to be added
  @param [in] length Length of the plaintext

  @returns digest update status
    @retval true Problem updating digest
    @retval false Success
*/
bool SHA256_digest::update_digest(const void *src, const std::uint32_t length) {
  DBUG_ENTER("SHA256_digest::update_digest");
  if (!m_ok || !src) {
    DBUG_PRINT("info", ("Either digest context is not ok or "
                        "source is emptry string"));
    DBUG_RETURN(true);
  }
  m_ok = EVP_DigestUpdate(md_context, src, length);
  DBUG_RETURN(!m_ok);
}

/**
  Retrive generated digest

  @param [out] digest Digest text
  @param [in]  length Length of the digest buffer

  Assumption : memory for digest has been allocated

  @returns digest retrieval status
    @retval true Error
    @retval false Success
*/
bool SHA256_digest::retrieve_digest(unsigned char *digest,
                                    const std::uint32_t length) {
  DBUG_ENTER("SHA256_digest::retrieve_digest");
  if (!m_ok || !digest || length != CACHING_SHA2_DIGEST_LENGTH) {
    DBUG_PRINT("info", ("Either digest context is not ok or "
                        "digest length is not as expected."));
    DBUG_RETURN(true);
  }
  m_ok = EVP_DigestFinal_ex(md_context, m_digest, nullptr);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EVP_MD_CTX_cleanup(md_context);
#else  /* OPENSSL_VERSION_NUMBER < 0x10100000L */
  EVP_MD_CTX_reset(md_context);
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
  memcpy(digest, m_digest, length);
  DBUG_RETURN(!m_ok);
}

/**
  Cleanup and reinit
*/
void SHA256_digest::scrub() {
  deinit();
  init();
}

/**
  Initialize digest context

  1. Allocate memory for digest context
  2. Call initialization function(s)
*/
void SHA256_digest::init() {
  DBUG_ENTER("SHA256_digest::init");
  m_ok = false;
  md_context = EVP_MD_CTX_create();
  if (!md_context) {
    DBUG_PRINT("info", ("Failed to create digest context"));
    DBUG_VOID_RETURN;
  }

  m_ok =
      static_cast<bool>(EVP_DigestInit_ex(md_context, EVP_sha256(), nullptr));

  if (!m_ok) {
    EVP_MD_CTX_destroy(md_context);
    md_context = nullptr;
    DBUG_PRINT("info", ("Failed to initialize digest context"));
  }
  DBUG_VOID_RETURN;
}

/**
  Release allocated memory for digest context
*/
void SHA256_digest::deinit() {
  if (md_context) EVP_MD_CTX_destroy(md_context);
  md_context = nullptr;
  m_ok = false;
}

/**
  Generate_scramble constructor

  @param [in] source Plaintext source
  @param [in] rnd    Salt
  @param [in] digest_type Digest type
*/
Generate_scramble::Generate_scramble(
    const std::string &source, const std::string &rnd,
    Digest_info digest_type) /*  = Digest_info::SHA256_DIGEST */
    : m_src(source), m_rnd(rnd), m_digest_type(digest_type) {
  switch (m_digest_type) {
    case Digest_info::SHA256_DIGEST: {
      m_digest_generator.reset(new SHA256_digest());
      m_digest_length = CACHING_SHA2_DIGEST_LENGTH;
      break;
    }
    default: {
      DBUG_ASSERT(false);
    }
  }
}

/**
  Scramble generation

  @param [out] out_scramble    Output buffer for generated scramble
  @param [in]  scramble_length Size of scramble buffer

  @note
    SHA2(src) => digest_stage1
    SHA2(digest_stage1) => digest_stage2
    SHA2(digest_stage2, m_rnd) => scramble_stage1
    XOR(digest_stage1, scramble_stage1) => scramble

  @returns Status of scramble generation
    @retval true  Error generating scramble
    @retval false Success
*/
bool Generate_scramble::scramble(unsigned char *out_scramble,
                                 const std::uint32_t scramble_length) {
  DBUG_ENTER("Generate_scramble::scramble");
  unsigned char *digest_stage1;
  unsigned char *digest_stage2;
  unsigned char *scramble_stage1;

  if (!out_scramble || scramble_length != m_digest_length) {
    DBUG_PRINT("info", ("Unexpected scrable length"
                        "Expected: %d, Actual: %d",
                        m_digest_length, !out_scramble ? 0 : scramble_length));
    DBUG_RETURN(true);
  }

  switch (m_digest_type) {
    case Digest_info::SHA256_DIGEST: {
      digest_stage1 =
          reinterpret_cast<unsigned char *>(alloca(m_digest_length));
      digest_stage2 =
          reinterpret_cast<unsigned char *>(alloca(m_digest_length));
      scramble_stage1 =
          reinterpret_cast<unsigned char *>(alloca(m_digest_length));
      break;
    }
    default: {
      DBUG_ASSERT(false);
      DBUG_RETURN(true);
    }
  }

  /* SHA2(src) => digest_stage1 */
  if (m_digest_generator->update_digest(m_src.c_str(), m_src.length()) ||
      m_digest_generator->retrieve_digest(digest_stage1, m_digest_length)) {
    DBUG_PRINT("info", ("Failed to generate digest_stage1: SHA2(src)"));
    DBUG_RETURN(true);
  }

  /* SHA2(digest_stage1) => digest_stage2 */
  m_digest_generator->scrub();
  if (m_digest_generator->update_digest(digest_stage1, m_digest_length) ||
      m_digest_generator->retrieve_digest(digest_stage2, m_digest_length)) {
    DBUG_PRINT("info",
               ("Failed to generate digest_stage2: SHA2(digest_stage1)"));
    DBUG_RETURN(true);
  }

  /* SHA2(digest_stage2, m_rnd) => scramble_stage1 */
  m_digest_generator->scrub();
  if (m_digest_generator->update_digest(digest_stage2, m_digest_length) ||
      m_digest_generator->update_digest(m_rnd.c_str(), m_rnd.length()) ||
      m_digest_generator->retrieve_digest(scramble_stage1, m_digest_length)) {
    DBUG_PRINT("info", ("Failed to generate scrmable_stage1: "
                        "SHA2(digest_stage2, m_rnd)"));
    DBUG_RETURN(true);
  }

  /* XOR(digest_stage1, scramble_stage1) => out_scramble */
  for (uint i = 0; i < m_digest_length; ++i)
    out_scramble[i] = (digest_stage1[i] ^ scramble_stage1[i]);

  DBUG_RETURN(false);
}

}  // namespace sha256_password

/*
  Generate scramble from password and salt.

  @param [out] out_scramble Buffer to put generated scramble
  @param [in] scramble_size Size of the output buffer
  @param [in] src           Source text buffer
  @param [in] src_size      Source text buffer size
  @param [in] salt          Salt text buffer
  @param [in] salt_size     Salt text buffer size

  @note
    SHA2(src) => X
    SHA2(X) => Y
    SHA2(XOR(salt, Y) => Z
    XOR(X, Z) => scramble

  @returns Status of scramble generation
    @retval true  Error
    @retval false Generation successful

*/
bool generate_sha256_scramble(unsigned char *out_scramble,
                              const std::size_t scramble_size, const char *src,
                              const std::size_t src_size, const char *salt,
                              const std::size_t salt_size) {
  DBUG_ENTER("generate_scramble");
  std::string source(src, src_size);
  std::string random(salt, salt_size);

  sha256_password::Generate_scramble scramble_generator(source, random);
  if (scramble_generator.scramble(out_scramble, scramble_size)) {
    DBUG_PRINT("info", ("Failed to generate SHA256 based scramble"));
    DBUG_RETURN(true);
  }

  DBUG_RETURN(false);
}

}  // namespace xcl
