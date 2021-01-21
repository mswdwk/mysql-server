/*
 * Copyright (c) 2019, 2021, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2.0,
 * as published by the Free Software Foundation.
 *
 * This program is also distributed with certain software (including
 * but not limited to OpenSSL) that is licensed under separate terms,
 * as designated in a particular file or component or in included license
 * documentation.  The authors of MySQL hereby grant you an additional
 * permission to link the program and your derivative works with the
 * separately licensed software that they have included with MySQL.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License, version 2.0, for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include "plugin/x/src/ngs/protocol_flusher_compression.h"

#include <lz4frame.h>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

#include "zlib.h"  // NOLINT(build/include_subdir)
#include "zstd.h"  // NOLINT(build/include_subdir)

#include "plugin/x/src/ngs/log.h"

namespace ngs {

using Result = xpl::iface::Protocol_flusher::Result;

namespace details {

using Encoding_buffer = protocol::Encoding_buffer;

class Compression_deflate : public ::protocol::Compression_buffer_interface {
 public:
  explicit Compression_deflate(const int32_t level) {
    DBUG_TRACE;
    m_stream.zalloc = Z_NULL;
    m_stream.zfree = Z_NULL;
    m_stream.opaque = Z_NULL;

    m_error = Z_OK != deflateInit(&m_stream, level);
  }

  ~Compression_deflate() override { deflateEnd(&m_stream); }

  bool process(Encoding_buffer *output_buffer,
               const Encoding_buffer *input_buffer) override {
    DBUG_TRACE;
    if (m_error) return false;

    auto in_page = input_buffer->m_front;
    auto out_page = output_buffer->m_current;

    while (in_page) {
      DBUG_DUMP("compress-in", in_page->m_begin_data,
                in_page->get_used_bytes());
      in_page = in_page->m_next_page;
    }

    in_page = input_buffer->m_front;

    if (out_page->is_full()) {
      out_page = output_buffer->get_next_page();
    }

    int flush = Z_NO_FLUSH;

    while (in_page) {
      m_stream.avail_in = in_page->get_used_bytes();
      m_stream.next_in = in_page->m_begin_data;

      m_all_uncompressed += m_stream.avail_in;

      if (m_stream.avail_in == 0 || nullptr == in_page->m_next_page)
        flush = Z_SYNC_FLUSH;

      do {
        auto out_size = m_stream.avail_out = out_page->get_free_bytes();
        m_stream.next_out = out_page->m_current_data;

        const auto result = deflate(&m_stream, flush);
        if (result != Z_OK) {
          if (Z_BUF_ERROR != result && Z_STREAM_END != result) {
            log_error(ER_XPLUGIN_COMPRESSION_ERROR, zError(result));
            m_error = true;
            return false;
          }
        }

        const auto wrote = out_size - m_stream.avail_out;
        out_page->m_current_data += wrote;
        m_all_compressed += wrote;

        if (0 == m_stream.avail_out) out_page = output_buffer->get_next_page();
      } while (0 == m_stream.avail_out);

      in_page = in_page->m_next_page;
    }

    return true;
  }

  void reset_counters() override {
    m_all_compressed = 0;
    m_all_uncompressed = 0;
  }

  void get_processed_data(uint32_t *out_uncompressed,
                          uint32_t *out_compressed) override {
    *out_uncompressed = m_all_uncompressed;
    *out_compressed = m_all_compressed;
  }

 private:
  uint32_t m_all_compressed = 0;
  uint32_t m_all_uncompressed = 0;
  bool m_error = false;
  z_stream m_stream;
};

class Compression_lz4 : public ::protocol::Compression_buffer_interface {
 public:
  explicit Compression_lz4(const int32_t level) {
    DBUG_TRACE;
    LZ4F_createCompressionContext(&m_ctxt, LZ4F_VERSION);
    m_pref.frameInfo.contentSize = 0;
    m_pref.autoFlush = 1;
    m_pref.frameInfo.blockMode = LZ4F_blockIndependent;
    m_pref.compressionLevel = level;
  }

  ~Compression_lz4() override { LZ4F_freeCompressionContext(m_ctxt); }

  /* lz4frame.h doesn't define a constant that say how long is LZ4 header
     generated by LZ4F_compressBegin or footer by LZ4F_compressEnd. In
     only mentions in documentation that its:

     ```Maximum header size is 15 bytes.```

     Thus the header-and-footer wont be larger than 23bytes.
  */
  constexpr static int k_lz4_frame_header_max = 16;
  constexpr static int k_lz4_frame_footer_max = 8;
  constexpr static int k_lz4_frame_output_buffer_minmum_size = 100;

  bool process(Encoding_buffer *output_buffer,
               const Encoding_buffer *input_buffer) override {
    if (m_error) return false;

    auto in_page = input_buffer->m_front;
    auto out_page = output_buffer->m_current;

    if (out_page->get_free_bytes() < k_lz4_frame_header_max) {
      out_page = output_buffer->get_next_page();
    }

    const auto result = LZ4F_compressBegin(m_ctxt, out_page->m_current_data,
                                           out_page->get_free_bytes(), &m_pref);

    if (LZ4F_isError(result)) {
      log_error(ER_XPLUGIN_COMPRESSION_ERROR, LZ4F_getErrorName(result));
      m_error = true;
      return false;
    }

    out_page->m_current_data += result;
    m_open_frame = false;

    while (in_page) {
      auto uncompressed_size = in_page->get_used_bytes();
      auto uncompressed_data = in_page->m_begin_data;
      m_all_uncompressed += uncompressed_size;

      do {
        auto compression_result = compress_update(
            &uncompressed_data, &uncompressed_size, output_buffer);

        if (LZ4F_isError(compression_result)) {
          log_error(ER_XPLUGIN_COMPRESSION_ERROR,
                    LZ4F_getErrorName(compression_result));
          m_error = true;
          return false;
        }

        m_all_compressed += compression_result;
      } while (0 < uncompressed_size);

      in_page = in_page->m_next_page;
    }

    const auto flush_result = compress_end(output_buffer);
    if (LZ4F_isError(flush_result)) {
      log_error(ER_XPLUGIN_COMPRESSION_ERROR, LZ4F_getErrorName(flush_result));
      m_error = true;
      return false;
    }

    m_all_compressed += flush_result;

    return true;
  }

  void reset_counters() override {
    m_all_compressed = 0;
    m_all_uncompressed = 0;
  }

  void get_processed_data(uint32_t *out_uncompressed,
                          uint32_t *out_compressed) override {
    *out_uncompressed = m_all_uncompressed;
    *out_compressed = m_all_compressed;
  }

 private:
  uint32_t get_maximum_input_for_output_size(const uint32_t output_size,
                                             const uint32_t input_size) {
    auto go_down_with_size = input_size;
    while (output_size < LZ4F_compressBound(go_down_with_size, &m_pref)) {
      go_down_with_size /= 2;

      if (0 == go_down_with_size) break;
    }

    return go_down_with_size;
  }

  void skip_small_pages(protocol::Page **inout_page, Encoding_buffer *buffer) {
    if (2 * k_lz4_frame_output_buffer_minmum_size >
        (*inout_page)->get_free_bytes()) {
      *inout_page = buffer->get_next_page();
    }
  }
  void copy_from_intermediate_to_output(Encoding_buffer *output_buffer,
                                        const uint32_t size) {
    auto out_page = output_buffer->m_current;
    auto intermediate_data = m_intermediate_buffer.get();
    auto go_down_with_size = size;

    while (go_down_with_size) {
      if (0 == out_page->get_free_bytes()) {
        out_page = output_buffer->get_next_page();
      }
      const auto to_copy =
          std::min(go_down_with_size, out_page->get_free_bytes());
      std::memcpy(out_page->m_current_data, intermediate_data, to_copy);
      out_page->m_current_data += to_copy;
      intermediate_data += to_copy;
      go_down_with_size -= to_copy;
    }
  }

  size_t compress_update(unsigned char **uncompressed_data,
                         uint32_t *uncompressed_size,
                         Encoding_buffer *output_buffer) {
    auto out_page = output_buffer->m_current;
    skip_small_pages(&out_page, output_buffer);

    auto output_size = out_page->get_free_bytes();
    auto out_data = out_page->m_current_data;

    const auto input_size =
        std::min(*uncompressed_size,
                 output_size - k_lz4_frame_output_buffer_minmum_size);

    auto adjusted_input_size =
        get_maximum_input_for_output_size(output_size, input_size);
    bool intermediate_buffer = false;

    // In this case we could disable auto-flush
    if (0 == adjusted_input_size && 0 != input_size) {
      const auto new_output_size =
          LZ4F_compressBound(*uncompressed_size, &m_pref);
      adjusted_input_size = input_size;

      if (new_output_size > output_size) {
        intermediate_buffer = true;

        output_size = new_output_size;
        out_data = get_intermediate_buffer_of_size(output_size);
      }
    }

    auto compression_result =
        LZ4F_compressUpdate(m_ctxt, out_data, output_size, *uncompressed_data,
                            adjusted_input_size, nullptr);

    if (LZ4F_isError(compression_result)) {
      return compression_result;
    }

    *uncompressed_size -= adjusted_input_size;
    *uncompressed_data += adjusted_input_size;

    if (intermediate_buffer) {
      copy_from_intermediate_to_output(
          output_buffer, static_cast<uint32_t>(compression_result));
    } else {
      out_page->m_current_data += compression_result;
    }

    return compression_result;
  }

  size_t compress_end(Encoding_buffer *output_buffer) {
    auto out_page = output_buffer->m_current;
    auto out_data = out_page->m_current_data;
    auto out_size = out_page->get_free_bytes();
    bool using_intemediate_buffer = false;

    const auto buffer_need_for_flush = LZ4F_compressBound(0, &m_pref);

    if (buffer_need_for_flush > out_size) {
      using_intemediate_buffer = true;
      out_size = buffer_need_for_flush;
      out_data = get_intermediate_buffer_of_size(out_size);
    }

    const auto flush_result =
        LZ4F_compressEnd(m_ctxt, out_data, out_size, nullptr);

    if (LZ4F_isError(flush_result)) {
      return flush_result;
    }

    if (using_intemediate_buffer) {
      copy_from_intermediate_to_output(output_buffer,
                                       static_cast<uint32_t>(flush_result));
    } else {
      out_page->m_current_data += flush_result;
    }

    return flush_result;
  }

  uint8_t *get_intermediate_buffer_of_size(const uint32_t possible_in_size) {
    if (m_intermediate_buffer_size < possible_in_size) {
      m_intermediate_buffer_size = possible_in_size;
      m_intermediate_buffer.reset(new uint8_t[m_intermediate_buffer_size]);
    }

    return m_intermediate_buffer.get();
  }

  uint32_t m_all_compressed = 0;
  uint32_t m_all_uncompressed = 0;
  uint32_t m_intermediate_buffer_size = 0;
  std::unique_ptr<uint8_t[]> m_intermediate_buffer;
  LZ4F_compressionContext_t m_ctxt;
  LZ4F_preferences_t m_pref{};
  bool m_error = false;
  bool m_open_frame = true;
};

class Compression_zstandard : public ::protocol::Compression_buffer_interface {
 public:
  explicit Compression_zstandard(const int32_t level)
      : m_stream{ZSTD_createCStream()} {
#if ZSTD_VERSION_NUMBER < 10400
    is_error(ZSTD_initCStream(m_stream, level));
#else

    if (is_error(ZSTD_CCtx_reset(m_stream, ZSTD_reset_session_only)) ||
        is_error(ZSTD_CCtx_refCDict(m_stream, nullptr)) ||
        is_error(
            ZSTD_CCtx_setParameter(m_stream, ZSTD_c_compressionLevel, level)))
      return;
#endif
  }

  ~Compression_zstandard() override { ZSTD_freeCStream(m_stream); }

  void reset_counters() override {
    m_all_compressed = 0;
    m_all_uncompressed = 0;
  }

  bool process(Encoding_buffer *output_buffer,
               const Encoding_buffer *input_buffer) override {
    DBUG_TRACE;
    if (m_error) return false;

    auto out_page = output_buffer->m_current;
    if (out_page->is_full()) {
      out_page = output_buffer->get_next_page();
    }

    auto in_page = input_buffer->m_front;
    uint32_t size = 0;
    while (in_page) {
      size += in_page->get_used_bytes();
      in_page = in_page->m_next_page;
    }

#if ZSTD_VERSION_NUMBER < 10400
    // is_error(ZSTD_resetCStream(m_stream, size));
#else
    if (is_error(ZSTD_CCtx_reset(m_stream, ZSTD_reset_session_only)) ||
        is_error(ZSTD_CCtx_setPledgedSrcSize(m_stream, size)))
      return false;
#endif

    in_page = input_buffer->m_front;
    ZSTD_inBuffer in_buffer;
    while (in_page) {
      in_buffer =
          ZSTD_inBuffer{in_page->m_begin_data, in_page->get_used_bytes(), 0};

      m_all_uncompressed += in_buffer.size;

      while (in_buffer.pos < in_buffer.size) {
        ZSTD_outBuffer out_buffer{out_page->m_current_data,
                                  out_page->get_free_bytes(), 0};

#if ZSTD_VERSION_NUMBER < 10400
        if (is_error(ZSTD_compressStream(m_stream, &out_buffer, &in_buffer)))
#else
        if (is_error(ZSTD_compressStream2(m_stream, &out_buffer, &in_buffer,
                                          ZSTD_e_continue)))
#endif
          return false;

        out_page->m_current_data += out_buffer.pos;
        m_all_compressed += out_buffer.pos;

        if (out_buffer.pos == out_buffer.size)
          out_page = output_buffer->get_next_page();
      }

      in_page = in_page->m_next_page;
    }

    size_t result = 0;
    do {
      ZSTD_outBuffer out_buffer{out_page->m_current_data,
                                out_page->get_free_bytes(), 0};
#if ZSTD_VERSION_NUMBER < 10400
      result = ZSTD_flushStream(m_stream, &out_buffer);
#else
      result =
          ZSTD_compressStream2(m_stream, &out_buffer, &in_buffer, ZSTD_e_end);
#endif

      if (is_error(result)) return false;

      out_page->m_current_data += out_buffer.pos;
      m_all_compressed += out_buffer.pos;

      if (result != 0 && out_buffer.pos == out_buffer.size)
        out_page = output_buffer->get_next_page();
    } while (result);

    return true;
  }

  void get_processed_data(uint32_t *out_uncompressed,
                          uint32_t *out_compressed) override {
    *out_uncompressed = m_all_uncompressed;
    *out_compressed = m_all_compressed;
  }

 private:
  bool is_error(const uint64_t result) {
    if (!ZSTD_isError(result)) return false;
    log_error(ER_XPLUGIN_COMPRESSION_ERROR, ZSTD_getErrorName(result));
    m_error = true;
    return true;
  }

  ZSTD_CStream *m_stream;
  uint32_t m_all_compressed = 0;
  uint32_t m_all_uncompressed = 0;
  bool m_error = false;
};

}  // namespace details

Protocol_flusher_compression::Protocol_flusher_compression(
    std::unique_ptr<xpl::iface::Protocol_flusher> flusher,
    protocol::XMessage_encoder *encoder, xpl::iface::Protocol_monitor *monitor,
    const Error_handler &error_handler, Memory_block_pool *memory_block_pool)
    : m_flusher(std::move(flusher)),
      m_encoder(encoder),
      m_monitor(monitor),
      m_on_error_handler(error_handler),
      m_pool(2, memory_block_pool) {  // TODO(lkotula): benchmark m_pool first
                                      // param (shouldn't be in review);
}

void Protocol_flusher_compression::trigger_flush_required() {
  m_flusher->trigger_flush_required();
}

void Protocol_flusher_compression::trigger_on_message(const uint8_t type) {
  m_flusher->trigger_on_message(type);
}

Result Protocol_flusher_compression::try_flush() {
  DBUG_TRACE;

  if (m_fata_compression_error) return Result::k_error;

  if (is_going_to_flush() && m_compression_ongoing) {
    end_compression();
  }

  const auto result = m_flusher->try_flush();
  DBUG_LOG("debug", "try_flush returned " << static_cast<int>(result));

  return result;
}

bool Protocol_flusher_compression::is_going_to_flush() {
  return m_flusher->is_going_to_flush();
}

void Protocol_flusher_compression::set_write_timeout(const uint32_t timeout) {
  m_flusher->set_write_timeout(timeout);
}

void Protocol_flusher_compression::set_compression_options(
    const Compression_algorithm algo, const Compression_style style,
    const int64_t max_num_of_messages, const int32_t level) {
  DBUG_TRACE;
  // Set the compression once.
  if (m_comp_algorithm.get()) return;

  switch (algo) {
    case Compression_algorithm::k_deflate:
      m_comp_algorithm.reset(new details::Compression_deflate(level));
      break;

    case Compression_algorithm::k_lz4:
      m_comp_algorithm.reset(new details::Compression_lz4(level));
      break;

    case Compression_algorithm::k_zstd:
      m_comp_algorithm.reset(new details::Compression_zstandard(level));
      break;

    case Compression_algorithm::k_none:
      break;
  }

  switch (style) {
    case Compression_style::k_single:
      m_comp_type = protocol::Compression_type::k_single;
      break;
    case Compression_style::k_multiple:
      m_comp_type = protocol::Compression_type::k_multiple;
      break;
    case Compression_style::k_group:
      m_comp_type = protocol::Compression_type::k_group;
      break;

    case Compression_style::k_none: {
    }
  }

  m_max_compressed_messages = max_num_of_messages;
}

void Protocol_flusher_compression::handle_compression(
    const uint8_t id, const bool can_be_compressed) {
  DBUG_LOG("debug", "handle_compression message-id="
                        << static_cast<int>(id) << ", compression  type:"
                        << static_cast<int>(m_comp_type));

  if (m_compression_ongoing) {
    if (can_be_compressed) {
      ++m_compressed_messages;
      if (protocol::Compression_type::k_multiple == m_comp_type) {
        if (m_comp_position.m_msg_id != id) {
          end_compression();
          begin_compression(id);
        }
      }

      if (m_max_compressed_messages > 0) {
        if (m_compressed_messages >= m_max_compressed_messages) {
          end_compression();
          begin_compression(id);
        }
      }

      return;
    }
    end_compression();

    return;
  }

  if (can_be_compressed) {
    begin_compression(id);
  }
}

void Protocol_flusher_compression::begin_compression(const uint8_t id) {
  DBUG_TRACE;
  m_compressed_messages = 0;
  if (m_fata_compression_error) return;

  m_compression_ongoing = true;
  m_comp_position =
      m_encoder->begin_compression(id, m_comp_type, &m_comp_buffor);
}

void Protocol_flusher_compression::abort_last_compressed() {
  if (m_compression_ongoing) {
    if (protocol::Compression_type::k_single == m_comp_type) {
      log_debug("abort_compression");
      m_encoder->abort_compression(m_comp_position);
      m_compression_ongoing = false;
      m_comp_algorithm->reset_counters();
    }
  }
}

void Protocol_flusher_compression::end_compression() {
  DBUG_TRACE;
  if (m_fata_compression_error) return;

  m_compression_ongoing = false;
  m_comp_algorithm->reset_counters();
  if (!m_encoder->end_compression(m_comp_position, m_comp_algorithm.get())) {
    m_fata_compression_error = true;
    m_on_error_handler(SOCKET_ECONNRESET);
    return;
  }
  uint32_t data_uncompressed, data_compressed;
  m_comp_algorithm->get_processed_data(&data_uncompressed, &data_compressed);

  m_monitor->on_send_before_compression(data_uncompressed);
  m_monitor->on_send_compressed(data_compressed);
}

}  // namespace ngs
