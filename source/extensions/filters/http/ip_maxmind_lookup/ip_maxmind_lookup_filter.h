#pragma once

#include <string>
#include <tuple>
#include <vector>

#include "envoy/extensions/filters/http/ip_maxmind_lookup/v3/ip_maxmind_lookup.pb.h"
#include "envoy/server/filter_config.h"

#include "source/common/common/logger.h"
#include "source/common/common/matchers.h"

#include "absl/strings/string_view.h"
#include "absl/container/inlined_vector.h"
#include "absl/types/span.h"

#include "maxminddb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpMaxmindLookupFilter {

class IpInput
{
public:
  virtual ~IpInput() = default;
  virtual absl::string_view ip_str(const Http::HeaderMap&) const = 0;
};

class MMDBData {
public:
  MMDBData(const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config::MMDBData& config);
  MMDBData(MMDBData&&) = default;

  const std::string& out_metadata_key() const { return out_metadata_key_; }
  absl::Span<const std::string> path() const { return path_; }

private:
  std::string out_metadata_key_;
  absl::InlinedVector<std::string, 2> path_;
};

class MMDBLookups {
public:
  MMDBLookups(const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config::MMDBLookups& config);
  MMDBLookups(MMDBLookups&&) = default;

  ~MMDBLookups() {
    MMDB_close(&db_);
  }

  MMDB_s const* mmdb() const { return &db_; }
  absl::Span<const MMDBData> data() const { return data_; }

private:
  MMDB_s db_;
  absl::InlinedVector<MMDBData, 2> data_;
};

class Config : public ::Envoy::Router::RouteSpecificFilterConfig,
               public Logger::Loggable<Logger::Id::config> {
public:
  Config(const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config& config,
         bool per_route = false);

  const std::string& out_metadata_namespace() const { return out_metadata_namespace_; }
  absl::Span<const MMDBLookups> dbs() const { return dbs_; }

  IpInput const& ip_input() const { return *ip_input_; }

private:
  std::string out_metadata_namespace_;
  std::unique_ptr<IpInput> ip_input_;
  absl::InlinedVector<MMDBLookups, 2> dbs_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * Header-To-Metadata examines request/response headers and either copies or
 * moves the values into request metadata based on configuration information.
 */
class IpMaxmindLookupFilter : public Http::StreamFilter,
                               public Logger::Loggable<Logger::Id::filter> {
public:
  IpMaxmindLookupFilter(const ConfigSharedPtr config);
  ~IpMaxmindLookupFilter() override;

  // Http::StreamFilterBase
  void onDestroy() override {}

  // StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

  // StreamEncoderFilter
  Http::FilterHeadersStatus encode100ContinueHeaders(Http::ResponseHeaderMap&) override {
    return Http::FilterHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers, bool) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override;

private:
  void process(const Http::HeaderMap& headers, envoy::config::core::v3::Metadata& metadata);
  const ConfigSharedPtr config_;

  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{};
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{};
};

} // namespace IpMaxmindLookupFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
