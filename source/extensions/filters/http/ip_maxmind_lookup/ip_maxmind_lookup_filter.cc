#include "envoy/extensions/filters/http/ip_maxmind_lookup/v3/ip_maxmind_lookup.pb.h"

#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "source/extensions/filters/http/ip_maxmind_lookup/ip_maxmind_lookup_filter.h"
#include "source/extensions/filters/http/well_known_names.h"

#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"

#include <tuple>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpMaxmindLookupFilter {

namespace {
class HeaderIpInput: public IpInput
{
public:
  enum RequestExtractFrom {
    HEADERS,
    COOKIES
  };

  explicit HeaderIpInput(absl::string_view key):
    key_(std::string{key})
  { }

  explicit HeaderIpInput(std::string const& key):
    key_(key)
  { }

  ~HeaderIpInput() override = default;

  absl::string_view ip_str(const Http::HeaderMap& headers) const override {
    const auto vals = headers.get(key_);
    // TODO: what to do if we have multiple results? Take the first/last one as an option?
    if (vals.size() == 1) {
      return vals[0]->value().getStringView();
    }
    return {};
  }

private:
  Http::LowerCaseString key_;
};

absl::optional<ProtobufWkt::Value> mmdbEntryToPB(MMDB_entry_data_s const& data)
{
  if (!data.has_data) {
    return {};
  }
  switch (data.type) {
    case MMDB_DATA_TYPE_FLOAT:
      return ValueUtil::numberValue(data.float_value);
    case MMDB_DATA_TYPE_DOUBLE:
      return ValueUtil::numberValue(data.double_value);
    case MMDB_DATA_TYPE_UINT16:
      return ValueUtil::numberValue(data.uint16);
    case MMDB_DATA_TYPE_UINT32:
      return ValueUtil::numberValue(data.uint32);
    case MMDB_DATA_TYPE_INT32:
      return ValueUtil::numberValue(data.int32);
    case MMDB_DATA_TYPE_UINT64:
      return ValueUtil::numberValue(data.uint64);
    case MMDB_DATA_TYPE_BOOLEAN:
      return ValueUtil::numberValue(data.boolean);
    case MMDB_DATA_TYPE_UTF8_STRING:
      return ValueUtil::stringValue(std::string{data.utf8_string, data.data_size});
    case MMDB_DATA_TYPE_BYTES:
      // TODO
    default:
      break;
  }
  return {};
}

absl::optional<ProtobufWkt::Value> mmdbGetPbValue(MMDB_s const* db, absl::string_view ip, absl::Span<const std::string> path)
{
  absl::InlinedVector<const char*, 3> cpath;
  cpath.reserve(path.size()+1);
  auto it = std::transform(path.begin(), path.end(), std::back_inserter(cpath), [](const auto& s) { return s.c_str(); });
  *it = nullptr;

  // ip might be not null-terminated, thus we need to create a temporary std::string
  int gai_error, mmdb_error;
  MMDB_lookup_result_s res = MMDB_lookup_string(db, std::string{ip}.c_str(), &gai_error, &mmdb_error);
  if (gai_error != 0) {
    return {};
  }
  if (MMDB_SUCCESS != mmdb_error) {
    return {};
  }
  if (!res.found_entry) {
    return {};
  }
  MMDB_entry_data_s data;
  const int status = MMDB_aget_value(&res.entry, &data, &cpath[0]);
  if (status != MMDB_SUCCESS) {
    return {};
  }
  return mmdbEntryToPB(data);
}

} // anonymous

MMDBData::MMDBData(const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config::MMDBData& config)
{
  out_metadata_key_ = config.out_metadata_key();
  const auto& path = config.path();
  path_.reserve(path.size());
  std::copy(std::begin(path), std::end(path), std::back_inserter(path_));
}

MMDBLookups::MMDBLookups(const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config::MMDBLookups& config)
{
  const char* path = config.path().c_str();
  const int status = MMDB_open(path, MMDB_MODE_MMAP, &db_);
  if (status != MMDB_SUCCESS) {
    // TODO: explicit IO error (see https://github.com/maxmind/libmaxminddb/blob/main/doc/libmaxminddb.md#example)
    throw EnvoyException(fmt::format("Unable to open maxmind DB {}: {}", path, MMDB_strerror(status)));
  }
  const auto& pb_data = config.data();
  data_.reserve(pb_data.size());
  for (auto const& v: pb_data) {
    data_.emplace_back(v);
  }
}

Config::Config(const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config& config,
               const bool) {
  out_metadata_namespace_ = config.out_metadata_namespace();

  // Input
  ip_input_ = std::make_unique<HeaderIpInput>(config.request().header());

  // Databases
  const auto& pb_dbs = config.dbs();
  dbs_.reserve(pb_dbs.size());
  for (auto const& pb_db: pb_dbs) {
    dbs_.emplace_back(pb_db);
  }
}

IpMaxmindLookupFilter::IpMaxmindLookupFilter(const ConfigSharedPtr config) : config_(config) {}

IpMaxmindLookupFilter::~IpMaxmindLookupFilter() = default;

Http::FilterHeadersStatus IpMaxmindLookupFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                                bool) {
  process(headers, decoder_callbacks_->streamInfo().dynamicMetadata());
  return Http::FilterHeadersStatus::Continue;
}

void IpMaxmindLookupFilter::setDecoderFilterCallbacks(
    Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

Http::FilterHeadersStatus IpMaxmindLookupFilter::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                                bool) {
  process(headers, encoder_callbacks_->streamInfo().dynamicMetadata());
  return Http::FilterHeadersStatus::Continue;
}

void IpMaxmindLookupFilter::process(const Http::HeaderMap& headers, envoy::config::core::v3::Metadata& metadata)
{
  const absl::string_view ip = config_->ip_input().ip_str(headers);
  if (ip.empty()) {
    // TODO: have an option to stop / return an error?
    return; 
  }

  auto& mmetadata = *metadata.mutable_filter_metadata();
  auto& fields = *mmetadata[config_->out_metadata_namespace()].mutable_fields();

  for (const auto& db: config_->dbs()) {
    for (const auto& data: db.data()) {
      auto maybe_val = mmdbGetPbValue(db.mmdb(), ip, data.path());
      if (maybe_val) {
        fields[data.out_metadata_key()] = *maybe_val;
      }
    }
  }
}

void IpMaxmindLookupFilter::setEncoderFilterCallbacks(
    Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

} // namespace IpMaxmindLookupFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
