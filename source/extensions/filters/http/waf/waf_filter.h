#pragma once

#include <string>
#include <regex>
#include <vector>
#include <functional>

#include "absl/strings/string_view.h"
#include "extensions/filters/http/common/pass_through_filter.h"
#include "envoy/extensions/filters/http/waf/v3/waf.pb.h"
#include "common/common/regex.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {

struct WAFSignature {
  static WAFSignature
  fromProtoBuf(envoy::extensions::filters::http::waf::v3::WAFSignature const& pbsign);

  uint32_t id;
  std::string name;
  std::string msg;
  std::regex operand;
  int32_t severity;
  int32_t certainity;
  envoy::extensions::filters::http::waf::v3::WAFCategory category;
};

using WAFSignaturesTy = std::vector<WAFSignature>;

struct RequestParameters;

class WAFFilterConfig {
public:
  WAFFilterConfig(const envoy::extensions::filters::http::waf::v3::WAF& proto_config);

  auto const& signatures() const { return signatures_; }

private:
  WAFSignaturesTy signatures_;
};

using WAFFilterConfigSharedPtr = std::shared_ptr<WAFFilterConfig>;

struct WAFFilterResult {
  // Has no error when constructed
  WAFFilterResult() = default;

  void addError(WAFSignature const& sign) { signs_.push_back(sign); }

  bool hasError() const { return !signs_.empty(); }

  auto signsBegin() const { return signs_.begin(); }
  auto signsEnd() const { return signs_.end(); }

private:
  std::vector<std::reference_wrapper<WAFSignature const>> signs_;
};

class WAFFilter : public Http::PassThroughDecoderFilter {
public:
  WAFFilter(WAFFilterConfigSharedPtr);
  ~WAFFilter() override;

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks&) override;

private:
  void abortWithStatus(Http::Code http_status_code, const absl::string_view msg);
  void filterParams(WAFFilterResult& fres, RequestParameters const& params) const;
  void filterString(WAFFilterResult& fres, absl::string_view str) const;

  const ProtobufWkt::Struct& getRouteMetadata() const;

  const WAFFilterConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;

  WAFSignaturesTy const& signatures() const;
};

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
