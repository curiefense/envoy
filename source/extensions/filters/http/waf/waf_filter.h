#pragma once

#include <string>
#include <regex>
#include <vector>
#include <functional>

#include "absl/strings/string_view.h"
#include "common/http/utility.h"
#include "common/common/regex.h"
#include "envoy/extensions/filters/http/waf/v3/waf.pb.h"
#include "envoy/server/factory_context.h"
#include "extensions/filters/http/common/pass_through_filter.h"

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

struct RequestParameters {
  using HeadersParamsTy = std::vector<std::pair<absl::string_view, absl::string_view>>;
  using CookiesParamsTy = HeadersParamsTy;

  RequestParameters() = default;
  RequestParameters(RequestParameters const&) = default;
  RequestParameters(RequestParameters&&) = default;
  RequestParameters& operator=(RequestParameters const&) = default;
  RequestParameters& operator=(RequestParameters&&) = default;

  static RequestParameters fromHeaders(Http::RequestHeaderMap const& headers);

  HeadersParamsTy const& headers() const { return headers_; }
  CookiesParamsTy const& cookies() const { return cookies_; }
  Http::Utility::QueryParams const& decoded_query() const { return decoded_query_; }
  Http::Utility::QueryParams const& decoded_form_data() const { return decoded_form_data_; }
  Http::Utility::QueryParams& mutable_decoded_form_data() { return decoded_form_data_; }
  absl::string_view raw_query() const { return raw_query_; }
  absl::string_view content_type() const { return content_type_; }
  absl::string_view path() const { return path_; }
  absl::string_view method() const { return method_; }
  absl::string_view query() const { return query_; }
  absl::string_view forwaded_for() const { return forwaded_for_; }
  void setHugeFormData() { huge_form_data_ = true; }
  bool hugeFormData() const { return huge_form_data_; }

  bool hasFormUrlEncodedData() const;
  bool hasFormData() const;

private:
  HeadersParamsTy headers_;
  CookiesParamsTy cookies_;
  Http::Utility::QueryParams decoded_query_;
  Http::Utility::QueryParams decoded_form_data_;
  absl::string_view raw_query_;
  absl::string_view content_type_;
  absl::string_view path_;
  absl::string_view method_;
  absl::string_view query_;
  absl::string_view forwaded_for_;
  bool huge_form_data_ = false;
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

class WAFFilterConfigPerRoute : public Router::RouteSpecificFilterConfig {
public:
  WAFFilterConfigPerRoute(const envoy::extensions::filters::http::waf::v3::WAFPerRoute& config,
                          Server::Configuration::ServerFactoryContext& context);

  ~WAFFilterConfigPerRoute() override = default;

  uint32_t xff_trusted_hops() const { return xff_trusted_hops_; }

private:
  uint32_t xff_trusted_hops_;
};

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

  void onDestroy() override;

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks&) override;

private:
  void abortWithStatus(Http::Code http_status_code, const absl::string_view msg);
  void filterParams(WAFFilterResult& fres, RequestParameters const& params) const;
  void filterString(WAFFilterResult& fres, absl::string_view str) const;

  const WAFFilterConfigPerRoute* getRouteConfig() const;

  void updateParamsWithUrlEncodedForm(Buffer::Instance& buf);
  WAFFilterResult finishFiltering();

  const WAFFilterConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;

  WAFSignaturesTy const& signatures() const;
  RequestParameters params_;
};

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
