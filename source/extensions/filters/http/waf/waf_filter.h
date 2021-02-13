#pragma once

#include <string>
#include <regex>
#include <vector>
#include <functional>
#include <unordered_map>

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
namespace Rules {
struct Rule;
}

class WAFFilterConfigPerRoute;

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
  using HeadersParamsTy = std::unordered_multimap<absl::string_view, absl::string_view>;
  using CookiesParamsTy = HeadersParamsTy;
  using ArgsParamsTy = std::unordered_map<std::string, std::string>;

  RequestParameters() = default;
  RequestParameters(RequestParameters&&) = default;
  RequestParameters& operator=(RequestParameters&&) = default;

  static RequestParameters create(Http::RequestHeaderMap const& headers_map,
                                  const WAFFilterConfigPerRoute* route_config);

  HeadersParamsTy const& headers() const { return headers_; }
  CookiesParamsTy const& cookies() const { return cookies_; }
  ArgsParamsTy const& args() const { return args_; }
  ArgsParamsTy& mutable_args() { return args_; }
  absl::string_view raw_query() const { return raw_query_; }
  absl::string_view content_type() const { return content_type_; }
  absl::string_view path() const { return path_; }
  absl::string_view method() const { return method_; }
  absl::string_view forwaded_for() const { return forwaded_for_; }
  absl::string_view client_ip_str() const { return client_ip_str_; }
  absl::string_view uri() const { return uri_; }
  Network::Address::Instance const& client_ip() const { return *client_ip_; }
  void setHugeFormData() { huge_form_data_ = true; }
  bool hugeFormData() const { return huge_form_data_; }

  bool hasFormUrlEncodedData() const;
  bool hasFormData() const;
  unsigned trusted_hops() const { return trusted_hops_; }

private:
  HeadersParamsTy headers_;
  CookiesParamsTy cookies_;
  ArgsParamsTy args_;
  absl::string_view raw_query_;
  absl::string_view content_type_;
  absl::string_view path_;
  absl::string_view method_;
  absl::string_view forwaded_for_;
  absl::string_view client_ip_str_;
  std::string uri_;
  Network::Address::InstanceConstSharedPtr client_ip_;
  bool huge_form_data_ = false;
  unsigned trusted_hops_;
};

using WAFSignaturesTy = std::vector<WAFSignature>;

struct RequestParameters;

class WAFTagRule {
public:
  WAFTagRule(const envoy::extensions::filters::http::waf::v3::WAFTagRule& tagrule);
  WAFTagRule(WAFTagRule&&) = default;
  WAFTagRule& operator=(WAFTagRule&&) = default;

  ~WAFTagRule();

  absl::string_view id() const { return id_; }
  absl::string_view name() const { return name_; }
  Rules::Rule const& rule() const { return *rule_; }
  auto const& tags() const { return tags_; }

private:
  std::string id_;
  std::string name_;
  std::vector<std::string> tags_;
  std::unique_ptr<Rules::Rule> rule_;
};

using WAFTagRulesTy = std::vector<WAFTagRule>;

class WAFFilterConfig {
public:
  WAFFilterConfig(const envoy::extensions::filters::http::waf::v3::WAF& proto_config);

  auto const& signatures() const { return signatures_; }
  auto const& tagrules() const { return tagrules_; }

private:
  WAFSignaturesTy signatures_;
  WAFTagRulesTy tagrules_;
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
  void addMatchingTagRule(WAFTagRule const& rule) { tagrules_.push_back(rule); }

  bool hasError() const { return !signs_.empty(); }
  absl::string_view errorMsg() const { return signs_.begin()->get().msg; }

  auto const& signs() const { return signs_; }
  auto const& tagrules() const { return tagrules_; }

private:
  std::vector<std::reference_wrapper<WAFSignature const>> signs_;
  std::vector<std::reference_wrapper<WAFTagRule const>> tagrules_;
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
  WAFTagRulesTy const& tagrules() const;

  RequestParameters params_;
};

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
