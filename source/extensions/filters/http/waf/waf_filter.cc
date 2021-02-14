#include <string>

// For inet_aton
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "absl/types/optional.h"
#include "absl/strings/str_format.h"
#include "extensions/filters/http/waf/waf_filter.h"
#include "extensions/filters/http/waf/rules.h"
#include "extensions/filters/http/well_known_names.h"
#include "envoy/config/core/v3/base.pb.h"
#include "common/network/utility.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "common/protobuf/message_validator_impl.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {

namespace {
struct RcDetailsValues {
  const std::string FaultAbort = "waf_filter_abort";
};
using RcDetails = ConstSingleton<RcDetailsValues>;

} // namespace

// Based on Http::Utility::parseCookieValue
template <class Func> static void parseCookie(absl::string_view value, Func keyvalue_func) {
  // Split the cookie header into individual cookies.
  for (const auto& s : StringUtil::splitToken(value, ";")) {
    // Find the key part of the cookie (i.e. the name of the cookie).
    size_t first_non_space = s.find_first_not_of(' ');
    size_t equals_index = s.find('=');
    if (equals_index == absl::string_view::npos) {
      // The cookie is malformed if it does not have an `=`. Continue
      // checking other cookies in this header.
      continue;
    }
    const absl::string_view k = s.substr(first_non_space, equals_index - first_non_space);
    absl::string_view v = s.substr(equals_index + 1, s.size() - 1);

    // Cookie values may be wrapped in double quotes.
    // https://tools.ietf.org/html/rfc6265#section-4.1.1
    if (v.size() >= 2 && v.back() == '"' && v[0] == '"') {
      v = v.substr(1, v.size() - 2);
    }
    keyvalue_func(k, v);
  }
}

static absl::string_view getClientIP(const absl::string_view xff, const unsigned trusted_hops) {
  // Insipired from
  // https://github.com/curiefense/curiefense/blob/83513f244b3b0424158f1d2320915924d1341831/curiefense/curieproxy/lua/utils.lua#L120-L132
  assert(trusted_hops >= 1);
  const std::vector<absl::string_view> ips =
      absl::StrSplit(absl::StripAsciiWhitespace(xff), absl::ByChar(','), absl::SkipWhitespace());
  const auto nips = ips.size();
  if (nips == 0) {
    return "";
  }
  absl::string_view ret;
  if (nips == 1) {
    ret = ips[0];
  } else if (nips <= trusted_hops) {
    // Take the last one
    ret = ips.back();
  } else {
    // Take the "trusted_hops"-nth from the right
    ret = *(ips.rbegin() + trusted_hops);
  }
  return absl::StripAsciiWhitespace(ret);
}

RequestParameters RequestParameters::create(Http::RequestHeaderMap const& headers_map,
                                            const WAFFilterConfigPerRoute* route_config) {
  RequestParameters ret;
  // Parse path & query
  if (auto* path = headers_map.Path()) {
    absl::string_view query = Http::Utility::findQueryStringStart(path->value());
    if (!query.empty()) {
      ret.raw_query_ = query;
      const auto decoded_query = Http::Utility::parseAndDecodeQueryString(query);
      ret.args_.insert(decoded_query.begin(), decoded_query.end());
    }

    ret.path_ = path->value().getStringView();
    // Cf.
    // https://github.com/curiefense/curiefense/blob/e62af2a6e5bfb2eab308d856693756b77343c983/curiefense/curieproxy/lua/utils.lua#L88
    ret.uri_ = Http::Utility::PercentEncoding::decode(ret.path_);
  }

  if (auto* content_type = headers_map.ContentType()) {
    ret.content_type_ = content_type->value().getStringView();
  }

  if (auto* method = headers_map.Method()) {
    ret.method_ = method->value().getStringView();
  }

  if (auto* xff = headers_map.ForwardedFor()) {
    ret.forwaded_for_ = xff->value().getStringView();
  }

  uint32_t trusted_hops = route_config ? route_config->xff_trusted_hops() : 1U;
  trusted_hops = std::max(trusted_hops, 1U);
  ret.trusted_hops_ = trusted_hops;
  absl::string_view client_ip_str = getClientIP(ret.forwaded_for(), trusted_hops);
  if (client_ip_str.empty()) {
    client_ip_str = "0.0.0.0";
  }
  ret.client_ip_str_ = client_ip_str;
  ret.client_ip_ = Network::Utility::parseInternetAddress(std::string{client_ip_str});

  // Parse headers & cookies
  ret.headers_.reserve(headers_map.size());
  headers_map.iterate([&ret](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    const auto& key = header.key();
    const auto val = header.value().getStringView();
    if (key == Http::Headers::get().Cookie.get()) {
      auto& cookies = ret.cookies_;
      parseCookie(val, [&cookies](absl::string_view key, absl::string_view value) {
        cookies.emplace(key, value);
      });
      // TODO: should we save the original "Cookie" header? (for now, we do)
    }
    absl::string_view keyv = key.getStringView();
    if (!keyv.empty() && keyv.front() == ':') {
      return Http::HeaderMap::Iterate::Continue;
    }
    ret.headers_.emplace(keyv, val);
    return Http::HeaderMap::Iterate::Continue;
  });
  return ret;
}

bool RequestParameters::hasFormUrlEncodedData() const {
  return absl::StartsWith(content_type(), Http::Headers::get().ContentTypeValues.FormUrlEncoded);
}

bool RequestParameters::hasFormData() const { return hasFormUrlEncodedData(); }

static ProtobufWkt::Struct createRequestMetadata(WAFFilterResult fres,
                                                 RequestParameters const& params) {
  ProtobufWkt::Struct value;
  auto& fields = *value.mutable_fields();
  auto& request_info = *fields["request.info"].mutable_struct_value()->mutable_fields();

  //
  // First, create the "attrs" metadata
  //

  auto& ri_attrs = *request_info["attrs"].mutable_struct_value()->mutable_fields();
  // Copy all route config into attrs
  ri_attrs["xff_trusted_hops"].set_number_value(params.trusted_hops());

  // Compute client address. This is based on xff_trusted_hops, which gives the
  // number of hops we trust in the X-Forwaded-For header. xff_trusted_hops is
  // set as a route metadata in the envoy configuration.
  {
    *ri_attrs["ip"].mutable_string_value() = params.client_ip_str();
    auto const* ip = params.client_ip().ip();
    if (auto const* ipv4 = ip->ipv4()) {
      // Envoy returns the address in network-order.
      ri_attrs["ipnum"].set_number_value(ntohl(ipv4->address()));
    } else {
      auto const* ipv6 = ip->ipv6();
      assert(ipv6 && "ip should be v4 or v6");
      *ri_attrs["ipnum"].mutable_string_value() = absl::StrFormat("%u", ipv6->address());
    }
  }

  // Add a tag if we have a filtering error
  if (fres.hasError()) {
    auto& tags = *ri_attrs["tags"].mutable_struct_value()->mutable_fields();
    for (auto const& sign : fres.signs()) {
      const std::string tagname = "wafsig:" + std::to_string(sign.get().id);
      tags[tagname].set_number_value(1);
    }
    for (auto const& tagrule : fres.tagrules()) {
      for (const absl::string_view tag : tagrule.get().tags()) {
        const std::string tagname = std::string{"wafrule:"} + std::string{tag};
        tags[tagname].set_number_value(1);
      }
    }
  }

  // And finally set remaining attributes
  *ri_attrs["path"].mutable_string_value() = params.path();
  *ri_attrs["method"].mutable_string_value() = params.method();
  *ri_attrs["query"].mutable_string_value() = params.raw_query();
  *ri_attrs["uri"].mutable_string_value() = params.uri();

  //
  // Now, add headers, cookies and args metadata
  //

  // TODO if a performance issue: we could directly generate protobuf
  // structures in RequestParameters to avoid yet another conversion.
  auto& ri_headers = *request_info["headers"].mutable_struct_value()->mutable_fields();
  for (auto const& h : params.headers()) {
    *ri_headers[h.first].mutable_string_value() = h.second;
  }

  auto& ri_cookies = *request_info["cookies"].mutable_struct_value()->mutable_fields();
  for (auto const& c : params.cookies()) {
    *ri_cookies[c.first].mutable_string_value() = c.second;
  }

  auto& ri_args = *request_info["args"].mutable_struct_value()->mutable_fields();
  for (auto const& q : params.args()) {
    *ri_args[q.first].mutable_string_value() = q.second;
  }
  return value;
}

WAFTagRule::WAFTagRule(const envoy::extensions::filters::http::waf::v3::WAFTagRule& tagrule)
    : id_(tagrule.id()), name_(tagrule.name()), rule_(Rules::ruleFromProto(tagrule.rule())) {
  if (rule_) {
    Rules::optimize(rule_);
  }
  auto const& tags = tagrule.tags();
  tags_.reserve(tags.size());
  std::copy(tags.begin(), tags.end(), std::back_inserter(tags_));
}

WAFTagRule::~WAFTagRule() = default;

WAFFilterConfigPerRoute::WAFFilterConfigPerRoute(
    const envoy::extensions::filters::http::waf::v3::WAFPerRoute& config,
    Server::Configuration::ServerFactoryContext&)
    : xff_trusted_hops_(config.xff_trusted_hops()) {}

WAFFilterConfig::WAFFilterConfig(
    const envoy::extensions::filters::http::waf::v3::WAF& proto_config) {
  const auto& pbsigns = proto_config.signatures();
  signatures_.reserve(pbsigns.size());
  std::transform(pbsigns.begin(), pbsigns.end(), std::back_inserter(signatures_),
                 WAFSignature::fromProtoBuf);

  const auto& tagrules = proto_config.tagrules();
  tagrules_.reserve(tagrules.size());
  std::copy_if(tagrules.begin(), tagrules.end(), std::back_inserter(tagrules_),
               [](auto const& tagrule) { return tagrule.active(); });
}

WAFSignature
WAFSignature::fromProtoBuf(envoy::extensions::filters::http::waf::v3::WAFSignature const& pbsign) {
  WAFSignature Ret;
  Ret.id = pbsign.id();
  Ret.name = pbsign.name();
  Ret.msg = pbsign.msg();
  Ret.operand = Regex::Utility::parseStdRegex(pbsign.operand());
  Ret.severity = pbsign.severity();
  Ret.certainity = pbsign.certainity();
  Ret.category = pbsign.category();
  return Ret;
}

WAFFilter::WAFFilter(WAFFilterConfigSharedPtr config) : config_(config) {}

WAFFilter::~WAFFilter() = default;

void WAFFilter::onDestroy() {}

WAFSignaturesTy const& WAFFilter::signatures() const { return config_->signatures(); }
WAFTagRulesTy const& WAFFilter::tagrules() const { return config_->tagrules(); }

void WAFFilter::abortWithStatus(Http::Code http_status_code, const absl::string_view msg) {
  decoder_callbacks_->sendLocalReply(http_status_code, msg, nullptr, absl::nullopt,
                                     RcDetails::get().FaultAbort);
}

void WAFFilter::filterString(WAFFilterResult& fres, absl::string_view str) const {
  std::cmatch m;
  for (auto& sign : signatures()) {
    if (std::regex_search(str.begin(), str.end(), m, sign.operand)) {
      fres.addError(sign);
    }
  }
}

void WAFFilter::filterParams(WAFFilterResult& fres, RequestParameters const& params) const {
  auto FilterContainer = [&](auto const& container) {
    for (auto const& h : container) {
      filterString(fres, h.second);
    }
  };
  FilterContainer(params.headers());
  FilterContainer(params.cookies());
  FilterContainer(params.args());

  // Apply tagging rules
  for (auto const& tagrule : tagrules()) {
    if (Rules::eval(tagrule.rule(), params)) {
      fres.addMatchingTagRule(tagrule);
    }
  }
}

const WAFFilterConfigPerRoute* WAFFilter::getRouteConfig() const {
  return Http::Utility::resolveMostSpecificPerFilterConfig<WAFFilterConfigPerRoute>(
      HttpFilterNames::get().WAF, decoder_callbacks_->route());
}

WAFFilterResult WAFFilter::finishFiltering() {
  WAFFilterResult fres;
  filterParams(fres, params_);

  const auto metadata = createRequestMetadata(fres, params_);
  decoder_callbacks_->streamInfo().setDynamicMetadata(
      Extensions::HttpFilters::HttpFilterNames::get().WAF, metadata);

  if (fres.hasError()) {
    abortWithStatus(Http::Code::NotAcceptable, fres.errorMsg());
  }
  return fres;
}

Http::FilterHeadersStatus WAFFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                   bool end_stream) {
  const WAFFilterConfigPerRoute* route_config = getRouteConfig();
  params_ = RequestParameters::create(headers, route_config);

  if (end_stream || !params_.hasFormData()) {
    return finishFiltering().hasError() ? Http::FilterHeadersStatus::StopIteration
                                        : Http::FilterHeadersStatus::Continue;
  }

  return Http::FilterHeadersStatus::Continue;
}

void WAFFilter::updateParamsWithUrlEncodedForm(Buffer::Instance& buf) {
  // TODO: plugin configuration variable
  if (buf.length() >= 10 * 1024 * 1024) {
    params_.setHugeFormData();
    return;
  }
  const std::string data = buf.toString();
  const auto decq = Http::Utility::parseFromBody(data);
  params_.mutable_args().insert(decq.begin(), decq.end());
}

Http::FilterDataStatus WAFFilter::decodeData(Buffer::Instance& buf, bool end_stream) {
  if (params_.hasFormUrlEncodedData()) {
    updateParamsWithUrlEncodedForm(buf);
  }
  if (end_stream) {
    return finishFiltering().hasError() ? Http::FilterDataStatus::StopIterationNoBuffer
                                        : Http::FilterDataStatus::Continue;
  }
  return Http::FilterDataStatus::Continue;
}

void WAFFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
