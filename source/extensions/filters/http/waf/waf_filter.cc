#include <string>

// For inet_aton
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "absl/types/optional.h"
#include "extensions/filters/http/waf/waf_filter.h"
#include "extensions/filters/http/well_known_names.h"
#include "envoy/config/core/v3/base.pb.h"
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

#ifdef _MSC_VER
uint32_t bswap32(uint32_t v) {
  static_assert(sizeof(uint32_t) == sizeof(unsigned long), "unsigned long isn't 32-bit wide!");
  return _byteswap_ulong(v);
}
#else
uint32_t bswap32(uint32_t v) {
  return __builtin_bswap32(v);
}
#endif

} // namespace

struct RequestParameters {
  using HeadersParamsTy = std::vector<std::pair<absl::string_view, absl::string_view>>;
  using CookiesParamsTy = HeadersParamsTy;

  RequestParameters(RequestParameters const&) = default;
  RequestParameters(RequestParameters&&) = default;

  static RequestParameters fromHeaders(Http::RequestHeaderMap const& headers);

  HeadersParamsTy const& headers() const { return headers_; }
  HeadersParamsTy const& cookies() const { return cookies_; }
  Http::Utility::QueryParams const& decoded_query() const { return decoded_query_; }
  absl::string_view raw_query() const { return raw_query_; }

private:
  RequestParameters() = default;

  HeadersParamsTy headers_;
  CookiesParamsTy cookies_;
  Http::Utility::QueryParams decoded_query_;
  absl::string_view raw_query_;
};

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

RequestParameters RequestParameters::fromHeaders(Http::RequestHeaderMap const& headers_map) {
  RequestParameters ret;
  // Parse query
  if (auto* path = headers_map.Path()) {
    absl::string_view query = Http::Utility::findQueryStringStart(path->value());
    if (!query.empty()) {
      ret.raw_query_ = query;
      ret.decoded_query_ = Http::Utility::parseAndDecodeQueryString(query);
    }
  }

  // Parse headers & cookies
  ret.headers_.reserve(headers_map.size());
  headers_map.iterate([&ret](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    const auto& key = header.key();
    const auto val = header.value().getStringView();
    if (key == Http::Headers::get().Cookie.get()) {
      auto& cookies = ret.cookies_;
      parseCookie(val, [&cookies](absl::string_view key, absl::string_view value) {
        cookies.emplace_back(key, value);
      });
      // TODO: should we save the original "Cookie" header? (for now, we do)
    }
    absl::string_view keyv = key.getStringView();
    if (!keyv.empty() && keyv.front() == ':') {
      return Http::HeaderMap::Iterate::Continue;
    }
    ret.headers_.emplace_back(keyv, val);
    return Http::HeaderMap::Iterate::Continue;
  });
  return ret;
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

static ProtobufWkt::Struct createRequestMetadata(WAFFilterResult fres,
                                                 RequestParameters const& params,
                                                 Http::RequestHeaderMap const& headers,
                                                 const WAFFilterConfigPerRoute* route_config) {
  ProtobufWkt::Struct value;
  auto& fields = *value.mutable_fields();
  auto& request_info = *fields["request.info"].mutable_struct_value()->mutable_fields();

  //
  // First, create the "attrs" metadata
  //

  auto& ri_attrs = *request_info["attrs"].mutable_struct_value()->mutable_fields();
  // Copy all route config into attrs
  uint32_t trusted_hops = route_config ? route_config->xff_trusted_hops() : 1U;
  trusted_hops = std::max(trusted_hops, 1U);
  ri_attrs["xff_trusted_hops"].set_number_value(trusted_hops);

  // Compute client address. This is based on xff_trusted_hops, which gives the
  // number of hops we trust in the X-Forwaded-For header. xff_trusted_hops is
  // set as a route metadata in the envoy configuration.
  {
    absl::string_view xff;
    if (auto* xffh = headers.ForwardedFor()) {
      xff = xffh->value().getStringView();
    }
    const absl::string_view client_ip = getClientIP(xff, trusted_hops);
    *ri_attrs["ip"].mutable_string_value() = client_ip;
    struct in_addr intaddr;
    // AG: I couldn't find any "IPv4 string to integer" string-view based
    // conversion function in envoy. The one I found also supports IPv6, and in
    // the end calls inet_pton. It's indeed a bit of shame of having to create
    // that std::string here.
    if (inet_aton(std::string{client_ip}.c_str(), &intaddr) == 0) {
      intaddr.s_addr = 0;
    } else {
      // inet_aton converts in network-order (that is big endian). We want the
      // number in little endian.
      intaddr.s_addr = bswap32(intaddr.s_addr);
    }
    ri_attrs["ipnum"].set_number_value(intaddr.s_addr);
  }

  // Add a tag if we have a filtering error
  if (fres.hasError()) {
    auto& tags = *ri_attrs["tags"].mutable_struct_value()->mutable_fields();
    const auto it_end = fres.signsEnd();
    for (auto it = fres.signsBegin(); it != it_end; ++it) {
      const std::string tagname = "wafsig:" + std::to_string(it->get().id);
      tags[tagname].set_number_value(1);
    }
  }

  // And finally set remaining attributes
  if (auto* path = headers.Path()) {
    const auto& pathv = path->value();
    *ri_attrs["path"].mutable_string_value() = pathv.getStringView();
  }
  if (auto* method = headers.Method()) {
    *ri_attrs["method"].mutable_string_value() = method->value().getStringView();
  }
  *ri_attrs["query"].mutable_string_value() = params.raw_query();

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
  for (auto const& q : params.decoded_query()) {
    *ri_args[q.first].mutable_string_value() = q.second;
  }
  return value;
}

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
  FilterContainer(params.decoded_query());
}

const WAFFilterConfigPerRoute* WAFFilter::getRouteConfig() const {
  return Http::Utility::resolveMostSpecificPerFilterConfig<WAFFilterConfigPerRoute>(
      HttpFilterNames::get().WAF, decoder_callbacks_->route());
}

Http::FilterHeadersStatus WAFFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  const RequestParameters params = RequestParameters::fromHeaders(headers);
  WAFFilterResult fres;
  filterParams(fres, params);

  const WAFFilterConfigPerRoute* route_config = getRouteConfig();

  // Add metadata (used for logs)
  const auto metadata = createRequestMetadata(fres, params, headers, route_config);
  decoder_callbacks_->streamInfo().setDynamicMetadata(
      Extensions::HttpFilters::HttpFilterNames::get().WAF, metadata);

  if (fres.hasError()) {
    abortWithStatus(Http::Code::NotAcceptable, fres.signsBegin()->get().msg);
    return Http::FilterHeadersStatus::StopIteration;
  }

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus WAFFilter::decodeData(Buffer::Instance&, bool) {
  return Http::FilterDataStatus::Continue;
}

void WAFFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
