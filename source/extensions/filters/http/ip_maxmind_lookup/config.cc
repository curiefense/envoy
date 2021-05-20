#include <string>

#include "envoy/extensions/filters/http/ip_maxmind_lookup/v3/ip_maxmind_lookup.pb.h"
#include "envoy/extensions/filters/http/ip_maxmind_lookup/v3/ip_maxmind_lookup.pb.validate.h"
#include "envoy/registry/registry.h"

#include "source/common/protobuf/utility.h"

#include "source/extensions/filters/http/ip_maxmind_lookup/config.h"
#include "source/extensions/filters/http/ip_maxmind_lookup/ip_maxmind_lookup_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpMaxmindLookupFilter {

Http::FilterFactoryCb IpMaxmindLookupConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config& proto_config,
    const std::string&, Server::Configuration::FactoryContext&) {
  ConfigSharedPtr filter_config(std::make_shared<Config>(proto_config, false));

  return [filter_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(
        Http::StreamFilterSharedPtr{new IpMaxmindLookupFilter{filter_config}});
  };
}

Router::RouteSpecificFilterConfigConstSharedPtr
IpMaxmindLookupConfig::createRouteSpecificFilterConfigTyped(
    const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config& config,
    Server::Configuration::ServerFactoryContext&, ProtobufMessage::ValidationVisitor&) {
  return std::make_shared<const Config>(config, true);
}

/**
 * Static registration for the header-to-metadata filter. @see RegisterFactory.
 */
REGISTER_FACTORY(IpMaxmindLookupConfig, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace IpMaxmindLookupFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
