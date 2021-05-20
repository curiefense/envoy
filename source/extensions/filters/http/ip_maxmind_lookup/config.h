#pragma once

#include "envoy/extensions/filters/http/ip_maxmind_lookup/v3/ip_maxmind_lookup.pb.h"
#include "envoy/extensions/filters/http/ip_maxmind_lookup/v3/ip_maxmind_lookup.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpMaxmindLookupFilter {

/**
 * Config registration for the header-to-metadata filter. @see NamedHttpFilterConfigFactory.
 */
class IpMaxmindLookupConfig
    : public Common::FactoryBase<envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config> {
public:
  IpMaxmindLookupConfig() : FactoryBase(HttpFilterNames::get().IpMaxmindLookup) {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
  Router::RouteSpecificFilterConfigConstSharedPtr createRouteSpecificFilterConfigTyped(
      const envoy::extensions::filters::http::ip_maxmind_lookup::v3::Config& config,
      Server::Configuration::ServerFactoryContext&, ProtobufMessage::ValidationVisitor&) override;
};

} // namespace IpMaxmindLookupFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
