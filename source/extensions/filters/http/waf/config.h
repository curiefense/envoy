#pragma once

#include "envoy/extensions/filters/http/waf/v3/waf.pb.h"
#include "envoy/extensions/filters/http/waf/v3/waf.pb.validate.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {

class WAFFilterFactory
    : public Common::FactoryBase<envoy::extensions::filters::http::waf::v3::WAF> {
public:
  WAFFilterFactory() : FactoryBase(HttpFilterNames::get().WAF) {}

private:
  Http::FilterFactoryCb
  createFilterFactoryFromProtoTyped(const envoy::extensions::filters::http::waf::v3::WAF& config,
                                    const std::string& stats_prefix,
                                    Server::Configuration::FactoryContext& context) override;
};

DECLARE_FACTORY(WAFFilterFactory);

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
