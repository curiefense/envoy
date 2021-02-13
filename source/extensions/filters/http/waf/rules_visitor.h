#pragma once

#include <cassert>
#include "extensions/filters/http/waf/rules.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {
namespace Rules {

// Visitor
template <class Impl, class ResultTy> struct ConstVisitor {
  ResultTy operator()(Rule const& R) { return visit(R); }
  ResultTy visit(Rule const& R) {
    switch (R.kind()) {
#define RULE_VISIT(K, Ty)                                                                          \
  case Rule::Kind::K:                                                                              \
    return static_cast<Impl*>(this)->visitRule(static_cast<Ty const&>(R));
      RULE_VISIT(NOT, NOTRule)
      RULE_VISIT(OR, ORRules)
      RULE_VISIT(AND, ANDRules)
      RULE_VISIT(CIDRRange, CIDRRangeRule)
      RULE_VISIT(Path, PathRule)
      RULE_VISIT(Query, QueryRule)
      RULE_VISIT(Method, MethodRule)
      RULE_VISIT(URI, URIRule)
      RULE_VISIT(Args, ArgsRule)
      RULE_VISIT(Headers, HeadersRule)
      RULE_VISIT(Cookies, CookiesRule)
#undef RULE_VISIT
    default:
      break;
    }
    assert(false);
  }
};

} // namespace Rules
} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
