#pragma once
#include <regex>
#include <ostream>

#include "absl/types/optional.h"
#include "envoy/extensions/filters/http/waf/v3/waf.pb.h"
#include "extensions/filters/http/waf/ip_interval_set.h"
#include "common/network/cidr_range.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {

struct RequestParameters;

namespace Rules {

struct Rule {
  enum class Kind : uint8_t {
    NOT,
    OR,
    AND,
    CIDRRange,
    OptimizedCIDRRanges,
    Path,
    Query,
    Method,
    URI,
    Args,
    Cookies,
    Headers
  };

  virtual ~Rule() = default;

  Kind kind() const { return K_; }

protected:
  Rule(Kind K) : K_(K) {}

private:
  const Kind K_;
};

using RulePtr = std::unique_ptr<Rule>;

struct UnaryRule : public Rule {
  UnaryRule(Kind K, RulePtr rule) : Rule(K), rule_(std::move(rule)) {}

  ~UnaryRule() override = default;

  Rule const& rule() const { return *rule_; }
  RulePtr& mutable_rule() { return rule_; }

private:
  RulePtr rule_;
};

struct NOTRule : public UnaryRule {
  NOTRule(RulePtr Rule) : UnaryRule(Kind::NOT, std::move(Rule)) {}
};

struct NaryRules : public Rule {
  NaryRules(Kind K) : Rule(K) {}

  ~NaryRules() override = default;

  void add(RulePtr rule);
  void reserve(size_t n) { rules_.reserve(n); }
  auto const& rules() const { return rules_; }
  auto& mutable_rules() { return rules_; }
  bool empty() const { return rules_.empty(); }

private:
  std::vector<RulePtr> rules_;
};

struct ORRules : public NaryRules {
  ORRules() : NaryRules(Kind::OR) {}
};

struct ANDRules : public NaryRules {
  ANDRules() : NaryRules(Kind::AND) {}
};

struct CIDRRangeRule : public Rule {
  CIDRRangeRule(Network::Address::CidrRange cidr) : Rule(Kind::CIDRRange), cidr_(std::move(cidr)) {}

  Network::Address::CidrRange const& range() const { return cidr_; }

private:
  Network::Address::CidrRange cidr_;
};

struct OptimizedCIDRRangesRule : public Rule {
  OptimizedCIDRRangesRule() : Rule(Kind::OptimizedCIDRRanges) {}

  IPIntervalSet const& intervals() const { return intervals_; }
  IPIntervalSet& mutable_intervals() { return intervals_; }

  bool contains(Network::Address::Instance const& addr) const { return intervals_.contains(addr); }

private:
  IPIntervalSet intervals_;
};

struct RegexRule : public Rule {
  RegexRule(Kind K, absl::string_view pattern);

  absl::optional<std::regex> const& re() const { return re_; }
  absl::string_view pattern() const { return pattern_; }

  virtual const char* name() const = 0;

private:
  absl::optional<std::regex> re_;
  std::string pattern_;
};

#define DEF_REGEX_RULE(ClsName, Name)                                                              \
  struct ClsName : public RegexRule {                                                              \
    ClsName(absl::string_view pattern) : RegexRule(Kind::Name, pattern) {}                         \
    const char* name() const override { return #Name; }                                            \
  };

DEF_REGEX_RULE(PathRule, Path)
DEF_REGEX_RULE(QueryRule, Query)
DEF_REGEX_RULE(MethodRule, Method)
DEF_REGEX_RULE(URIRule, URI)

#undef DEF_REGEX_RULE

struct MapRule : public RegexRule {
  MapRule(Kind K, absl::string_view key, absl::string_view pattern)
      : RegexRule(K, pattern), key_(key) {}

  absl::string_view key() const { return key_; }

private:
  std::string key_;
};

#define DEF_MAP_RULE(ClsName, Name)                                                                \
  struct ClsName : public MapRule {                                                                \
    ClsName(absl::string_view key, absl::string_view pattern)                                      \
        : MapRule(Kind::Name, key, pattern) {}                                                     \
    const char* name() const override { return #Name; }                                            \
  };

DEF_MAP_RULE(ArgsRule, Args)
DEF_MAP_RULE(CookiesRule, Cookies)
DEF_MAP_RULE(HeadersRule, Headers)

#undef DEF_MAP_RULE

// Optimizer
void optimize(RulePtr& R);

// Evaluator
bool eval(Rule const& R, RequestParameters const& params);

// Printer
void print(Rule const& R, std::ostream& os);

std::unique_ptr<Rule>
ruleFromProto(envoy::extensions::filters::http::waf::v3::WAFRuleEntry const& entry);

std::unique_ptr<Rule> ruleFromProto(envoy::extensions::filters::http::waf::v3::WAFRule const& rule);

} // namespace Rules
} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
