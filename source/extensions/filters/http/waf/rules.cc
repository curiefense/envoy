#include <ostream>
#include "extensions/filters/http/waf/waf_filter.h"
#include "extensions/filters/http/waf/rules.h"
#include "extensions/filters/http/waf/rules_visitor.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {
namespace Rules {

namespace WAFProto = envoy::extensions::filters::http::waf::v3;

// Objects
//

RegexRule::RegexRule(Kind K, absl::string_view pattern) : Rule(K), pattern_(pattern) {
  try {
    re_.emplace(std::string{pattern}, std::regex::optimize);
  } catch (std::regex_error const&) {
  }
}

void NaryRules::add(RulePtr rule) {
  if (rule) {
    rules_.emplace_back(std::move(rule));
  }
}

// Evaluator
//

namespace {
struct Evaluator : ConstVisitor<Evaluator, bool> {
  friend struct ConstVisitor<Evaluator, bool>;

  Evaluator(RequestParameters const& params) : params_(params) {}

protected:
  bool visitRule(NOTRule const& R) { return !this->visit(R.rule()); }

  bool visitRule(ORRules const& R) {
    return std::any_of(R.rules().begin(), R.rules().end(),
                       [&](RulePtr const& rc) { return this->visit(*rc); });
  }

  bool visitRule(ANDRules const& R) {
    return std::all_of(R.rules().begin(), R.rules().end(),
                       [&](RulePtr const& rc) { return this->visit(*rc); });
  }

  bool visitRule(CIDRRangeRule const& R) { return R.range().isInRange(params_.client_ip()); }

  bool visitRule(PathRule const& R) { return evalRegex(R, params_.path()); }

  bool visitRule(QueryRule const& R) { return evalRegex(R, params_.raw_query()); }

  bool visitRule(MethodRule const& R) { return evalRegex(R, params_.method()); }

  bool visitRule(URIRule const& R) { return evalRegex(R, params_.uri()); }

  bool visitRule(ArgsRule const& R) { return evalMap(R, params_.args()); }

  bool visitRule(CookiesRule const& R) { return evalMap(R, params_.cookies()); }

  bool visitRule(HeadersRule const& R) { return evalMap(R, params_.headers()); }

private:
  static bool evalRegex(RegexRule const& R, const absl::string_view str) {
    auto const& re = R.re();
    if (re) {
      std::cmatch m;
      return std::regex_search(str.begin(), str.end(), m, re.value());
    }
    return R.pattern() == str;
  }

  template <class Container> static bool evalMap(MapRule const& R, Container const& cont) {
    auto getKey = [](const absl::string_view key) {
      if constexpr (std::is_same_v<typename Container::key_type, std::string>) {
        return std::string{key};
      } else {
        return key;
      }
    };
    const auto r = cont.equal_range(getKey(R.key()));
    if (r.first == cont.end()) {
      return false;
    }
    return std::any_of(r.first, r.second, [&](auto it) { return evalRegex(R, it.second); });
  }

  RequestParameters const& params_;
};
} // namespace

bool eval(Rule const& R, RequestParameters const& params) { return Evaluator{params}(R); }

// Printer
//

namespace {
struct Printer : ConstVisitor<Printer, void> {
  friend struct ConstVisitor<Printer, void>;

  Printer(std::ostream& os) : os_(os) {}

protected:
  void visitRule(NOTRule const& R) {
    os_ << "!(";
    this->visit(R.rule());
    os_ << ")";
  }

  void visitRule(NaryRules const& R) {
    switch (R.kind()) {
    case Rule::Kind::OR:
      os_ << "OR";
      break;
    case Rule::Kind::AND:
      os_ << "AND";
      break;
    default:
      break;
    }
    os_ << "(";
    auto const& rules = R.rules();
    const size_t nrules = rules.size();
    if (nrules == 0) {
      os_ << "no_rules";
    } else {
      for (size_t i = 0; i < (nrules - 1); ++i) {
        this->visit(*rules[i]);
        os_ << ",";
      }
      this->visit(*rules.back());
    }
    os_ << ")";
  }

  void visitRule(CIDRRangeRule const& R) { os_ << "CIDR(" << R.range().asString() << ")"; }

  void visitRule(RegexRule const& R) { os_ << R.name() << "(" << R.pattern() << ")"; }

  void visitRule(MapRule const& R) {
    os_ << R.name() << "(";
    os_ << "key='" << R.key() << "',";
    os_ << "pattern='" << R.pattern() << "')";
  }

private:
  std::ostream& os_;
};
} // namespace

void print(Rule const& R, std::ostream& os) { Printer{os}(R); }

// Convertion from protobuf
//

namespace {

template <class T> std::unique_ptr<NaryRules> ruleFromRelation(T const& obj) {
  switch (obj.relation()) {
  case T::OR:
    return std::make_unique<ORRules>();
  case T::AND:
    return std::make_unique<ANDRules>();
  default:
    return {};
  }
}

std::unique_ptr<Rule> ruleFromProto(WAFProto::WAFRuleEntryMatchMap const& entry,
                                    const absl::string_view pattern) {
  const absl::string_view key = entry.key();
  switch (entry.field()) {
  case WAFProto::WAFRuleEntryMatchMap::args:
    return std::make_unique<ArgsRule>(key, pattern);
  case WAFProto::WAFRuleEntryMatchMap::headers:
    return std::make_unique<HeadersRule>(key, pattern);
  case WAFProto::WAFRuleEntryMatchMap::cookies:
    return std::make_unique<CookiesRule>(key, pattern);
  default:
    return {};
  }
}

std::unique_ptr<Rule> ruleFromProto(WAFProto::WAFRuleEntryMatchValue const& entry,
                                    const absl::string_view pattern) {
  switch (entry.field()) {
  case WAFProto::WAFRuleEntryMatchValue::path:
    return std::make_unique<PathRule>(pattern);
  case WAFProto::WAFRuleEntryMatchValue::query:
    return std::make_unique<QueryRule>(pattern);
  case WAFProto::WAFRuleEntryMatchValue::uri:
    return std::make_unique<URIRule>(pattern);
  case WAFProto::WAFRuleEntryMatchValue::method:
    return std::make_unique<MethodRule>(pattern);
  case WAFProto::WAFRuleEntryMatchValue::ip: {
    auto range = Network::Address::CidrRange::create(std::string{pattern});
    if (range.length() == -1) {
      return {};
    }
    return std::make_unique<CIDRRangeRule>(std::move(range));
  }
  default:
    return {};
  }
}

std::unique_ptr<Rule> ruleFromProto(WAFProto::WAFRuleSection const& sec) {
  std::unique_ptr<NaryRules> ret = ruleFromRelation(sec);
  auto const& entries = sec.entries();
  ret->reserve(entries.size());
  for (auto const& entry : entries) {
    ret->add(Rules::ruleFromProto(entry));
  }
  return ret;
}

} // namespace

std::unique_ptr<Rule> ruleFromProto(WAFProto::WAFRuleEntry const& entry) {
  absl::string_view pattern = entry.pattern();
  bool invert = false;
  if (!pattern.empty() && pattern[0] == '!') {
    pattern = pattern.substr(1);
    invert = true;
  }
  std::unique_ptr<Rule> ret;
  switch (entry.entry_case()) {
  case WAFProto::WAFRuleEntry::kMap:
    ret = ruleFromProto(entry.map(), pattern);
    break;
  case WAFProto::WAFRuleEntry::kValue:
    ret = ruleFromProto(entry.value(), pattern);
    break;
  default:
    return {};
  }
  if (invert) {
    auto not_ = std::make_unique<NOTRule>(std::move(ret));
    ret = std::move(not_);
  }
  return ret;
}

std::unique_ptr<Rule> ruleFromProto(WAFProto::WAFRule const& rule) {
  std::unique_ptr<NaryRules> ret = ruleFromRelation(rule);
  auto const& sections = rule.sections();
  ret->reserve(sections.size());
  for (auto const& sec : sections) {
    ret->add(ruleFromProto(sec));
  }
  return ret;
}

} // namespace Rules
} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
