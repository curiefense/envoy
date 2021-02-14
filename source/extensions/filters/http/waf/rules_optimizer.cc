#include "extensions/filters/http/waf/rules.h"
#include "extensions/filters/http/waf/rules_visitor.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {
namespace Rules {

// Flattener
namespace {
struct Flattener : public MutableVisitor<Flattener> {
  friend struct MutableVisitor<Flattener>;

protected:
  void visitRule(RulePtr& P, NaryRules& R) {
    auto& rules = R.mutable_rules();
    if (rules.size() == 1) {
      std::unique_ptr<Rule> newP(std::move(rules[0]));
      P = std::move(newP);
      this->visit(P);
      return;
    }
    for (RulePtr& rule : rules) {
      this->visit(rule);
    }
  }

  void visitRule(RulePtr&, UnaryRule& R) { this->visit(R.mutable_rule()); }

  void visitRule(RulePtr&, Rule&) {}
};

// CIDR optimizer:
// Optimize OR(CIDR(A),CIDR(B),CIDR(C),...) into OR(...,OptimizedCIDRRangesRule(A,B,C))
//
struct CIDROptimizer : public MutableVisitor<CIDROptimizer> {
  friend struct MutableVisitor<CIDROptimizer>;

protected:
  void visitRule(RulePtr& P, ORRules& Or) {
    constexpr size_t cidrs_opt = 4;
    // If we have more than `cidrs_opt` CIDR ranges, optimize it
    auto& rules = Or.mutable_rules();
    size_t ncidrs = 0;
    for (const auto& c : rules) {
      if (c->kind() == Rule::Kind::CIDRRange) {
        if (++ncidrs >= cidrs_opt) {
          // Early stop
          break;
        }
      }
    }
    if (ncidrs < cidrs_opt) {
      for (auto& c : rules) {
        this->visit(c);
      }
      return;
    }

    auto retOR = std::make_unique<ORRules>();
    auto retOptCIDR = std::make_unique<OptimizedCIDRRangesRule>();
    auto& intervals = retOptCIDR->mutable_intervals();
    for (auto& c : rules) {
      Rule const& rc = *c;
      if (rc.kind() != Rule::Kind::CIDRRange) {
        retOR->add(std::move(c));
      } else {
        intervals.insert(static_cast<CIDRRangeRule const&>(rc).range());
      }
    }
    if (retOR->empty()) {
      P = std::move(retOptCIDR);
    } else {
      retOR->add(std::move(retOptCIDR));
      P = std::move(retOR);
    }
  }

  void visitRule(RulePtr&, ANDRules& R) {
    for (auto& c : R.mutable_rules()) {
      this->visit(c);
    }
  }

  void visitRule(RulePtr&, UnaryRule& R) { this->visit(R.mutable_rule()); }

  void visitRule(RulePtr&, Rule&) {}
};

} // namespace

void optimize(RulePtr& R) {
  Flattener{}.visit(R);
  CIDROptimizer{}.visit(R);
}

} // namespace Rules
} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
