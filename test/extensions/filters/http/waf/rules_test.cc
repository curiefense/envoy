#include <memory>

#include "envoy/extensions/filters/http/waf/v3/waf.pb.h"

#include "common/http/header_map_impl.h"
#include "common/protobuf/protobuf.h"

#include "extensions/filters/http/waf/waf_filter.h"
#include "extensions/filters/http/waf/rules.h"
#include "extensions/filters/http/well_known_names.h"

#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;
using testing::Return;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace WAF {

namespace WAFProto = envoy::extensions::filters::http::waf::v3;

class WAFRulesTest : public testing::Test {
public:
  WAFRulesTest() {}

protected:
  static std::unique_ptr<Rules::Rule> initializeValueRuleEntry(absl::string_view const field,
                                                               absl::string_view const pattern) {
    const auto yaml = fmt::format(R"EOF(
    value:
      field: {}
    pattern: '{}'
    )EOF",
                                  field, pattern);
    WAFProto::WAFRuleEntry ret;
    TestUtility::loadFromYaml(yaml, ret);
    return Rules::ruleFromProto(ret);
  }
  static std::unique_ptr<Rules::Rule> initializeMapRuleEntry(absl::string_view const field,
                                                             absl::string_view const key,
                                                             absl::string_view const pattern) {
    const auto yaml = fmt::format(R"EOF(
    map:
      field: {}
      key: '{}'
    pattern: '{}'
    )EOF",
                                  field, key, pattern);
    WAFProto::WAFRuleEntry ret;
    TestUtility::loadFromYaml(yaml, ret);
    return Rules::ruleFromProto(ret);
  }

  static std::unique_ptr<Rules::Rule> initializeTagRules(std::string const& rules_yaml) {
    WAFProto::WAFRule ret;
    TestUtility::loadFromYaml(rules_yaml, ret);
    return Rules::ruleFromProto(ret);
  }

  static void testRuleMatch(Rules::Rule const& R, Http::TestRequestHeaderMapImpl const& headers) {
    const auto params = RequestParameters::create(headers, nullptr);
    EXPECT_TRUE(Rules::eval(R, params));
  }

  static void testRuleNoMatch(Rules::Rule const& R, Http::TestRequestHeaderMapImpl const& headers) {
    const auto params = RequestParameters::create(headers, nullptr);
    EXPECT_FALSE(Rules::eval(R, params));
  }
};

TEST_F(WAFRulesTest, TestPath) {
  const auto rule = initializeValueRuleEntry("path", "toto");
  testRuleMatch(*rule, {{":path", "/toto"}});
}

TEST_F(WAFRulesTest, TestNot) {
  const auto rule = initializeValueRuleEntry("path", "!toto");
  testRuleNoMatch(*rule, {{":path", "/toto"}});
  testRuleMatch(*rule, {{":path", "/tata"}});
}

TEST_F(WAFRulesTest, TestQueryURI) {
  Http::TestRequestHeaderMapImpl headers({
      {":path", "/?a=toto%20tata"},
  });
  auto rule = initializeValueRuleEntry("query", "toto%20tata");
  testRuleMatch(*rule, headers);
  rule = initializeValueRuleEntry("uri", "toto tata");
  testRuleMatch(*rule, headers);
}

TEST_F(WAFRulesTest, TestMethod) {
  const auto rule = initializeValueRuleEntry("method", "^(GET|POST)$");
  testRuleMatch(*rule, {{":method", "GET"}});
  testRuleMatch(*rule, {{":method", "POST"}});
  testRuleNoMatch(*rule, {{":method", "POSTO"}});
  testRuleNoMatch(*rule, {{":method", "PUT"}});
}

TEST_F(WAFRulesTest, TestCIDRRangev4) {
  const auto rule = initializeValueRuleEntry("ip", "192.168.0.0/16");
  testRuleMatch(*rule, {{"x-forwarded-for", "192.168.1.1"}});
  testRuleNoMatch(*rule, {{"x-forwarded-for", "192.169.0.1"}});
}

TEST_F(WAFRulesTest, TestCIDRRangev6) {
  const auto rule = initializeValueRuleEntry("ip", "fe80::/10");
  testRuleMatch(*rule, {{"x-forwarded-for", "fe80::1"}});
  testRuleNoMatch(*rule, {{"x-forwarded-for", "2001:660::1"}});
}

TEST_F(WAFRulesTest, TestCookies) {
  const auto rule = initializeMapRuleEntry("cookies", "a", "toto");
  testRuleMatch(*rule, {{"cookie", "a=tototiti"}});
  testRuleNoMatch(*rule, {{"cookie", "a=tata"}});
}

TEST_F(WAFRulesTest, TestCookiesNot) {
  const auto rule = initializeMapRuleEntry("cookies", "a", "!toto");
  testRuleNoMatch(*rule, {{"cookie", "a=tototiti"}});
  testRuleMatch(*rule, {{"cookie", "a=tata"}});
}

TEST_F(WAFRulesTest, TestHeaders) {
  const auto rule = initializeMapRuleEntry("headers", "myheader", "dangerous");
  testRuleMatch(*rule, {{"myheader", "thisisdangerous"}});
  testRuleNoMatch(*rule, {{"myheader", "clean"}});
}

TEST_F(WAFRulesTest, TestArgs) {
  const auto rule = initializeMapRuleEntry("args", "q", "^this is dangerous$");
  testRuleMatch(*rule, {{":path", "/api?q=this%20is%20dangerous"}});
  testRuleNoMatch(*rule, {{":path", "/api?v=this%20is%20dangerous"}});
}

TEST_F(WAFRulesTest, TestFull0) {
  const auto rule = initializeTagRules(R"EOF(
  relation: OR
  sections:
    - relation: AND
      entries:
        - value:
            field: path
          pattern: 'mypath'
        - value:
            field: ip
          pattern: '192.168.0.0/16'
    - relation: AND 
      entries:
        - value:
            field: path
          pattern: 'toto'
        - value:
            field: ip
          pattern: '127.0.0.1/32'
  )EOF");

  testRuleMatch(*rule, {{":path", "/mypath"}, {"x-forwarded-for", "192.168.1.1"}});
  testRuleNoMatch(*rule, {{":path", "/api"}, {"x-forwarded-for", "192.168.1.1"}});
  testRuleNoMatch(*rule, {{":path", "/mypath"}, {"x-forwarded-for", "10.0.1.1"}});

  testRuleMatch(*rule, {{":path", "/toto"}, {"x-forwarded-for", "127.0.0.1"}});
  testRuleNoMatch(*rule, {{":path", "/path"}, {"x-forwarded-for", "127.0.0.1"}});
  testRuleNoMatch(*rule, {{":path", "/toto"}, {"x-forwarded-for", "127.0.0.2"}});
}

TEST_F(WAFRulesTest, TestFull1) {
  const auto rule = initializeTagRules(R"EOF(
  relation: AND
  sections:
    - relation: OR
      entries:
        - value:
            field: path
          pattern: 'mypath'
        - value:
            field: path
          pattern: 'toto'
    - relation: OR
      entries:
        - value:
            field: ip
          pattern: '192.168.0.0/16'
        - value:
            field: ip
          pattern: '127.0.0.1/32'
  )EOF");

  testRuleMatch(*rule, {{":path", "/mypath"}, {"x-forwarded-for", "127.0.0.1"}});
  testRuleMatch(*rule, {{":path", "/mypath"}, {"x-forwarded-for", "192.168.1.1"}});
  testRuleMatch(*rule, {{":path", "/toto"}, {"x-forwarded-for", "192.168.1.1"}});
  testRuleMatch(*rule, {{":path", "/toto"}, {"x-forwarded-for", "127.0.0.1"}});

  testRuleNoMatch(*rule, {{":path", "/toto"}, {"x-forwarded-for", "10.0.0.1"}});
  testRuleNoMatch(*rule, {{":path", "/api"}, {"x-forwarded-for", "127.0.0.1"}});
}

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
