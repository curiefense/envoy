#include <memory>

#include "envoy/extensions/filters/http/waf/v3/waf.pb.h"

#include "common/http/header_map_impl.h"
#include "common/protobuf/protobuf.h"

#include "extensions/filters/http/waf/waf_filter.h"
#include "extensions/filters/http/well_known_names.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/stream_info/mocks.h"
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

namespace {

ProtobufWkt::Map<std::string, ProtobufWkt::Value> const*
metadataGetAttrs(const ProtobufWkt::Struct& obj) {
  auto& obj_fields = obj.fields();
  auto it_ri = obj_fields.find("request.info");
  if (it_ri == obj_fields.end()) {
    return nullptr;
  }
  if (!it_ri->second.has_struct_value()) {
    return nullptr;
  }
  auto& ri_fields = it_ri->second.struct_value().fields();
  auto it_attrs = ri_fields.find("attrs");
  if (it_attrs == ri_fields.end()) {
    return nullptr;
  }
  if (!it_attrs->second.has_struct_value()) {
    return nullptr;
  }
  return &it_attrs->second.struct_value().fields();
}

MATCHER_P2(ClientIpEq, exp_ip, exp_ipnum, "") {
  const ProtobufWkt::Struct& obj = arg;
  auto* pattrs_fields = metadataGetAttrs(obj);
  if (!pattrs_fields) {
    return false;
  }
  auto& attrs_fields = *pattrs_fields;

  auto it_ip = attrs_fields.find("ip");
  if (it_ip == attrs_fields.end()) {
    return false;
  }
  EXPECT_EQ(it_ip->second.string_value(), exp_ip);

  auto it_ipnum = attrs_fields.find("ipnum");
  if (it_ipnum == attrs_fields.end()) {
    return false;
  }
  const uint32_t obj_ipnum = it_ipnum->second.number_value();
  EXPECT_EQ(obj_ipnum, exp_ipnum);

  return true;
}

MATCHER_P(ContainsAllTags, exp_tags, "") {
  const ProtobufWkt::Struct& obj = arg;
  auto* pattrs_fields = metadataGetAttrs(obj);
  if (!pattrs_fields) {
    return false;
  }
  auto& attrs_fields = *pattrs_fields;

  auto it_tags = attrs_fields.find("tags");
  if (it_tags == attrs_fields.end()) {
    return exp_tags.empty();
  }
  if (!it_tags->second.has_struct_value()) {
    return false;
  }
  auto& tags = it_tags->second.struct_value().fields();
  for (const char* exp_tag : exp_tags) {
    EXPECT_TRUE(tags.find(exp_tag) != tags.end());
  }
  return true;
}

} // namespace
class WAFIntegrationTest : public testing::Test {
  const std::string yaml_config = R"EOF(
    signatures:
    - category:
        sqli:
          subcategory: statement_injection
      certainity: 5
      id: 1
      msg: dangerous query
      name: '1'
      operand: dangerousquery
      severity: 5
    - category:
        sqli:
          subcategory: statement_injection
      certainity: 5
      id: 2
      msg: dangerous query
      name: '2'
      operand: ahackerwashere
      severity: 5
    - category:
        sqli:
          subcategory: statement_injection
      certainity: 5
      id: 10 
      msg: dangerous query
      name: '10'
      operand: 'test with space'
      severity: 5
  )EOF";

public:
  WAFIntegrationTest() {}

  void initializeFilter(unsigned xff_trusted_hops = 1) {
    envoy::extensions::filters::http::waf::v3::WAF waf_config;
    TestUtility::loadFromYaml(yaml_config, waf_config);
    config_ = std::make_shared<WAFFilterConfig>(waf_config);
    filter_ = std::make_shared<WAFFilter>(config_);
    filter_->setDecoderFilterCallbacks(decoder_callbacks_);
    EXPECT_CALL(decoder_callbacks_, streamInfo()).WillRepeatedly(ReturnRef(req_info_));

    auto& filter_metadata = *metadata_.mutable_filter_metadata();
    (*filter_metadata[HttpFilters::HttpFilterNames::get().WAF].mutable_fields())["xff_trusted_hops"]
        .set_number_value(xff_trusted_hops);
    EXPECT_CALL(decoder_callbacks_.route_->route_entry_, metadata())
        .WillOnce(testing::ReturnRef(metadata_));
  }

  void cleanup() { filter_->onDestroy(); }

protected:
  void testClientIp(const char* xff, uint32_t xff_trusted_hops, const char* expected_ip,
                    uint32_t expected_ip_num) {
    initializeFilter(xff_trusted_hops);

    Http::TestRequestHeaderMapImpl headers{
        {":method", "GET"}, {":path", "/"}, {"x-forwarded-for", xff}};

    EXPECT_CALL(req_info_, setDynamicMetadata(HttpFilters::HttpFilterNames::get().WAF,
                                              ClientIpEq(expected_ip, expected_ip_num)));
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers, true));
    cleanup();
  }

  WAFFilterConfigSharedPtr config_;
  std::shared_ptr<WAFFilter> filter_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  NiceMock<Envoy::StreamInfo::MockStreamInfo> req_info_;
  envoy::config::core::v3::Metadata metadata_;
};

TEST_F(WAFIntegrationTest, TestTagsHeaders) {
  Http::TestRequestHeaderMapImpl headers({
      {":method", "GET"},
      {":path", "/"},
      {"header0", "dangerousquery"},
      {"header1", "ahackerwashere"},
  });
  const std::array<const char*, 2> expected_tags({"wafsig:1", "wafsig:2"});
  initializeFilter(1);
  EXPECT_CALL(req_info_, setDynamicMetadata(HttpFilters::HttpFilterNames::get().WAF,
                                            ContainsAllTags(expected_tags)));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers, true));
  cleanup();
}

TEST_F(WAFIntegrationTest, TestTagsCookies) {
  Http::TestRequestHeaderMapImpl headers({
      {":method", "GET"},
      {":path", "/"},
      {"cookies", "a=b; b=dangerousquery"},
      {"cookies", "c; c=; ; ; d=ahackerwashere"},
  });
  const std::array<const char*, 2> expected_tags({"wafsig:1", "wafsig:2"});
  initializeFilter(1);
  EXPECT_CALL(req_info_, setDynamicMetadata(HttpFilters::HttpFilterNames::get().WAF,
                                            ContainsAllTags(expected_tags)));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers, true));
  cleanup();
}

TEST_F(WAFIntegrationTest, TestTagsQuery) {
  Http::TestRequestHeaderMapImpl headers({
      {":method", "GET"},
      {":path", "/ep?a=myarg&b=test%20with%20space"},
  });
  const std::array<const char*, 1> expected_tags({"wafsig:10"});
  initializeFilter(1);
  EXPECT_CALL(req_info_, setDynamicMetadata(HttpFilters::HttpFilterNames::get().WAF,
                                            ContainsAllTags(expected_tags)));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers, true));
  cleanup();
}

TEST_F(WAFIntegrationTest, TestTagsHeadersCookiesQuery) {
  Http::TestRequestHeaderMapImpl headers({{":method", "GET"},
                                          {":path", "/ep?a=myarg&b=test%20with%20space"},
                                          {"cookies", "a=b; b=dangerousquery"},
                                          {"myheader", "ahackerwashere"}});
  const std::array<const char*, 3> expected_tags({"wafsig:1", "wafsig:2", "wafsig:10"});
  initializeFilter(1);
  EXPECT_CALL(req_info_, setDynamicMetadata(HttpFilters::HttpFilterNames::get().WAF,
                                            ContainsAllTags(expected_tags)));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers, true));
  cleanup();
}

#define TEST_CLIENT_IP "89.234.162.243"
#define TEST_CLIENT_IP_NUM 0x59EAA2F3
TEST_F(WAFIntegrationTest, TestClientIP0) {
  testClientIp("  " TEST_CLIENT_IP "  , 4.4.4.4  , 5.5.5.5   ", 0, "4.4.4.4", 0x04040404);
}

TEST_F(WAFIntegrationTest, TestClientIP1) {
  testClientIp("  " TEST_CLIENT_IP "  , 4.4.4.4  , 5.5.5.5   ", 1, "4.4.4.4", 0x04040404);
}

TEST_F(WAFIntegrationTest, TestClientIP2) {
  testClientIp("  " TEST_CLIENT_IP "  , 4.4.4.4  , 5.5.5.5   ", 2, TEST_CLIENT_IP,
               TEST_CLIENT_IP_NUM);
}

TEST_F(WAFIntegrationTest, TestClientIP3) {
  testClientIp("  " TEST_CLIENT_IP "  , 4.4.4.4  , 5.5.5.5   ", 3, "5.5.5.5", 0x05050505);
}

TEST_F(WAFIntegrationTest, TestClientIP4) {
  testClientIp("  " TEST_CLIENT_IP "  , 4.4.4.4  , 5.5.5.5   ", 4, "5.5.5.5", 0x05050505);
}

TEST_F(WAFIntegrationTest, TestClientIPEmptyXFF0) { testClientIp("", 1, "", 0); }

TEST_F(WAFIntegrationTest, TestClientIPEmptyXFF1) { testClientIp("    ", 1, "", 0); }

TEST_F(WAFIntegrationTest, TestClientIPEmptySplit) {
  testClientIp(TEST_CLIENT_IP ", , ,4.4.4.4", 1, TEST_CLIENT_IP, TEST_CLIENT_IP_NUM);
}

TEST_F(WAFIntegrationTest, TestClientIPOneXFF0) {
  testClientIp("   " TEST_CLIENT_IP "    ", 0, TEST_CLIENT_IP, TEST_CLIENT_IP_NUM);
}

TEST_F(WAFIntegrationTest, TestClientIPOneXFF1) {
  testClientIp("   " TEST_CLIENT_IP "    ", 1, TEST_CLIENT_IP, TEST_CLIENT_IP_NUM);
}

TEST_F(WAFIntegrationTest, TestClientIPOneXFF2) {
  testClientIp("   " TEST_CLIENT_IP "    ", 2, TEST_CLIENT_IP, TEST_CLIENT_IP_NUM);
}
#undef TEST_CLIENT_IP

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
