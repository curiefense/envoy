#include <memory>

#include "common/network/utility.h"

#include "extensions/filters/http/waf/ip_interval_set.h"
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

class WAFIPIntervalSetTest : public testing::Test {
public:
  WAFIPIntervalSetTest() {}
};

TEST_F(WAFIPIntervalSetTest, Testv4) {
  IPIntervalSet set;
  set.insert(Network::Address::CidrRange::create("127.0.0.1/32"));
  set.insert(Network::Address::CidrRange::create("192.168.0.0/24"));
  set.insert(Network::Address::CidrRange::create("192.168.1.0/24"));
  set.insert(Network::Address::CidrRange::create("10.0.0.0/24"));
  set.insert(Network::Address::CidrRange::create("10.0.0.0/16"));
  set.insert(Network::Address::CidrRange::create("8.8.8.0/31"));

  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("127.0.0.0")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("127.0.0.1")));
  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("127.0.0.2")));

  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("192.167.255.255")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("192.168.0.0")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("192.168.1.0")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("192.168.1.255")));
  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("192.168.2.0")));

  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("9.255.255.255")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("10.0.0.0")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("10.0.0.1")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("10.0.5.5")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("10.0.255.255")));
  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("10.1.0.0")));

  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("8.8.7.255")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("8.8.8.0")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("8.8.8.1")));
  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("8.8.8.2")));
}

TEST_F(WAFIPIntervalSetTest, Testv6) {
  IPIntervalSet set;
  set.insert(Network::Address::CidrRange::create("::1/128"));
  set.insert(Network::Address::CidrRange::create("2001::/16"));
  set.insert(Network::Address::CidrRange::create("2002::/16"));

  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("::")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("::1")));
  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("::2")));

  EXPECT_FALSE(set.contains(
      *Network::Utility::parseInternetAddress("2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("2001::1")));
  EXPECT_TRUE(set.contains(
      *Network::Utility::parseInternetAddress("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
  EXPECT_TRUE(set.contains(*Network::Utility::parseInternetAddress("2002::1")));
  EXPECT_TRUE(set.contains(
      *Network::Utility::parseInternetAddress("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
  EXPECT_FALSE(set.contains(*Network::Utility::parseInternetAddress("2003::")));
}

} // namespace WAF
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
