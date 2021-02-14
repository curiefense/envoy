#include "common/network/utility.h"
#include "extensions/filters/http/waf/ip_interval_set.h"

namespace Envoy {

static uint32_t cidr2mask(const unsigned cidr) {
  assert(cidr <= 32);
  if (cidr == 0) {
    return 0xFFFFFFFF;
  }
  return (1U << (32 - cidr)) - 1U;
}

static absl::uint128 prefix2mask(const unsigned prefix) {
  assert(prefix <= 128);
  if (prefix == 0) {
    return absl::Uint128Max();
  }
  return (absl::uint128(1U) << (128 - prefix)) - 1U;
}

void IPIntervalSet::insert(Network::Address::CidrRange const& range) {
  auto const* ip = range.ip();
  if (!ip) {
    return;
  }
  if (Network::Address::Ipv4 const* v4 = ip->ipv4()) {
    const uint32_t address = ntohl(v4->address());
    const int cidr = range.length();
    if (cidr < 0) {
      return;
    }
    const uint32_t mask = cidr2mask(cidr);
    const uint32_t start = address & (~mask);
    const uint32_t end = address | mask;
    v4set_.insert(start, end + 1U);
  } else {
    Network::Address::Ipv6 const* v6 = ip->ipv6();
    const absl::uint128 address = Network::Utility::Ip6ntohl(v6->address());
    const int prefix = range.length();
    if (prefix < 0) {
      return;
    }
    const absl::uint128 mask = prefix2mask(prefix);
    const absl::uint128 start = address & (~mask);
    const absl::uint128 end = address | mask;
    v6set_.insert(start, end + 1U);
  }
}

bool IPIntervalSet::contains(Network::Address::Instance const& addr) const {
  auto* ip = addr.ip();
  if (!ip) {
    return false;
  }
  if (Network::Address::Ipv4 const* v4 = ip->ipv4()) {
    return v4set_.contains(ntohl(v4->address()));
  }
  return v6set_.contains(Network::Utility::Ip6ntohl(ip->ipv6()->address()));
}

} // namespace Envoy
