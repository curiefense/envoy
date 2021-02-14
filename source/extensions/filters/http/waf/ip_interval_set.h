#pragma once

#include "common/network/cidr_range.h"
#include "common/common/utility.h"

namespace Envoy {

class IPIntervalSet {
public:
  using IPv4IntervalSet = IntervalSetImpl<uint32_t>;
  using IPv6IntervalSet = IntervalSetImpl<absl::uint128>;

  void insert(Network::Address::CidrRange const& range);
  bool contains(Network::Address::Instance const& addr) const;
  void clear();

  IPv4IntervalSet const& v4set() const { return v4set_; }
  IPv6IntervalSet const& v6set() const { return v6set_; }

private:
  IPv4IntervalSet v4set_;
  IPv6IntervalSet v6set_;
};

} // namespace Envoy
