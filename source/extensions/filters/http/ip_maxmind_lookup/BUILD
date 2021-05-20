load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "ip_maxmind_lookup_filter_lib",
    srcs = ["ip_maxmind_lookup_filter.cc"],
    hdrs = ["ip_maxmind_lookup_filter.h"],
    external_deps = ["libmaxminddb"],
    deps = [
        "//envoy/server:filter_config_interface",
        "//source/common/common:base64_lib",
        "//source/common/http:header_utility_lib",
        "//source/common/http:utility_lib",
        "//source/extensions/filters/http:well_known_names",
        "@envoy_api//envoy/extensions/filters/http/ip_maxmind_lookup/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        "//envoy/registry",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "//source/extensions/filters/http/ip_maxmind_lookup:ip_maxmind_lookup_filter_lib",
        "@envoy_api//envoy/extensions/filters/http/ip_maxmind_lookup/v3:pkg_cc_proto",
    ],
)
