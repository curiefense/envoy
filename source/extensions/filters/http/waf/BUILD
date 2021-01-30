load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "waf_filter_lib",
    srcs = ["waf_filter.cc"],
    hdrs = ["waf_filter.h"],
    deps = [
        "//source/common/http:headers_lib",
        "//source/common/http:utility_lib",
        "//source/common/protobuf",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "//source/extensions/filters/http:well_known_names",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/waf/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    security_posture = "robust_to_untrusted_downstream",
    deps = [
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "//source/extensions/filters/http/waf:waf_filter_lib",
        "@envoy_api//envoy/extensions/filters/http/waf/v3:pkg_cc_proto",
    ],
    category = "envoy.filters.http",
)
