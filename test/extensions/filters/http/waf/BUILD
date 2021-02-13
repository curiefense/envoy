load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "waf_filter_test",
    srcs = [
        "waf_filter_test.cc",
    ],
    extension_name = "envoy.filters.http.waf",
    deps = [
        "//source/extensions/filters/http/waf:config",
        "//test/mocks/api:api_mocks",
        "//test/mocks/http:http_mocks",
        "//test/mocks/server:factory_context_mocks",
        "//test/integration:http_integration_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:utility_lib",
    ],
)

envoy_extension_cc_test(
    name = "rules_test",
    srcs = [
        "rules_test.cc",
    ],
    extension_name = "envoy.filters.http.waf",
    deps = [
        "//source/extensions/filters/http/waf:config",
        "//test/integration:http_integration_lib",
        "//test/test_common:simulated_time_system_lib",
        "//test/test_common:utility_lib",
    ],
)
