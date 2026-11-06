# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_pkg//pkg:mappings.bzl", "pkg_files", "strip_prefix")

filegroup(
    name = "key_management_test_vectors",
    srcs = [
        "aes256_cmac.key",
        "hmac_sha256.key",
    ],
    visibility = ["//:__subpackages__"],
)

# Key cleared by the integration ClearKey test; deployed to share/test_vectors/key_management/.
pkg_files(
    name = "clearable_key_pkg",
    srcs = ["clearable_aes256.key"],
    strip_prefix = strip_prefix.from_root("score/tests"),
    visibility = ["//visibility:public"],
)
