/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace score::crypto::daemon::key_management
{
namespace
{

TEST(SecureKeyBytesTest, MoveConstructionTransfersBytesAndEmptiesSource)
{
    SecureKeyBytes source;
    source.bytes = {0x01U, 0x02U, 0x03U};

    SecureKeyBytes target(std::move(source));

    EXPECT_EQ(target.bytes, (std::vector<std::uint8_t>{0x01U, 0x02U, 0x03U}));
    EXPECT_TRUE(source.bytes.empty());  // NOLINT(bugprone-use-after-move)
}

TEST(SecureKeyBytesTest, MoveAssignmentReplacesBytesAndEmptiesSource)
{
    SecureKeyBytes target;
    target.bytes = {0xAAU, 0xBBU};
    SecureKeyBytes source;
    source.bytes = {0x10U, 0x20U, 0x30U, 0x40U};

    target = std::move(source);

    EXPECT_EQ(target.bytes, (std::vector<std::uint8_t>{0x10U, 0x20U, 0x30U, 0x40U}));
    EXPECT_TRUE(source.bytes.empty());  // NOLINT(bugprone-use-after-move)
}

TEST(SecureKeyBytesTest, SelfMoveAssignmentKeepsBytes)
{
    SecureKeyBytes keys;
    keys.bytes = {0x05U, 0x06U};
    SecureKeyBytes& alias = keys;

    keys = std::move(alias);

    EXPECT_EQ(keys.bytes, (std::vector<std::uint8_t>{0x05U, 0x06U}));
}

}  // namespace
}  // namespace score::crypto::daemon::key_management
