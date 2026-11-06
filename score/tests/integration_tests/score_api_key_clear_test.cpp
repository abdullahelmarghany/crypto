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

/// @file score_api_key_clear_test.cpp
/// @brief Verifies IKeyManagementContext::ClearKey on a file-backed slot.
///
/// Uses a dedicated slot (AES256_Clearable_IntegrationTestKey_OpenSSL) whose key
/// file exists only for this test, because clearing it is permanent for the
/// lifetime of the deployment. The test runs as uid 0, which is in the slot's
/// allowed_write_uids.

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string_view>
#include <utility>

using namespace score::crypto;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

constexpr auto kClearableSlot = "AES256_Clearable_IntegrationTestKey_OpenSSL";
constexpr std::string_view kClearableAlgorithm{"AES-256"};

class KeyClearTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

        auto stack_result = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
        stack_ = std::move(stack_result.value());

        auto ctx_result = stack_->CreateCryptoContext();
        ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
        ctx_ = std::move(ctx_result.value());

        KeyManagementContextConfig key_mgmt_config;
        key_mgmt_config.SetProviderType(ProviderType::kSoftware);
        auto key_mgmt_result = ctx_->CreateKeyManagementContext(key_mgmt_config);
        ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
        key_mgmt_ = std::move(key_mgmt_result.value());
    }

    void ExpectSlotState(const CryptoResourceId& slot, KeySlotState expected_state)
    {
        auto info_result = key_mgmt_->GetKeySlotInfo(slot);
        ASSERT_TRUE(info_result.has_value()) << "GetKeySlotInfo failed";
        const auto& info = info_result.value();
        EXPECT_EQ(info.state, expected_state);
        // The slot descriptor is deployment config and survives a clear.
        EXPECT_EQ(std::string_view{info.algorithm}, kClearableAlgorithm);
        EXPECT_EQ(info.permitted_operations, KeyOperationPermission::kMac);
    }

    ICryptoStack::Uptr stack_;
    ICryptoContext::Uptr ctx_;
    std::unique_ptr<IKeyManagementContext> key_mgmt_;
};

TEST_F(KeyClearTest, ClearKey_ProvisionedSlot_KeyCanNoLongerBeLoaded)
{
    auto slot_result = ctx_->ResolveResource(kClearableSlot, ResourceType::kKeySlot);
    ASSERT_TRUE(slot_result.has_value()) << "Failed to resolve key slot: " << kClearableSlot;
    const auto slot = slot_result.value();

    ExpectSlotState(slot, KeySlotState::kOccupied);
    {
        auto key_result = key_mgmt_->LoadKey(slot);
        ASSERT_TRUE(key_result.has_value()) << "Slot must hold a key before it is cleared";
    }

    auto clear_result = key_mgmt_->ClearKey(slot);
    ASSERT_TRUE(clear_result.has_value()) << "ClearKey failed";

    ExpectSlotState(slot, KeySlotState::kEmpty);
    EXPECT_FALSE(key_mgmt_->LoadKey(slot).has_value()) << "Cleared slot must not yield a key";

    // Clearing an empty slot succeeds and leaves it empty.
    EXPECT_TRUE(key_mgmt_->ClearKey(slot).has_value());
    ExpectSlotState(slot, KeySlotState::kEmpty);
}

TEST_F(KeyClearTest, ClearKey_NonSlotResource_IsRejected)
{
    const CryptoResourceId not_a_slot{1U, ResourceType::kKey};

    auto clear_result = key_mgmt_->ClearKey(not_a_slot);

    ASSERT_FALSE(clear_result.has_value());
    EXPECT_EQ(*clear_result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
