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

/// @file score_api_key_slot_store_test.cpp
/// @brief End-to-end tests for storing keys into key slots.
///
/// Covers GenerateKey and ImportKey into a slot and PersistKey of an ephemeral
/// key, each followed by LoadKey and an HMAC-SHA256 computation with the stored
/// key, and GenerateKey of an ECDSA key pair into a private and a public slot.
/// With the PKCS#11 backend, generate, import and persist also run against
/// SoftHSM slots. Each test writes its own empty slot (see
/// integration_test_config.json); a slot cannot be emptied again, so every test runs once per daemon instance.

#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"
#include "score/result/result.h"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace score::crypto;
using tests::utility::read_bin;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

constexpr std::string_view kSlotAlgorithm = "HMAC-SHA256";
constexpr std::string_view kMacAlgorithm = "HMAC-SHA256";
constexpr std::size_t kMacSize = 32U;

constexpr std::string_view kGenerateSlot = "Store_Generate_OpenSSL";
constexpr std::string_view kImportSlot = "Store_Import_OpenSSL";
constexpr std::string_view kPersistSlot = "Store_Persist_OpenSSL";
constexpr std::string_view kKeyPairPrivateSlot = "Store_KeyPair_Private_OpenSSL";
constexpr std::string_view kKeyPairPublicSlot = "Store_KeyPair_Public_OpenSSL";
constexpr std::string_view kKeyPairAlgorithm = "ECDSA-P256";
constexpr std::string_view kSignatureAlgorithm = "ECDSA-P256-SHA256";
constexpr std::size_t kSignatureSize = 64U;

std::string GetTestVectorPath(const std::string_view relative_path)
{
    const char* dir = std::getenv("TEST_VECTORS_DIR");
    return std::string{dir != nullptr ? dir : "/opt/crypto/share/test_vectors"} + std::string{relative_path};
}

class KeySlotStoreTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);
        auto stack = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack.has_value()) << "Failed to create crypto stack";
        stack_ = std::move(stack.value());

        auto ctx = stack_->CreateCryptoContext();
        ASSERT_TRUE(ctx.has_value()) << "Failed to create crypto context";
        ctx_ = std::move(ctx.value());

        KeyManagementContextConfig key_mgmt_config;
        key_mgmt_config.SetProviderType(ProviderType::kSoftware);
        auto key_mgmt = ctx_->CreateKeyManagementContext(key_mgmt_config);
        ASSERT_TRUE(key_mgmt.has_value()) << "Failed to create key management context";
        key_mgmt_ = std::move(key_mgmt.value());
    }

    CryptoResourceId ResolveSlot(std::string_view name)
    {
        auto slot = ctx_->ResolveResource(std::string{name}, ResourceType::kKeySlot);
        EXPECT_TRUE(slot.has_value()) << "Failed to resolve key slot " << name;
        return slot.has_value() ? slot.value() : CryptoResourceId{};
    }

    /// The slot reports @p expected through GetKeySlotInfo().
    static void ExpectSlotState(IKeyManagementContext& key_mgmt, const CryptoResourceId& slot, KeySlotState expected)
    {
        auto info = key_mgmt.GetKeySlotInfo(slot);
        ASSERT_TRUE(info.has_value()) << "GetKeySlotInfo failed";
        EXPECT_EQ(info.value().state, expected);
    }

    /// HMAC-SHA256 of @p data with @p key, via a single Init/Update/Finalize.
    std::vector<std::uint8_t> ComputeMac(const CryptoResourceId& key,
                                         const std::vector<std::uint8_t>& data,
                                         ProviderType provider = ProviderType::kSoftware)
    {
        MacContextConfig mac_config;
        mac_config.SetAlgorithm(std::string{kMacAlgorithm}).SetKey(key).SetProviderType(provider);
        auto mac = ctx_->CreateMacContext(mac_config);
        EXPECT_TRUE(mac.has_value()) << "Failed to create MAC context";
        if (!mac.has_value())
        {
            return {};
        }
        std::vector<std::uint8_t> out(kMacSize, 0U);
        EXPECT_TRUE(mac.value()->Init().has_value());
        EXPECT_TRUE(mac.value()->Update({data.data(), data.size()}).has_value());
        auto written = mac.value()->Finalize({out.data(), out.size()});
        EXPECT_TRUE(written.has_value());
        return out;
    }

    ICryptoStack::Uptr stack_;
    ICryptoContext::Uptr ctx_;
    std::unique_ptr<IKeyManagementContext> key_mgmt_;
    const std::vector<std::uint8_t> input_ = read_bin(GetTestVectorPath("/mac/input_hello_world.bin"));
};

TEST_F(KeySlotStoreTest, ImportKeyIntoSlot_MacMatchesKnownAnswer)
{
    const auto key_bytes = read_bin(GetTestVectorPath("/mac/key_aes_256.key"));
    const auto expected_mac = read_bin(GetTestVectorPath("/mac/hmac_sha256_hello_world.bin"));
    ASSERT_FALSE(key_bytes.empty());
    ASSERT_EQ(expected_mac.size(), kMacSize);
    const auto slot = ResolveSlot(kImportSlot);

    ImportKeyParams params;
    params.SetKeyData(key_bytes.data(), key_bytes.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm(std::string{kSlotAlgorithm});
    auto stored = key_mgmt_->ImportKey(slot, params);
    ASSERT_TRUE(stored.has_value()) << "ImportKey into slot failed: " << stored.error().Message();
    ExpectSlotState(*key_mgmt_, slot, KeySlotState::kOccupied);

    auto key = key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(key.has_value()) << "LoadKey from stored slot failed";
    EXPECT_EQ(ComputeMac(key.value(), input_), expected_mac);

    // The slot is now occupied: neither import nor generate may replace the key.
    auto again = key_mgmt_->ImportKey(slot, params);
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(*again.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeySlotOccupied))
        << again.error().Message();

    GenerateKeyParams gen;
    gen.SetAlgorithm(std::string{kSlotAlgorithm});
    auto generated = key_mgmt_->GenerateKey(slot, std::nullopt, gen);
    ASSERT_FALSE(generated.has_value());
    EXPECT_EQ(*generated.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeySlotOccupied))
        << generated.error().Message();
}

TEST_F(KeySlotStoreTest, GenerateKeyIntoSlot_KeyLoadsAndIsStable)
{
    const auto slot = ResolveSlot(kGenerateSlot);
    ExpectSlotState(*key_mgmt_, slot, KeySlotState::kEmpty);

    GenerateKeyParams wrong;
    wrong.SetAlgorithm("AES-128");
    auto mismatch = key_mgmt_->GenerateKey(slot, std::nullopt, wrong);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(*mismatch.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kAlgorithmMismatch))
        << mismatch.error().Message();

    GenerateKeyParams params;
    params.SetAlgorithm(std::string{kSlotAlgorithm});
    auto stored = key_mgmt_->GenerateKey(slot, std::nullopt, params);
    ASSERT_TRUE(stored.has_value()) << "GenerateKey into slot failed: " << stored.error().Message();
    ExpectSlotState(*key_mgmt_, slot, KeySlotState::kOccupied);

    // Two loads of the slot yield the same key material.
    auto first = key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(first.has_value());
    const auto mac_first = ComputeMac(first.value(), input_);
    static_cast<void>(first.value().Release());

    auto second = key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(ComputeMac(second.value(), input_), mac_first);
}

TEST_F(KeySlotStoreTest, PersistKey_SlotKeyMatchesEphemeralKey)
{
    const auto slot = ResolveSlot(kPersistSlot);

    GenerateKeyParams params;
    params.SetAlgorithm(std::string{kSlotAlgorithm}).SetPermissions(KeyOperationPermission::kMac);
    auto ephemeral = key_mgmt_->GenerateKey(params);
    ASSERT_TRUE(ephemeral.has_value()) << "GenerateKey failed";

    auto persisted = key_mgmt_->PersistKey(slot, ephemeral.value());
    ASSERT_TRUE(persisted.has_value()) << "PersistKey failed: " << persisted.error().Message();
    ExpectSlotState(*key_mgmt_, slot, KeySlotState::kOccupied);

    // The ephemeral key is still usable and the slot holds the same material.
    const auto ephemeral_mac = ComputeMac(ephemeral.value(), input_);
    auto loaded = key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(loaded.has_value()) << "LoadKey from persisted slot failed";
    EXPECT_EQ(ComputeMac(loaded.value(), input_), ephemeral_mac);

    auto again = key_mgmt_->PersistKey(slot, ephemeral.value());
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(*again.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeySlotOccupied))
        << again.error().Message();
}

TEST_F(KeySlotStoreTest, GenerateKeyPairIntoSlots_PublicSlotVerifiesPrivateSlotSignature)
{
    const auto private_slot = ResolveSlot(kKeyPairPrivateSlot);
    const auto public_slot = ResolveSlot(kKeyPairPublicSlot);

    GenerateKeyParams params;
    params.SetAlgorithm(std::string{kKeyPairAlgorithm});
    auto stored = key_mgmt_->GenerateKey(private_slot, public_slot, params);
    ASSERT_TRUE(stored.has_value()) << "GenerateKey into key pair slots failed: " << stored.error().Message();
    ExpectSlotState(*key_mgmt_, private_slot, KeySlotState::kOccupied);
    ExpectSlotState(*key_mgmt_, public_slot, KeySlotState::kOccupied);

    auto private_key = key_mgmt_->LoadKey(private_slot);
    ASSERT_TRUE(private_key.has_value()) << "LoadKey from private slot failed";
    auto public_key = key_mgmt_->LoadKey(public_slot);
    ASSERT_TRUE(public_key.has_value()) << "LoadKey from public slot failed";

    SignContextConfig sign_config;
    sign_config.SetAlgorithm(std::string{kSignatureAlgorithm}).SetKey(private_key.value());
    auto sign = ctx_->CreateSignContext(sign_config);
    ASSERT_TRUE(sign.has_value()) << "Failed to create sign context";
    std::vector<std::uint8_t> signature(kSignatureSize, 0U);
    auto written = sign.value()->SingleShot({input_.data(), input_.size()}, {signature.data(), signature.size()});
    ASSERT_TRUE(written.has_value()) << "Signing with the private slot key failed";

    VerifySignatureContextConfig verify_config;
    verify_config.SetAlgorithm(std::string{kSignatureAlgorithm}).SetKey(public_key.value());
    auto verify = ctx_->CreateVerifySignatureContext(verify_config);
    ASSERT_TRUE(verify.has_value()) << "Failed to create verify context";
    auto verified = verify.value()->SingleShot({input_.data(), input_.size()}, {signature.data(), signature.size()});
    ASSERT_TRUE(verified.has_value()) << "Verification call failed";
    EXPECT_TRUE(verified.value()) << "The public slot must hold the public half of the private slot key";

    // Both slots are occupied now; a second pair must not replace either.
    auto again = key_mgmt_->GenerateKey(private_slot, public_slot, params);
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(*again.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeySlotOccupied))
        << again.error().Message();
}

#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
constexpr std::string_view kPkcs11SlotAlgorithm = "HMAC-SHA256";
constexpr std::string_view kPkcs11GenerateSlot = "Store_Generate_PKCS11";
constexpr std::string_view kPkcs11ImportSlot = "Store_Import_PKCS11";
constexpr std::string_view kPkcs11PersistSlot = "Store_Persist_PKCS11";

/// The same flows against slots of the PKCS#11 provider (SoftHSM), whose keys
/// are stored as token objects named by the slot's pkcs11.label.
class Pkcs11KeySlotStoreTest : public KeySlotStoreTest
{
  protected:
    void SetUp() override
    {
        KeySlotStoreTest::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        KeyManagementContextConfig config;
        config.SetProviderType(ProviderType::kHardware);
        auto key_mgmt = ctx_->CreateKeyManagementContext(config);
        ASSERT_TRUE(key_mgmt.has_value()) << "Failed to create PKCS#11 key management context";
        hw_key_mgmt_ = std::move(key_mgmt.value());
    }

    std::unique_ptr<IKeyManagementContext> hw_key_mgmt_;
};

TEST_F(Pkcs11KeySlotStoreTest, ImportKeyIntoSlot_MacMatchesKnownAnswer)
{
    const auto key_bytes = read_bin(GetTestVectorPath("/mac/key_aes_256.key"));
    const auto expected_mac = read_bin(GetTestVectorPath("/mac/hmac_sha256_hello_world.bin"));
    ASSERT_FALSE(key_bytes.empty());
    const auto slot = ResolveSlot(kPkcs11ImportSlot);

    ImportKeyParams params;
    params.SetKeyData(key_bytes.data(), key_bytes.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm(std::string{kPkcs11SlotAlgorithm});
    auto stored = hw_key_mgmt_->ImportKey(slot, params);
    ASSERT_TRUE(stored.has_value()) << "ImportKey into PKCS#11 slot failed: " << stored.error().Message();
    ExpectSlotState(*hw_key_mgmt_, slot, KeySlotState::kOccupied);

    auto key = hw_key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(key.has_value()) << "LoadKey from stored PKCS#11 slot failed";
    EXPECT_EQ(ComputeMac(key.value(), input_, ProviderType::kHardware), expected_mac);

    auto again = hw_key_mgmt_->ImportKey(slot, params);
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(*again.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeySlotOccupied))
        << again.error().Message();
}

TEST_F(Pkcs11KeySlotStoreTest, GenerateKeyIntoSlot_KeyLoadsAndIsStable)
{
    const auto slot = ResolveSlot(kPkcs11GenerateSlot);

    GenerateKeyParams params;
    params.SetAlgorithm(std::string{kPkcs11SlotAlgorithm});
    auto stored = hw_key_mgmt_->GenerateKey(slot, std::nullopt, params);
    ASSERT_TRUE(stored.has_value()) << "GenerateKey into PKCS#11 slot failed: " << stored.error().Message();
    ExpectSlotState(*hw_key_mgmt_, slot, KeySlotState::kOccupied);

    auto first = hw_key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(first.has_value());
    const auto mac_first = ComputeMac(first.value(), input_, ProviderType::kHardware);
    static_cast<void>(first.value().Release());

    auto second = hw_key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(ComputeMac(second.value(), input_, ProviderType::kHardware), mac_first);

    auto again = hw_key_mgmt_->GenerateKey(slot, std::nullopt, params);
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(*again.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeySlotOccupied))
        << again.error().Message();
}

TEST_F(Pkcs11KeySlotStoreTest, PersistKey_SlotKeyMatchesSessionKey)
{
    const auto slot = ResolveSlot(kPkcs11PersistSlot);

    GenerateKeyParams params;
    params.SetAlgorithm(std::string{kPkcs11SlotAlgorithm}).SetPermissions(KeyOperationPermission::kMac);

    // An OpenSSL key would have to enter the token as plaintext.
    auto software_key = key_mgmt_->GenerateKey(params);
    ASSERT_TRUE(software_key.has_value());
    auto foreign = hw_key_mgmt_->PersistKey(slot, software_key.value());
    ASSERT_FALSE(foreign.has_value());
    EXPECT_EQ(*foreign.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeyNotExportable))
        << foreign.error().Message();

    auto session_key = hw_key_mgmt_->GenerateKey(params);
    ASSERT_TRUE(session_key.has_value()) << "GenerateKey on PKCS#11 failed";
    auto persisted = hw_key_mgmt_->PersistKey(slot, session_key.value());
    ASSERT_TRUE(persisted.has_value()) << "PersistKey into PKCS#11 slot failed: " << persisted.error().Message();
    ExpectSlotState(*hw_key_mgmt_, slot, KeySlotState::kOccupied);

    const auto session_mac = ComputeMac(session_key.value(), input_, ProviderType::kHardware);
    auto loaded = hw_key_mgmt_->LoadKey(slot);
    ASSERT_TRUE(loaded.has_value()) << "LoadKey from persisted PKCS#11 slot failed";
    EXPECT_EQ(ComputeMac(loaded.value(), input_, ProviderType::kHardware), session_mac);

    auto again = hw_key_mgmt_->PersistKey(slot, session_key.value());
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(*again.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeySlotOccupied))
        << again.error().Message();
}
#endif  // SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
