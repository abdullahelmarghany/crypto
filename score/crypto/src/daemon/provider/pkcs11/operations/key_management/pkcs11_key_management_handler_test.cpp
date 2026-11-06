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

/// @file test_pkcs11_key_handler.cpp
/// @brief Integration tests for Pkcs11KeyManagementHandler and Pkcs11KeySlotHandler
///        using a live SoftHSM2 token.
///
/// ### Test coverage
///  1. GenerateKey_AES256_ReturnsHandle          — KEY_GENERATE via Execute()
///  2. ImportAndRelease_HmacSha256_FullLifecycle — KEY_GENERATE (simulated) + KEY_RELEASE
///  3. LoadKey_ByLabel_ReturnsHandle             — KEY_LOAD via Execute()
///  4. LoadKey_ExtractableKey_ReturnsNativeHandle — token object load
///
/// All tests share the SofthsmTestFixture (SetUp / TearDown initialises a fresh
/// in-memory SoftHSM2 token per test).

#include "score/crypto/tests/softhsm/softhsm_test_fixture.hpp"

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_slot_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/nodes/key_slot_data_node.hpp"
#include "score/crypto/src/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_slot_handler.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include <gtest/gtest.h>
#include <pkcs11.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Namespace aliases
// ---------------------------------------------------------------------------
namespace pkcs11_ns = score::crypto::daemon::provider::pkcs11;
namespace km = score::crypto::daemon::key_management;
namespace dm = score::crypto::daemon::data_manager;
namespace common = score::crypto::daemon::common;
namespace provider = score::crypto::daemon::provider;
namespace handler = score::crypto::daemon::provider::handler;

// ---------------------------------------------------------------------------
// Helper: build a Pkcs11Provider that is already Initialize()'d.
// ---------------------------------------------------------------------------
static std::shared_ptr<pkcs11_ns::Pkcs11Provider> MakeProvider(const std::string& label, const std::string& pin)
{
    pkcs11_ns::Pkcs11ProviderConfig cfg{};
    cfg.tokenLabel = label;
    cfg.userPin = pin;
    cfg.providerName = "SOFTHSM_TEST";

    auto provider = std::make_shared<pkcs11_ns::Pkcs11Provider>(std::move(cfg));
    return provider;
}

// ===========================================================================
// Test fixture: extends SofthsmTestFixture, adds a Pkcs11Provider + executor
// ===========================================================================
class Pkcs11KeyHandlerTest : public tests::softhsm::SofthsmTestFixture
{
  protected:
    std::shared_ptr<pkcs11_ns::Pkcs11Provider> m_provider;
    std::shared_ptr<pkcs11_ns::Pkcs11KeyManagementHandler> m_km_handler;
    std::shared_ptr<dm::DataManager> m_data_manager;
    km::KeyManagementService::Sptr m_service;
    km::SlotRegistry::Sptr m_slot_registry;
    dm::DataNodeId m_parent_id{0U};

    static constexpr dm::ClientId kClient = (42ULL << 32) | 1000ULL;

    void SetUp() override
    {
        SofthsmTestFixture::SetUp();
        if (HasFatalFailure())
        {
            return;
        }

        m_provider = MakeProvider("Test Token", "1234");
        ASSERT_TRUE(m_provider->Initialize(provider::ProviderInitContext{1, "SOFTHSM_TEST"}))
            << "Pkcs11Provider::Initialize() failed";

        m_data_manager = std::make_shared<dm::DataManager>();
        m_slot_registry = std::make_shared<km::SlotRegistry>();
        m_service = std::make_shared<km::KeyManagementService>(m_data_manager, nullptr, m_slot_registry);

        // Register a placeholder parent node.
        auto parent_node = std::make_shared<dm::DataNode>(/*exclusiveAccess=*/false);
        auto reg = m_data_manager->addNode(kClient, parent_node);
        ASSERT_TRUE(reg.has_value());
        m_parent_id = reg.value();

        // Inject the service into the provider so the factory can use it.
        m_provider->SetKeyManagementService(m_service);

        // Create key management handler via factory pattern.
        auto factory = m_provider->GetCryptoHandlerFactory();
        ASSERT_NE(factory, nullptr);

        // KEY:MANAGEMENT handlers are bound to no algorithm.
        auto handler_result = factory->CreateKeyManagementHandler();
        ASSERT_TRUE(handler_result.has_value()) << "CreateHandler failed for key management";
        auto handler = handler_result.value();
        m_km_handler = std::dynamic_pointer_cast<pkcs11_ns::Pkcs11KeyManagementHandler>(handler);
        ASSERT_NE(m_km_handler, nullptr);

        // Initialize handler context with client identity and assigned node IDs
        handler::InitializationParams init_params{.client_id = kClient,
                                                  .context_node_id = m_parent_id,
                                                  .provider_id = 1,
                                                  .key_node_id = 0U,
                                                  .bound_key_handler = nullptr};
        auto init_result = m_km_handler->InitializeContext(init_params);
        ASSERT_TRUE(init_result.has_value()) << "InitializeContext failed";
    }

    void TearDown() override
    {
        m_km_handler.reset();
        m_service.reset();
        m_data_manager.reset();
        if (m_provider)
        {
            m_provider->Shutdown();
            m_provider.reset();
        }
        SofthsmTestFixture::TearDown();
    }

    /// Build parameters for the operation. Context (client_id, context_node_id) comes from InitializeContext().
    void SetStandardParams(common::RequestParameters& params) const
    {
        params.clear();
        // Do NOT include context_id, client_id, or parent_id here
        // These are set via InitializeContext() on the handler
    }

    /// Register a slot and return its DataNodeId.
    dm::DataNodeId RegisterSlotNode(const km::KeySlotConfig& slot_cfg)
    {
        km::SlotHandle handle = m_slot_registry->RegisterSlot(slot_cfg);
        auto slot_node = std::make_shared<km::KeySlotDataNode>(handle, m_slot_registry);
        auto node_id = m_data_manager->addNode(kClient, std::move(slot_node));
        return node_id.has_value() ? node_id.value() : 0U;
    }
};

// ===========================================================================
// Test 1 — GenerateKey_AES256_ReturnsHandle
// ===========================================================================
/// Generates an ephemeral AES-256 key on the PKCS#11 token via KEY_GENERATE.
TEST_F(Pkcs11KeyHandlerTest, GenerateKey_AES256_ReturnsHandle)
{
    common::RequestParameters params;
    SetStandardParams(params);
    const std::string algo = "AES-256";
    params.push_back(std::string_view(algo));
    params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kEncrypt));

    auto result = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, params);
    ASSERT_TRUE(result.has_value()) << "KEY_GENERATE AES-256 failed";
    ASSERT_FALSE(result.value().empty());
    const auto key_node_id = std::get<std::uint64_t>(result.value()[0]);
    EXPECT_NE(key_node_id, 0U);

    // Cleanup: release via KEY_RELEASE
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(key_node_id));
    auto rel = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    EXPECT_TRUE(rel.has_value());
}

// ===========================================================================
// Test 2 — HmacSha256_GenerateAndRelease_FullLifecycle
// ===========================================================================
/// Generates a HMAC-SHA256 key and then releases it via Execute.
TEST_F(Pkcs11KeyHandlerTest, HmacSha256_GenerateAndRelease_FullLifecycle)
{
    common::RequestParameters gen_params;
    SetStandardParams(gen_params);
    const std::string algo = "HMAC-SHA256";
    gen_params.push_back(std::string_view(algo));
    gen_params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kMac));

    auto gen = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen_params);
    ASSERT_TRUE(gen.has_value()) << "KEY_GENERATE HMAC-SHA256 failed";
    const auto key_node_id = std::get<std::uint64_t>(gen.value()[0]);
    EXPECT_NE(key_node_id, 0U);

    // Release
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(key_node_id));

    auto release = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    EXPECT_TRUE(release.has_value()) << "KEY_RELEASE failed";
}

/// Secret keys are never exported in plaintext, not even with kExport: both
/// KEY_EXPORT and KEY_GET_EXPORT_SIZE refuse with kKeyNotExportable for the
/// native-format sentinel and for an explicit kRaw.
TEST_F(Pkcs11KeyHandlerTest, ExportSecretKey_WithExportPermission_IsNotExportable)
{
    common::RequestParameters gen_params;
    SetStandardParams(gen_params);
    const std::string algo = "AES-256";
    gen_params.push_back(std::string_view(algo));
    gen_params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kEncrypt |
                                                    score::crypto::KeyOperationPermission::kExport));

    auto gen = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen_params);
    ASSERT_TRUE(gen.has_value()) << "KEY_GENERATE AES-256 failed";
    const auto key_node_id = std::get<std::uint64_t>(gen.value()[0]);

    const std::uint32_t wire_formats[] = {
        km::operations::kFormatNative,
        static_cast<std::uint32_t>(score::crypto::FormatType::kRaw),
    };
    for (const auto wire_format : wire_formats)
    {
        for (const auto op : {km::operations::KEY_EXPORT, km::operations::KEY_GET_EXPORT_SIZE})
        {
            common::RequestParameters params;
            SetStandardParams(params);
            params.push_back(static_cast<std::uint64_t>(key_node_id));
            params.push_back(wire_format);
            auto result =
                m_km_handler->Execute({score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, op}, params);
            ASSERT_FALSE(result.has_value()) << "op " << static_cast<unsigned>(op) << " format " << wire_format;
            EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeyNotExportable)
                << "op " << static_cast<unsigned>(op) << " format " << wire_format;
        }
    }

    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(key_node_id));
    auto release = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    EXPECT_TRUE(release.has_value()) << "KEY_RELEASE failed";
}

// ===========================================================================
// Test 3 — LoadKey_ByLabel_ReturnsHandle (native PKCS#11 path)
// ===========================================================================
/// Pre-creates a persistent (CKA_TOKEN=true) HMAC key with label "test_hmac"
/// on the token, then calls KEY_LOAD via Execute.
TEST_F(Pkcs11KeyHandlerTest, LoadKey_ByLabel_ReturnsHandle)
{
    const std::string label = "test_hmac";
    std::vector<uint8_t> key_bytes(32, 0xAA);

    const CK_OBJECT_HANDLE token_obj = CreateTokenKey(key_bytes, label, CKK_GENERIC_SECRET, /*extractable=*/false);
    ASSERT_NE(token_obj, static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE)) << "Pre-creating the token key failed";

    km::KeySlotConfig slot{};
    slot.slot_name = "test/hmac_slot";
    slot.algorithm = "HMAC-SHA256";
    // Config-time: populate provider names; runtime would populate provider_ids via ResolveProviderIds
    slot.provider_names = {"SOFTHSM_TEST"};
    slot.provider_ids = {1};  // 1 = SoftHSM (assuming default registration order)
    slot.allowed_operations = score::crypto::KeyOperationPermission::kMac;
    slot.access_policy.allowed_uids.push_back(static_cast<uint32_t>(kClient & 0xFFFFFFFFU));
    // Write a temporary deployment descriptor containing the PKCS#11 label.
    const std::string deploy_path =
        std::string{std::filesystem::temp_directory_path().string()} + "/test_pkcs11_hmac_slot.kv";
    {
        std::ofstream f(deploy_path);
        f << "[metadata]\navailability=active\n[key]\n"
          << std::string{km::deployment_keys::kPkcs11Label} << "=" << label << "\n";
    }
    slot.deployment_path = deploy_path;
    slot.deployment_format = "kv";

    const auto slot_node_id = RegisterSlotNode(slot);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters load_params;
    SetStandardParams(load_params);
    load_params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_LOAD}, load_params);
    ASSERT_TRUE(result.has_value()) << "KEY_LOAD failed";
    ASSERT_FALSE(result.value().empty());
    const auto key_node_id = std::get<std::uint64_t>(result.value()[0]);
    EXPECT_NE(key_node_id, 0U);
}

// ===========================================================================
// Test 4 — LoadKey_ExtractableKey_ReturnsNativeHandle
// ===========================================================================
/// Pre-creates an EXTRACTABLE persistent HMAC key, then verifies LoadKey still
/// returns a valid handle (extractability does not affect slot handler dispatch).
TEST_F(Pkcs11KeyHandlerTest, LoadKey_ExtractableKey_ReturnsNativeHandle)
{
    const std::string label = "test_hmac_extractable";
    std::vector<uint8_t> key_bytes(32, 0xCC);

    const CK_OBJECT_HANDLE token_obj = CreateTokenKey(key_bytes, label, CKK_GENERIC_SECRET, /*extractable=*/true);
    ASSERT_NE(token_obj, static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE))
        << "Pre-creating the extractable token key failed";

    km::KeySlotConfig slot{};
    slot.slot_name = "test/hmac_extract_slot";
    slot.algorithm = "HMAC-SHA256";
    // Config-time: populate provider names; runtime would populate provider_ids via ResolveProviderIds
    slot.provider_names = {"SOFTHSM_TEST"};
    slot.provider_ids = {1};  // 1 = SoftHSM (assuming default registration order)
    slot.allowed_operations = score::crypto::KeyOperationPermission::kMac;
    slot.access_policy.allowed_uids.push_back(static_cast<uint32_t>(kClient & 0xFFFFFFFFU));
    // Write a temporary deployment descriptor containing the PKCS#11 label.
    const std::string deploy_path =
        std::string{std::filesystem::temp_directory_path().string()} + "/test_pkcs11_hmac_extract_slot.kv";
    {
        std::ofstream f(deploy_path);
        f << "[metadata]\navailability=active\n[key]\n"
          << std::string{km::deployment_keys::kPkcs11Label} << "=" << label << "\n";
    }
    slot.deployment_path = deploy_path;
    slot.deployment_format = "kv";

    const auto slot_node_id = RegisterSlotNode(slot);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters load_params;
    SetStandardParams(load_params);
    load_params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_km_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_LOAD}, load_params);
    ASSERT_TRUE(result.has_value()) << "KEY_LOAD (extractable key) failed: " << static_cast<int>(result.error());
    ASSERT_FALSE(result.value().empty());
    EXPECT_NE(std::get<std::uint64_t>(result.value()[0]), 0U);
}

// ===========================================================================
// ClearKey — destroys the slot's token object(s)
// ===========================================================================

class Pkcs11KeyClearTest : public Pkcs11KeyHandlerTest
{
  protected:
    dm::DataNodeId RegisterClearableSlot(const std::string& label, std::vector<common::ProviderId> provider_ids)
    {
        return RegisterSlotWithKeyLines(
            label, std::string{km::deployment_keys::kPkcs11Label} + "=" + label + "\n", std::move(provider_ids));
    }

    dm::DataNodeId RegisterSlotWithKeyLines(const std::string& name,
                                            const std::string& key_lines,
                                            std::vector<common::ProviderId> provider_ids)
    {
        km::KeySlotConfig slot{};
        slot.slot_name = "test/clearable_" + name;
        slot.algorithm = "HMAC-SHA256";
        slot.provider_names = {"SOFTHSM_TEST"};
        slot.provider_ids = std::move(provider_ids);
        slot.allowed_operations = score::crypto::KeyOperationPermission::kMac;
        slot.access_policy.allowed_write_uids.push_back(static_cast<uint32_t>(kClient >> 32U));
        m_deploy_path = std::filesystem::temp_directory_path().string() + "/test_pkcs11_clear_" + name + ".kv";
        m_all_deploy_paths.push_back(m_deploy_path);
        {
            std::ofstream f(m_deploy_path);
            f << "[metadata]\navailability=active\n[key]\n" << key_lines;
        }
        slot.deployment_path = m_deploy_path;
        slot.deployment_format = "kv";
        return RegisterSlotNode(slot);
    }

    void TearDown() override
    {
        for (const auto& path : m_all_deploy_paths)
        {
            std::filesystem::remove(path);
        }
        Pkcs11KeyHandlerTest::TearDown();
    }

    score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Run(std::uint16_t op,
                                                                                     dm::DataNodeId slot_node)
    {
        common::RequestParameters params;
        SetStandardParams(params);
        params.push_back(static_cast<std::uint64_t>(slot_node));
        return m_km_handler->Execute({score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, op}, params);
    }

    std::uint64_t SlotState(dm::DataNodeId slot_node)
    {
        auto info = Run(km::operations::KEY_SLOT_INFO, slot_node);
        return info.has_value() ? std::get<std::uint64_t>(info.value()[0]) : ~0ULL;
    }

    dm::DataNodeId RegisterLabelAndIdSlot(const std::string& name, const std::string& label, const std::string& id)
    {
        return RegisterSlotWithKeyLines(name,
                                        std::string{km::deployment_keys::kPkcs11Label} + "=" + label + "\n" +
                                            std::string{km::deployment_keys::kPkcs11ObjectId} + "=" + id + "\n",
                                        {1});
    }

    /// Number of token objects labelled @p label, read straight from the token.
    CK_ULONG CountObjectsWithLabel(const std::string& label)
    {
        std::vector<CK_UTF8CHAR> value(label.begin(), label.end());
        CK_ATTRIBUTE tmpl{CKA_LABEL, value.data(), static_cast<CK_ULONG>(value.size())};
        if (function_list->C_FindObjectsInit(session, &tmpl, 1U) != CKR_OK)
        {
            return 0U;
        }
        CK_ULONG total = 0U;
        CK_OBJECT_HANDLE found[8]{};
        CK_ULONG count = 0U;
        while ((function_list->C_FindObjects(session, found, 8U, &count) == CKR_OK) && (count > 0U))
        {
            total += count;
        }
        function_list->C_FindObjectsFinal(session);
        return total;
    }

    bool SetObjectId(CK_OBJECT_HANDLE object, std::vector<uint8_t> id)
    {
        CK_ATTRIBUTE attr{CKA_ID, id.data(), static_cast<CK_ULONG>(id.size())};
        return function_list->C_SetAttributeValue(session, object, &attr, 1U) == CKR_OK;
    }

    std::string m_deploy_path;
    std::vector<std::string> m_all_deploy_paths;
};

TEST_F(Pkcs11KeyClearTest, ClearKey_TokenKey_IsDestroyedAndSlotBecomesEmpty)
{
    const std::string label = "test_hmac_clear";
    // Two objects with the same label: both belong to the slot and must go.
    ASSERT_NE(CreateTokenKey(std::vector<uint8_t>(32, 0xA1), label, CKK_GENERIC_SECRET, false),
              static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    ASSERT_NE(CreateTokenKey(std::vector<uint8_t>(32, 0xA2), label, CKK_GENERIC_SECRET, false),
              static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    const auto slot_node = RegisterClearableSlot(label, {1});
    ASSERT_NE(slot_node, 0U);
    ASSERT_TRUE(Run(km::operations::KEY_LOAD, slot_node).has_value());

    auto clear = Run(km::operations::KEY_CLEAR, slot_node);

    ASSERT_TRUE(clear.has_value()) << "KEY_CLEAR failed: " << static_cast<int>(clear.error());
    EXPECT_EQ(SlotState(slot_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kEmpty));
    EXPECT_FALSE(Run(km::operations::KEY_LOAD, slot_node).has_value());
    // Clearing an empty slot succeeds.
    EXPECT_TRUE(Run(km::operations::KEY_CLEAR, slot_node).has_value());
}

TEST_F(Pkcs11KeyClearTest, ClearKey_OtherSlotKeysAreKept)
{
    ASSERT_NE(CreateTokenKey(std::vector<uint8_t>(32, 0xB1), "test_hmac_keep", CKK_GENERIC_SECRET, false),
              static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    ASSERT_NE(CreateTokenKey(std::vector<uint8_t>(32, 0xB2), "test_hmac_drop", CKK_GENERIC_SECRET, false),
              static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    const auto keep_node = RegisterClearableSlot("test_hmac_keep", {1});
    const auto keep_deploy_path = m_deploy_path;
    const auto drop_node = RegisterClearableSlot("test_hmac_drop", {1});
    ASSERT_NE(keep_node, 0U);
    ASSERT_NE(drop_node, 0U);

    ASSERT_TRUE(Run(km::operations::KEY_CLEAR, drop_node).has_value());

    EXPECT_EQ(SlotState(drop_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kEmpty));
    EXPECT_EQ(SlotState(keep_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kOccupied));
    std::filesystem::remove(keep_deploy_path);
}

TEST_F(Pkcs11KeyClearTest, ClearKey_NonPrimaryProvider_IsDenied)
{
    const std::string label = "test_hmac_clear_denied";
    ASSERT_NE(CreateTokenKey(std::vector<uint8_t>(32, 0xC1), label, CKK_GENERIC_SECRET, false),
              static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    const auto slot_node = RegisterClearableSlot(label, {7, 1});
    ASSERT_NE(slot_node, 0U);

    auto clear = Run(km::operations::KEY_CLEAR, slot_node);

    ASSERT_FALSE(clear.has_value());
    EXPECT_EQ(clear.error(), common::DaemonErrorCode::kAccessDenied);
    // The slot's primary provider (7) is not registered here, so KEY_SLOT_INFO cannot
    // reach the slot; check the token directly that the key survived.
    EXPECT_EQ(CountObjectsWithLabel(label), 1U);
}

TEST_F(Pkcs11KeyClearTest, EmptyLabelAndId_LoadAndClearAreRejected)
{
    // A class-only template would match every secret key on the token.
    const auto bystander =
        CreateTokenKey(std::vector<uint8_t>(32, 0xD1), "test_hmac_bystander", CKK_GENERIC_SECRET, false);
    ASSERT_NE(bystander, static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    const auto keep_node = RegisterClearableSlot("test_hmac_bystander", {1});
    const auto keep_deploy_path = m_deploy_path;
    ASSERT_NE(keep_node, 0U);
    const auto slot_node = RegisterSlotWithKeyLines("empty_label_id",
                                                    std::string{km::deployment_keys::kPkcs11Label} + "=\n" +
                                                        std::string{km::deployment_keys::kPkcs11ObjectId} + "=\n",
                                                    {1});
    ASSERT_NE(slot_node, 0U);

    auto load = Run(km::operations::KEY_LOAD, slot_node);
    auto clear = Run(km::operations::KEY_CLEAR, slot_node);

    // HandleLoad reports every slot load failure as kAlgorithmExecutionFailed.
    EXPECT_FALSE(load.has_value());
    ASSERT_FALSE(clear.has_value());
    EXPECT_EQ(clear.error(), common::DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(SlotState(keep_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kOccupied));
    std::filesystem::remove(keep_deploy_path);
}

TEST_F(Pkcs11KeyClearTest, LabelWithMalformedId_IsRejectedAndLabelledKeyKept)
{
    // A malformed ID must not degrade to a label-only match.
    const std::string label = "test_hmac_malformed_id";
    ASSERT_NE(CreateTokenKey(std::vector<uint8_t>(32, 0xE1), label, CKK_GENERIC_SECRET, false),
              static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    const auto label_only_node = RegisterClearableSlot(label, {1});
    ASSERT_NE(label_only_node, 0U);

    for (const std::string id : {"abc", "zz", "0x01"})
    {
        const auto slot_node =
            RegisterLabelAndIdSlot("malformed_" + std::to_string(m_all_deploy_paths.size()), label, id);
        ASSERT_NE(slot_node, 0U);

        auto clear = Run(km::operations::KEY_CLEAR, slot_node);
        ASSERT_FALSE(clear.has_value()) << "id=" << id;
        EXPECT_EQ(clear.error(), common::DaemonErrorCode::kInvalidArgument) << "id=" << id;
        EXPECT_FALSE(Run(km::operations::KEY_SLOT_INFO, slot_node).has_value()) << "id=" << id;
        EXPECT_FALSE(Run(km::operations::KEY_LOAD, slot_node).has_value()) << "id=" << id;
    }

    EXPECT_EQ(SlotState(label_only_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kOccupied));
    // An empty object_id counts as absent, so label-only lookup is intended here.
    const auto empty_id_node = RegisterLabelAndIdSlot("empty_id", label, "");
    ASSERT_NE(empty_id_node, 0U);
    EXPECT_EQ(SlotState(empty_id_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kOccupied));
}

TEST_F(Pkcs11KeyClearTest, MixedCaseHexId_MatchesOnlyTheObjectWithThatId)
{
    const std::string label = "test_hmac_with_id";
    const auto object = CreateTokenKey(std::vector<uint8_t>(32, 0xF1), label, CKK_GENERIC_SECRET, false);
    ASSERT_NE(object, static_cast<CK_OBJECT_HANDLE>(CK_INVALID_HANDLE));
    ASSERT_TRUE(SetObjectId(object, {0xABU, 0x01U, 0xCDU}));
    const auto other_id_node = RegisterLabelAndIdSlot("other_id", label, "ab01ce");
    const auto upper_node = RegisterLabelAndIdSlot("upper_id", label, "AB01CD");
    const auto mixed_node = RegisterLabelAndIdSlot("mixed_id", label, "aB01cD");
    ASSERT_NE(other_id_node, 0U);
    ASSERT_NE(upper_node, 0U);
    ASSERT_NE(mixed_node, 0U);

    EXPECT_EQ(SlotState(other_id_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kEmpty));
    EXPECT_EQ(SlotState(upper_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kOccupied));
    EXPECT_TRUE(Run(km::operations::KEY_LOAD, mixed_node).has_value());

    // Clearing the slot with a different ID leaves the object alone.
    ASSERT_TRUE(Run(km::operations::KEY_CLEAR, other_id_node).has_value());
    EXPECT_EQ(SlotState(upper_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kOccupied));

    ASSERT_TRUE(Run(km::operations::KEY_CLEAR, mixed_node).has_value());
    EXPECT_EQ(SlotState(upper_node), static_cast<std::uint64_t>(score::crypto::KeySlotState::kEmpty));
}

// ---------------------------------------------------------------------------
// Main entry point: @googletest//:gtest_main supplies main()
// ---------------------------------------------------------------------------
