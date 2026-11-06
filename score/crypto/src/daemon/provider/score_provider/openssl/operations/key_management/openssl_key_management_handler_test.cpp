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

/// @file test_key_management_context.cpp
/// @brief Integration tests for OpenSslKeyManagementHandler + KeyManagementService.
///
/// Uses real DataManager, real SlotRegistry (built-in slot definitions from
/// binary config configuration), real
/// OpenSslKeyManagementHandler and FileBackedSlotHandler. Exercises the full
/// handler dispatch flow without mocks.

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/key_management/openssl_key_management_handler.hpp"
#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/config/src/flatbuffer_config_parser.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/key_management/core/key_entry.hpp"
#include "score/crypto/src/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/nodes/key_slot_data_node.hpp"
#include "score/crypto/src/daemon/key_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/src/daemon/key_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/key_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/provider/executors/key_mgmt_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"

#include <gtest/gtest.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace km = score::crypto::daemon::key_management;
namespace dm = score::crypto::daemon::data_manager;
namespace ossl = score::crypto::daemon::provider::openssl;
namespace handler = score::crypto::daemon::provider::handler;
namespace handler_ns = score::crypto::daemon::provider::score_provider::openssl::handler;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace crypto_executor = score::crypto::daemon::provider::crypto_executor;

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------
class KeyManagementHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_data_manager = std::make_shared<dm::DataManager>();
        m_km_handler = std::make_shared<ossl::OpenSslKeyFactory>(kProviderId);
        m_slot_handler = std::make_shared<km::FileBackedSlotHandler>(m_km_handler);
        m_slot_registry = std::make_shared<km::SlotRegistry>();

        // Load test slot definitions from test config
        config::KeyConfig test_config{};
        auto result = config::FlatBufferConfigParser::ParseFromFile(
            "score/crypto/tests/key_management/config/key_management_test_config.bin", test_config);
        ASSERT_TRUE(result.has_value()) << "Failed to parse test config";

        // Use ConfigDrivenSlotCatalog to properly convert and register slots
        km::ConfigDrivenSlotCatalog catalog{test_config};
        catalog.Load(*m_slot_registry);

        // KeyManagementService needs a DataManager, optional ProviderManager, and config.
        m_service =
            std::make_shared<km::KeyManagementService>(m_data_manager, nullptr /*provider_manager*/, m_slot_registry);

        // Register a placeholder parent (context) node so we have a valid parent_id.
        auto parent_node = std::make_shared<dm::DataNode>(/*exclusiveAccess=*/false);
        auto reg = m_data_manager->addNode(kAllowedClient, parent_node);
        ASSERT_TRUE(reg.has_value());
        m_parent_id = reg.value();

        // Build the handler: factory creates executor and injects into handler
        auto executor =
            std::make_unique<crypto_executor::KeyManagementExecutor>(m_km_handler, m_slot_handler, m_service);
        m_handler = std::make_shared<handler_ns::OpenSslKeyManagementHandler>(std::move(executor));

        // Initialize handler context with client identity and assigned node IDs
        handler::InitializationParams init_params{.client_id = kAllowedClient,
                                                  .context_node_id = m_parent_id,
                                                  .provider_id = kProviderId,
                                                  .key_node_id = 0U,
                                                  .bound_key_handler = nullptr};
        auto init_result = m_handler->InitializeContext(init_params);
        ASSERT_TRUE(init_result.has_value()) << "InitializeContext failed";
    }

    /// Helper: clear parameters. Context (client_id, context_node_id) comes from InitializeContext().
    void SetStandardParams(common::RequestParameters& params) const
    {
        params.clear();
        // Do NOT include context_id, client_id, or parent_id here
        // These are set via InitializeContext() on the handler
    }

    /// Helper: resolve a slot and register it as a KeySlotDataNode.
    dm::DataNodeId ResolveSlotToDataNode(const std::string& slot_name, dm::ClientId client_id)
    {
        auto handle = m_slot_registry->ResolveSlot(slot_name, client_id);
        if (!handle.has_value())
        {
            return 0U;
        }
        auto slot_node = std::make_shared<km::KeySlotDataNode>(handle.value(), m_slot_registry);
        auto node_id = m_data_manager->addNode(client_id, std::move(slot_node));
        return node_id.has_value() ? node_id.value() : 0U;
    }

    /// Client with UID=1000 (allowed) in upper 32 bits, PID=42 in lower 32 bits
    static constexpr dm::ClientId kAllowedClient = (1000ULL << 32) | 42ULL;
    /// Client with UID=9999 (not in allowed_uids list) in upper 32 bits
    static constexpr dm::ClientId kDeniedClient = (9999ULL << 32) | 42ULL;
    static constexpr common::ProviderId kProviderId = 0;  // OPENSSL provider (registered first)

    km::SlotRegistry::Sptr m_slot_registry;
    km::IKeyFactory::Sptr m_km_handler;
    km::IKeySlotHandler::Sptr m_slot_handler;
    km::KeyManagementService::Sptr m_service;
    std::shared_ptr<handler_ns::OpenSslKeyManagementHandler> m_handler;
    dm::DataNodeId m_parent_id{0U};
    // Keep last to destroy first
    dm::DataManager::Sptr m_data_manager;
};

// ============================================================================
// PeekKeyHandle: permission metadata before any key material is loaded
// ============================================================================

TEST_F(KeyManagementHandlerTest, PeekKeyHandle_KnownSlot_ReturnsAllowedOperationsWithoutLoading)
{
    const auto slot_node = ResolveSlotToDataNode("test/hmac-sha256", kAllowedClient);
    ASSERT_NE(slot_node, 0U) << "slot resolution failed";

    auto peek = m_service->PeekKeyHandle(kAllowedClient, slot_node);
    ASSERT_TRUE(peek.has_value()) << "PeekKeyHandle failed for a known slot";

    // The slot's allowed_operations govern whatever key it holds.
    EXPECT_EQ(peek.value().permissions, score::crypto::KeyOperationPermission::kMac);
    EXPECT_FALSE(peek.value().is_asymmetric);
}

TEST_F(KeyManagementHandlerTest, PeekKeyHandle_UnknownNode_ReturnsError)
{
    constexpr dm::DataNodeId kNoSuchNode = 0xFFFF'FFF0U;
    auto peek = m_service->PeekKeyHandle(kAllowedClient, kNoSuchNode);
    ASSERT_FALSE(peek.has_value());
    EXPECT_EQ(peek.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST_F(KeyManagementHandlerTest, PeekKeyHandle_NonKeyNode_ReturnsError)
{
    // The fixture's parent node is a plain DataNode, neither slot nor key.
    auto peek = m_service->PeekKeyHandle(kAllowedClient, m_parent_id);
    ASSERT_FALSE(peek.has_value());
    EXPECT_EQ(peek.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ============================================================================
// GetKeySlotInfo tests (via Execute with KEY_SLOT_INFO)
// ============================================================================

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_KnownSlot_ReturnsState)
{
    const auto slot_node_id = ResolveSlotToDataNode("test/hmac-sha256", kAllowedClient);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters params;
    SetStandardParams(params);
    params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result.value().empty());
}

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_SecondSlot_ReturnsState)
{
    const auto slot_node_id = ResolveSlotToDataNode("test/aes-256-cmac", kAllowedClient);
    ASSERT_NE(slot_node_id, 0U);

    common::RequestParameters params;
    SetStandardParams(params);
    params.push_back(static_cast<std::uint64_t>(slot_node_id));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_TRUE(result.has_value());
}

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_InvalidSlotNodeId_ReturnsError)
{
    common::RequestParameters params;
    SetStandardParams(params);
    params.push_back(static_cast<std::uint64_t>(0xFFFFFFFFU));  // invalid

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_FALSE(result.has_value());
}

TEST_F(KeyManagementHandlerTest, GetKeySlotInfo_DeniedClient_ReturnsError)
{
    // A client whose UID is NOT in the slot's allowed_uids must be denied access.
    // We verify this at the SlotRegistry::ResolveSlot level (where access control
    // is enforced) rather than through the handler, because the handler's context
    // is fixed at InitializeContext time.

    // 1. Ensure the slot exists and can be resolved by the allowed client.
    const auto allowed_slot = m_slot_registry->ResolveSlot("test/hmac-sha256", kAllowedClient);
    ASSERT_TRUE(allowed_slot.has_value()) << "Slot must be resolvable by allowed client";

    // 2. The denied client (UID 9999) must fail resolution.
    const auto denied_slot = m_slot_registry->ResolveSlot("test/hmac-sha256", kDeniedClient);
    ASSERT_FALSE(denied_slot.has_value()) << "Denied client must not resolve the slot";

    // 3. Additionally, build a handler initialized as kDeniedClient and verify
    //    that KEY_SLOT_INFO returns an error when no valid slot node can be provided.
    auto denied_executor =
        std::make_unique<crypto_executor::KeyManagementExecutor>(m_km_handler, m_slot_handler, m_service);
    auto denied_handler = std::make_shared<handler_ns::OpenSslKeyManagementHandler>(std::move(denied_executor));

    auto denied_parent_node = std::make_shared<dm::DataNode>(/*exclusiveAccess=*/false);
    auto denied_parent = m_data_manager->addNode(kDeniedClient, denied_parent_node);
    ASSERT_TRUE(denied_parent.has_value());

    handler::InitializationParams denied_init{.client_id = kDeniedClient,
                                              .context_node_id = denied_parent.value(),
                                              .provider_id = kProviderId,
                                              .key_node_id = 0U,
                                              .bound_key_handler = nullptr};
    auto init_result = denied_handler->InitializeContext(denied_init);
    ASSERT_TRUE(init_result.has_value()) << "Handler init must succeed (denial is at slot level)";

    // Denied client has no valid slot data node, so an invalid id yields an error.
    common::RequestParameters params;
    params.push_back(static_cast<std::uint64_t>(0xFFFFFFFFU));

    auto result = denied_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_SLOT_INFO}, params);
    ASSERT_FALSE(result.has_value()) << "Denied client must not access slot info";
}

// ============================================================================
// GenerateKey tests (ephemeral keys, via Execute with KEY_GENERATE)
// ============================================================================

TEST_F(KeyManagementHandlerTest, GenerateKey_HmacSha256_ReturnsNodeId)
{
    common::RequestParameters params;
    SetStandardParams(params);
    const std::string algo = "HMAC-SHA256";
    params.push_back(std::string_view(algo));
    params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kMac));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, params);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result.value().empty());
    EXPECT_NE(std::get<std::uint64_t>(result.value()[0]), 0U);
}

TEST_F(KeyManagementHandlerTest, GenerateKey_UnknownAlgorithm_ReturnsError)
{
    common::RequestParameters params;
    SetStandardParams(params);
    const std::string algo = "UNKNOWN-ALGO";
    params.push_back(std::string_view(algo));
    params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kMac));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, params);
    ASSERT_FALSE(result.has_value());
    // The request parser resolves the name; the catalog does not know it.
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
}

TEST_F(KeyManagementHandlerTest, GenerateKey_EcdsaSignatureRow_ReturnsNodeId)
{
    // A signature row labels its key: the row's curve selects the key.
    common::RequestParameters params;
    SetStandardParams(params);
    const std::string algo = "ECDSA-P384-SHA256";
    params.push_back(std::string_view(algo));
    params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kSign));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, params);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result.value().empty());
    EXPECT_NE(std::get<std::uint64_t>(result.value()[0]), 0U);
}

// ============================================================================
// Configured slots: names are resolved when the configuration is loaded
// ============================================================================

TEST(ConfigDrivenSlotCatalogTest, Load_UnknownAlgorithm_SkipsOnlyThatSlot)
{
    config::KeyConfig key_config{};
    config::KeyConfig::KeySlotEntry known{};
    known.slot_name = "test/known";
    known.algorithm = "HMAC-SHA256";
    known.provider_names = {"OPENSSL"};
    known.allowed_operations = "MAC";
    known.allowed_uids = {1000U};
    key_config.AddSlotEntry(known);

    config::KeyConfig::KeySlotEntry unknown = known;
    unknown.slot_name = "test/unknown";
    unknown.algorithm = "HMAC-SHA-256";
    key_config.AddSlotEntry(unknown);

    km::SlotRegistry registry{};
    km::ConfigDrivenSlotCatalog catalog{key_config};
    catalog.Load(registry);

    EXPECT_EQ(registry.GetSlotCount(), 1U);
    constexpr dm::ClientId kClient = (1000ULL << 32) | 42ULL;
    EXPECT_TRUE(registry.ResolveSlot("test/known", kClient).has_value());
    EXPECT_FALSE(registry.ResolveSlot("test/unknown", kClient).has_value());
}

// ============================================================================
// Execute dispatch tests
// ============================================================================

TEST_F(KeyManagementHandlerTest, Execute_UnknownAction_ReturnsError)
{
    common::RequestParameters params;
    SetStandardParams(params);

    auto result = m_handler->Execute({score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, 0xFFFFU}, params);
    ASSERT_FALSE(result.has_value());
}

// ============================================================================
// ReleaseKey tests
// ============================================================================

TEST_F(KeyManagementHandlerTest, GenerateAndRelease_EphemeralKey_FullLifecycle)
{
    // Generate
    common::RequestParameters gen_params;
    SetStandardParams(gen_params);
    const std::string algo = "HMAC-SHA256";
    gen_params.push_back(std::string_view(algo));
    gen_params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kMac));

    auto gen = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen_params);
    ASSERT_TRUE(gen.has_value());
    const auto key_node_id = std::get<std::uint64_t>(gen.value()[0]);

    // Release
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(key_node_id));

    auto release = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    ASSERT_TRUE(release.has_value());
}

TEST_F(KeyManagementHandlerTest, ReleaseKey_InvalidNodeId_ReturnsError)
{
    common::RequestParameters rel_params;
    SetStandardParams(rel_params);
    rel_params.push_back(static_cast<std::uint64_t>(0xDEADBEEFU));

    auto result = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel_params);
    ASSERT_FALSE(result.has_value());
}

// ============================================================================
// Multiple ephemeral keys -- independent lifecycle
// ============================================================================

TEST_F(KeyManagementHandlerTest, MultipleEphemeralKeys_IndependentLifecycle)
{
    const std::string algo1 = "HMAC-SHA256";
    const std::string algo2 = "HMAC-SHA512";

    // Generate key 1
    common::RequestParameters gen1_params;
    SetStandardParams(gen1_params);
    gen1_params.push_back(std::string_view(algo1));
    gen1_params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kMac));

    auto g1 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen1_params);
    ASSERT_TRUE(g1.has_value());
    const auto g1_id = std::get<std::uint64_t>(g1.value()[0]);

    // Generate key 2
    common::RequestParameters gen2_params;
    SetStandardParams(gen2_params);
    gen2_params.push_back(std::string_view(algo2));
    gen2_params.push_back(static_cast<std::uint64_t>(score::crypto::KeyOperationPermission::kMac));

    auto g2 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_GENERATE}, gen2_params);
    ASSERT_TRUE(g2.has_value());
    const auto g2_id = std::get<std::uint64_t>(g2.value()[0]);

    EXPECT_NE(g1_id, g2_id);

    // Release in reverse order
    common::RequestParameters rel2_params;
    SetStandardParams(rel2_params);
    rel2_params.push_back(g2_id);
    auto r2 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel2_params);
    EXPECT_TRUE(r2.has_value());

    common::RequestParameters rel1_params;
    SetStandardParams(rel1_params);
    rel1_params.push_back(g1_id);
    auto r1 = m_handler->Execute(
        {score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, km::operations::KEY_RELEASE}, rel1_params);
    EXPECT_TRUE(r1.has_value());
}

// ============================================================================
// ClearKey tests (via Execute with KEY_CLEAR)
// ============================================================================

class KeyClearTest : public KeyManagementHandlerTest
{
  protected:
    void SetUp() override
    {
        KeyManagementHandlerTest::SetUp();
        m_dir =
            std::filesystem::temp_directory_path() /
            ("score_crypto_key_clear_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(m_dir);
        m_key_path = m_dir / "slot.key";
        {
            std::ofstream key{m_key_path, std::ios::binary};
            key << std::string(32U, 'K');
        }
        std::ofstream kv{m_dir / "slot.kv"};
        kv << "[metadata]\navailability=active\n[key]\nkey_path=" << m_key_path.string() << "\nkey_format=raw\n";
    }

    void TearDown() override
    {
        std::filesystem::remove_all(m_dir);
    }

    /// Register a slot backed by the temp key file and return its slot node for kAllowedClient.
    dm::DataNodeId RegisterClearableSlot(const std::string& name,
                                         std::vector<std::uint32_t> write_uids,
                                         std::vector<common::ProviderId> provider_ids)
    {
        km::KeySlotConfig cfg{};
        cfg.slot_name = name;
        cfg.algorithm = "AES-256";
        cfg.provider_ids = std::move(provider_ids);
        cfg.allowed_operations = score::crypto::KeyOperationPermission::kMac;
        cfg.access_policy.allowed_uids = {1000U};
        cfg.access_policy.allowed_write_uids = std::move(write_uids);
        cfg.deployment_path = (m_dir / "slot.kv").string();
        cfg.deployment_format = "kv";
        static_cast<void>(m_slot_registry->RegisterSlot(cfg));
        return ResolveSlotToDataNode(name, kAllowedClient);
    }

    score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Run(std::uint16_t op,
                                                                                     dm::DataNodeId slot_node)
    {
        common::RequestParameters params;
        SetStandardParams(params);
        params.push_back(static_cast<std::uint64_t>(slot_node));
        return m_handler->Execute({score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, op}, params);
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_key_path;
};

TEST_F(KeyClearTest, ClearKey_WriteAllowed_ErasesKeyAndSlotBecomesEmpty)
{
    const auto slot_node = RegisterClearableSlot("test/clearable", {1000U}, {kProviderId});
    ASSERT_NE(slot_node, 0U);
    ASSERT_TRUE(Run(km::operations::KEY_LOAD, slot_node).has_value());

    auto clear = Run(km::operations::KEY_CLEAR, slot_node);

    ASSERT_TRUE(clear.has_value());
    EXPECT_FALSE(std::filesystem::exists(m_key_path));
    auto info = Run(km::operations::KEY_SLOT_INFO, slot_node);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(std::get<std::uint64_t>(info.value()[0]),
              static_cast<std::uint64_t>(score::crypto::KeySlotState::kEmpty));
    // The key loaded before the clear must not be shared to a new load.
    EXPECT_FALSE(Run(km::operations::KEY_LOAD, slot_node).has_value());
}

TEST_F(KeyClearTest, ClearKey_EmptySlot_Succeeds)
{
    const auto slot_node = RegisterClearableSlot("test/clearable", {1000U}, {kProviderId});
    ASSERT_NE(slot_node, 0U);

    ASSERT_TRUE(Run(km::operations::KEY_CLEAR, slot_node).has_value());
    EXPECT_TRUE(Run(km::operations::KEY_CLEAR, slot_node).has_value());
}

TEST_F(KeyClearTest, ClearKey_UidWithoutWriteAccess_IsDenied)
{
    const auto slot_node = RegisterClearableSlot("test/clearable", {0U}, {kProviderId});
    ASSERT_NE(slot_node, 0U);

    auto clear = Run(km::operations::KEY_CLEAR, slot_node);

    ASSERT_FALSE(clear.has_value());
    EXPECT_EQ(clear.error(), common::DaemonErrorCode::kAccessDenied);
    EXPECT_TRUE(std::filesystem::exists(m_key_path));
}

TEST_F(KeyClearTest, ClearKey_NonPrimaryProvider_IsDenied)
{
    constexpr common::ProviderId kOtherProvider = 5U;
    const auto slot_node = RegisterClearableSlot("test/clearable", {1000U}, {kOtherProvider, kProviderId});
    ASSERT_NE(slot_node, 0U);

    auto clear = Run(km::operations::KEY_CLEAR, slot_node);

    ASSERT_FALSE(clear.has_value());
    EXPECT_EQ(clear.error(), common::DaemonErrorCode::kAccessDenied);
    EXPECT_TRUE(std::filesystem::exists(m_key_path));
}

TEST_F(KeyClearTest, ClearKey_InvalidSlotNode_ReturnsInvalidArgument)
{
    auto clear = Run(km::operations::KEY_CLEAR, m_parent_id);

    ASSERT_FALSE(clear.has_value());
    EXPECT_EQ(clear.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ============================================================================
// Storing keys into slots (KEY_GENERATE_TO_SLOT, KEY_IMPORT_TO_SLOT, KEY_PERSIST)
// ============================================================================

class KeyManagementStoreToSlotTest : public KeyManagementHandlerTest
{
  protected:
    void SetUp() override
    {
        KeyManagementHandlerTest::SetUp();
        m_dir = std::filesystem::temp_directory_path() /
                ("score_crypto_store_to_slot_" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(m_dir);
    }

    void TearDown() override
    {
        std::filesystem::remove_all(m_dir);
    }

    /// Register an empty AES-256/MAC slot whose deployment descriptor points at
    /// a key file that does not exist yet. Returns the slot data node id.
    dm::DataNodeId AddEmptySlot(const std::string& name,
                                std::vector<std::uint32_t> write_uids = {kWriterUid},
                                std::vector<common::ProviderId> provider_ids = {kProviderId})
    {
        const auto descriptor = m_dir / (name + ".kv");
        std::ofstream kv{descriptor};
        kv << "[metadata]\navailability=active\n[key]\nkey_path=" << KeyPath(name) << "\n";
        kv.close();

        km::KeySlotConfig cfg{};
        cfg.slot_name = "store/" + name;
        cfg.algorithm = "AES-256";
        cfg.provider_ids = std::move(provider_ids);
        cfg.allowed_operations = score::crypto::KeyOperationPermission::kMac;
        cfg.access_policy.allowed_uids = {kWriterUid};
        cfg.access_policy.allowed_write_uids = std::move(write_uids);
        cfg.deployment_path = descriptor.string();
        cfg.deployment_format = "kv";
        m_slot_registry->RegisterSlot(std::move(cfg));
        return ResolveSlotToDataNode("store/" + name, kAllowedClient);
    }

    std::string KeyPath(const std::string& name) const
    {
        return (m_dir / "keys" / (name + ".key")).string();
    }

    std::vector<std::uint8_t> ReadKeyFile(const std::string& name) const
    {
        std::ifstream in{KeyPath(name), std::ios::binary};
        return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    }

    score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Exec(std::uint16_t op,
                                                                                      common::RequestParameters params)
    {
        return m_handler->Execute({score::crypto::daemon::common::actors::OP_ACTOR_KEY_MANAGEMENT, op}, params);
    }

    score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> ImportToSlot(
        dm::DataNodeId slot,
        const std::string& algorithm)
    {
        common::RequestParameters params;
        params.push_back(static_cast<std::uint64_t>(slot));
        params.push_back(std::string_view(algorithm));
        params.push_back(static_cast<std::uint32_t>(score::crypto::KeyOperationPermission::kMac));
        params.push_back(static_cast<std::uint32_t>(score::crypto::FormatType::kRaw));
        params.push_back(score::cpp::span<const std::uint8_t>{m_key.data(), m_key.size()});
        return Exec(km::operations::KEY_IMPORT_TO_SLOT, std::move(params));
    }

    score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> GenerateToSlot(
        dm::DataNodeId slot,
        const std::string& algorithm)
    {
        common::RequestParameters params;
        params.push_back(static_cast<std::uint64_t>(slot));
        params.push_back(std::string_view(algorithm));
        return Exec(km::operations::KEY_GENERATE_TO_SLOT, std::move(params));
    }

    /// Generate a volatile AES-256 key with @p perms; returns its node id.
    std::uint64_t GenerateVolatile(score::crypto::KeyOperationPermission perms)
    {
        common::RequestParameters params;
        params.push_back(std::string_view("AES-256"));
        params.push_back(static_cast<std::uint32_t>(perms));
        auto res = Exec(km::operations::KEY_GENERATE, std::move(params));
        return res.has_value() ? std::get<std::uint64_t>(res.value()[0]) : 0U;
    }

    score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Persist(dm::DataNodeId slot,
                                                                                         std::uint64_t key)
    {
        common::RequestParameters params;
        params.push_back(static_cast<std::uint64_t>(slot));
        params.push_back(key);
        return Exec(km::operations::KEY_PERSIST, std::move(params));
    }

    static constexpr std::uint32_t kWriterUid = 1000U;
    std::filesystem::path m_dir;
    const std::vector<std::uint8_t> m_key = std::vector<std::uint8_t>(32U, 0x5AU);
};

TEST_F(KeyManagementStoreToSlotTest, ImportToSlot_StoresRawBytesAndSlotLoads)
{
    const auto slot = AddEmptySlot("import");
    ASSERT_NE(slot, 0U);

    auto result = ImportToSlot(slot, "AES-256");
    ASSERT_TRUE(result.has_value()) << static_cast<int>(result.error());

    EXPECT_EQ(ReadKeyFile("import"), m_key);
    const auto perms = std::filesystem::status(KeyPath("import")).permissions() & std::filesystem::perms::all;
    EXPECT_EQ(perms, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

    common::RequestParameters load;
    load.push_back(static_cast<std::uint64_t>(slot));
    auto loaded = Exec(km::operations::KEY_LOAD, std::move(load));
    ASSERT_TRUE(loaded.has_value());
    auto handle = m_service->PeekKeyHandle(kAllowedClient, std::get<std::uint64_t>(loaded.value()[0]));
    ASSERT_TRUE(handle.has_value());
    EXPECT_EQ(handle.value().permissions, score::crypto::KeyOperationPermission::kMac);
}

TEST_F(KeyManagementStoreToSlotTest, GenerateToSlot_StoresFreshKeyOfSlotSize)
{
    const auto slot = AddEmptySlot("generate");
    ASSERT_NE(slot, 0U);

    auto result = GenerateToSlot(slot, "AES-256");
    ASSERT_TRUE(result.has_value()) << static_cast<int>(result.error());

    EXPECT_EQ(ReadKeyFile("generate").size(), 32U);
    common::RequestParameters info;
    info.push_back(static_cast<std::uint64_t>(slot));
    auto state = Exec(km::operations::KEY_SLOT_INFO, std::move(info));
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(std::get<std::uint64_t>(state.value()[0]),
              static_cast<std::uint64_t>(score::crypto::KeySlotState::kOccupied));
}

TEST_F(KeyManagementStoreToSlotTest, StoreIntoOccupiedSlot_IsRefused)
{
    const auto slot = AddEmptySlot("occupied");
    ASSERT_TRUE(ImportToSlot(slot, "AES-256").has_value());

    auto again = GenerateToSlot(slot, "AES-256");
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(again.error(), common::DaemonErrorCode::kKeySlotOccupied);
    EXPECT_EQ(ReadKeyFile("occupied"), m_key);
}

TEST_F(KeyManagementStoreToSlotTest, AlgorithmNotMatchingSlot_IsRefused)
{
    const auto slot = AddEmptySlot("mismatch");

    auto result = ImportToSlot(slot, "AES-128");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAlgorithmMismatch);
    EXPECT_FALSE(std::filesystem::exists(KeyPath("mismatch")));
}

TEST_F(KeyManagementStoreToSlotTest, ClientWithoutWriteAccess_IsRefused)
{
    const auto slot = AddEmptySlot("read-only", /*write_uids=*/{0U});

    auto result = GenerateToSlot(slot, "AES-256");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAccessDenied);
    EXPECT_FALSE(std::filesystem::exists(KeyPath("read-only")));
}

TEST_F(KeyManagementStoreToSlotTest, SecondaryProvider_IsRefused)
{
    constexpr common::ProviderId kOtherPrimary = 7;
    const auto slot = AddEmptySlot("secondary", {kWriterUid}, {kOtherPrimary, kProviderId});

    auto result = ImportToSlot(slot, "AES-256");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAccessDenied);
}

TEST_F(KeyManagementStoreToSlotTest, Persist_StoresVolatileKeyWhichStaysUsable)
{
    const auto slot = AddEmptySlot("persist");
    const auto key =
        GenerateVolatile(score::crypto::KeyOperationPermission::kMac | score::crypto::KeyOperationPermission::kExport);
    ASSERT_NE(key, 0U);

    auto result = Persist(slot, key);
    ASSERT_TRUE(result.has_value()) << static_cast<int>(result.error());

    // The volatile key is still registered and holds the bytes now in the slot.
    auto entry = m_service->ResolveKeyForOperation(kAllowedClient, key);
    ASSERT_TRUE(entry.has_value());
    auto exported = entry.value()->GetKeyHandler()->Export();
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported.value().bytes, ReadKeyFile("persist"));
}

TEST_F(KeyManagementStoreToSlotTest, Persist_KeyNarrowerThanSlot_IsRefused)
{
    const auto slot = AddEmptySlot("narrow");
    const auto key = GenerateVolatile(score::crypto::KeyOperationPermission::kEncrypt);
    ASSERT_NE(key, 0U);

    auto result = Persist(slot, key);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
    EXPECT_FALSE(std::filesystem::exists(KeyPath("narrow")));
}
