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

#include "score/crypto/src/daemon/key_management/slot/file_backed_slot_handler.hpp"

#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace score::crypto::daemon::key_management
{
namespace
{
using Error = common::DaemonErrorCode;

/// Holds plain bytes and hands them out as its storage form.
class FakeKeyHandler final : public IKeyHandler
{
  public:
    explicit FakeKeyHandler(std::vector<std::uint8_t> bytes, ProviderKeyHandle handle = {})
        : m_bytes{std::move(bytes)}, m_handle{handle}
    {
    }

    const ProviderKeyHandle& GetHandle() const noexcept override
    {
        return m_handle;
    }
    common::ProviderId GetProviderId() const noexcept override
    {
        return m_handle.provider_id;
    }
    score::crypto::Expected<std::monostate, Error> Release() override
    {
        m_bytes.clear();
        return std::monostate{};
    }
    score::crypto::Expected<SecureKeyBytes, Error> Export() const override
    {
        return score::crypto::make_unexpected(Error::kKeyOperationNotPermitted);
    }
    score::crypto::Expected<SecureKeyBytes, Error> SerializeForStorage() const override
    {
        SecureKeyBytes out;
        out.bytes = m_bytes;
        return out;
    }
    score::crypto::Expected<SecureKeyBytes, Error> SerializePublicKeyForStorage() const override
    {
        SecureKeyBytes out;
        out.bytes = m_public_bytes;
        return out;
    }

    void SetPublicBytes(std::vector<std::uint8_t> bytes)
    {
        m_public_bytes = std::move(bytes);
    }

    const std::vector<std::uint8_t>& Bytes() const
    {
        return m_bytes;
    }

  private:
    std::vector<std::uint8_t> m_bytes;
    std::vector<std::uint8_t> m_public_bytes;
    ProviderKeyHandle m_handle;
};

/// Import echoes the bytes and the requested permissions back as a FakeKeyHandler.
class FakeKeyFactory final : public IKeyFactory
{
  public:
    score::crypto::Expected<IKeyHandler::Sptr, Error> ImportKey(const KeyImportRequest& request) override
    {
        ProviderKeyHandle handle{};
        handle.permissions = request.permissions;
        handle.algorithm = request.algorithm;
        return std::make_shared<FakeKeyHandler>(
            std::vector<std::uint8_t>(request.key_data, request.key_data + request.key_data_size), handle);
    }
};

class FileBackedSlotHandlerStoreTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_dir =
            std::filesystem::temp_directory_path() /
            ("score_crypto_slot_store_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(m_dir);
        m_key_path = m_dir / "keys" / "slot.key";

        const auto descriptor = m_dir / "slot.kv";
        std::ofstream kv{descriptor};
        kv << "[metadata]\navailability=active\n[key]\nkey_path=" << m_key_path.string() << "\n";
        kv.close();

        m_public_key_path = m_dir / "keys" / "slot.pub";
        const auto public_descriptor = m_dir / "slot_pub.kv";
        std::ofstream public_kv{public_descriptor};
        public_kv << "[metadata]\navailability=active\n[key]\nkey_path=" << m_public_key_path.string()
                  << "\nkey_format=der\n";
        public_kv.close();

        m_private_slot.slot_name = "test/pair_private";
        m_private_slot.algorithm = "ECDSA-P256";
        m_private_slot.allowed_operations = score::crypto::KeyOperationPermission::kSign;
        m_private_slot.deployment_path = descriptor.string();
        m_private_slot.deployment_format = "kv";
        m_public_slot = m_private_slot;
        m_public_slot.slot_name = "test/pair_public";
        m_public_slot.allowed_operations = score::crypto::KeyOperationPermission::kVerify;
        m_public_slot.deployment_path = public_descriptor.string();

        m_pair.SetPublicBytes(m_public_key);

        m_slot.slot_name = "test/store";
        m_slot.algorithm = "AES-256";
        m_slot.allowed_operations = score::crypto::KeyOperationPermission::kMac;
        m_slot.deployment_path = descriptor.string();
        m_slot.deployment_format = "kv";
    }

    void TearDown() override
    {
        std::filesystem::remove_all(m_dir);
    }

    std::shared_ptr<FakeKeyFactory> m_factory{std::make_shared<FakeKeyFactory>()};
    std::filesystem::path m_dir;
    std::filesystem::path m_key_path;
    std::filesystem::path m_public_key_path;
    KeySlotConfig m_slot;
    KeySlotConfig m_private_slot;
    KeySlotConfig m_public_slot;
    const std::vector<std::uint8_t> m_key{0x10U, 0x20U, 0x30U, 0x40U};
    const std::vector<std::uint8_t> m_public_key{0x30U, 0x59U, 0x01U};
    FakeKeyHandler m_pair{{0x30U, 0x81U, 0x02U}};
};

void WriteDescriptor(const std::string& descriptor, const std::filesystem::path& key_path, const std::string& extra)
{
    std::ofstream kv{descriptor, std::ios::trunc};
    kv << "[metadata]\navailability=active\n[key]\nkey_path=" << key_path.string() << "\n" << extra;
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreThenLoad_RoundTripsMaterialWithSlotPermissions)
{
    FileBackedSlotHandler slot_handler{m_factory};
    ASSERT_EQ(slot_handler.GetSlotState(m_slot).value(), score::crypto::KeySlotState::kEmpty);

    FakeKeyHandler key{m_key};
    ASSERT_TRUE(slot_handler.StoreKey(m_slot, key).has_value());

    EXPECT_EQ(slot_handler.GetSlotState(m_slot).value(), score::crypto::KeySlotState::kOccupied);
    const auto perms = std::filesystem::status(m_key_path).permissions() & std::filesystem::perms::all;
    EXPECT_EQ(perms, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

    auto loaded = slot_handler.LoadKey(m_slot);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(static_cast<FakeKeyHandler&>(*loaded.value()).Bytes(), m_key);  // NOLINT
    EXPECT_EQ(loaded.value()->GetHandle().permissions, score::crypto::KeyOperationPermission::kMac);
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreIntoOccupiedSlot_IsRefusedAndKeepsExistingKey)
{
    FileBackedSlotHandler slot_handler{m_factory};
    FakeKeyHandler first{m_key};
    ASSERT_TRUE(slot_handler.StoreKey(m_slot, first).has_value());

    FakeKeyHandler second{{0xFFU, 0xEEU}};
    auto result = slot_handler.StoreKey(m_slot, second);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kKeySlotOccupied);
    auto stored = common::storage::ReadFile(m_key_path.string(), 1024U);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored.value(), m_key);
}

TEST_F(FileBackedSlotHandlerStoreTest, Store_GoesThroughInjectedWriterWithKeyPath)
{
    std::string written_path;
    std::vector<std::uint8_t> written;
    auto writer = [&](const std::string& path,
                      score::crypto::span<const std::uint8_t> data) -> score::crypto::Expected<std::monostate, Error> {
        written_path = path;
        written.assign(data.begin(), data.end());
        return common::storage::CreatePrivateFileIfAbsent(path, data);
    };
    FileBackedSlotHandler slot_handler{m_factory, writer};
    FakeKeyHandler key{m_key};

    ASSERT_TRUE(slot_handler.StoreKey(m_slot, key).has_value());

    EXPECT_EQ(written_path, m_key_path.string());
    EXPECT_EQ(written, m_key);
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreRaceLostToAnotherWriter_ReportsOccupied)
{
    auto writer = [](const std::string&,
                     score::crypto::span<const std::uint8_t>) -> score::crypto::Expected<std::monostate, Error> {
        return score::crypto::make_unexpected(Error::kResourceBusy);
    };
    FileBackedSlotHandler slot_handler{m_factory, writer};
    FakeKeyHandler key{m_key};

    auto result = slot_handler.StoreKey(m_slot, key);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kKeySlotOccupied);
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreWriteFailure_IsReportedAndSlotStaysEmpty)
{
    auto writer = [](const std::string&,
                     score::crypto::span<const std::uint8_t>) -> score::crypto::Expected<std::monostate, Error> {
        return score::crypto::make_unexpected(Error::kPersistFailed);
    };
    FileBackedSlotHandler slot_handler{m_factory, writer};
    FakeKeyHandler key{m_key};

    auto result = slot_handler.StoreKey(m_slot, key);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kPersistFailed);
    EXPECT_EQ(slot_handler.GetSlotState(m_slot).value(), score::crypto::KeySlotState::kEmpty);
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreWithoutKeyPath_IsRejected)
{
    std::ofstream kv{m_slot.deployment_path, std::ios::trunc};
    kv << "[metadata]\navailability=active\n[key]\n";
    kv.close();
    FileBackedSlotHandler slot_handler{m_factory};
    FakeKeyHandler key{m_key};

    auto result = slot_handler.StoreKey(m_slot, key);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreIntoSlotNamingNativeFormat_Succeeds)
{
    WriteDescriptor(m_slot.deployment_path, m_key_path, "key_format=raw\n");
    FileBackedSlotHandler slot_handler{m_factory};
    FakeKeyHandler key{m_key};

    EXPECT_TRUE(slot_handler.StoreKey(m_slot, key).has_value());
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreIntoSlotNamingOtherFormat_IsRejectedAndWritesNothing)
{
    WriteDescriptor(m_slot.deployment_path, m_key_path, "key_format=pem\n");
    FileBackedSlotHandler slot_handler{m_factory};
    FakeKeyHandler key{m_key};

    auto result = slot_handler.StoreKey(m_slot, key);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidFormat);
    EXPECT_FALSE(std::filesystem::exists(m_key_path));
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreKeyPair_FillsPrivateAndPublicSlots)
{
    FileBackedSlotHandler slot_handler{m_factory};

    ASSERT_TRUE(slot_handler.StoreKeyPair(m_private_slot, m_public_slot, m_pair).has_value());

    EXPECT_EQ(common::storage::ReadFile(m_key_path.string(), 1024U).value(), m_pair.Bytes());
    EXPECT_EQ(common::storage::ReadFile(m_public_key_path.string(), 1024U).value(), m_public_key);
    EXPECT_EQ(slot_handler.GetSlotState(m_private_slot).value(), score::crypto::KeySlotState::kOccupied);
    EXPECT_EQ(slot_handler.GetSlotState(m_public_slot).value(), score::crypto::KeySlotState::kOccupied);
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreKeyPair_PublicSlotOccupied_LeavesPrivateSlotEmpty)
{
    FileBackedSlotHandler slot_handler{m_factory};
    FakeKeyHandler existing{m_key};
    ASSERT_TRUE(slot_handler.StoreKey(m_public_slot, existing).has_value());

    auto result = slot_handler.StoreKeyPair(m_private_slot, m_public_slot, m_pair);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kKeySlotOccupied);
    EXPECT_FALSE(std::filesystem::exists(m_key_path));
    EXPECT_EQ(common::storage::ReadFile(m_public_key_path.string(), 1024U).value(), m_key);
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreKeyPair_PrivateWriteFails_RemovesPublicKeyAgain)
{
    auto writer = [this](
                      const std::string& path,
                      score::crypto::span<const std::uint8_t> data) -> score::crypto::Expected<std::monostate, Error> {
        if (path == m_key_path.string())
        {
            return score::crypto::make_unexpected(Error::kPersistFailed);
        }
        return common::storage::CreatePrivateFileIfAbsent(path, data);
    };
    FileBackedSlotHandler slot_handler{m_factory, writer};

    auto result = slot_handler.StoreKeyPair(m_private_slot, m_public_slot, m_pair);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kPersistFailed);
    EXPECT_FALSE(std::filesystem::exists(m_key_path));
    EXPECT_FALSE(std::filesystem::exists(m_public_key_path));
}

TEST_F(FileBackedSlotHandlerStoreTest, StoreKeyPair_SameKeyFileForBothSlots_IsRejected)
{
    WriteDescriptor(m_public_slot.deployment_path, m_key_path, "");
    FileBackedSlotHandler slot_handler{m_factory};

    auto result = slot_handler.StoreKeyPair(m_private_slot, m_public_slot, m_pair);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
    EXPECT_FALSE(std::filesystem::exists(m_key_path));
}

}  // namespace
}  // namespace score::crypto::daemon::key_management
