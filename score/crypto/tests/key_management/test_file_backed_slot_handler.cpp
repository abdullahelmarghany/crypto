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

#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/slot/file_backed_slot_handler.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace km = score::crypto::daemon::key_management;
using score::crypto::KeySlotState;
using score::crypto::daemon::common::DaemonErrorCode;

namespace
{

class FileBackedSlotHandlerClearTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_dir = std::filesystem::temp_directory_path() /
                ("score_crypto_fbsh_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(m_dir);
        m_key_path = m_dir / "slot.key";
        m_slot.slot_name = "clear_test";
        m_slot.algorithm = "AES-256";
        m_slot.deployment_path = (m_dir / "slot.kv").string();
        m_slot.deployment_format = "kv";
    }

    void TearDown() override
    {
        std::filesystem::remove_all(m_dir);
    }

    void WriteDescriptor(const std::string& key_path_line)
    {
        std::ofstream kv{m_slot.deployment_path};
        kv << "[metadata]\navailability=active\n[key]\n" << key_path_line << "\nkey_format=raw\n";
    }

    void WriteKey()
    {
        std::ofstream key{m_key_path, std::ios::binary};
        key << std::string(32U, 'K');
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_key_path;
    km::KeySlotConfig m_slot;
    km::FileBackedSlotHandler m_handler{nullptr};
};

TEST_F(FileBackedSlotHandlerClearTest, ClearErasesKeyFileAndKeepsDescriptor)
{
    WriteDescriptor("key_path=" + m_key_path.string());
    WriteKey();
    ASSERT_EQ(m_handler.GetSlotState(m_slot).value(), KeySlotState::kOccupied);

    const auto result = m_handler.ClearSlot(m_slot);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(m_key_path));
    EXPECT_TRUE(std::filesystem::exists(m_slot.deployment_path));
    EXPECT_EQ(m_handler.GetSlotState(m_slot).value(), KeySlotState::kEmpty);
    const auto load = m_handler.LoadKey(m_slot);
    ASSERT_FALSE(load.has_value());
    EXPECT_EQ(load.error(), DaemonErrorCode::kKeySlotEmpty);
}

TEST_F(FileBackedSlotHandlerClearTest, ClearingEmptySlotSucceeds)
{
    WriteDescriptor("key_path=" + m_key_path.string());

    EXPECT_TRUE(m_handler.ClearSlot(m_slot).has_value());
    EXPECT_TRUE(m_handler.ClearSlot(m_slot).has_value());
    EXPECT_EQ(m_handler.GetSlotState(m_slot).value(), KeySlotState::kEmpty);
}

TEST_F(FileBackedSlotHandlerClearTest, ClearingSlotWithoutDescriptorSucceeds)
{
    EXPECT_TRUE(m_handler.ClearSlot(m_slot).has_value());
}

TEST_F(FileBackedSlotHandlerClearTest, ClearingSlotWithoutKeyPathSucceeds)
{
    WriteDescriptor("other=value");

    EXPECT_TRUE(m_handler.ClearSlot(m_slot).has_value());
}

TEST_F(FileBackedSlotHandlerClearTest, ClearRefusesSymlinkedKeyFile)
{
    const auto target = m_dir / "real.key";
    {
        std::ofstream key{target, std::ios::binary};
        key << "secret";
    }
    std::filesystem::create_symlink(target, m_key_path);
    WriteDescriptor("key_path=" + m_key_path.string());

    const auto result = m_handler.ClearSlot(m_slot);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_TRUE(std::filesystem::exists(target));
}

TEST_F(FileBackedSlotHandlerClearTest, ClearRefusesFileLargerThanAKeyAndLeavesItUntouched)
{
    // One byte above the 8 KiB key file limit that LoadKey also enforces.
    const std::string content(8U * 1024U + 1U, 'K');
    {
        std::ofstream key{m_key_path, std::ios::binary};
        key << content;
    }
    WriteDescriptor("key_path=" + m_key_path.string());

    const auto result = m_handler.ClearSlot(m_slot);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(std::filesystem::file_size(m_key_path), content.size());
}

}  // namespace
