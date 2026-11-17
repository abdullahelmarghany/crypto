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

#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include "score/os/mocklib/fcntl_mock.h"
#include "score/os/mocklib/stat_mock.h"
#include "score/os/mocklib/unistdmock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace score::crypto::daemon::common::storage
{
namespace
{

std::filesystem::path TestPath(const std::string& suffix)
{
    return std::filesystem::temp_directory_path() /
           ("score_crypto_file_io_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
            "_" + suffix);
}

TEST(FileIoTest, MissingFileIsReportedAsAbsent)
{
    const auto path = TestPath("missing");

    const auto result = FileExists(path.string());

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result.value());
}

TEST(FileIoTest, RegularFileIsReportedAsPresent)
{
    const auto path = TestPath("present");
    {
        std::ofstream output{path};
        ASSERT_TRUE(output.is_open());
        output << "data";
    }

    const auto result = FileExists(path.string());

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
    std::filesystem::remove(path);
}

TEST(FileIoTest, MissingFileReadRetainsEmptyResourceMeaning)
{
    const auto path = TestPath("missing_read");

    const auto result = ReadFile(path.string(), 1024U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kResourceNotAllocated);
}

TEST(FileIoTest, RemovingMissingFileIsIdempotent)
{
    const auto path = TestPath("missing_remove");

    const auto result = RemoveFile(path.string());

    EXPECT_TRUE(result.has_value());
}

std::vector<char> ReadAll(const std::filesystem::path& path)
{
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

void WriteText(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream output{path, std::ios::binary};
    output << text;
}

constexpr std::size_t kMaxEraseSize = 16384U;

TEST(SecureEraseFileTest, OverwritesContentWithZerosAndUnlinks)
{
    const auto path = TestPath("erase");
    const auto alias = TestPath("erase_alias");
    const std::string secret(10000U, 'K');
    WriteText(path, secret);
    // A hard link shares the inode, so it shows what was written to the erased file.
    std::filesystem::create_hard_link(path, alias);

    const auto result = SecureEraseFile(path.string(), kMaxEraseSize);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(path));
    const auto content = ReadAll(alias);
    ASSERT_EQ(content.size(), secret.size());
    for (const char byte : content)
    {
        ASSERT_EQ(byte, '\0');
    }
    std::filesystem::remove(alias);
}

TEST(SecureEraseFileTest, RefusesSymlinkAndLeavesTargetUntouched)
{
    const auto target = TestPath("erase_target");
    const auto link = TestPath("erase_link");
    WriteText(target, "secret");
    std::filesystem::create_symlink(target, link);

    const auto result = SecureEraseFile(link.string(), kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_TRUE(std::filesystem::is_symlink(link));
    const auto content = ReadAll(target);
    EXPECT_EQ(std::string(content.begin(), content.end()), "secret");
    std::filesystem::remove(link);
    std::filesystem::remove(target);
}

TEST(SecureEraseFileTest, RefusesDirectory)
{
    const auto dir = TestPath("erase_dir");
    std::filesystem::create_directory(dir);

    const auto result = SecureEraseFile(dir.string(), kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_TRUE(std::filesystem::is_directory(dir));
    std::filesystem::remove(dir);
}

TEST(SecureEraseFileTest, RefusesFifo)
{
    const auto fifo = TestPath("erase_fifo");
    ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);

    const auto result = SecureEraseFile(fifo.string(), kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_TRUE(std::filesystem::exists(fifo));
    std::filesystem::remove(fifo);
}

TEST(SecureEraseFileTest, RefusesFileLargerThanMaxSizeAndLeavesItUntouched)
{
    const auto path = TestPath("erase_oversized");
    const std::string content(kMaxEraseSize + 1U, 'K');
    WriteText(path, content);

    const auto result = SecureEraseFile(path.string(), kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    const auto remaining = ReadAll(path);
    EXPECT_EQ(std::string(remaining.begin(), remaining.end()), content);
    std::filesystem::remove(path);
}

TEST(SecureEraseFileTest, MissingFileIsReportedAsAbsent)
{
    const auto result = SecureEraseFile(TestPath("erase_missing").string(), kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kResourceNotAllocated);
}

TEST(SecureEraseFileTest, EmptyPathIsRejected)
{
    const auto result = SecureEraseFile("", kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrEq;

using OsResult = score::cpp::expected_blank<score::os::Error>;

OsResult OsFailure(int error_number)
{
    return score::cpp::make_unexpected(score::os::Error::createFromErrno(error_number));
}

/// Drives SecureEraseFile through the baselibs OS mocks to reach EINTR, short writes and the
/// checks made after open, which a real filesystem cannot trigger on demand.
class SecureEraseFileOsTest : public ::testing::Test
{
  protected:
    static constexpr std::int32_t kFileFd = 10;
    static constexpr std::int32_t kDirFd = 11;
    static constexpr const char* kPath = "/keys/slot.key";
    static constexpr const char* kDir = "/keys";

    void SetUp() override
    {
        score::os::Stat::set_testing_instance(stat_);
        score::os::Fcntl::set_testing_instance(fcntl_);
        score::os::Unistd::set_testing_instance(unistd_);

        link_status_.st_mode = S_IFREG | 0600;
        link_status_.st_dev = 1U;
        link_status_.st_ino = 2U;
        link_status_.st_size = 8;
        file_status_ = link_status_;

        ON_CALL(stat_, stat(_, _, _)).WillByDefault([this](const char*, score::os::StatBuffer& buf, bool) {
            buf = link_status_;
            return OsResult{};
        });
        ON_CALL(stat_, fstat(_, _)).WillByDefault([this](std::int32_t, score::os::StatBuffer& buf) {
            buf = file_status_;
            return OsResult{};
        });
        ON_CALL(fcntl_, open(StrEq(kPath), _)).WillByDefault([this](const char* path, score::os::Fcntl::Open) {
            opened_.emplace_back(path);
            return score::cpp::expected<std::int32_t, score::os::Error>{kFileFd};
        });
        ON_CALL(fcntl_, open(StrEq(kDir), _)).WillByDefault([this](const char* path, score::os::Fcntl::Open) {
            opened_.emplace_back(path);
            return score::cpp::expected<std::int32_t, score::os::Error>{kDirFd};
        });
        ON_CALL(unistd_, pwrite(_, _, _, _))
            .WillByDefault([this](std::int32_t, const void* buf, std::size_t count, off_t offset) {
                return Pwrite(buf, count, offset);
            });
        ON_CALL(unistd_, fsync(_)).WillByDefault([this](std::int32_t fd) {
            synced_.push_back(fd);
            return OsResult{};
        });
        ON_CALL(unistd_, close(_)).WillByDefault(Return(OsResult{}));
        ON_CALL(unistd_, unlink(_)).WillByDefault([this](const char* path) {
            unlinked_.emplace_back(path);
            return OsResult{};
        });
    }

    void TearDown() override
    {
        score::os::Unistd::restore_instance();
        score::os::Fcntl::restore_instance();
        score::os::Stat::restore_instance();
    }

    /// The first call is interrupted, later calls write at most 3 bytes.
    score::cpp::expected<ssize_t, score::os::Error> Pwrite(const void* buf, std::size_t count, off_t offset)
    {
        ++pwrite_calls_;
        if (pwrite_calls_ == 1)
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EINTR));
        if (fail_pwrite_)
            return score::cpp::make_unexpected(score::os::Error::createFromErrno(EIO));
        const std::size_t n = count < 3U ? count : 3U;
        const auto* bytes = static_cast<const std::uint8_t*>(buf);
        for (std::size_t i = 0U; i < n; ++i)
        {
            written_.at(static_cast<std::size_t>(offset) + i) = bytes[i];
        }
        return static_cast<ssize_t>(n);
    }

    NiceMock<score::os::StatMock> stat_;
    NiceMock<score::os::FcntlMock> fcntl_;
    NiceMock<score::os::UnistdMock> unistd_;
    score::os::StatBuffer link_status_{};
    score::os::StatBuffer file_status_{};
    bool fail_pwrite_{false};
    int pwrite_calls_{0};
    std::vector<std::uint8_t> written_ = std::vector<std::uint8_t>(8U, 0xAAU);
    std::vector<std::string> opened_;
    std::vector<std::int32_t> synced_;
    std::vector<std::string> unlinked_;
};

TEST_F(SecureEraseFileOsTest, RetriesInterruptedAndShortWritesThenSyncsFileAndParent)
{
    const auto result = SecureEraseFile(kPath, kMaxEraseSize);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(written_, std::vector<std::uint8_t>(8U, 0U));
    EXPECT_EQ(pwrite_calls_, 4);
    EXPECT_EQ(synced_, (std::vector<std::int32_t>{kFileFd, kDirFd}));
    EXPECT_EQ(unlinked_, std::vector<std::string>{kPath});
    EXPECT_EQ(opened_, (std::vector<std::string>{kPath, kDir}));
}

TEST_F(SecureEraseFileOsTest, WriteFailureKeepsFile)
{
    fail_pwrite_ = true;

    const auto result = SecureEraseFile(kPath, kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kPersistFailed);
    EXPECT_TRUE(unlinked_.empty());
}

TEST_F(SecureEraseFileOsTest, SyncFailureKeepsFile)
{
    ON_CALL(unistd_, fsync(kFileFd)).WillByDefault(Return(OsFailure(EIO)));

    const auto result = SecureEraseFile(kPath, kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kPersistFailed);
    EXPECT_TRUE(unlinked_.empty());
}

TEST_F(SecureEraseFileOsTest, SymlinkIsRefusedBeforeOpen)
{
    link_status_.st_mode = S_IFLNK | 0777;
    EXPECT_CALL(fcntl_, open(_, _)).Times(0);

    const auto result = SecureEraseFile(kPath, kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
}

TEST_F(SecureEraseFileOsTest, FileSwappedAfterCheckIsRefusedWithoutWriting)
{
    file_status_.st_ino = 3U;

    const auto result = SecureEraseFile(kPath, kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(pwrite_calls_, 0);
    EXPECT_TRUE(unlinked_.empty());
}

TEST_F(SecureEraseFileOsTest, NonRegularFileIsRefusedAfterOpen)
{
    file_status_.st_mode = S_IFCHR | 0600;

    const auto result = SecureEraseFile(kPath, kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(pwrite_calls_, 0);
    EXPECT_TRUE(unlinked_.empty());
}

TEST_F(SecureEraseFileOsTest, OversizedFileIsRefusedAfterOpenWithoutWriting)
{
    file_status_.st_size = 9;

    const auto result = SecureEraseFile(kPath, 8U);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(pwrite_calls_, 0);
    EXPECT_TRUE(unlinked_.empty());
}

TEST_F(SecureEraseFileOsTest, OpenPermissionErrorIsAccessDenied)
{
    ON_CALL(fcntl_, open(StrEq(kPath), _))
        .WillByDefault(Return(score::cpp::make_unexpected(score::os::Error::createFromErrno(EACCES))));

    const auto result = SecureEraseFile(kPath, kMaxEraseSize);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kAccessDenied);
}

/// Names of the entries in @p dir.
std::vector<std::string> DirEntries(const std::filesystem::path& dir)
{
    std::vector<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator{dir})
    {
        names.push_back(entry.path().filename().string());
    }
    std::sort(names.begin(), names.end());
    return names;
}

TEST(FileIoTest, CreatedFileIsOwnerOnlyAndReadable)
{
    const auto path = TestPath("private") / "nested" / "key.bin";
    const std::vector<std::uint8_t> data{0x01U, 0x02U, 0x03U};

    const auto result = CreatePrivateFileIfAbsent(path.string(), {data.data(), data.size()});

    ASSERT_TRUE(result.has_value());
    const auto perms = std::filesystem::status(path).permissions();
    EXPECT_EQ(perms & std::filesystem::perms::all,
              std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    const auto read = ReadFile(path.string(), 1024U);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read.value(), data);
    // The staging file is gone once the key is published.
    EXPECT_EQ(DirEntries(path.parent_path()), std::vector<std::string>{"key.bin"});
    std::filesystem::remove_all(path.parent_path().parent_path());
}

TEST(FileIoTest, CreateRefusesExistingFile)
{
    const auto dir = TestPath("private_existing");
    std::filesystem::create_directories(dir);
    const auto path = dir / "key.bin";
    WriteText(path, "old");
    const std::vector<std::uint8_t> data{0xAAU};

    const auto result = CreatePrivateFileIfAbsent(path.string(), {data.data(), data.size()});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kResourceBusy);
    const auto read = ReadFile(path.string(), 1024U);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read.value(), (std::vector<std::uint8_t>{'o', 'l', 'd'}));
    EXPECT_EQ(DirEntries(dir), std::vector<std::string>{"key.bin"});
    std::filesystem::remove_all(dir);
}

TEST(FileIoTest, PublishLosingRaceToExistingFileKeepsItAndDropsStagedData)
{
    const auto dir = TestPath("publish_race");
    const auto path = dir / "key.bin";
    const std::vector<std::uint8_t> data{0x11U, 0x22U};
    auto staged = StagePrivateFile(path.string(), {data.data(), data.size()});
    ASSERT_TRUE(staged.has_value());

    // Another writer publishes first; link() then fails with EEXIST.
    WriteText(path, "winner");
    const auto result = PublishStagedFile(staged.value());

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kResourceBusy);
    const auto read = ReadFile(path.string(), 1024U);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read.value(), (std::vector<std::uint8_t>{'w', 'i', 'n', 'n', 'e', 'r'}));
    EXPECT_FALSE(std::filesystem::exists(staged.value().temp_path));
    std::filesystem::remove_all(dir);
}

TEST(FileIoTest, CrashBetweenWriteAndLinkLeavesNoFinalFileAndNextCreateCleansUp)
{
    const auto dir = TestPath("crash");
    const auto path = dir / "key.bin";
    const std::vector<std::uint8_t> lost{0x01U, 0x02U, 0x03U, 0x04U};

    // Simulated crash: the data is staged but never published.
    auto staged = StagePrivateFile(path.string(), {lost.data(), lost.size()});
    ASSERT_TRUE(staged.has_value());
    const auto exists = FileExists(path.string());
    ASSERT_TRUE(exists.has_value());
    EXPECT_FALSE(exists.value());
    ASSERT_TRUE(std::filesystem::exists(staged.value().temp_path));
    EXPECT_EQ(std::filesystem::status(staged.value().temp_path).permissions() & std::filesystem::perms::all,
              std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

    const std::vector<std::uint8_t> data{0xA5U};
    const auto result = CreatePrivateFileIfAbsent(path.string(), {data.data(), data.size()});

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(DirEntries(dir), std::vector<std::string>{"key.bin"});
    const auto read = ReadFile(path.string(), 1024U);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read.value(), data);
    std::filesystem::remove_all(dir);
}

TEST(FileIoTest, StaleCleanupRemovesOnlyOwnStagingFiles)
{
    const auto dir = TestPath("stale");
    std::filesystem::create_directories(dir);
    WriteText(dir / ".key.bin.stage.12.3", "stale");
    WriteText(dir / ".key.bin.stage.x.3", "not a staging name");
    WriteText(dir / ".key.bin.stage.12.3.bak", "not a staging name");
    WriteText(dir / ".key.bin.1.stage.12.3", "staging file of key.bin.1");
    WriteText(dir / ".other.bin.stage.12.3", "staging file of other.bin");
    WriteText(dir / "key.bin.stage.12.3", "visible file");

    RemoveStaleStagedFiles((dir / "key.bin").string());

    EXPECT_EQ(DirEntries(dir),
              (std::vector<std::string>{".key.bin.1.stage.12.3",
                                        ".key.bin.stage.12.3.bak",
                                        ".key.bin.stage.x.3",
                                        ".other.bin.stage.12.3",
                                        "key.bin.stage.12.3"}));
    std::filesystem::remove_all(dir);
}

TEST(FileIoTest, StaleCleanupLeavesFileLargerThanAStagedFileUntouched)
{
    const auto dir = TestPath("stale_oversized");
    std::filesystem::create_directories(dir);
    const auto oversized = dir / ".key.bin.stage.12.3";
    const std::string content(kMaxPrivateFileSize + 1U, 'K');
    WriteText(oversized, content);

    RemoveStaleStagedFiles((dir / "key.bin").string());

    ASSERT_TRUE(std::filesystem::exists(oversized));
    const auto remaining = ReadAll(oversized);
    EXPECT_EQ(std::string(remaining.begin(), remaining.end()), content);
    std::filesystem::remove_all(dir);
}

TEST(FileIoTest, StagingRefusesDataLargerThanMaxPrivateFileSize)
{
    const auto dir = TestPath("stage_oversized");
    const std::vector<std::uint8_t> data(kMaxPrivateFileSize + 1U, 0x01U);

    const auto staged = StagePrivateFile((dir / "key.bin").string(), {data.data(), data.size()});

    ASSERT_FALSE(staged.has_value());
    EXPECT_EQ(staged.error(), DaemonErrorCode::kInvalidArgument);
    std::filesystem::remove_all(dir);
}

TEST(FileIoTest, StagingUsesHiddenSiblingOfFinalPath)
{
    const auto dir = TestPath("symlink");
    std::filesystem::create_directories(dir);
    const auto path = dir / "key.bin";
    const std::vector<std::uint8_t> data{0x01U};

    auto staged = StagePrivateFile(path.string(), {data.data(), data.size()});
    ASSERT_TRUE(staged.has_value());
    EXPECT_EQ(staged.value().final_path, path.string());
    EXPECT_EQ(staged.value().temp_path.rfind((dir / ".key.bin.stage.").string(), 0U), 0U);
    std::filesystem::remove(staged.value().temp_path);
    std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace score::crypto::daemon::common::storage
