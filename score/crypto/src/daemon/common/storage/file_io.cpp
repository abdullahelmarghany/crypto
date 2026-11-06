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

#include "score/filesystem/error.h"
#include "score/filesystem/filestream/file_factory.h"
#include "score/filesystem/filestream/file_stream.h"
#include "score/filesystem/filesystem.h"
#include "score/os/fcntl.h"
#include "score/os/stat.h"
#include "score/os/unistd.h"

#include <sys/stat.h>

#include <array>
#include <cerrno>
#include <cstdint>

namespace score::crypto::daemon::common::storage
{

score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode> ReadFile(const std::string& path,
                                                                             std::size_t max_size)
{
    const auto exists = FileExists(path);
    if (!exists.has_value())
    {
        return score::crypto::make_unexpected(exists.error());
    }
    if (!exists.value())
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kResourceNotAllocated);
    }

    score::filesystem::FileFactory factory{};
    auto open_result = factory.Open(score::filesystem::Path{path}, std::ios::binary | std::ios::in);
    if (!open_result.has_value())
    {
        return score::crypto::make_unexpected(open_result.error() ==
                                                      score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist
                                                  ? DaemonErrorCode::kResourceNotAllocated
                                                  : DaemonErrorCode::kInternalError);
    }

    auto& stream = *open_result.value();
    stream.seekg(0, std::ios::end);
    const auto size = stream.tellg();
    if (size <= 0 || static_cast<std::uintmax_t>(size) > max_size)
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    stream.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream)
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    return data;
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WriteFile(const std::string& path,
                                                                   score::crypto::span<const std::uint8_t> data)
{
    if (path.empty() || data.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    const score::filesystem::Path target_path{path};
    score::filesystem::StandardFilesystem fs{};
    const auto parent = target_path.ParentPath();
    if (!parent.Empty())
    {
        if (!fs.CreateDirectories(parent).has_value())
            return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }

    score::filesystem::FileFactory factory{};
    auto stream_result = factory.AtomicUpdate(target_path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!stream_result.has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    auto& stream = *stream_result.value();
    stream.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    stream.flush();
    if (!stream)
        // Stream is in a bad state; Close() (called by the destructor) will detect this
        // and clean up the temp file rather than renaming it.
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    // Close() triggers the atomic rename — check it explicitly to confirm success.
    // The destructor calls Close() again on the way out; a second call on an already-closed
    // stream returns an error that the destructor ignores, which is safe.
    if (!stream_result.value()->Close().has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    return std::monostate{};
}

score::crypto::Expected<std::monostate, DaemonErrorCode> WriteNewPrivateFile(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data)
{
    if (path.empty() || data.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    const score::filesystem::Path target_path{path};
    score::filesystem::StandardFilesystem fs{};
    const auto parent = target_path.ParentPath();
    if (!parent.Empty())
    {
        if (!fs.CreateDirectories(parent).has_value())
            return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }

    // kExclusive also refuses a dangling symlink planted at the target path.
    using Open = score::os::Fcntl::Open;
    using Mode = score::os::Stat::Mode;
    const auto created =
        score::os::Fcntl::instance().open(path.c_str(),
                                          Open::kWriteOnly | Open::kCreate | Open::kExclusive | Open::kCloseOnExec,
                                          Mode::kReadUser | Mode::kWriteUser);
    if (!created.has_value())
        return score::crypto::make_unexpected(created.error().GetOsDependentErrorCode() == EEXIST
                                                  ? DaemonErrorCode::kResourceBusy
                                                  : DaemonErrorCode::kPersistFailed);
    static_cast<void>(score::os::Unistd::instance().close(created.value()));

    auto write_result = WriteFile(path, data);
    if (!write_result.has_value())
        static_cast<void>(RemoveFile(path));
    return write_result;
}

score::crypto::Expected<bool, DaemonErrorCode> FileExists(const std::string& path)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.IsRegularFile(score::filesystem::Path{path});
    if (!result.has_value())
    {
        if (result.error() == score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist)
            return false;
        return score::crypto::make_unexpected(DaemonErrorCode::kInternalError);
    }
    return result.value();
}

score::crypto::Expected<std::monostate, DaemonErrorCode> RemoveFile(const std::string& path)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    score::filesystem::StandardFilesystem fs{};
    const auto result = fs.Remove(score::filesystem::Path{path});
    if (!result.has_value())
    {
        const auto status = fs.Status(score::filesystem::Path{path});
        if (status.has_value() && status->Type() == score::filesystem::FileType::kNotFound)
            return std::monostate{};
        if (result.error() == score::filesystem::ErrorCode::kFileOrDirectoryDoesNotExist)
            return std::monostate{};
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    }
    return std::monostate{};
}

namespace
{

/// Flush the directory holding @p path so that a preceding unlink or link is durable.
bool SyncParentDirectory(const std::string& path)
{
    auto parent = score::filesystem::Path{path}.ParentPath();
    if (parent.Empty())
    {
        parent = score::filesystem::Path{"."};
    }
    score::filesystem::StandardFilesystem standard{};
    score::filesystem::FileFactory streams{};
    const score::filesystem::FileUtils utils{standard, streams};
    return utils.SyncDirectory(parent).has_value();
}

bool IsInterrupted(const score::os::Error& error)
{
    return error.GetOsDependentErrorCode() == EINTR;
}

bool OverwriteWithZeros(std::int32_t fd, std::int64_t size)
{
    static constexpr std::array<std::uint8_t, 4096U> kZeros{};
    std::int64_t offset = 0;
    while (offset < size)
    {
        const auto remaining = static_cast<std::size_t>(size - offset);
        const std::size_t chunk = remaining < kZeros.size() ? remaining : kZeros.size();
        const auto written = score::os::Unistd::instance().pwrite(fd, kZeros.data(), chunk, static_cast<off_t>(offset));
        if (!written.has_value())
        {
            if (IsInterrupted(written.error()))
                continue;
            return false;
        }
        if (written.value() <= 0)
            return false;
        offset += static_cast<std::int64_t>(written.value());
    }
    return true;
}

bool Fsync(std::int32_t fd)
{
    for (;;)
    {
        const auto result = score::os::Unistd::instance().fsync(fd);
        if (result.has_value())
            return true;
        if (!IsInterrupted(result.error()))
            return false;
    }
}

DaemonErrorCode OpenErrorToDaemonError(const score::os::Error& error)
{
    switch (error.GetOsDependentErrorCode())
    {
        case ENOENT:
            return DaemonErrorCode::kResourceNotAllocated;
        case ELOOP:
        case EISDIR:
        case ENXIO:
            return DaemonErrorCode::kInvalidArgument;
        case EACCES:
        case EPERM:
        case EROFS:
            return DaemonErrorCode::kAccessDenied;
        default:
            return DaemonErrorCode::kPersistFailed;
    }
}

bool IsErasable(const score::os::StatBuffer& st, std::size_t max_size)
{
    return S_ISREG(st.st_mode) && (st.st_size >= 0) && (static_cast<std::uintmax_t>(st.st_size) <= max_size);
}

}  // namespace

score::crypto::Expected<std::monostate, DaemonErrorCode> SecureEraseFile(const std::string& path, std::size_t max_size)
{
    if (path.empty())
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    // score::os::Fcntl cannot express O_NOFOLLOW. Inspect the path itself first, then require that
    // the opened file is the same inode, so a symlink swapped in between is never written through.
    score::os::StatBuffer link_status{};
    const auto lstat_result = score::os::Stat::instance().stat(path.c_str(), link_status, false);
    if (!lstat_result.has_value())
        return score::crypto::make_unexpected(OpenErrorToDaemonError(lstat_result.error()));
    if (!IsErasable(link_status, max_size))
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);

    // kNonBlocking keeps a FIFO swapped in after the check from blocking the open.
    using Open = score::os::Fcntl::Open;
    constexpr auto kFlags = Open::kWriteOnly | Open::kCloseOnExec | Open::kNonBlocking;
    auto opened = score::os::Fcntl::instance().open(path.c_str(), kFlags);
    while (!opened.has_value() && IsInterrupted(opened.error()))
    {
        opened = score::os::Fcntl::instance().open(path.c_str(), kFlags);
    }
    if (!opened.has_value())
        return score::crypto::make_unexpected(OpenErrorToDaemonError(opened.error()));
    const std::int32_t fd = opened.value();

    score::os::StatBuffer file_status{};
    if (!score::os::Stat::instance().fstat(fd, file_status).has_value())
    {
        static_cast<void>(score::os::Unistd::instance().close(fd));
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    }
    if (!IsErasable(file_status, max_size) || (file_status.st_dev != link_status.st_dev) ||
        (file_status.st_ino != link_status.st_ino))
    {
        static_cast<void>(score::os::Unistd::instance().close(fd));
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    if (!OverwriteWithZeros(fd, file_status.st_size) || !Fsync(fd))
    {
        static_cast<void>(score::os::Unistd::instance().close(fd));
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    }
    const auto closed = score::os::Unistd::instance().close(fd);
    if (!closed.has_value() && !IsInterrupted(closed.error()))
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    if (!score::os::Unistd::instance().unlink(path.c_str()).has_value())
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);

    // Make the unlink durable.
    if (!SyncParentDirectory(path))
        return score::crypto::make_unexpected(DaemonErrorCode::kPersistFailed);
    return std::monostate{};
}

}  // namespace score::crypto::daemon::common::storage
