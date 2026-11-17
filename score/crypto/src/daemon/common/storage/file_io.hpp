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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <variant>
#include <vector>

namespace score::crypto::daemon::common::storage
{

/// Read the entire binary contents of @p path into a byte vector.
///
/// @param path     Absolute or relative path to the file.
/// @param max_size Maximum accepted file size in bytes. Returns kInvalidArgument
///                 if the file is empty or exceeds this limit.
/// @return Byte vector on success; kResourceNotAllocated if the file is absent,
///         kInvalidArgument if size is out of range, kInternalError if the file
///         cannot be opened for another reason or on a partial read.
[[nodiscard]] score::crypto::Expected<std::vector<std::uint8_t>, DaemonErrorCode> ReadFile(const std::string& path,
                                                                                           std::size_t max_size);

/// Write @p data to @p path atomically via a temporary file and rename.
///
/// Creates parent directories if they do not exist. Writes to a sibling
/// <path>.tmp first, then renames atomically. The temporary file is removed
/// on rename failure.
///
/// @return std::monostate on success; kInvalidArgument if path or data is
///         empty, kInternalError if the directory cannot be created,
///         kPersistFailed on write or rename failure.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> WriteFile(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data);

/// Largest file StagePrivateFile writes (8 KiB). A staging-named file larger
/// than this was not written by it, so cleanup leaves such a file untouched.
constexpr std::size_t kMaxPrivateFileSize = 8U * 1024U;

/// A file written next to its final path but not yet visible under it.
struct StagedFile
{
    std::string temp_path;   ///< Hidden sibling ".<name>.stage.<pid>.<seq>" holding the data
    std::string final_path;  ///< Path the data is published under
};

/// Write @p data to a new hidden sibling of @p path and fsync it.
///
/// Creates parent directories if needed. The staging file is created with
/// O_CREAT | O_EXCL | O_NOFOLLOW and mode 0600. @p path itself is not touched.
///
/// @return The staged file; kInvalidArgument if path or data is empty or
///         data is larger than kMaxPrivateFileSize, kInternalError if the directory cannot be created, kPersistFailed
///         on a create or write failure (nothing is left behind).
[[nodiscard]] score::crypto::Expected<StagedFile, DaemonErrorCode> StagePrivateFile(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data);

/// Publish @p staged under its final path unless that path already exists.
///
/// Hard-links the staging file to the final path, which fails atomically when
/// the final path exists, then removes the staging file and fsyncs the
/// directory. On failure the staging file is overwritten with zeros and removed.
///
/// @return std::monostate on success; kResourceBusy if the final path already
///         exists, kPersistFailed on any other link failure.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> PublishStagedFile(const StagedFile& staged);

/// Remove staging files that StagePrivateFile left for @p path, e.g. after a
/// crash between staging and publishing. Their contents are zeroed first.
///
/// Only names of the exact StagePrivateFile form are considered, so files of
/// other paths in the same directory are never touched. A symlink, a
/// non-regular file or a file larger than kMaxPrivateFileSize is left in place.
void RemoveStaleStagedFiles(const std::string& path);

/// Create @p path with mode 0600 holding @p data, unless it already exists.
///
/// Removes stale staging files for @p path, then StagePrivateFile() and
/// PublishStagedFile(). A crash at any point leaves either no file or the
/// complete file at @p path, never an empty or partial one. Calls are
/// serialised within the process so that cleanup never races a store.
///
/// @return std::monostate on success; kResourceBusy if @p path already exists,
///         otherwise the StagePrivateFile / PublishStagedFile errors.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> CreatePrivateFileIfAbsent(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data);

/// Write primitive used by the storage components that persist files. Production code uses
/// WriteFile. A test substitutes a writer to make a write succeed or fail at a chosen point.
using FileWriter = std::function<score::crypto::Expected<std::monostate, DaemonErrorCode>(
    const std::string& path,
    score::crypto::span<const std::uint8_t> data)>;

/// Check whether @p path refers to an existing regular file.
///
/// Returns false for missing paths, directories, symlinks to non-existent
/// targets, and other non-regular-file entries. Filesystem errors are returned
/// as failures instead of being reported as absence.
[[nodiscard]] score::crypto::Expected<bool, DaemonErrorCode> FileExists(const std::string& path);

/// Remove the file at @p path.
///
/// Idempotent: returns success if the file does not exist.
///
/// @return std::monostate on success or if the file was already absent;
///         kInvalidArgument if path is empty, kPersistFailed on a filesystem error.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> RemoveFile(const std::string& path);

/// Overwrite the regular file at @p path with zeros, flush it, unlink it and
/// flush the parent directory.
///
/// Symlinks are refused and so is anything that is not a regular file or is
/// larger than @p max_size; such a file is left untouched. The path is checked
/// with lstat before opening and the opened file must be the same inode, so a
/// symlink swapped in between is refused before anything is written. The limit
/// keeps a wrong path from destroying a file that cannot be a key and bounds
/// the time spent overwriting. The overwrite is best-effort: on flash media (wear levelling) and on
/// copy-on-write or journaling filesystems the old blocks may survive, so key
/// material must not be copied to other persistent locations either.
///
/// @return std::monostate on success; kInvalidArgument if path is empty, a
///         symlink, not a regular file or larger than @p max_size;
///         kResourceNotAllocated if the file is
///         absent; kAccessDenied if it cannot be opened for writing;
///         kPersistFailed on a write, sync or unlink failure.
[[nodiscard]] score::crypto::Expected<std::monostate, DaemonErrorCode> SecureEraseFile(const std::string& path,
                                                                                       std::size_t max_size);

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_FILE_IO_HPP
