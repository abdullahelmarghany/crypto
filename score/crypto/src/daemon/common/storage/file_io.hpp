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
