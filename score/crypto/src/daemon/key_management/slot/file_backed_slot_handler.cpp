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

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/secure_memory.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/key_management/detail/slot_info_builder.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/slot/deployment_loader.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace score::crypto::daemon::key_management
{
namespace
{
namespace file_io = common::storage;
using Error = common::DaemonErrorCode;

/// Map the deployment "key_format" property to a format. Without the property
/// the factory picks the key type's native format.
score::crypto::Expected<std::optional<::score::crypto::FormatType>, Error> ResolveKeyFormat(
    const SlotDeploymentInfo& deploy_info)
{
    const auto it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyFormat});
    if (it == deploy_info.key_properties.end())
        return std::optional<::score::crypto::FormatType>{};
    if (it->second == "raw")
        return std::optional<::score::crypto::FormatType>{::score::crypto::FormatType::kRaw};
    if (it->second == "der")
        return std::optional<::score::crypto::FormatType>{::score::crypto::FormatType::kDer};
    if (it->second == "pem")
        return std::optional<::score::crypto::FormatType>{::score::crypto::FormatType::kPem};
    return score::crypto::make_unexpected(Error::kInvalidFormat);
}
}  // namespace

FileBackedSlotHandler::FileBackedSlotHandler(IKeyFactory::Sptr factory, file_io::FileWriter writer)
    : m_factory{std::move(factory)}, m_write_file{std::move(writer)}
{
}

score::crypto::Expected<IKeyHandler::Sptr, Error> FileBackedSlotHandler::LoadKey(const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
        return score::crypto::make_unexpected(deploy_result.error());

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if (path_it == deploy_info.key_properties.end() || path_it->second.empty())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto read_result = file_io::ReadFile(path_it->second, kMaxKeyFileSize);
    if (!read_result.has_value())
    {
        const auto file_io_err = read_result.error();
        return score::crypto::make_unexpected(file_io_err == Error::kResourceNotAllocated ? Error::kKeySlotEmpty
                                                                                          : file_io_err);
    }

    auto& buffer = read_result.value();

    const auto algorithm = ::score::crypto::GetAlgorithmDescriptor(slot.algorithm);
    if (!algorithm.has_value())
    {
        common::SecureZeroizeAndClear(buffer);
        return score::crypto::make_unexpected(Error::kUnsupportedAlgorithm);
    }

    const auto format = ResolveKeyFormat(deploy_info);
    if (!format.has_value())
    {
        common::SecureZeroizeAndClear(buffer);
        return score::crypto::make_unexpected(format.error());
    }

    KeyImportRequest req{};
    req.format = format.value();
    req.key_data = buffer.data();
    req.key_data_size = buffer.size();
    req.algorithm = algorithm.value();
    req.permissions = slot.allowed_operations;

    auto import_result = m_factory->ImportKey(req);
    common::SecureZeroizeAndClear(buffer);
    return import_result;
}

score::crypto::Expected<std::string, Error> FileBackedSlotHandler::ResolveEmptyKeyPath(const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
        return score::crypto::make_unexpected(deploy_result.error());

    const auto& key_props = deploy_result.value().key_properties;
    const auto path_it = key_props.find(std::string{deployment_keys::kKeyPath});
    if (path_it == key_props.end() || path_it->second.empty())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    // Keys are stored in their native encoding: raw for symmetric keys, DER for
    // asymmetric ones. A slot that names another format could not load them.
    const auto algorithm = ::score::crypto::GetAlgorithmDescriptor(slot.algorithm);
    if (!algorithm.has_value())
        return score::crypto::make_unexpected(Error::kUnsupportedAlgorithm);
    const bool symmetric = (algorithm->key_type == ::score::crypto::KeyType::kSecret) ||
                           (algorithm->key_type == ::score::crypto::KeyType::kAes);
    const auto format_it = key_props.find(std::string{deployment_keys::kKeyFormat});
    if ((format_it != key_props.end()) && (format_it->second != (symmetric ? "raw" : "der")))
        return score::crypto::make_unexpected(Error::kInvalidFormat);

    const auto exists = file_io::FileExists(path_it->second);
    if (!exists.has_value())
        return score::crypto::make_unexpected(exists.error());
    if (exists.value())
        return score::crypto::make_unexpected(Error::kKeySlotOccupied);
    return path_it->second;
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::WriteKeyFile(const std::string& key_path,
                                                                                   SecureKeyBytes& material)
{
    auto& bytes = material.bytes;
    if (bytes.empty() || bytes.size() > kMaxKeyFileSize)
    {
        common::SecureZeroizeAndClear(bytes);
        return score::crypto::make_unexpected(Error::kPersistFailed);
    }

    auto write_result = m_write_file(key_path, {bytes.data(), bytes.size()});
    common::SecureZeroizeAndClear(bytes);
    if (!write_result.has_value())
    {
        // The writer refuses an existing path, so losing a race to another store
        // reads as an occupied slot.
        return score::crypto::make_unexpected(write_result.error() == Error::kResourceBusy ? Error::kKeySlotOccupied
                                                                                           : write_result.error());
    }
    return std::monostate{};
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::StoreKey(const KeySlotConfig& slot,
                                                                               IKeyHandler& handler)
{
    auto key_path = ResolveEmptyKeyPath(slot);
    if (!key_path.has_value())
        return score::crypto::make_unexpected(key_path.error());

    auto serialised = handler.SerializeForStorage();
    if (!serialised.has_value())
        return score::crypto::make_unexpected(serialised.error());
    return WriteKeyFile(key_path.value(), serialised.value());
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::StoreKeyPair(const KeySlotConfig& private_slot,
                                                                                   const KeySlotConfig& public_slot,
                                                                                   IKeyHandler& handler)
{
    auto private_path = ResolveEmptyKeyPath(private_slot);
    if (!private_path.has_value())
        return score::crypto::make_unexpected(private_path.error());
    auto public_path = ResolveEmptyKeyPath(public_slot);
    if (!public_path.has_value())
        return score::crypto::make_unexpected(public_path.error());
    if (private_path.value() == public_path.value())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto private_key = handler.SerializeForStorage();
    if (!private_key.has_value())
        return score::crypto::make_unexpected(private_key.error());
    auto public_key = handler.SerializePublicKeyForStorage();
    if (!public_key.has_value())
    {
        common::SecureZeroizeAndClear(private_key.value().bytes);
        return score::crypto::make_unexpected(public_key.error());
    }

    // The public key goes first: undoing it if the private store fails leaves
    // no secret behind.
    auto public_result = WriteKeyFile(public_path.value(), public_key.value());
    if (!public_result.has_value())
    {
        common::SecureZeroizeAndClear(private_key.value().bytes);
        return public_result;
    }
    auto private_result = WriteKeyFile(private_path.value(), private_key.value());
    if (!private_result.has_value())
        static_cast<void>(file_io::RemoveFile(public_path.value()));
    return private_result;
}

score::crypto::Expected<score::crypto::KeySlotState, Error> FileBackedSlotHandler::GetSlotState(
    const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        if (deploy_result.error() == Error::kResourceNotAllocated)
            return score::crypto::KeySlotState::kEmpty;
        return score::crypto::make_unexpected(deploy_result.error());
    }

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if (path_it == deploy_info.key_properties.end() || path_it->second.empty())
        return score::crypto::KeySlotState::kEmpty;

    const auto exists = file_io::FileExists(path_it->second);
    if (!exists)
        return score::crypto::make_unexpected(exists.error());
    return exists.value() ? score::crypto::KeySlotState::kOccupied : score::crypto::KeySlotState::kEmpty;
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::ClearSlot(const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        if (deploy_result.error() == Error::kResourceNotAllocated)
            return std::monostate{};
        return score::crypto::make_unexpected(deploy_result.error());
    }

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if (path_it == deploy_info.key_properties.end() || path_it->second.empty())
        return std::monostate{};

    auto erase_result = file_io::SecureEraseFile(path_it->second, kMaxKeyFileSize);
    if (!erase_result.has_value() && erase_result.error() != Error::kResourceNotAllocated)
        return score::crypto::make_unexpected(erase_result.error());
    return std::monostate{};
}

score::crypto::Expected<score::crypto::KeySlotInfo, Error> FileBackedSlotHandler::GetSlotInfo(const KeySlotConfig& slot)
{
    auto state_result = GetSlotState(slot);
    if (!state_result.has_value())
        return score::crypto::make_unexpected(state_result.error());
    return detail::BuildKeySlotInfo(slot, state_result.value());
}

}  // namespace score::crypto::daemon::key_management
