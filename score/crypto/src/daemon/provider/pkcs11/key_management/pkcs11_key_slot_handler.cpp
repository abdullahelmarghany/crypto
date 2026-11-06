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

#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_slot_handler.hpp"

#include "score/crypto/src/daemon/key_management/detail/slot_info_builder.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_handler.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_slot_object.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_session_guard.hpp"

#include "score/mw/log/logging.h"

#include <array>
#include <iterator>
#include <mutex>
#include <string>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

// =============================================================================
// Pkcs11KeySlotHandler
// =============================================================================

Pkcs11KeySlotHandler::Pkcs11KeySlotHandler(std::shared_ptr<Pkcs11Provider> provider,
                                           std::weak_ptr<Pkcs11Module> module,
                                           std::shared_ptr<Pkcs11KeyStore> key_store)
    : m_provider{std::move(provider)}, m_module{std::move(module)}, m_key_store{std::move(key_store)}
{
}

score::crypto::Expected<key_management::IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeySlotHandler::LoadKey(const key_management::KeySlotConfig& slot)
{
    if (!m_provider)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // The slot configuration stores the algorithm name; resolve it to its catalog row.
    const auto algorithm = ::score::crypto::GetAlgorithmDescriptor(slot.algorithm);
    if (!algorithm.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "LoadKey: unknown algorithm '" << slot.algorithm << "' for slot '"
                                   << slot.slot_name << "'";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // Load deployment info to get PKCS#11 object identifiers.
    auto deploy_result = key_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        return score::crypto::make_unexpected(deploy_result.error());
    }
    const auto& key_props = deploy_result.value().key_properties;

    auto search_res = BuildSearchTemplate(key_props);
    if (!search_res.has_value())
    {
        score::mw::log::LogError()
            << LOG_PREFIX << "LoadKey: slot '" << slot.slot_name
            << "' has no usable pkcs11.label or pkcs11.object_id (missing, empty or malformed hex) in deployment info";
        return score::crypto::make_unexpected(search_res.error());
    }
    SearchTemplate search_tmpl = std::move(search_res.value());
    std::vector<CK_ATTRIBUTE> tmpl = ToAttributes(search_tmpl);

    // Acquire RO session (User auth needed for secret key objects).
    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::User};
    auto session_result = m_provider->AcquireSession(reqs);
    if (!session_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "LoadKey: failed to acquire RO session for slot '" << slot.slot_name
                                   << "'";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const CK_SESSION_HANDLE session = session_result.value();

    auto module = m_module.lock();
    if (!module)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    CK_RV rv = fns->C_FindObjectsInit(session, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()));
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_FindObjectsInit failed: rv=" << static_cast<unsigned long>(rv);
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeySlotEmpty);
    }

    CK_OBJECT_HANDLE found_object = CK_INVALID_HANDLE;
    CK_ULONG found_count = 0U;
    rv = fns->C_FindObjects(session, &found_object, 1U, &found_count);
    static_cast<void>(fns->C_FindObjectsFinal(session));  // always finalise

    if (rv != CKR_OK || found_count == 0U || found_object == CK_INVALID_HANDLE)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_FindObjects: object not found for slot '" << slot.slot_name
                                   << "'";
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeySlotEmpty);
    }

    // Retrieve CKA_VALUE_LEN (key size in bytes).
    CK_ULONG value_len = 0U;
    CK_ATTRIBUTE value_len_attr{CKA_VALUE_LEN, &value_len, sizeof(value_len)};
    rv = fns->C_GetAttributeValue(session, found_object, &value_len_attr, 1U);
    // Some tokens don't support CKA_VALUE_LEN -- fall back to algorithm-derived size.
    if (rv != CKR_OK)
    {
        const auto algo_info = detail::LookupAlgorithm(algorithm.value());
        value_len = algo_info.has_value() ? static_cast<CK_ULONG>(algo_info->value_len) : 0U;
    }

    // Store the search template so any handler can independently locate the key
    // via Pkcs11KeyStore::ResolveObject() on its own session.
    const auto handle = m_key_store->RegisterTokenObject(
        search_tmpl, algorithm.value(), static_cast<std::size_t>(value_len), slot.allowed_operations);

    m_provider->ReleaseSession(session, reqs);

    return std::make_shared<Pkcs11KeyHandler>(m_key_store, std::move(handle));
}

score::crypto::Expected<score::crypto::KeySlotState, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeySlotHandler::GetSlotState(const key_management::KeySlotConfig& slot)
{
    using key_management::deployment_keys::kPkcs11Label;
    using key_management::deployment_keys::kPkcs11ObjectId;

    if (!m_provider)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // Load deployment info to get PKCS#11 object identifiers.
    auto deploy_result = key_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        return score::crypto::KeySlotState::kEmpty;
    }
    const auto& key_props = deploy_result.value().key_properties;

    const auto label_it = key_props.find(std::string{kPkcs11Label});
    const auto id_it = key_props.find(std::string{kPkcs11ObjectId});
    const bool has_label = (label_it != key_props.end()) && !label_it->second.empty();
    const bool has_id = (id_it != key_props.end()) && !id_it->second.empty();
    if (!has_label && !has_id)
    {
        return score::crypto::KeySlotState::kEmpty;
    }

    // Same template as LoadKey/ClearSlot; a malformed object_id is a config error.
    auto search_res = BuildSearchTemplate(key_props);
    if (!search_res.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "GetSlotState: slot '" << slot.slot_name
                                   << "' has an invalid pkcs11.object_id in deployment info";
        return score::crypto::make_unexpected(search_res.error());
    }
    SearchTemplate search_tmpl = std::move(search_res.value());
    std::vector<CK_ATTRIBUTE> tmpl = ToAttributes(search_tmpl);

    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::User};
    auto session_result = m_provider->AcquireSession(reqs);
    if (!session_result.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const CK_SESSION_HANDLE session = session_result.value();

    auto module = m_module.lock();
    if (!module)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    const CK_RV rv_init = fns->C_FindObjectsInit(session, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()));
    score::crypto::KeySlotState state = score::crypto::KeySlotState::kEmpty;
    if (rv_init == CKR_OK)
    {
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        CK_ULONG count = 0U;
        if (fns->C_FindObjects(session, &obj, 1U, &count) == CKR_OK && count > 0U)
        {
            state = score::crypto::KeySlotState::kOccupied;
        }
        static_cast<void>(fns->C_FindObjectsFinal(session));
    }

    m_provider->ReleaseSession(session, reqs);
    return state;
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeySlotHandler::ClearSlot(
    const key_management::KeySlotConfig& slot)
{
    if (!m_provider)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    auto deploy_result = key_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        if (deploy_result.error() == score::crypto::daemon::common::DaemonErrorCode::kResourceNotAllocated)
        {
            return std::monostate{};
        }
        return score::crypto::make_unexpected(deploy_result.error());
    }

    // Without a label or ID the class-only template would match every key of that class.
    auto search_res = BuildSearchTemplate(deploy_result.value().key_properties);
    if (!search_res.has_value())
    {
        score::mw::log::LogError()
            << LOG_PREFIX << "ClearSlot: slot '" << slot.slot_name
            << "' has no usable pkcs11.label or pkcs11.object_id (missing, empty or malformed hex) in deployment info";
        return score::crypto::make_unexpected(search_res.error());
    }
    SearchTemplate search_tmpl = std::move(search_res.value());
    std::vector<CK_ATTRIBUTE> tmpl = ToAttributes(search_tmpl);

    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
    auto session_result = m_provider->AcquireSession(reqs);
    if (!session_result.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "ClearSlot: failed to acquire RW session for slot '"
                                   << slot.slot_name << "'";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const CK_SESSION_HANDLE session = session_result.value();

    auto module = m_module.lock();
    CK_FUNCTION_LIST* fns = module ? module->GetFunctionList() : nullptr;
    if (fns == nullptr)
    {
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    CK_RV rv = fns->C_FindObjectsInit(session, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()));
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "ClearSlot: C_FindObjectsInit failed: rv=" << static_cast<unsigned long>(rv);
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    // Collect all matches first; objects are not destroyed while a search is active.
    std::vector<CK_OBJECT_HANDLE> objects;
    std::array<CK_OBJECT_HANDLE, 16U> batch{};
    CK_ULONG found = 0U;
    do
    {
        found = 0U;
        rv = fns->C_FindObjects(session, batch.data(), static_cast<CK_ULONG>(batch.size()), &found);
        if (rv != CKR_OK)
        {
            break;
        }
        objects.insert(objects.end(), batch.begin(), std::next(batch.begin(), static_cast<std::ptrdiff_t>(found)));
    } while (found > 0U);
    static_cast<void>(fns->C_FindObjectsFinal(session));

    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "ClearSlot: C_FindObjects failed: rv=" << static_cast<unsigned long>(rv);
        m_provider->ReleaseSession(session, reqs);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    for (const CK_OBJECT_HANDLE object : objects)
    {
        rv = fns->C_DestroyObject(session, object);
        // A concurrent clear may already have destroyed the object.
        if (rv != CKR_OK && rv != CKR_OBJECT_HANDLE_INVALID)
        {
            score::mw::log::LogError() << LOG_PREFIX << "ClearSlot: C_DestroyObject failed for slot '" << slot.slot_name
                                       << "': rv=" << static_cast<unsigned long>(rv);
            m_provider->ReleaseSession(session, reqs);
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kPersistFailed);
        }
    }

    m_provider->ReleaseSession(session, reqs);
    return std::monostate{};
}

score::crypto::Expected<score::crypto::KeySlotInfo, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeySlotHandler::GetSlotInfo(const key_management::KeySlotConfig& slot)
{
    auto state = GetSlotState(slot);
    if (!state.has_value())
    {
        return score::crypto::make_unexpected(state.error());
    }
    return key_management::detail::BuildKeySlotInfo(slot, state.value());
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeySlotHandler::StoreKey(
    const key_management::KeySlotConfig& slot,
    key_management::IKeyHandler& handler)
{
    using Error = score::crypto::daemon::common::DaemonErrorCode;

    // Any other provider's key would have to cross into the token as plaintext.
    auto* pkcs11_key = dynamic_cast<Pkcs11KeyHandler*>(&handler);
    if (pkcs11_key == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "StoreKey: slot '" << slot.slot_name
                                   << "' only takes keys of its own PKCS#11 provider";
        return score::crypto::make_unexpected(Error::kKeyNotExportable);
    }

    auto module = m_module.lock();
    if ((!m_provider) || (!module) || (module->GetFunctionList() == nullptr))
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    CK_FUNCTION_LIST& fns = *module->GetFunctionList();

    auto name = LoadStorableSearchTemplate(slot);
    if (!name.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "StoreKey: slot '" << slot.slot_name
                                   << "' has no usable pkcs11.label / pkcs11.object_id";
        return score::crypto::make_unexpected(name.error());
    }
    TokenKeyTemplate tmpl{name.value(), slot.allowed_operations, CKK_GENERIC_SECRET, true};

    const std::lock_guard<std::mutex> lock{SlotStoreMutex()};
    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
    Pkcs11SessionGuard guard(*m_provider, reqs);
    if (!guard)
    {
        return score::crypto::make_unexpected(Error::kProviderBusy);
    }

    // A session key is only addressable in its creating session, which is
    // what ResolveObject returns for it; a token key resolves on ours.
    auto resolved = pkcs11_key->ResolveObject(guard.get());
    if (!resolved.has_value())
    {
        return score::crypto::make_unexpected(resolved.error());
    }
    const CK_SESSION_HANDLE session = resolved.value().session();

    auto exists = SlotObjectExists(fns, session, name.value());
    if (!exists.has_value())
    {
        return score::crypto::make_unexpected(exists.error());
    }
    if (exists.value())
    {
        return score::crypto::make_unexpected(Error::kKeySlotOccupied);
    }

    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    const CK_RV rv = fns.C_CopyObject(session, resolved.value().object(), tmpl.data(), tmpl.size(), &copy);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "StoreKey: C_CopyObject into slot '" << slot.slot_name
                                   << "' failed: rv=" << static_cast<unsigned long>(rv);
        return score::crypto::make_unexpected(Error::kOperationFailed);
    }
    // CKA_EXTRACTABLE may only go from TRUE to FALSE and is read-only once
    // FALSE, so touch it only on a copy that is extractable against the slot.
    CK_BBOOL extractable_value = CK_FALSE;
    CK_ATTRIBUTE extractable{CKA_EXTRACTABLE, &extractable_value, sizeof(extractable_value)};
    CK_RV attr_rv = fns.C_GetAttributeValue(session, copy, &extractable, 1U);
    if ((attr_rv == CKR_OK) && (extractable_value == CK_TRUE) &&
        (!score::crypto::HasPermission(slot.allowed_operations, score::crypto::KeyOperationPermission::kExport)))
    {
        extractable_value = CK_FALSE;
        attr_rv = fns.C_SetAttributeValue(session, copy, &extractable, 1U);
    }
    if (attr_rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "StoreKey: restricting CKA_EXTRACTABLE in slot '" << slot.slot_name
                                   << "' failed: rv=" << static_cast<unsigned long>(attr_rv);
        static_cast<void>(fns.C_DestroyObject(session, copy));
        return score::crypto::make_unexpected(Error::kOperationFailed);
    }
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::pkcs11
