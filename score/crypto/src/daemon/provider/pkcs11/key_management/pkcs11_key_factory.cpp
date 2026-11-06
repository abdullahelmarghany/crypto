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

#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_factory.hpp"

#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_handler.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_slot_object.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_session_guard.hpp"

#include "score/mw/log/logging.h"

#include <mutex>

namespace score::crypto::daemon::provider::pkcs11
{

// ========== Private definition for LOG_PREFIX ==========
#ifndef LOG_PREFIX
#define LOG_PREFIX "[Pkcs11KeyFactory] "
#endif

Pkcs11KeyFactory::Pkcs11KeyFactory(std::weak_ptr<Pkcs11Provider> provider,
                                   std::weak_ptr<Pkcs11Module> module,
                                   std::shared_ptr<Pkcs11KeyStore> key_store)
    : m_provider{std::move(provider)}, m_module{std::move(module)}, m_key_store{std::move(key_store)}
{
}

score::crypto::Expected<key_management::IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyFactory::GenerateKey(const key_management::KeyGenerationRequest& request)
{
    auto provider = m_provider.lock();
    if (!provider)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const auto algo_info = detail::LookupAlgorithm(request.algorithm);
    if (!algo_info.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "GenerateKey: unsupported algorithm '" << request.algorithm.name
                                   << "'";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
    Pkcs11SessionGuard guard(*provider, reqs);
    if (!guard)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const CK_SESSION_HANDLE session = guard.get();

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_extractable =
        score::crypto::HasPermission(request.permissions, score::crypto::KeyOperationPermission::kExport) ? CK_TRUE
                                                                                                          : CK_FALSE;
    CK_ULONG val_len = algo_info->value_len;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = algo_info->ck_key_type;
    KeyUsageFlags flags = BuildUsageFlags(request.permissions);

    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &ck_false, sizeof(CK_BBOOL)},
        {CKA_SENSITIVE, &ck_true, sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE, &ck_extractable, sizeof(CK_BBOOL)},
        {CKA_ENCRYPT, &flags.ck_encrypt, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &flags.ck_decrypt, sizeof(CK_BBOOL)},
        {CKA_SIGN, &flags.ck_sign, sizeof(CK_BBOOL)},
        {CKA_VERIFY, &flags.ck_verify, sizeof(CK_BBOOL)},
        {CKA_WRAP, &flags.ck_wrap, sizeof(CK_BBOOL)},
        {CKA_UNWRAP, &flags.ck_unwrap, sizeof(CK_BBOOL)},
        {CKA_DERIVE, &flags.ck_derive, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &val_len, sizeof(CK_ULONG)},
    };

    CK_MECHANISM mechanism{algo_info->gen_mechanism, nullptr, 0U};
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    auto module = m_module.lock();
    if (!module)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    const CK_RV rv = fns->C_GenerateKey(session, &mechanism, attrs, sizeof(attrs) / sizeof(attrs[0]), &object);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_GenerateKey failed: rv=" << static_cast<unsigned long>(rv);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    const auto handle = m_key_store->Register(
        session, object, request.algorithm, static_cast<std::size_t>(val_len), request.permissions);

    // Session intentionally NOT released here.  PKCS#11 §5.7: session objects
    // (CKA_TOKEN=false) are destroyed when the creating session is closed.
    // The session must remain open for the entire key lifetime.  It is released
    // in Pkcs11KeyStore::Release() after C_DestroyObject.
    static_cast<void>(guard.release());
    return std::make_shared<Pkcs11KeyHandler>(m_key_store, std::move(handle));
}

score::crypto::Expected<key_management::IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyFactory::ImportKey(const key_management::KeyImportRequest& request)
{
    auto provider = m_provider.lock();
    if (!provider || (request.key_data == nullptr) || (request.key_data_size == 0U))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const auto algo_info = detail::LookupAlgorithm(request.algorithm);
    if (!algo_info.has_value())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    const auto valid = ValidateSymmetricImport(request);
    if (!valid.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "ImportKey: " << request.key_data_size
                                   << " bytes are not a valid raw '" << request.algorithm.name << "' key";
        return score::crypto::make_unexpected(valid.error());
    }

    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
    Pkcs11SessionGuard guard(*provider, reqs);
    if (!guard)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kProviderBusy);
    }
    const CK_SESSION_HANDLE session = guard.get();

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_extractable =
        score::crypto::HasPermission(request.permissions, score::crypto::KeyOperationPermission::kExport) ? CK_TRUE
                                                                                                          : CK_FALSE;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = algo_info->ck_key_type;
    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (CK_ATTRIBUTE) requires non-const pValue.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    CK_BYTE_PTR key_value =
        const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(static_cast<const void*>(request.key_data)));
    KeyUsageFlags flags = BuildUsageFlags(request.permissions);

    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &ck_false, sizeof(CK_BBOOL)},
        {CKA_SENSITIVE, &ck_true, sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE, &ck_extractable, sizeof(CK_BBOOL)},
        {CKA_ENCRYPT, &flags.ck_encrypt, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &flags.ck_decrypt, sizeof(CK_BBOOL)},
        {CKA_SIGN, &flags.ck_sign, sizeof(CK_BBOOL)},
        {CKA_VERIFY, &flags.ck_verify, sizeof(CK_BBOOL)},
        {CKA_WRAP, &flags.ck_wrap, sizeof(CK_BBOOL)},
        {CKA_UNWRAP, &flags.ck_unwrap, sizeof(CK_BBOOL)},
        {CKA_DERIVE, &flags.ck_derive, sizeof(CK_BBOOL)},
        {CKA_VALUE, key_value, static_cast<CK_ULONG>(request.key_data_size)},
    };

    auto module = m_module.lock();
    if (!module)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }
    CK_FUNCTION_LIST* fns = module->GetFunctionList();
    if (fns == nullptr)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    }

    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    const CK_RV rv = fns->C_CreateObject(session, attrs, sizeof(attrs) / sizeof(attrs[0]), &object);
    if (rv != CKR_OK)
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    const auto handle =
        m_key_store->Register(session, object, request.algorithm, request.key_data_size, request.permissions);

    // Session intentionally NOT released.  See GenerateKey rationale above.
    static_cast<void>(guard.release());
    return std::make_shared<Pkcs11KeyHandler>(m_key_store, std::move(handle));
}

score::crypto::Expected<key_management::SecureKeyBytes, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyFactory::ExportKey(const key_management::ProviderKeyHandle& handle,
                            std::optional<score::crypto::FormatType> format)
{
    if (!handle.is_asymmetric)
    {
        score::mw::log::LogError() << LOG_PREFIX << "ExportKey: secret keys are not exportable";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);
    }
    return IKeyFactory::ExportKey(handle, format);
}

score::crypto::Expected<std::size_t, score::crypto::daemon::common::DaemonErrorCode> Pkcs11KeyFactory::GetExportKeySize(
    const key_management::ProviderKeyHandle& handle,
    std::optional<score::crypto::FormatType> format)
{
    if (!handle.is_asymmetric)
    {
        score::mw::log::LogError() << LOG_PREFIX << "GetExportKeySize: secret keys are not exportable";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);
    }
    return IKeyFactory::GetExportKeySize(handle, format);
}

// ---------------------------------------------------------------------------
// Keys created directly as token objects of a slot
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyFactory::CreateTokenKey(const key_management::KeySlotConfig& slot,
                                 const ::score::crypto::AlgorithmDescriptor& algorithm,
                                 const key_management::KeyImportRequest* import)
{
    using Error = score::crypto::daemon::common::DaemonErrorCode;
    auto provider = m_provider.lock();
    auto module = m_module.lock();
    if ((!provider) || (!module) || (module->GetFunctionList() == nullptr))
    {
        return score::crypto::make_unexpected(Error::kInternalError);
    }
    CK_FUNCTION_LIST& fns = *module->GetFunctionList();

    const auto algo_info = detail::LookupAlgorithm(algorithm);
    if (!algo_info.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "store: unsupported algorithm '" << algorithm.name << "'";
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    auto name = LoadStorableSearchTemplate(slot);
    if (!name.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "store: slot '" << slot.slot_name
                                   << "' has no usable pkcs11.label / pkcs11.object_id";
        return score::crypto::make_unexpected(name.error());
    }

    TokenKeyTemplate tmpl{name.value(), slot.allowed_operations, algo_info->ck_key_type, false};
    CK_ULONG value_len = algo_info->value_len;
    if (import == nullptr)
    {
        tmpl.Add(CKA_VALUE_LEN, &value_len, sizeof(value_len));
    }
    else
    {
        // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (CK_ATTRIBUTE) requires non-const pValue.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        tmpl.Add(CKA_VALUE,
                 const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(static_cast<const void*>(import->key_data))),
                 static_cast<CK_ULONG>(import->key_data_size));
    }

    const std::lock_guard<std::mutex> lock{SlotStoreMutex()};
    const Pkcs11HandlerRequirements reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
    Pkcs11SessionGuard guard(*provider, reqs);
    if (!guard)
    {
        return score::crypto::make_unexpected(Error::kProviderBusy);
    }

    auto exists = SlotObjectExists(fns, guard.get(), name.value());
    if (!exists.has_value())
    {
        return score::crypto::make_unexpected(exists.error());
    }
    if (exists.value())
    {
        return score::crypto::make_unexpected(Error::kKeySlotOccupied);
    }

    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_RV rv = CKR_OK;
    if (import == nullptr)
    {
        CK_MECHANISM mechanism{algo_info->gen_mechanism, nullptr, 0U};
        rv = fns.C_GenerateKey(guard.get(), &mechanism, tmpl.data(), tmpl.size(), &object);
    }
    else
    {
        rv = fns.C_CreateObject(guard.get(), tmpl.data(), tmpl.size(), &object);
    }
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "store: creating token key for slot '" << slot.slot_name
                                   << "' failed: rv=" << static_cast<unsigned long>(rv);
        return score::crypto::make_unexpected(Error::kOperationFailed);
    }
    // A token object outlives the session, which goes back to the pool.
    return std::monostate{};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyFactory::GenerateKeyToSlot(const key_management::KeySlotConfig& slot,
                                    const key_management::KeyGenerationRequest& request,
                                    key_management::IKeySlotHandler& /*slot_handler*/)
{
    return CreateTokenKey(slot, request.algorithm, nullptr);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11KeyFactory::ImportKeyToSlot(const key_management::KeySlotConfig& slot,
                                  const key_management::KeyImportRequest& request,
                                  key_management::IKeySlotHandler& /*slot_handler*/)
{
    if ((request.key_data == nullptr) || (request.key_data_size == 0U))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    return CreateTokenKey(slot, request.algorithm, &request);
}

}  // namespace score::crypto::daemon::provider::pkcs11
