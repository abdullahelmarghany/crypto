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

#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_slot_object.hpp"

#include "score/crypto/src/daemon/key_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{
namespace
{
using Error = score::crypto::daemon::common::DaemonErrorCode;
}  // namespace

KeyUsageFlags BuildUsageFlags(score::crypto::KeyOperationPermission perm) noexcept
{
    using P = score::crypto::KeyOperationPermission;
    auto has = [perm](P bit) -> CK_BBOOL {
        return ((perm & bit) != P::kNone) ? CK_TRUE : CK_FALSE;
    };
    KeyUsageFlags f;
    f.ck_encrypt = has(P::kEncrypt);
    f.ck_decrypt = has(P::kDecrypt);
    // kMac maps to CKA_SIGN + CKA_VERIFY for symmetric keys (e.g. HMAC, AES-CMAC).
    f.ck_sign = ((has(P::kSign) == CK_TRUE) || (has(P::kMac) == CK_TRUE)) ? CK_TRUE : CK_FALSE;
    f.ck_verify = ((has(P::kVerify) == CK_TRUE) || (has(P::kMac) == CK_TRUE)) ? CK_TRUE : CK_FALSE;
    f.ck_wrap = has(P::kWrap);
    f.ck_unwrap = has(P::kUnwrap);
    f.ck_derive = has(P::kDerive);
    return f;
}

score::crypto::Expected<SearchTemplate, Error> BuildSearchTemplate(
    const std::unordered_map<std::string, std::string>& key_props)
{
    using key_management::deployment_keys::kPkcs11Label;
    using key_management::deployment_keys::kPkcs11ObjectClass;
    using key_management::deployment_keys::kPkcs11ObjectId;

    SearchTemplate search_tmpl;
    const auto label_it = key_props.find(std::string{kPkcs11Label});
    if (label_it != key_props.end())
    {
        search_tmpl.label = label_it->second;
    }
    const auto id_it = key_props.find(std::string{kPkcs11ObjectId});
    if ((id_it != key_props.end()) && !id_it->second.empty())
    {
        auto id_bytes = detail::TryHexDecode(id_it->second);
        if (!id_bytes.has_value())
        {
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        }
        search_tmpl.id = std::move(id_bytes.value());
    }
    if (search_tmpl.label.empty() && search_tmpl.id.empty())
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    // Object class defaults to CKO_SECRET_KEY.
    const auto class_it = key_props.find(std::string{kPkcs11ObjectClass});
    if (class_it != key_props.end())
    {
        if (class_it->second == "private_key")
        {
            search_tmpl.obj_class = CKO_PRIVATE_KEY;
        }
        else if (class_it->second == "public_key")
        {
            search_tmpl.obj_class = CKO_PUBLIC_KEY;
        }
    }
    return search_tmpl;
}

/// Attribute list for C_FindObjectsInit. Points into @p search_tmpl, which must outlive it.
std::vector<CK_ATTRIBUTE> ToAttributes(SearchTemplate& search_tmpl)
{
    std::vector<CK_ATTRIBUTE> attrs;
    attrs.push_back({CKA_CLASS, &search_tmpl.obj_class, sizeof(search_tmpl.obj_class)});
    if (!search_tmpl.label.empty())
    {
        // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (CK_ATTRIBUTE) requires non-const pValue.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        attrs.push_back(
            {CKA_LABEL, const_cast<char*>(search_tmpl.label.data()), static_cast<CK_ULONG>(search_tmpl.label.size())});
    }
    if (!search_tmpl.id.empty())
    {
        attrs.push_back({CKA_ID, search_tmpl.id.data(), static_cast<CK_ULONG>(search_tmpl.id.size())});
    }
    return attrs;
}

score::crypto::Expected<SearchTemplate, Error> LoadStorableSearchTemplate(const key_management::KeySlotConfig& slot)
{
    auto deploy_result = key_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        return score::crypto::make_unexpected(deploy_result.error());
    }
    const auto& key_props = deploy_result.value().key_properties;

    // Only secret keys can be stored: the provider has no asymmetric support.
    const auto class_it = key_props.find(std::string{key_management::deployment_keys::kPkcs11ObjectClass});
    if ((class_it != key_props.end()) && (class_it->second != "secret_key"))
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    return BuildSearchTemplate(key_props);
}

score::crypto::Expected<bool, Error> SlotObjectExists(CK_FUNCTION_LIST& fns,
                                                      CK_SESSION_HANDLE session,
                                                      SearchTemplate search_tmpl)
{
    std::vector<CK_ATTRIBUTE> tmpl = ToAttributes(search_tmpl);
    if (fns.C_FindObjectsInit(session, tmpl.data(), static_cast<CK_ULONG>(tmpl.size())) != CKR_OK)
    {
        return score::crypto::make_unexpected(Error::kOperationFailed);
    }
    CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
    CK_ULONG count = 0U;
    const CK_RV rv = fns.C_FindObjects(session, &object, 1U, &count);
    static_cast<void>(fns.C_FindObjectsFinal(session));
    if (rv != CKR_OK)
    {
        return score::crypto::make_unexpected(Error::kOperationFailed);
    }
    return count > 0U;
}

std::mutex& SlotStoreMutex() noexcept
{
    static std::mutex mutex;
    return mutex;
}

TokenKeyTemplate::TokenKeyTemplate(const SearchTemplate& name,
                                   score::crypto::KeyOperationPermission allowed_operations,
                                   CK_KEY_TYPE key_type,
                                   bool for_copy)
    : m_label{name.label},
      m_id{name.id},
      m_key_type{key_type},
      m_extractable{static_cast<CK_BBOOL>(
          score::crypto::HasPermission(allowed_operations, score::crypto::KeyOperationPermission::kExport) ? CK_TRUE
                                                                                                           : CK_FALSE)},
      m_flags{BuildUsageFlags(allowed_operations)}
{
    if (!for_copy)
    {
        Add(CKA_CLASS, &m_class, sizeof(m_class));
        Add(CKA_KEY_TYPE, &m_key_type, sizeof(m_key_type));
        Add(CKA_PRIVATE, &m_true, sizeof(CK_BBOOL));
        Add(CKA_SENSITIVE, &m_true, sizeof(CK_BBOOL));
    }
    Add(CKA_TOKEN, &m_true, sizeof(CK_BBOOL));
    if (!m_label.empty())
    {
        Add(CKA_LABEL, m_label.data(), static_cast<CK_ULONG>(m_label.size()));
    }
    if (!m_id.empty())
    {
        Add(CKA_ID, m_id.data(), static_cast<CK_ULONG>(m_id.size()));
    }
    if (!for_copy)
    {
        Add(CKA_EXTRACTABLE, &m_extractable, sizeof(CK_BBOOL));
    }
    Add(CKA_ENCRYPT, &m_flags.ck_encrypt, sizeof(CK_BBOOL));
    Add(CKA_DECRYPT, &m_flags.ck_decrypt, sizeof(CK_BBOOL));
    Add(CKA_SIGN, &m_flags.ck_sign, sizeof(CK_BBOOL));
    Add(CKA_VERIFY, &m_flags.ck_verify, sizeof(CK_BBOOL));
    Add(CKA_WRAP, &m_flags.ck_wrap, sizeof(CK_BBOOL));
    Add(CKA_UNWRAP, &m_flags.ck_unwrap, sizeof(CK_BBOOL));
    Add(CKA_DERIVE, &m_flags.ck_derive, sizeof(CK_BBOOL));
}

void TokenKeyTemplate::Add(CK_ATTRIBUTE_TYPE type, void* value, CK_ULONG size)
{
    m_attributes.push_back({type, value, size});
}

}  // namespace score::crypto::daemon::provider::pkcs11
