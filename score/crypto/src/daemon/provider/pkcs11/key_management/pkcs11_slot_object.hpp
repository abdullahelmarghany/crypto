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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_SLOT_OBJECT_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_SLOT_OBJECT_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"

#include <pkcs11.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

/// @brief Per-usage CK_BBOOL values derived from a KeyOperationPermission bitmask.
struct KeyUsageFlags
{
    CK_BBOOL ck_encrypt{CK_FALSE};
    CK_BBOOL ck_decrypt{CK_FALSE};
    CK_BBOOL ck_sign{CK_FALSE};    ///< covers kSign and kMac (PKCS#11 CKA_SIGN = MAC for symmetric)
    CK_BBOOL ck_verify{CK_FALSE};  ///< covers kVerify and kMac
    CK_BBOOL ck_wrap{CK_FALSE};
    CK_BBOOL ck_unwrap{CK_FALSE};
    CK_BBOOL ck_derive{CK_FALSE};
};

[[nodiscard]] KeyUsageFlags BuildUsageFlags(score::crypto::KeyOperationPermission perm) noexcept;

/// Build the token object search template from the slot deployment properties.
/// At least one of pkcs11.label / pkcs11.object_id must be set and non-empty,
/// otherwise kInvalidArgument. An empty object_id counts as absent; any other
/// object_id must be valid hex (kInvalidArgument otherwise), so a malformed ID
/// cannot silently degrade to a label-only match.
[[nodiscard]] score::crypto::Expected<SearchTemplate, score::crypto::daemon::common::DaemonErrorCode>
BuildSearchTemplate(const std::unordered_map<std::string, std::string>& key_props);

/// Attribute list for C_FindObjectsInit. Points into @p search_tmpl, which must outlive it.
[[nodiscard]] std::vector<CK_ATTRIBUTE> ToAttributes(SearchTemplate& search_tmpl);

/// Search template of a slot that keys may be stored into: BuildSearchTemplate()
/// of the slot deployment, restricted to secret-key objects (kInvalidArgument
/// for any other pkcs11.object_class).
[[nodiscard]] score::crypto::Expected<SearchTemplate, score::crypto::daemon::common::DaemonErrorCode>
LoadStorableSearchTemplate(const key_management::KeySlotConfig& slot);

/// Whether an object matching @p search_tmpl exists on the token of @p session.
[[nodiscard]] score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode>
SlotObjectExists(CK_FUNCTION_LIST& fns, CK_SESSION_HANDLE session, SearchTemplate search_tmpl);

/// Serialises the "is the slot empty, then create the object" sequence of all
/// PKCS#11 slot stores in this process.
[[nodiscard]] std::mutex& SlotStoreMutex() noexcept;

/// Attribute template for a token secret key stored into a slot.
///
/// Carries CKA_TOKEN=TRUE, CKA_LABEL / CKA_ID from @p name and the usage flags
/// of the slot's allowed_operations; with @p for_copy unset also CKA_CLASS,
/// CKA_KEY_TYPE, CKA_PRIVATE=TRUE, CKA_SENSITIVE=TRUE and CKA_EXTRACTABLE
/// (TRUE only if the slot allows kExport). A copy keeps the source's
/// CKA_EXTRACTABLE: tokens such as SoftHSM refuse it in a C_CopyObject
/// template, so the caller clears it afterwards with C_SetAttributeValue.
/// The attributes point into this object, so it is neither copyable nor movable.
class TokenKeyTemplate final
{
  public:
    TokenKeyTemplate(const SearchTemplate& name,
                     score::crypto::KeyOperationPermission allowed_operations,
                     CK_KEY_TYPE key_type,
                     bool for_copy);

    TokenKeyTemplate(const TokenKeyTemplate&) = delete;
    TokenKeyTemplate& operator=(const TokenKeyTemplate&) = delete;
    TokenKeyTemplate(TokenKeyTemplate&&) = delete;
    TokenKeyTemplate& operator=(TokenKeyTemplate&&) = delete;
    ~TokenKeyTemplate() = default;

    /// Append an attribute; @p value must outlive this template.
    void Add(CK_ATTRIBUTE_TYPE type, void* value, CK_ULONG size);

    [[nodiscard]] CK_ATTRIBUTE* data() noexcept
    {
        return m_attributes.data();
    }
    [[nodiscard]] CK_ULONG size() const noexcept
    {
        return static_cast<CK_ULONG>(m_attributes.size());
    }

  private:
    std::string m_label;
    std::vector<uint8_t> m_id;
    CK_OBJECT_CLASS m_class{CKO_SECRET_KEY};
    CK_KEY_TYPE m_key_type;
    CK_BBOOL m_true{CK_TRUE};
    CK_BBOOL m_extractable;
    KeyUsageFlags m_flags;
    std::vector<CK_ATTRIBUTE> m_attributes;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_SLOT_OBJECT_HPP
