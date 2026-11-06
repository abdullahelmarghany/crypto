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

#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

namespace score::crypto
{
namespace
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;
namespace actors = ::score::crypto::daemon::common::actors;
namespace keymgmt_ops = ::score::crypto::daemon::key_management::operations;

constexpr std::uint64_t kContextId = 42U;
constexpr std::uint64_t kSlotId = 7U;
constexpr proto::OperationIdentifier kKeyClear{actors::OP_ACTOR_KEY_MANAGEMENT, keymgmt_ops::KEY_CLEAR};

/// Records every request and answers each with the same canned response.
class FakeConnection final : public api::control_plane::IConnection
{
  public:
    Expected<proto::ControlResponse, CryptoErrorCode> SendRequest(const proto::ControlRequest& request) override
    {
        requests.push_back(request);
        return response;
    }

    proto::DataNodeId GetConnectionNodeId() const override
    {
        return 0U;
    }

    std::vector<proto::ControlRequest> requests;
    Expected<proto::ControlResponse, CryptoErrorCode> response{make_unexpected(CryptoErrorCode::kInternalError)};
};

proto::ControlResponse MakeResponse(proto::OperationResult result)
{
    proto::ControlResponse response{};
    response.operation.operations.push_back(proto::SingleOperationResponse{kKeyClear, result, {std::uint64_t{0U}}});
    return response;
}

class KeyManagementContextImplClearKeyTest : public ::testing::Test
{
  protected:
    std::shared_ptr<FakeConnection> connection_{std::make_shared<FakeConnection>()};
    KeyManagementContextImpl key_mgmt_{connection_, kContextId};
};

TEST_F(KeyManagementContextImplClearKeyTest, SendsKeyClearWithSlotId)
{
    connection_->response = MakeResponse(proto::OPERATION_RESULT_SUCCESS);

    const auto result = key_mgmt_.ClearKey(CryptoResourceId{kSlotId, ResourceType::kKeySlot});

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(connection_->requests.size(), 1U);
    const auto& request = connection_->requests.front();
    EXPECT_EQ(request.data_node_id, kContextId);
    ASSERT_EQ(request.operation.operations.size(), 1U);
    const auto& operation = request.operation.operations.front();
    EXPECT_EQ(operation.operationId.operationActor, kKeyClear.operationActor);
    EXPECT_EQ(operation.operationId.operationAction, kKeyClear.operationAction);
    ASSERT_EQ(operation.parameters.size(), 1U);
    const auto* const slot_id = std::get_if<std::uint64_t>(&operation.parameters.front());
    ASSERT_NE(slot_id, nullptr);
    EXPECT_EQ(*slot_id, kSlotId);
}

TEST_F(KeyManagementContextImplClearKeyTest, NonSlotResourceIsRejectedWithoutRequest)
{
    const auto result = key_mgmt_.ClearKey(CryptoResourceId{kSlotId, ResourceType::kKey});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    EXPECT_TRUE(connection_->requests.empty());
}

TEST_F(KeyManagementContextImplClearKeyTest, DaemonErrorIsForwarded)
{
    connection_->response = MakeResponse(static_cast<proto::OperationResult>(CryptoErrorCode::kAccessDenied));

    const auto result = key_mgmt_.ClearKey(CryptoResourceId{kSlotId, ResourceType::kKeySlot});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kAccessDenied));
}

TEST_F(KeyManagementContextImplClearKeyTest, ConnectionFailureIsAnError)
{
    connection_->response = make_unexpected(CryptoErrorCode::kInternalError);

    EXPECT_FALSE(key_mgmt_.ClearKey(CryptoResourceId{kSlotId, ResourceType::kKeySlot}).has_value());
}

}  // namespace
}  // namespace score::crypto
