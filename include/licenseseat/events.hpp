#pragma once

#include "licenseseat.hpp"

/**
 * @file events.hpp
 * @brief Event bus and callback system for LicenseSeat SDK
 *
 * Provides an event-driven architecture similar to the Swift SDK's EventBus.
 */

#include <algorithm>
#include <any>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace licenseseat {

/// Event data type - can hold any value
using EventData = std::any;

/// Event handler callback type
using EventHandler = std::function<void(const EventData&)>;

/// Backward-compatible name for the public client subscription handle.
using EventSubscription = Subscription;

/**
 * @brief Event bus for SDK-wide event handling
 *
 * Supports the following events (matching Swift SDK):
 * - "license:loaded" - License loaded from cache
 * - "activation:start" - Activation started
 * - "activation:success" - Activation succeeded
 * - "activation:error" - Activation failed
 * - "validation:start" - Validation started
 * - "validation:success" - Validation succeeded (online)
 * - "validation:failed" - Validation failed
 * - "validation:error" - Validation error
 * - "validation:offline-success" - Offline validation succeeded
 * - "validation:offline-failed" - Offline validation failed
 * - "deactivation:start" - Deactivation started
 * - "deactivation:success" - Deactivation succeeded
 * - "deactivation:error" - Deactivation failed
 * - "network:online" - Network became available
 * - "network:offline" - Network became unavailable
 * - "autovalidation:cycle" - Auto-validation cycle completed
 * - "autovalidation:stopped" - Auto-validation stopped
 * - "offlineToken:ready" - Legacy offline token ready
 * - "offlineToken:verified" - Legacy offline token verified
 * - "machineFile:fetching" - Machine file fetch started
 * - "machineFile:fetched" - Machine file fetched from server
 * - "machineFile:fetchError" - Machine file fetch failed
 * - "machineFile:ready" - Machine file cached locally
 * - "machineFile:verified" - Machine file verified locally
 * - "machineFile:verificationFailed" - Machine file verification failed
 * - "sdk:reset" - SDK state was reset
 */
class EventBus {
  private:
    struct HandlerEntry {
        uint64_t id;
        EventHandler handler;
    };

    struct State {
        std::unordered_map<std::string, std::vector<HandlerEntry>> handlers;
        std::mutex mutex;
        uint64_t next_id = 0;
    };

  public:
    EventBus() : state_(std::make_shared<State>()) {}
    ~EventBus() = default;

    // Non-copyable
    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;

    // Not movable (contains mutex)
    EventBus(EventBus&&) = delete;
    EventBus& operator=(EventBus&&) = delete;

    /**
     * @brief Subscribe to an event
     *
     * @param event Event name
     * @param handler Callback function
     * @return Subscription handle to unsubscribe
     */
    EventSubscription on(const std::string& event, EventHandler handler) {
        const auto state = state_;
        std::lock_guard<std::mutex> lock(state->mutex);

        auto id = state->next_id++;
        state->handlers[event].push_back({id, std::move(handler)});

        return EventSubscription([weak_state = std::weak_ptr<State>(state), event, id]() {
            if (const auto live_state = weak_state.lock()) {
                remove_handler(*live_state, event, id);
            }
        });
    }

    /**
     * @brief Emit an event to all subscribers
     *
     * @param event Event name
     * @param data Event data (optional)
     */
    void emit(const std::string& event, const EventData& data = {}) {
        std::vector<EventHandler> handlers_copy;

        {
            const auto state = state_;
            std::lock_guard<std::mutex> lock(state->mutex);
            auto it = state->handlers.find(event);
            if (it != state->handlers.end()) {
                for (const auto& [id, handler] : it->second) {
                    handlers_copy.push_back(handler);
                }
            }
        }

        // Call handlers outside the lock to prevent deadlocks
        for (const auto& handler : handlers_copy) {
            try {
                handler(data);
            } catch (...) {
                // Ignore exceptions from handlers
            }
        }
    }

    /**
     * @brief Remove all handlers for an event
     *
     * @param event Event name
     */
    void clear(const std::string& event) {
        const auto state = state_;
        std::lock_guard<std::mutex> lock(state->mutex);
        state->handlers.erase(event);
    }

    /**
     * @brief Remove all handlers for all events
     */
    void clear_all() {
        const auto state = state_;
        std::lock_guard<std::mutex> lock(state->mutex);
        state->handlers.clear();
    }

  private:
    static void remove_handler(State& state, const std::string& event, uint64_t id) {
        std::lock_guard<std::mutex> lock(state.mutex);
        auto it = state.handlers.find(event);
        if (it != state.handlers.end()) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                                     [id](const HandlerEntry& e) { return e.id == id; }),
                      vec.end());
        }
    }

    std::shared_ptr<State> state_;
};

// Common event names as constants (matches Swift SDK EventBus)
namespace events {
// License lifecycle events
constexpr const char* LICENSE_LOADED = "license:loaded";
constexpr const char* LICENSE_REVOKED = "license:revoked";

// Activation events
constexpr const char* ACTIVATION_START = "activation:start";
constexpr const char* ACTIVATION_SUCCESS = "activation:success";
constexpr const char* ACTIVATION_ERROR = "activation:error";

// Validation events
constexpr const char* VALIDATION_START = "validation:start";
constexpr const char* VALIDATION_SUCCESS = "validation:success";
constexpr const char* VALIDATION_FAILED = "validation:failed";
constexpr const char* VALIDATION_ERROR = "validation:error";
constexpr const char* VALIDATION_OFFLINE_SUCCESS = "validation:offline-success";
constexpr const char* VALIDATION_OFFLINE_FAILED = "validation:offline-failed";
constexpr const char* VALIDATION_AUTH_FAILED = "validation:auth-failed";
constexpr const char* VALIDATION_AUTO_FAILED = "validation:auto-failed";

// Deactivation events
constexpr const char* DEACTIVATION_START = "deactivation:start";
constexpr const char* DEACTIVATION_SUCCESS = "deactivation:success";
constexpr const char* DEACTIVATION_ERROR = "deactivation:error";

// Network events
constexpr const char* NETWORK_ONLINE = "network:online";
constexpr const char* NETWORK_OFFLINE = "network:offline";

// Auto-validation events
constexpr const char* AUTOVALIDATION_CYCLE = "autovalidation:cycle";
constexpr const char* AUTOVALIDATION_STOPPED = "autovalidation:stopped";

// Offline token events
constexpr const char* OFFLINE_TOKEN_FETCHING = "offlineToken:fetching";
constexpr const char* OFFLINE_TOKEN_FETCHED = "offlineToken:fetched";
constexpr const char* OFFLINE_TOKEN_FETCH_ERROR = "offlineToken:fetchError";
constexpr const char* OFFLINE_TOKEN_READY = "offlineToken:ready";
constexpr const char* OFFLINE_TOKEN_VERIFIED = "offlineToken:verified";
constexpr const char* OFFLINE_TOKEN_VERIFICATION_FAILED = "offlineToken:verificationFailed";

// Machine file events
constexpr const char* MACHINE_FILE_FETCHING = "machineFile:fetching";
constexpr const char* MACHINE_FILE_FETCHED = "machineFile:fetched";
constexpr const char* MACHINE_FILE_FETCH_ERROR = "machineFile:fetchError";
constexpr const char* MACHINE_FILE_READY = "machineFile:ready";
constexpr const char* MACHINE_FILE_VERIFIED = "machineFile:verified";
constexpr const char* MACHINE_FILE_VERIFICATION_FAILED = "machineFile:verificationFailed";

// Heartbeat events
constexpr const char* HEARTBEAT_SUCCESS = "heartbeat:success";
constexpr const char* HEARTBEAT_ERROR = "heartbeat:error";

// SDK events
constexpr const char* SDK_RESET = "sdk:reset";
constexpr const char* SDK_ERROR = "sdk:error";
} // namespace events

} // namespace licenseseat
