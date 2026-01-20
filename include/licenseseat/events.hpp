#pragma once

/**
 * @file events.hpp
 * @brief Event bus and callback system for LicenseSeat SDK
 *
 * Provides an event-driven architecture similar to the Swift SDK's EventBus.
 */

#include <algorithm>
#include <any>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace licenseseat {

/// Event data type - can hold any value
using EventData = std::any;

/// Event handler callback type
using EventHandler = std::function<void(const EventData&)>;

/// Internal subscription handle for EventBus (separate from Client's Subscription)
class EventSubscription {
  public:
    EventSubscription() = default;
    explicit EventSubscription(std::function<void()> unsubscribe) : unsubscribe_(std::move(unsubscribe)) {}

    /// Cancel this subscription
    void cancel() {
        if (unsubscribe_) {
            unsubscribe_();
            unsubscribe_ = nullptr;
        }
    }

    /// Check if subscription is active
    [[nodiscard]] bool is_active() const { return unsubscribe_ != nullptr; }

  private:
    std::function<void()> unsubscribe_;
};

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
 * - "offlineLicense:ready" - Offline license ready
 * - "offlineLicense:verified" - Offline license verified
 * - "sdk:reset" - SDK state was reset
 */
class EventBus {
  public:
    EventBus() = default;
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
        std::lock_guard<std::mutex> lock(mutex_);

        auto id = next_id_++;
        handlers_[event].push_back({id, std::move(handler)});

        return EventSubscription([this, event, id]() { this->remove_handler(event, id); });
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
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = handlers_.find(event);
            if (it != handlers_.end()) {
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
        std::lock_guard<std::mutex> lock(mutex_);
        handlers_.erase(event);
    }

    /**
     * @brief Remove all handlers for all events
     */
    void clear_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        handlers_.clear();
    }

  private:
    struct HandlerEntry {
        uint64_t id;
        EventHandler handler;
    };

    void remove_handler(const std::string& event, uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = handlers_.find(event);
        if (it != handlers_.end()) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                                     [id](const HandlerEntry& e) { return e.id == id; }),
                      vec.end());
        }
    }

    std::unordered_map<std::string, std::vector<HandlerEntry>> handlers_;
    std::mutex mutex_;
    uint64_t next_id_ = 0;
};

// Common event names as constants
namespace events {
constexpr const char* LICENSE_LOADED = "license:loaded";
constexpr const char* ACTIVATION_START = "activation:start";
constexpr const char* ACTIVATION_SUCCESS = "activation:success";
constexpr const char* ACTIVATION_ERROR = "activation:error";
constexpr const char* VALIDATION_START = "validation:start";
constexpr const char* VALIDATION_SUCCESS = "validation:success";
constexpr const char* VALIDATION_FAILED = "validation:failed";
constexpr const char* VALIDATION_ERROR = "validation:error";
constexpr const char* VALIDATION_OFFLINE_SUCCESS = "validation:offline-success";
constexpr const char* VALIDATION_OFFLINE_FAILED = "validation:offline-failed";
constexpr const char* DEACTIVATION_START = "deactivation:start";
constexpr const char* DEACTIVATION_SUCCESS = "deactivation:success";
constexpr const char* DEACTIVATION_ERROR = "deactivation:error";
constexpr const char* NETWORK_ONLINE = "network:online";
constexpr const char* NETWORK_OFFLINE = "network:offline";
constexpr const char* AUTOVALIDATION_CYCLE = "autovalidation:cycle";
constexpr const char* AUTOVALIDATION_STOPPED = "autovalidation:stopped";
constexpr const char* OFFLINE_LICENSE_READY = "offlineLicense:ready";
constexpr const char* OFFLINE_LICENSE_VERIFIED = "offlineLicense:verified";
constexpr const char* SDK_RESET = "sdk:reset";
}  // namespace events

}  // namespace licenseseat
