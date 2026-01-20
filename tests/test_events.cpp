#include <gtest/gtest.h>
#include <licenseseat/events.hpp>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

namespace licenseseat {
namespace {

// ==================== EventBus Tests ====================

class EventBusTest : public ::testing::Test {
  protected:
    EventBus bus;
};

TEST_F(EventBusTest, CanSubscribeAndReceiveEvents) {
    bool called = false;
    std::string received_data;

    auto sub = bus.on("test:event", [&](const EventData& data) {
        called = true;
        if (data.has_value()) {
            received_data = std::any_cast<std::string>(data);
        }
    });

    bus.emit("test:event", std::string("hello"));

    EXPECT_TRUE(called);
    EXPECT_EQ(received_data, "hello");
}

TEST_F(EventBusTest, SubscriptionCanBeCancelled) {
    int call_count = 0;

    auto sub = bus.on("test:event", [&](const EventData& /*data*/) { call_count++; });

    bus.emit("test:event");
    EXPECT_EQ(call_count, 1);

    sub.cancel();

    bus.emit("test:event");
    EXPECT_EQ(call_count, 1);  // Should not increase after cancel
}

TEST_F(EventBusTest, MultipleSubscribersReceiveEvents) {
    int count1 = 0;
    int count2 = 0;

    auto sub1 = bus.on("test:event", [&](const EventData& /*data*/) { count1++; });
    auto sub2 = bus.on("test:event", [&](const EventData& /*data*/) { count2++; });

    bus.emit("test:event");

    EXPECT_EQ(count1, 1);
    EXPECT_EQ(count2, 1);
}

TEST_F(EventBusTest, DifferentEventsAreIndependent) {
    int count_a = 0;
    int count_b = 0;

    auto sub_a = bus.on("event:a", [&](const EventData& /*data*/) { count_a++; });
    auto sub_b = bus.on("event:b", [&](const EventData& /*data*/) { count_b++; });

    bus.emit("event:a");

    EXPECT_EQ(count_a, 1);
    EXPECT_EQ(count_b, 0);
}

TEST_F(EventBusTest, ClearRemovesAllHandlersForEvent) {
    int count = 0;

    bus.on("test:event", [&](const EventData& /*data*/) { count++; });
    bus.on("test:event", [&](const EventData& /*data*/) { count++; });

    bus.clear("test:event");
    bus.emit("test:event");

    EXPECT_EQ(count, 0);
}

TEST_F(EventBusTest, ClearAllRemovesEverything) {
    int count = 0;

    bus.on("event:a", [&](const EventData& /*data*/) { count++; });
    bus.on("event:b", [&](const EventData& /*data*/) { count++; });

    bus.clear_all();
    bus.emit("event:a");
    bus.emit("event:b");

    EXPECT_EQ(count, 0);
}

TEST_F(EventBusTest, SubscriptionIsActiveWorks) {
    auto sub = bus.on("test:event", [](const EventData& /*data*/) {});

    EXPECT_TRUE(sub.is_active());

    sub.cancel();

    EXPECT_FALSE(sub.is_active());
}

TEST_F(EventBusTest, EmitWithNoSubscribersDoesNotCrash) {
    // Should not crash even with no subscribers
    bus.emit("nonexistent:event");
    bus.emit("another:event", std::string("data"));
    SUCCEED();
}

TEST_F(EventBusTest, HandlerExceptionDoesNotPropagateOrAffectOthers) {
    int count = 0;

    bus.on("test:event", [](const EventData& /*data*/) { throw std::runtime_error("oops"); });
    bus.on("test:event", [&](const EventData& /*data*/) { count++; });

    // Should not throw and second handler should still run
    bus.emit("test:event");

    EXPECT_EQ(count, 1);
}

TEST_F(EventBusTest, ThreadSafetyMultipleThreadsEmitting) {
    std::atomic<int> count{0};

    bus.on("test:event", [&](const EventData& /*data*/) { count++; });

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < 100; ++j) {
                bus.emit("test:event");
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(count, 1000);
}

// ==================== Event Constants Tests ====================

TEST(EventConstantsTest, EventNamesAreDefined) {
    EXPECT_STREQ(events::LICENSE_LOADED, "license:loaded");
    EXPECT_STREQ(events::ACTIVATION_START, "activation:start");
    EXPECT_STREQ(events::ACTIVATION_SUCCESS, "activation:success");
    EXPECT_STREQ(events::ACTIVATION_ERROR, "activation:error");
    EXPECT_STREQ(events::VALIDATION_START, "validation:start");
    EXPECT_STREQ(events::VALIDATION_SUCCESS, "validation:success");
    EXPECT_STREQ(events::VALIDATION_FAILED, "validation:failed");
    EXPECT_STREQ(events::VALIDATION_ERROR, "validation:error");
    EXPECT_STREQ(events::VALIDATION_OFFLINE_SUCCESS, "validation:offline-success");
    EXPECT_STREQ(events::VALIDATION_OFFLINE_FAILED, "validation:offline-failed");
    EXPECT_STREQ(events::DEACTIVATION_START, "deactivation:start");
    EXPECT_STREQ(events::DEACTIVATION_SUCCESS, "deactivation:success");
    EXPECT_STREQ(events::DEACTIVATION_ERROR, "deactivation:error");
    EXPECT_STREQ(events::NETWORK_ONLINE, "network:online");
    EXPECT_STREQ(events::NETWORK_OFFLINE, "network:offline");
    EXPECT_STREQ(events::AUTOVALIDATION_CYCLE, "autovalidation:cycle");
    EXPECT_STREQ(events::AUTOVALIDATION_STOPPED, "autovalidation:stopped");
    EXPECT_STREQ(events::OFFLINE_LICENSE_READY, "offlineLicense:ready");
    EXPECT_STREQ(events::OFFLINE_LICENSE_VERIFIED, "offlineLicense:verified");
    EXPECT_STREQ(events::SDK_RESET, "sdk:reset");
}

}  // namespace
}  // namespace licenseseat
