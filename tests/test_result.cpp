#include <gtest/gtest.h>
#include <licenseseat/licenseseat.hpp>

namespace licenseseat {
namespace {

TEST(ResultTest, OkResultIsNotError) {
    auto result = Result<int>::ok(42);

    EXPECT_TRUE(result.is_ok());
    EXPECT_FALSE(result.is_error());
    EXPECT_EQ(result.value(), 42);
    EXPECT_EQ(result.error_code(), ErrorCode::Success);
}

TEST(ResultTest, ErrorResultIsNotOk) {
    auto result = Result<int>::error(ErrorCode::NetworkError, "Connection failed");

    EXPECT_FALSE(result.is_ok());
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
    EXPECT_EQ(result.error_message(), "Connection failed");
}

TEST(ResultTest, VoidOkResult) {
    auto result = Result<void>::ok();

    EXPECT_TRUE(result.is_ok());
    EXPECT_FALSE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::Success);
}

TEST(ResultTest, VoidErrorResult) {
    auto result = Result<void>::error(ErrorCode::AuthenticationFailed);

    EXPECT_FALSE(result.is_ok());
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::AuthenticationFailed);
}

TEST(ResultTest, StringResult) {
    auto result = Result<std::string>::ok("hello world");

    EXPECT_TRUE(result.is_ok());
    EXPECT_EQ(result.value(), "hello world");
}

TEST(ErrorCodeTest, ToStringConversion) {
    EXPECT_STREQ(error_code_to_string(ErrorCode::Success), "Success");
    EXPECT_STREQ(error_code_to_string(ErrorCode::NetworkError), "Network error");
    EXPECT_STREQ(error_code_to_string(ErrorCode::InvalidLicenseKey), "Invalid license key");
    EXPECT_STREQ(error_code_to_string(ErrorCode::LicenseExpired), "License expired");
    EXPECT_STREQ(error_code_to_string(ErrorCode::AuthenticationFailed), "Authentication failed");
    EXPECT_STREQ(error_code_to_string(ErrorCode::Unknown), "Unknown error");
}

} // namespace
} // namespace licenseseat
