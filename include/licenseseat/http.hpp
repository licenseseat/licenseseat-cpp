#pragma once

/**
 * @file http.hpp
 * @brief HTTP client abstraction for LicenseSeat SDK
 *
 * Provides a clean HTTP client interface using cpp-httplib under the hood.
 * Handles HTTPS, retries, and common error scenarios.
 */

#include "licenseseat.hpp"

#include <functional>
#include <string>

namespace licenseseat {
namespace http {

/// HTTP method
enum class Method { GET, POST, PUT, DELETE_METHOD };

/// HTTP response structure
struct Response {
    int status_code = 0;
    std::string body;
    bool success = false;
    std::string error_message;
};

/// HTTP request structure
struct Request {
    Method method = Method::GET;
    std::string path;
    std::string body;
    std::string content_type = "application/json";
};

/**
 * @brief HTTP client interface
 *
 * Abstract interface for HTTP operations. Can be mocked for testing.
 */
class HttpClientInterface {
  public:
    virtual ~HttpClientInterface() = default;

    /// Send an HTTP request and return the response
    [[nodiscard]] virtual Response send(const Request& request) = 0;

    /// Check if the client is properly configured
    [[nodiscard]] virtual bool is_configured() const = 0;
};

/**
 * @brief HTTP client using cpp-httplib
 *
 * Implements HttpClientInterface using cpp-httplib for actual HTTP communication.
 * Supports HTTPS with SSL certificate verification.
 */
class HttpClient : public HttpClientInterface {
  public:
    /// Configuration for the HTTP client
    struct Config {
        std::string base_url;
        std::string api_key;
        int timeout_seconds = 30;
        bool verify_ssl = true;
        int max_retries = 3;
        int retry_interval_ms = 1000;
    };

    /// Construct with configuration
    explicit HttpClient(Config config);

    /// Destructor
    ~HttpClient() override;

    // Non-copyable
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // Movable
    HttpClient(HttpClient&&) noexcept;
    HttpClient& operator=(HttpClient&&) noexcept;

    /// Send an HTTP request
    [[nodiscard]] Response send(const Request& request) override;

    /// Check if properly configured
    [[nodiscard]] bool is_configured() const override;

    /// Get the base URL
    [[nodiscard]] const std::string& base_url() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Convert HTTP status code to ErrorCode
[[nodiscard]] inline ErrorCode status_code_to_error_code(int status) {
    if (status >= 200 && status < 300) {
        return ErrorCode::Success;
    }

    switch (status) {
        case 400:
            return ErrorCode::InvalidParameter;
        case 401:
            return ErrorCode::AuthenticationFailed;
        case 403:
            return ErrorCode::PermissionDenied;
        case 404:
            return ErrorCode::LicenseNotFound;
        case 422:
            return ErrorCode::ValidationFailed;
        case 500:
        case 502:
        case 503:
        case 504:
            return ErrorCode::ServerError;
        default:
            if (status >= 400 && status < 500) {
                return ErrorCode::InvalidParameter;
            }
            if (status >= 500) {
                return ErrorCode::ServerError;
            }
            return ErrorCode::NetworkError;
    }
}

}  // namespace http
}  // namespace licenseseat
