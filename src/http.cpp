#include "licenseseat/http.hpp"

#include <httplib.h>

#include <chrono>
#include <mutex>
#include <thread>

// Detect SSL support in cpp-httplib
#if defined(CPPHTTPLIB_OPENSSL_SUPPORT)
#define LICENSESEAT_HTTP_HAS_SSL 1
#else
#define LICENSESEAT_HTTP_HAS_SSL 0
#endif

namespace licenseseat {
namespace http {

// ==================== HttpClient Implementation ====================

class HttpClient::Impl {
  public:
    explicit Impl(Config config) : config_(std::move(config)) {
        // Parse base URL to extract host and port
        std::string url = config_.base_url;

        // Remove trailing slash
        while (!url.empty() && url.back() == '/') {
            url.pop_back();
        }

        // Determine if HTTPS
        bool use_https = false;
        if (url.substr(0, 8) == "https://") {
            use_https = true;
            url = url.substr(8);
        } else if (url.substr(0, 7) == "http://") {
            url = url.substr(7);
        }

        // Extract host and port
        std::string host;
        int port = use_https ? 443 : 80;

        auto colon_pos = url.find(':');
        auto slash_pos = url.find('/');

        if (colon_pos != std::string::npos && (slash_pos == std::string::npos || colon_pos < slash_pos)) {
            host = url.substr(0, colon_pos);
            std::string port_str;
            if (slash_pos != std::string::npos) {
                port_str = url.substr(colon_pos + 1, slash_pos - colon_pos - 1);
                base_path_ = url.substr(slash_pos);
            } else {
                port_str = url.substr(colon_pos + 1);
            }
            port = std::stoi(port_str);
        } else {
            if (slash_pos != std::string::npos) {
                host = url.substr(0, slash_pos);
                base_path_ = url.substr(slash_pos);
            } else {
                host = url;
            }
        }

        // Create the appropriate client
        if (use_https) {
#if LICENSESEAT_HTTP_HAS_SSL
            ssl_client_ = std::make_unique<httplib::SSLClient>(host, port);
            ssl_client_->set_connection_timeout(config_.timeout_seconds);
            ssl_client_->set_read_timeout(config_.timeout_seconds);
            ssl_client_->set_write_timeout(config_.timeout_seconds);

            if (!config_.verify_ssl) {
                ssl_client_->enable_server_certificate_verification(false);
            }
#else
            // SSL not available - HTTPS URLs will fail at request time
            https_requested_ = true;
            client_ = std::make_unique<httplib::Client>(host, port);
            client_->set_connection_timeout(config_.timeout_seconds);
            client_->set_read_timeout(config_.timeout_seconds);
            client_->set_write_timeout(config_.timeout_seconds);
#endif
        } else {
            client_ = std::make_unique<httplib::Client>(host, port);
            client_->set_connection_timeout(config_.timeout_seconds);
            client_->set_read_timeout(config_.timeout_seconds);
            client_->set_write_timeout(config_.timeout_seconds);
        }

        configured_ = true;
    }

    Response send(const Request& request) {
        std::lock_guard<std::mutex> lock(mutex_);

        Response response;

#if !LICENSESEAT_HTTP_HAS_SSL
        // If HTTPS was requested but SSL is not available, fail gracefully
        if (https_requested_) {
            response.error_message = "HTTPS not supported: cpp-httplib was compiled without SSL support";
            return response;
        }
#endif

        std::string full_path = base_path_ + request.path;

        // Add auth header
        httplib::Headers headers;
        if (!config_.api_key.empty()) {
            headers.emplace("Authorization", "Bearer " + config_.api_key);
        }
        headers.emplace("Content-Type", request.content_type);
        headers.emplace("User-Agent", "LicenseSeat-CPP-SDK/0.1.0");

        // Retry loop
        for (int attempt = 0; attempt <= config_.max_retries; ++attempt) {
            httplib::Result result;

#if LICENSESEAT_HTTP_HAS_SSL
            if (ssl_client_) {
                result = send_with_ssl(request.method, full_path, headers, request.body,
                                       request.content_type);
            } else if (client_) {
                result = send_without_ssl(request.method, full_path, headers, request.body,
                                          request.content_type);
            }
#else
            if (client_) {
                result = send_without_ssl(request.method, full_path, headers, request.body,
                                          request.content_type);
            }
#endif
            else {
                response.error_message = "HTTP client not configured";
                return response;
            }

            if (result) {
                response.status_code = result->status;
                response.body = result->body;
                response.success = (result->status >= 200 && result->status < 300);
                return response;
            }

            // Check if we should retry
            auto error = result.error();
            if (error == httplib::Error::Connection || error == httplib::Error::Read ||
                error == httplib::Error::Write) {
                if (attempt < config_.max_retries) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(config_.retry_interval_ms));
                    continue;
                }
            }

            // Set error message based on error type
            switch (error) {
                case httplib::Error::Connection:
                    response.error_message = "Connection failed";
                    break;
                case httplib::Error::Read:
                    response.error_message = "Read failed";
                    break;
                case httplib::Error::Write:
                    response.error_message = "Write failed";
                    break;
#if LICENSESEAT_HTTP_HAS_SSL
                case httplib::Error::SSLConnection:
                    response.error_message = "SSL connection failed";
                    break;
                case httplib::Error::SSLServerVerification:
                    response.error_message = "SSL certificate verification failed";
                    break;
#endif
                default:
                    response.error_message = "Unknown network error";
            }
            break;
        }

        return response;
    }

    bool is_configured() const { return configured_; }

    const std::string& base_url() const { return config_.base_url; }

  private:
#if LICENSESEAT_HTTP_HAS_SSL
    httplib::Result send_with_ssl(Method method, const std::string& path,
                                   const httplib::Headers& headers, const std::string& body,
                                   const std::string& content_type) {
        switch (method) {
            case Method::GET:
                return ssl_client_->Get(path, headers);
            case Method::POST:
                return ssl_client_->Post(path, headers, body, content_type);
            case Method::PUT:
                return ssl_client_->Put(path, headers, body, content_type);
            case Method::DELETE_METHOD:
                return ssl_client_->Delete(path, headers);
        }
        return httplib::Result();
    }
#endif

    httplib::Result send_without_ssl(Method method, const std::string& path,
                                      const httplib::Headers& headers, const std::string& body,
                                      const std::string& content_type) {
        switch (method) {
            case Method::GET:
                return client_->Get(path, headers);
            case Method::POST:
                return client_->Post(path, headers, body, content_type);
            case Method::PUT:
                return client_->Put(path, headers, body, content_type);
            case Method::DELETE_METHOD:
                return client_->Delete(path, headers);
        }
        return httplib::Result();
    }

    Config config_;
    std::string base_path_;
    std::unique_ptr<httplib::Client> client_;
#if LICENSESEAT_HTTP_HAS_SSL
    std::unique_ptr<httplib::SSLClient> ssl_client_;
#else
    bool https_requested_ = false;
#endif
    bool configured_ = false;
    std::mutex mutex_;
};

HttpClient::HttpClient(Config config) : impl_(std::make_unique<Impl>(std::move(config))) {}

HttpClient::~HttpClient() = default;

HttpClient::HttpClient(HttpClient&&) noexcept = default;
HttpClient& HttpClient::operator=(HttpClient&&) noexcept = default;

Response HttpClient::send(const Request& request) {
    return impl_->send(request);
}

bool HttpClient::is_configured() const {
    return impl_->is_configured();
}

const std::string& HttpClient::base_url() const {
    return impl_->base_url();
}

}  // namespace http
}  // namespace licenseseat
