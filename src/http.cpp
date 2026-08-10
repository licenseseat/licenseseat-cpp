#include "licenseseat/http.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <httplib.h>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#if defined(CPPHTTPLIB_OPENSSL_SUPPORT)
#define LICENSESEAT_HTTP_HAS_SSL 1
#else
#define LICENSESEAT_HTTP_HAS_SSL 0
#endif

namespace licenseseat {
namespace http {
namespace {

constexpr std::size_t MAX_BASE_URL_BYTES = 2048;
constexpr std::size_t MAX_REQUEST_TARGET_BYTES = 8192;
constexpr std::size_t MAX_API_KEY_BYTES = 4096;
constexpr int MAX_TIMEOUT_SECONDS = 300;
constexpr int MAX_RETRIES = 5;
constexpr int MAX_RETRY_INTERVAL_MS = 60000;

struct ParsedUrl {
    bool valid = false;
    bool https = false;
    bool loopback = false;
    std::string host;
    int port = 0;
    std::string base_path;
    std::string error;
};

bool contains_unsafe_text(const std::string& value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char character) {
        return character <= 0x20 || character == 0x7f;
    });
}

std::string ascii_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(character >= 'A' && character <= 'Z' ? character + ('a' - 'A')
                                                                      : character);
    });
    return value;
}

bool is_loopback_host(const std::string& host) {
    const auto lowered = ascii_lower(host);
    return lowered == "localhost" || lowered == "127.0.0.1" || lowered == "::1";
}

bool parse_port(const std::string& value, int& port) {
    if (value.empty() || value.size() > 5)
        return false;
    uint32_t parsed = 0;
    for (unsigned char character : value) {
        if (character < '0' || character > '9')
            return false;
        parsed = parsed * 10 + static_cast<uint32_t>(character - '0');
    }
    if (parsed == 0 || parsed > 65535)
        return false;
    port = static_cast<int>(parsed);
    return true;
}

bool valid_host(const std::string& host, bool ipv6) {
    if (host.empty() || host.size() > 253)
        return false;
    if (ipv6) {
        in6_addr address{};
        return inet_pton(AF_INET6, host.c_str(), &address) == 1;
    }

    in_addr ipv4_address{};
    if (inet_pton(AF_INET, host.c_str(), &ipv4_address) == 1)
        return true;
    if (std::all_of(host.begin(), host.end(), [](unsigned char character) {
            return (character >= '0' && character <= '9') || character == '.';
        })) {
        return false;
    }

    std::size_t label_start = 0;
    while (label_start < host.size()) {
        const auto label_end = host.find('.', label_start);
        const auto length =
            (label_end == std::string::npos ? host.size() : label_end) - label_start;
        if (length == 0 || length > 63 || host[label_start] == '-' ||
            host[label_start + length - 1] == '-') {
            return false;
        }
        for (std::size_t index = label_start; index < label_start + length; ++index) {
            const auto character = static_cast<unsigned char>(host[index]);
            if (!((character >= 'a' && character <= 'z') ||
                  (character >= 'A' && character <= 'Z') ||
                  (character >= '0' && character <= '9') || character == '-')) {
                return false;
            }
        }
        if (label_end == std::string::npos)
            return true;
        label_start = label_end + 1;
    }
    return false;
}

int hex_value(unsigned char character) {
    if (character >= '0' && character <= '9')
        return character - '0';
    if (character >= 'a' && character <= 'f')
        return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
        return character - 'A' + 10;
    return -1;
}

bool valid_percent_encoding(const std::string& value) {
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] != '%')
            continue;
        if (index + 2 >= value.size() || hex_value(value[index + 1]) < 0 ||
            hex_value(value[index + 2]) < 0) {
            return false;
        }
        const auto decoded = static_cast<unsigned char>((hex_value(value[index + 1]) << 4) |
                                                        hex_value(value[index + 2]));
        if (decoded < 0x20 || decoded == 0x7f)
            return false;
        index += 2;
    }
    return true;
}

bool valid_url_path(const std::string& path) {
    if (path.empty() || path.front() != '/' || path.find("//") != std::string::npos ||
        !valid_percent_encoding(path)) {
        return false;
    }

    std::size_t segment_start = 1;
    while (segment_start <= path.size()) {
        const auto segment_end = path.find('/', segment_start);
        const auto raw = path.substr(
            segment_start,
            (segment_end == std::string::npos ? path.size() : segment_end) - segment_start);
        std::string decoded;
        decoded.reserve(raw.size());
        for (std::size_t index = 0; index < raw.size(); ++index) {
            if (raw[index] != '%') {
                decoded.push_back(raw[index]);
                continue;
            }
            const auto byte = static_cast<unsigned char>((hex_value(raw[index + 1]) << 4) |
                                                         hex_value(raw[index + 2]));
            if (byte == '/' || byte == '\\')
                return false;
            decoded.push_back(static_cast<char>(byte));
            index += 2;
        }
        if (decoded == "." || decoded == "..")
            return false;
        if (segment_end == std::string::npos)
            break;
        segment_start = segment_end + 1;
    }
    return true;
}

ParsedUrl parse_base_url(const HttpClient::Config& config) {
    ParsedUrl parsed;
    const auto& url = config.base_url;
    if (url.empty() || url.size() > MAX_BASE_URL_BYTES || contains_unsafe_text(url) ||
        url.find('\\') != std::string::npos || url.find('?') != std::string::npos ||
        url.find('#') != std::string::npos) {
        parsed.error = "Base URL is empty or malformed";
        return parsed;
    }

    std::size_t scheme_bytes = 0;
    if (url.compare(0, 8, "https://") == 0) {
        parsed.https = true;
        parsed.port = 443;
        scheme_bytes = 8;
    } else if (url.compare(0, 7, "http://") == 0) {
        parsed.port = 80;
        scheme_bytes = 7;
    } else {
        parsed.error = "Base URL must use an explicit https:// or http:// scheme";
        return parsed;
    }

    const auto path_start = url.find('/', scheme_bytes);
    const auto authority =
        url.substr(scheme_bytes,
                   path_start == std::string::npos ? std::string::npos : path_start - scheme_bytes);
    if (authority.empty() || authority.find('@') != std::string::npos) {
        parsed.error = "Base URL authority is invalid";
        return parsed;
    }

    bool ipv6 = false;
    if (authority.front() == '[') {
        ipv6 = true;
        const auto closing = authority.find(']');
        if (closing == std::string::npos || closing == 1) {
            parsed.error = "Base URL contains an invalid IPv6 host";
            return parsed;
        }
        parsed.host = authority.substr(1, closing - 1);
        const auto remainder = authority.substr(closing + 1);
        if (!remainder.empty() &&
            (remainder.front() != ':' || !parse_port(remainder.substr(1), parsed.port))) {
            parsed.error = "Base URL contains an invalid port";
            return parsed;
        }
    } else {
        const auto colon = authority.find(':');
        if (colon != std::string::npos) {
            if (authority.find(':', colon + 1) != std::string::npos) {
                parsed.error = "IPv6 hosts in base URLs must use brackets";
                return parsed;
            }
            parsed.host = authority.substr(0, colon);
            if (!parse_port(authority.substr(colon + 1), parsed.port)) {
                parsed.error = "Base URL contains an invalid port";
                return parsed;
            }
        } else {
            parsed.host = authority;
        }
    }

    if (!valid_host(parsed.host, ipv6)) {
        parsed.error = "Base URL contains an invalid host";
        return parsed;
    }
    parsed.loopback = is_loopback_host(parsed.host);

    if (path_start != std::string::npos)
        parsed.base_path = url.substr(path_start);
    while (parsed.base_path.size() > 1 && parsed.base_path.back() == '/') {
        parsed.base_path.pop_back();
    }
    if (parsed.base_path == "/")
        parsed.base_path.clear();
    if (!parsed.base_path.empty() && !valid_url_path(parsed.base_path)) {
        parsed.error = "Base URL contains an invalid path";
        return parsed;
    }

    if (!parsed.https && (!config.allow_insecure_http || !parsed.loopback)) {
        parsed.error = "Plaintext HTTP is allowed only for explicitly enabled loopback endpoints";
        return parsed;
    }
    if (!config.verify_ssl && !parsed.loopback) {
        parsed.error = "TLS certificate verification can be disabled only for loopback endpoints";
        return parsed;
    }

    parsed.valid = true;
    return parsed;
}

bool valid_request_path(const std::string& path) {
    if (path.empty() || path.front() != '/' || path.size() > MAX_REQUEST_TARGET_BYTES ||
        contains_unsafe_text(path) || path.find('\\') != std::string::npos ||
        path.find('#') != std::string::npos || path.find("://") != std::string::npos ||
        path.compare(0, 2, "//") == 0) {
        return false;
    }
    const auto query = path.find('?');
    if (query != std::string::npos && path.find('?', query + 1) != std::string::npos)
        return false;
    const auto path_only = path.substr(0, query);
    const auto query_only = query == std::string::npos ? std::string{} : path.substr(query + 1);
    return valid_url_path(path_only) && valid_percent_encoding(query_only);
}

bool parse_decimal_size(const std::string& value, std::size_t& result) {
    if (value.empty() || value.size() > 20)
        return false;
    std::size_t parsed = 0;
    for (unsigned char character : value) {
        if (character < '0' || character > '9')
            return false;
        const auto digit = static_cast<std::size_t>(character - '0');
        if (parsed > (std::numeric_limits<std::size_t>::max() - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    result = parsed;
    return true;
}

bool is_json_content_type(const std::string& content_type) {
    auto media_type = ascii_lower(content_type.substr(0, content_type.find(';')));
    while (!media_type.empty() && media_type.back() == ' ')
        media_type.pop_back();
    const auto start = media_type.find_first_not_of(' ');
    if (start != std::string::npos)
        media_type.erase(0, start);
    return media_type == "application/json" ||
           (media_type.size() > 5 && media_type.compare(media_type.size() - 5, 5, "+json") == 0);
}

const char* method_name(Method method) {
    switch (method) {
        case Method::GET:
            return "GET";
        case Method::POST:
            return "POST";
        case Method::PUT:
            return "PUT";
        case Method::DELETE_METHOD:
            return "DELETE";
    }
    return "";
}

bool is_retryable_error(httplib::Error error) {
    return error == httplib::Error::Connection || error == httplib::Error::Read ||
           error == httplib::Error::Write || error == httplib::Error::ConnectionTimeout;
}

} // namespace

class HttpClient::Impl {
  public:
    explicit Impl(Config config) : config_(std::move(config)), parsed_(parse_base_url(config_)) {
        if (!parsed_.valid || config_.timeout_seconds <= 0 ||
            config_.timeout_seconds > MAX_TIMEOUT_SECONDS || config_.max_retries < 0 ||
            config_.max_retries > MAX_RETRIES || config_.retry_interval_ms < 0 ||
            config_.retry_interval_ms > MAX_RETRY_INTERVAL_MS || config_.max_request_bytes == 0 ||
            config_.max_request_bytes > 16 * 1024 * 1024 || config_.max_response_bytes == 0 ||
            config_.max_response_bytes > 16 * 1024 * 1024 ||
            config_.api_key.size() > MAX_API_KEY_BYTES || contains_unsafe_text(config_.api_key)) {
            configuration_error_ =
                parsed_.error.empty() ? "HTTP configuration is invalid" : parsed_.error;
            return;
        }

        if (parsed_.https) {
#if LICENSESEAT_HTTP_HAS_SSL
            ssl_client_ = std::make_unique<httplib::SSLClient>(parsed_.host, parsed_.port);
            configure_client(*ssl_client_);
            ssl_client_->enable_server_certificate_verification(config_.verify_ssl);
#else
            configuration_error_ = "HTTPS is unavailable because SSL support is not compiled in";
            return;
#endif
        } else {
            client_ = std::make_unique<httplib::Client>(parsed_.host, parsed_.port);
            configure_client(*client_);
        }
        configured_ = true;
    }

    Response send(const Request& request) {
        std::lock_guard<std::mutex> lock(mutex_);
        Response response;
        if (!configured_) {
            response.error_message = configuration_error_.empty() ? "HTTP client is not configured"
                                                                  : configuration_error_;
            return response;
        }
        if (!valid_request_path(request.path)) {
            response.error_message = "Request path is invalid";
            return response;
        }
        if (request.body.size() > config_.max_request_bytes) {
            response.error_message = "Request body exceeds the configured size limit";
            return response;
        }
        if (request.content_type.empty() || request.content_type.size() > 256 ||
            contains_unsafe_text(request.content_type) ||
            (!request.body.empty() && !is_json_content_type(request.content_type))) {
            response.error_message = "Request content type is invalid";
            return response;
        }
        if (request.authenticated && config_.api_key.empty()) {
            response.error_message = "API key is required for this request";
            return response;
        }

        const auto full_path = parsed_.base_path + request.path;
        if (full_path.size() > MAX_REQUEST_TARGET_BYTES) {
            response.error_message = "Request target exceeds the configured size limit";
            return response;
        }
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(config_.timeout_seconds);
        const int retries = request.retryable ? config_.max_retries : 0;

        for (int attempt = 0; attempt <= retries; ++attempt) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                response.error_message = "Request deadline exceeded";
                return response;
            }
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

            bool oversized = false;
            bool invalid_headers = false;
            std::string response_body;
            std::string response_content_type;
            httplib::Request outgoing;
            outgoing.method = method_name(request.method);
            outgoing.path = full_path;
            outgoing.body = request.body;
            outgoing.headers.emplace("Accept", "application/json");
            outgoing.headers.emplace("Accept-Encoding", "identity");
            outgoing.headers.emplace("User-Agent",
                                     std::string("LicenseSeat-CPP-SDK/") + licenseseat::VERSION);
            if (!request.body.empty())
                outgoing.headers.emplace("Content-Type", request.content_type);
            if (request.authenticated) {
                outgoing.headers.emplace("Authorization", "Bearer " + config_.api_key);
            }
            outgoing.response_handler = [&](const httplib::Response& incoming) {
                const auto content_length_count = incoming.get_header_value_count("Content-Length");
                if (content_length_count > 1) {
                    invalid_headers = true;
                    return false;
                }
                const auto transfer_encoding_count =
                    incoming.get_header_value_count("Transfer-Encoding");
                if (transfer_encoding_count > 1 ||
                    (transfer_encoding_count > 0 && content_length_count > 0)) {
                    invalid_headers = true;
                    return false;
                }
                if (transfer_encoding_count == 1 &&
                    ascii_lower(incoming.get_header_value("Transfer-Encoding")) != "chunked") {
                    invalid_headers = true;
                    return false;
                }
                if (content_length_count > 0) {
                    std::size_t declared = 0;
                    if (!parse_decimal_size(incoming.get_header_value("Content-Length"),
                                            declared)) {
                        invalid_headers = true;
                        return false;
                    }
                    if (declared > config_.max_response_bytes) {
                        oversized = true;
                        return false;
                    }
                    response_body.reserve(declared);
                }
                if (incoming.get_header_value_count("Content-Type") > 1 ||
                    incoming.get_header_value_count("Content-Encoding") > 1) {
                    invalid_headers = true;
                    return false;
                }
                response_content_type = incoming.get_header_value("Content-Type");
                const auto encoding = ascii_lower(incoming.get_header_value("Content-Encoding"));
                if (!encoding.empty() && encoding != "identity") {
                    invalid_headers = true;
                    return false;
                }
                return true;
            };
            outgoing.content_receiver = [&](const char* data, std::size_t length, uint64_t,
                                            uint64_t) {
                if (length > config_.max_response_bytes - response_body.size()) {
                    oversized = true;
                    return false;
                }
                response_body.append(data, length);
                return true;
            };

            httplib::Result result;
#if LICENSESEAT_HTTP_HAS_SSL
            if (ssl_client_) {
                configure_timeout(*ssl_client_, remaining);
                result = ssl_client_->send(outgoing);
            } else
#endif
                if (client_) {
                configure_timeout(*client_, remaining);
                result = client_->send(outgoing);
            }

            if (result) {
                response.status_code = result->status;
                response.body = std::move(response_body);
                response.content_type = std::move(response_content_type);
                response.success = response.status_code >= 200 && response.status_code < 300;
                if (response.success && request.expect_json &&
                    (response.body.empty() || !is_json_content_type(response.content_type))) {
                    response.success = false;
                    response.error_message =
                        response.body.empty()
                            ? "Successful JSON response has an empty body"
                            : "Successful response has an unexpected content type";
                }
                return response;
            }

            if (oversized) {
                response.error_message = "Response body exceeds the configured size limit";
                return response;
            }
            if (invalid_headers) {
                response.error_message = "Response contains invalid or unsupported headers";
                return response;
            }

            const auto error = result.error();
            if (attempt < retries && is_retryable_error(error)) {
                const auto delay = std::chrono::milliseconds(config_.retry_interval_ms);
                if (std::chrono::steady_clock::now() + delay >= deadline) {
                    response.error_message = "Request deadline exceeded";
                    return response;
                }
                std::this_thread::sleep_for(delay);
                continue;
            }

            switch (error) {
                case httplib::Error::ConnectionTimeout:
                    response.error_message = "Connection timed out";
                    break;
                case httplib::Error::Connection:
                    response.error_message = "Connection failed";
                    break;
                case httplib::Error::Read:
                    response.error_message = "Response read failed";
                    break;
                case httplib::Error::Write:
                    response.error_message = "Request write failed";
                    break;
#if LICENSESEAT_HTTP_HAS_SSL
                case httplib::Error::SSLConnection:
                    response.error_message = "TLS connection failed";
                    break;
                case httplib::Error::SSLServerVerification:
                    response.error_message = "TLS certificate verification failed";
                    break;
#endif
                default:
                    response.error_message = "Network request failed";
                    break;
            }
            return response;
        }
        response.error_message = "Network request failed";
        return response;
    }

    bool is_configured() const { return configured_; }
    const std::string& base_url() const { return config_.base_url; }

  private:
    template <typename ClientType> void configure_client(ClientType& client) {
        client.set_follow_location(false);
        client.set_decompress(false);
        client.set_keep_alive(false);
        client.set_path_encode(false);
    }

    template <typename ClientType>
    void configure_timeout(ClientType& client, std::chrono::milliseconds timeout) {
        client.set_connection_timeout(timeout);
        client.set_read_timeout(timeout);
        client.set_write_timeout(timeout);
    }

    Config config_;
    ParsedUrl parsed_;
    std::string configuration_error_;
    std::unique_ptr<httplib::Client> client_;
#if LICENSESEAT_HTTP_HAS_SSL
    std::unique_ptr<httplib::SSLClient> ssl_client_;
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

} // namespace http
} // namespace licenseseat
