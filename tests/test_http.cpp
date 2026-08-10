#include <atomic>
#include <gtest/gtest.h>
#include <httplib.h>
#include <licenseseat/http.hpp>
#include <thread>

namespace licenseseat {
namespace http {
namespace {

class LocalHttpServer {
  public:
    ~LocalHttpServer() {
        server.stop();
        if (thread.joinable())
            thread.join();
    }

    int start() {
        const int port = server.bind_to_any_port("127.0.0.1");
        if (port > 0) {
            thread = std::thread([this]() { server.listen_after_bind(); });
            // stop() can race ahead of listen_after_bind() and be lost. Wait
            // until the server has entered its accept loop so even tests whose
            // requests fail locally can tear the fixture down deterministically.
            for (int attempt = 0; attempt < 5000 && !server.is_running(); ++attempt)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (!server.is_running())
                return -1;
        }
        return port;
    }

    httplib::Server server;
    std::thread thread;
};

// ==================== HttpClient Config Tests ====================

TEST(HttpClientConfigTest, DefaultConfig) {
    HttpClient::Config config;

    EXPECT_TRUE(config.base_url.empty());
    EXPECT_TRUE(config.api_key.empty());
    EXPECT_EQ(config.timeout_seconds, 30);
    EXPECT_TRUE(config.verify_ssl);
    EXPECT_FALSE(config.allow_insecure_http);
    EXPECT_EQ(config.max_retries, 3);
    EXPECT_EQ(config.retry_interval_ms, 1000);
}

// ==================== HttpClient Construction Tests ====================

TEST(HttpClientTest, ConstructWithHttpUrl) {
    HttpClient::Config config;
    config.base_url = "http://localhost:8080";
    config.api_key = "test_key";
    config.allow_insecure_http = true;

    HttpClient client(config);

    EXPECT_TRUE(client.is_configured());
    EXPECT_EQ(client.base_url(), "http://localhost:8080");
}

TEST(HttpClientTest, ConstructWithHttpsUrl) {
    HttpClient::Config config;
    config.base_url = "https://api.example.com";
    config.api_key = "test_key";

    HttpClient client(config);

    EXPECT_TRUE(client.is_configured());
    EXPECT_EQ(client.base_url(), "https://api.example.com");
}

TEST(HttpClientTest, ConstructWithUrlAndPath) {
    HttpClient::Config config;
    config.base_url = "https://api.example.com/v1";
    config.api_key = "test_key";

    HttpClient client(config);

    EXPECT_TRUE(client.is_configured());
}

TEST(HttpClientTest, ConstructWithPortInUrl) {
    HttpClient::Config config;
    config.base_url = "https://api.example.com:8443/api";
    config.api_key = "test_key";

    HttpClient client(config);

    EXPECT_TRUE(client.is_configured());
}

TEST(HttpClientTest, RejectsPlaintextNonLoopbackAndUnverifiedRemoteTls) {
    HttpClient::Config plaintext;
    plaintext.base_url = "http://example.com";
    plaintext.api_key = "test_key";
    plaintext.allow_insecure_http = true;
    EXPECT_FALSE(HttpClient(plaintext).is_configured());

    HttpClient::Config unverified;
    unverified.base_url = "https://example.com";
    unverified.api_key = "test_key";
    unverified.verify_ssl = false;
    EXPECT_FALSE(HttpClient(unverified).is_configured());
}

TEST(HttpClientTest, RejectsMalformedOrAmbiguousBaseUrls) {
    const std::vector<std::string> invalid_urls = {"example.com",
                                                   "ftp://example.com",
                                                   "https://user@example.com",
                                                   "https://example.com?host=evil",
                                                   "https://example.com#fragment",
                                                   "https://example.com\\evil",
                                                   "https://example.com:0",
                                                   "https://example.com:65536",
                                                   "https://example.com:443:444",
                                                   "https://-example.com",
                                                   "https://label-.example.com",
                                                   "https://two..dots.example.com",
                                                   "https://999.999.999.999",
                                                   "https://[1::2::3]",
                                                   "https://" + std::string(64, 'a') + ".com",
                                                   "https://example.com/../admin",
                                                   "https://example.com/api/..",
                                                   "https://example.com/api/%2e%2e/admin",
                                                   "https://example.com/api/%2Fadmin",
                                                   "https://example.com/api/%zz",
                                                   "http://127.0.0.2"};

    for (const auto& url : invalid_urls) {
        HttpClient::Config config;
        config.base_url = url;
        config.api_key = "test_key";
        config.allow_insecure_http = true;
        EXPECT_FALSE(HttpClient(config).is_configured()) << url;
    }
}

TEST(HttpClientTest, RejectsUnsafeCredentialsAndOutOfRangeLimits) {
    HttpClient::Config config;
    config.base_url = "https://example.com";
    config.api_key = "secret\r\nInjected: true";
    EXPECT_FALSE(HttpClient(config).is_configured());

    config.api_key = "test_key";
    config.timeout_seconds = 0;
    EXPECT_FALSE(HttpClient(config).is_configured());
    config.timeout_seconds = 30;
    config.max_retries = 6;
    EXPECT_FALSE(HttpClient(config).is_configured());
    config.max_retries = 0;
    config.max_response_bytes = 0;
    EXPECT_FALSE(HttpClient(config).is_configured());
}

TEST(HttpClientTest, CanBeMoved) {
    HttpClient::Config config;
    config.base_url = "https://api.example.com";
    config.api_key = "test_key";

    HttpClient client1(config);
    HttpClient client2 = std::move(client1);

    EXPECT_TRUE(client2.is_configured());
}

// ==================== Request Structure Tests ====================

TEST(HttpRequestTest, DefaultValues) {
    Request request;

    EXPECT_EQ(request.method, Method::GET);
    EXPECT_TRUE(request.path.empty());
    EXPECT_TRUE(request.body.empty());
    EXPECT_EQ(request.content_type, "application/json");
    EXPECT_TRUE(request.authenticated);
    EXPECT_FALSE(request.retryable);
    EXPECT_TRUE(request.expect_json);
}

// ==================== Response Structure Tests ====================

TEST(HttpResponseTest, DefaultValues) {
    Response response;

    EXPECT_EQ(response.status_code, 0);
    EXPECT_TRUE(response.body.empty());
    EXPECT_FALSE(response.success);
    EXPECT_TRUE(response.error_message.empty());
}

// ==================== Hostile Peer / Transport Tests ====================

TEST(HttpClientTransportTest, SendsAuthorizationOnlyForProtectedRequests) {
    LocalHttpServer local;
    std::atomic<bool> protected_auth{false};
    std::atomic<bool> public_auth{false};
    std::atomic<bool> identity_encoding{false};
    local.server.Get("/protected", [&](const httplib::Request& req, httplib::Response& res) {
        protected_auth = req.get_header_value("Authorization") == "Bearer super-secret";
        identity_encoding = req.get_header_value("Accept-Encoding") == "identity";
        res.set_content("{}", "application/json");
    });
    local.server.Get("/public", [&](const httplib::Request& req, httplib::Response& res) {
        public_auth = req.has_header("Authorization");
        res.set_content("{}", "application/json");
    });
    const int port = local.start();
    ASSERT_GT(port, 0);

    HttpClient::Config config;
    config.base_url = "http://127.0.0.1:" + std::to_string(port);
    config.api_key = "super-secret";
    config.allow_insecure_http = true;
    config.max_retries = 0;
    HttpClient client(config);

    Request protected_request;
    protected_request.path = "/protected";
    EXPECT_TRUE(client.send(protected_request).success);

    Request public_request;
    public_request.path = "/public";
    public_request.authenticated = false;
    EXPECT_TRUE(client.send(public_request).success);
    EXPECT_TRUE(protected_auth.load());
    EXPECT_FALSE(public_auth.load());
    EXPECT_TRUE(identity_encoding.load());
}

TEST(HttpClientTransportTest, RejectsInvalidTargetsAndOversizedRequestsBeforeSending) {
    LocalHttpServer local;
    std::atomic<int> hits{0};
    local.server.Post("/safe", [&](const httplib::Request&, httplib::Response& res) {
        ++hits;
        res.set_content("{}", "application/json");
    });
    const int port = local.start();
    ASSERT_GT(port, 0);

    HttpClient::Config config;
    config.base_url = "http://127.0.0.1:" + std::to_string(port);
    config.api_key = "test_key";
    config.allow_insecure_http = true;
    config.max_request_bytes = 8;
    config.max_retries = 0;
    HttpClient client(config);

    for (const auto& path : {std::string(""), std::string("safe"), std::string("//evil/path"),
                             std::string("/../admin"), std::string("/safe#fragment"),
                             std::string("/https://evil.test")}) {
        Request request;
        request.path = path;
        request.method = Method::POST;
        EXPECT_FALSE(client.send(request).success) << path;
    }

    Request oversized;
    oversized.method = Method::POST;
    oversized.path = "/safe";
    oversized.body = std::string(9, 'x');
    auto response = client.send(oversized);
    EXPECT_FALSE(response.success);
    EXPECT_NE(response.error_message.find("size limit"), std::string::npos);

    Request wrong_content_type;
    wrong_content_type.method = Method::POST;
    wrong_content_type.path = "/safe";
    wrong_content_type.body = "{}";
    wrong_content_type.content_type = "text/plain";
    const auto invalid_content_type = client.send(wrong_content_type);
    EXPECT_FALSE(invalid_content_type.success);
    EXPECT_NE(invalid_content_type.error_message.find("content type"), std::string::npos);
    EXPECT_EQ(hits.load(), 0);
}

TEST(HttpClientTransportTest, RejectsCombinedOversizedRequestTargets) {
    HttpClient::Config config;
    config.base_url = "http://localhost:1/" + std::string(2000, 'a');
    config.api_key = "test_key";
    config.allow_insecure_http = true;
    config.max_retries = 0;
    HttpClient client(config);
    ASSERT_TRUE(client.is_configured());

    Request request;
    request.path = "/" + std::string(7000, 'b');
    const auto response = client.send(request);

    EXPECT_FALSE(response.success);
    EXPECT_NE(response.error_message.find("Request target"), std::string::npos);
}

TEST(HttpClientTransportTest, RejectsOversizedEncodedAndNonJsonSuccessResponses) {
    LocalHttpServer local;
    local.server.Get("/large", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(std::string(1024, 'x'), "application/json");
    });
    local.server.Get("/encoded", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Content-Encoding", "gzip");
        res.set_content("{}", "application/json");
    });
    local.server.Get("/text", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("ok", "text/plain");
    });
    const int port = local.start();
    ASSERT_GT(port, 0);

    HttpClient::Config config;
    config.base_url = "http://127.0.0.1:" + std::to_string(port);
    config.api_key = "test_key";
    config.allow_insecure_http = true;
    config.max_response_bytes = 128;
    config.max_retries = 0;
    HttpClient client(config);

    for (const auto& path : {"/large", "/encoded", "/text"}) {
        Request request;
        request.path = path;
        request.authenticated = false;
        const auto response = client.send(request);
        EXPECT_FALSE(response.success) << path;
        EXPECT_FALSE(response.error_message.empty()) << path;
    }
}

TEST(HttpClientTransportTest, DoesNotFollowRedirects) {
    LocalHttpServer local;
    std::atomic<int> target_hits{0};
    local.server.Get("/redirect", [](const httplib::Request&, httplib::Response& res) {
        res.set_redirect("/target", 302);
    });
    local.server.Get("/target", [&](const httplib::Request&, httplib::Response& res) {
        ++target_hits;
        res.set_content("{}", "application/json");
    });
    const int port = local.start();
    ASSERT_GT(port, 0);

    HttpClient::Config config;
    config.base_url = "http://127.0.0.1:" + std::to_string(port);
    config.api_key = "test_key";
    config.allow_insecure_http = true;
    config.max_retries = 0;
    HttpClient client(config);

    Request request;
    request.path = "/redirect";
    const auto response = client.send(request);
    EXPECT_FALSE(response.success);
    EXPECT_EQ(response.status_code, 302);
    EXPECT_EQ(target_hits.load(), 0);
}

TEST(HttpClientTransportTest, RequiresBodiesForExpectedJsonSuccesses) {
    LocalHttpServer local;
    local.server.Get("/empty", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
        res.set_content("", "application/json");
    });
    local.server.Get("/bodyless",
                     [](const httplib::Request&, httplib::Response& res) { res.status = 204; });
    const int port = local.start();
    ASSERT_GT(port, 0);

    HttpClient::Config config;
    config.base_url = "http://127.0.0.1:" + std::to_string(port);
    config.api_key = "test_key";
    config.allow_insecure_http = true;
    config.max_retries = 0;
    HttpClient client(config);

    Request json_request;
    json_request.path = "/empty";
    const auto empty_json = client.send(json_request);
    EXPECT_FALSE(empty_json.success);
    EXPECT_NE(empty_json.error_message.find("empty body"), std::string::npos);

    Request bodyless_request;
    bodyless_request.path = "/bodyless";
    bodyless_request.expect_json = false;
    EXPECT_TRUE(client.send(bodyless_request).success);
}

TEST(HttpClientTransportTest, RejectsDuplicateContentLengthHeaders) {
    LocalHttpServer local;
    local.server.Get("/duplicate", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
        res.body = "{}";
        res.headers.emplace("Content-Type", "application/json");
        res.headers.emplace("Content-Length", "2");
        res.headers.emplace("Content-Length", "2");
    });
    const int port = local.start();
    ASSERT_GT(port, 0);

    HttpClient::Config config;
    config.base_url = "http://127.0.0.1:" + std::to_string(port);
    config.api_key = "test_key";
    config.allow_insecure_http = true;
    config.max_retries = 0;
    HttpClient client(config);

    Request request;
    request.path = "/duplicate";
    const auto response = client.send(request);
    EXPECT_FALSE(response.success);
    EXPECT_FALSE(response.error_message.empty());
}

// ==================== Status Code Mapping Tests ====================

TEST(StatusCodeMappingTest, SuccessCodes) {
    EXPECT_EQ(status_code_to_error_code(200), ErrorCode::Success);
    EXPECT_EQ(status_code_to_error_code(201), ErrorCode::Success);
    EXPECT_EQ(status_code_to_error_code(204), ErrorCode::Success);
}

TEST(StatusCodeMappingTest, ClientErrorCodes) {
    EXPECT_EQ(status_code_to_error_code(400), ErrorCode::InvalidParameter);
    EXPECT_EQ(status_code_to_error_code(401), ErrorCode::AuthenticationFailed);
    EXPECT_EQ(status_code_to_error_code(403), ErrorCode::PermissionDenied);
    EXPECT_EQ(status_code_to_error_code(404), ErrorCode::LicenseNotFound);
    EXPECT_EQ(status_code_to_error_code(422), ErrorCode::ValidationFailed);
}

TEST(StatusCodeMappingTest, ServerErrorCodes) {
    EXPECT_EQ(status_code_to_error_code(500), ErrorCode::ServerError);
    EXPECT_EQ(status_code_to_error_code(502), ErrorCode::ServerError);
    EXPECT_EQ(status_code_to_error_code(503), ErrorCode::ServerError);
    EXPECT_EQ(status_code_to_error_code(504), ErrorCode::ServerError);
}

TEST(StatusCodeMappingTest, OtherCodes) {
    EXPECT_EQ(status_code_to_error_code(405), ErrorCode::InvalidParameter); // Other 4xx
    EXPECT_EQ(status_code_to_error_code(507), ErrorCode::ServerError);      // Other 5xx
}

// ==================== MockHttpClient for Testing ====================
// This can be used in other tests to mock HTTP calls

class MockHttpClient : public HttpClientInterface {
  public:
    MockHttpClient() = default;

    void set_response(Response resp) { response_ = std::move(resp); }

    void set_configured(bool configured) { configured_ = configured; }

    Response send(const Request& request) override {
        last_request_ = request;
        return response_;
    }

    bool is_configured() const override { return configured_; }

    const Request& last_request() const { return last_request_; }

  private:
    Response response_;
    Request last_request_;
    bool configured_ = true;
};

TEST(MockHttpClientTest, CanSetResponse) {
    MockHttpClient client;

    Response expected;
    expected.status_code = 200;
    expected.body = "{\"valid\": true}";
    expected.success = true;

    client.set_response(expected);

    Request request;
    request.path = "/api/test";

    auto response = client.send(request);

    EXPECT_EQ(response.status_code, 200);
    EXPECT_EQ(response.body, "{\"valid\": true}");
    EXPECT_TRUE(response.success);
}

TEST(MockHttpClientTest, CapturesLastRequest) {
    MockHttpClient client;

    Request request;
    request.method = Method::POST;
    request.path = "/api/licenses/validate";
    request.body = "{\"license_key\": \"KEY-123\"}";

    (void)client.send(request);

    const auto& captured = client.last_request();
    EXPECT_EQ(captured.method, Method::POST);
    EXPECT_EQ(captured.path, "/api/licenses/validate");
    EXPECT_EQ(captured.body, "{\"license_key\": \"KEY-123\"}");
}

// Note: We don't test actual HTTP calls here as that would require a running server.
// Integration tests with a mock server would be added separately.

} // namespace
} // namespace http
} // namespace licenseseat
