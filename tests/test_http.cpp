#include <gtest/gtest.h>
#include <licenseseat/http.hpp>

namespace licenseseat {
namespace http {
namespace {

// ==================== HttpClient Config Tests ====================

TEST(HttpClientConfigTest, DefaultConfig) {
    HttpClient::Config config;

    EXPECT_TRUE(config.base_url.empty());
    EXPECT_TRUE(config.api_key.empty());
    EXPECT_EQ(config.timeout_seconds, 30);
    EXPECT_TRUE(config.verify_ssl);
    EXPECT_EQ(config.max_retries, 3);
    EXPECT_EQ(config.retry_interval_ms, 1000);
}

// ==================== HttpClient Construction Tests ====================

TEST(HttpClientTest, ConstructWithHttpUrl) {
    HttpClient::Config config;
    config.base_url = "http://localhost:8080";
    config.api_key = "test_key";

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
}

// ==================== Response Structure Tests ====================

TEST(HttpResponseTest, DefaultValues) {
    Response response;

    EXPECT_EQ(response.status_code, 0);
    EXPECT_TRUE(response.body.empty());
    EXPECT_FALSE(response.success);
    EXPECT_TRUE(response.error_message.empty());
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
    EXPECT_EQ(status_code_to_error_code(405), ErrorCode::InvalidParameter);  // Other 4xx
    EXPECT_EQ(status_code_to_error_code(507), ErrorCode::ServerError);       // Other 5xx
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

}  // namespace
}  // namespace http
}  // namespace licenseseat
