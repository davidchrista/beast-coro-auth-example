#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/write.hpp>
#include <cstdio>

#include <algorithm>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/config.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "jwt-cpp/jwt.h"

#include <boost/json.hpp>
#include <boost/json/src.hpp>

using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::use_awaitable;
using boost::asio::ip::tcp;
namespace this_coro = boost::asio::this_coro;

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

awaitable<std::string> get(std::string const &host, std::string const &port,
                           std::string const &target, int version)
{
  auto executor = co_await this_coro::executor;

  tcp::resolver resolver(executor);
  beast::tcp_stream stream(executor);

  auto const results = co_await resolver.async_resolve(host, port, use_awaitable);

  stream.expires_after(std::chrono::seconds(30));

  co_await stream.async_connect(results, use_awaitable);

  http::request<http::string_body> req{http::verb::get, target, version};
  req.set(http::field::host, host);
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

  stream.expires_after(std::chrono::seconds(30));

  co_await http::async_write(stream, req, use_awaitable);

  beast::flat_buffer b;

  http::response<http::string_body> res;

  co_await http::async_read(stream, b, res, use_awaitable);

  stream.socket().shutdown(tcp::socket::shutdown_both);

  co_return res.body();
}

awaitable<std::string> get_ssl(ssl::context &ctx, std::string const &host, std::string const &port,
                               std::string const &target, int version)
{
  auto executor = co_await this_coro::executor;

  tcp::resolver resolver(executor);
  beast::ssl_stream<beast::tcp_stream> stream(executor, ctx);

  SSL_set_tlsext_host_name(stream.native_handle(), host.c_str());

  auto const results = co_await resolver.async_resolve(host, port, use_awaitable);

  beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

  co_await beast::get_lowest_layer(stream).async_connect(results, use_awaitable);

  beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

  co_await stream.async_handshake(ssl::stream_base::client, use_awaitable);

  http::request<http::string_body> req{http::verb::get, target, version};
  req.set(http::field::host, host);
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

  beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

  co_await http::async_write(stream, req, use_awaitable);

  beast::flat_buffer b;

  http::response<http::string_body> res;

  co_await http::async_read(stream, b, res, use_awaitable);

  beast::get_lowest_layer(stream).socket().shutdown(tcp::socket::shutdown_both);

  co_return res.body();
}

awaitable<std::string> fetchJwks()
{
  ssl::context ctx(ssl::context::tlsv12_client);
  co_return co_await get_ssl(ctx, "dev-gzm0pgbh.us.auth0.com", "443", "/.well-known/jwks.json", 11);
}

std::string pemFromJwks(const std::string &jwks)
{
  using namespace boost::json;
  error_code ec;
  value json = parse(jwks, ec);
  if (ec)
    return {};
  if (!json.is_object() || !json.as_object().contains("keys") ||
      !json.as_object()["keys"].is_array() || json.as_object()["keys"].as_array().empty())
    return {};
  auto keyJson = json.as_object()["keys"].as_array()[0];
  if (!keyJson.is_object() || !keyJson.as_object().contains("x5c"))
    return {};
  auto x5c = keyJson.as_object()["x5c"];
  if (!x5c.is_array() || x5c.as_array().empty() || !x5c.as_array()[0].is_string())
    return {};
  auto key = value_to<std::string>(x5c.as_array()[0]);
  auto fullKey = std::string("-----BEGIN CERTIFICATE-----\n") + key +
                 std::string("\n-----END CERTIFICATE-----");
  return fullKey;
}

std::string extractKeyFromPem(const std::string &pem)
{
  OpenSSL_add_all_algorithms();

  const auto createX509 = [](const char *pem) -> X509 * {
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pem);
    X509 *x509 = nullptr;
    x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return x509;
  };

  X509 *cert = createX509(pem.c_str());
  if (!cert)
    return {};

  EVP_PKEY *pubKey = X509_get_pubkey(cert);
  X509_free(cert);
  if (!pubKey)
    return {};

  const auto pkeyToString = [](EVP_PKEY *key) -> std::string {
    BIO *bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PUBKEY(bio, key);
    BUF_MEM *mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string s(mem->data, mem->length);
    BIO_free(bio);
    return s;
  };

  auto ret = pkeyToString(pubKey);
  EVP_PKEY_free(pubKey);

  return ret;
}

awaitable<bool> authorize(const http::request<http::string_body> &req)
{
  std::string authHeader = req.base()["Authorization"].to_string();
  if (authHeader.empty())
    co_return false;
  if (authHeader.substr(0, 6) != "Bearer")
    co_return false;

  const auto &token = authHeader.substr(7);

  auto jwks = co_await fetchJwks();
  auto pem = pemFromJwks(jwks);
  auto pubKey = extractKeyFromPem(pem);

  const auto decoded = jwt::decode(token);
  const auto auds = decoded.get_audience();
  const auto verify = jwt::verify()
                          .allow_algorithm(jwt::algorithm::rs256(pubKey, "", "", ""))
                          .with_issuer("https://dev-gzm0pgbh.us.auth0.com/");
  verify.verify(decoded);
  
  if (auds.count("http://localhost:4000"))
    co_return true;
  co_return false;
}

template <bool isRequest, class Body, class Fields>
awaitable<void> send(beast::tcp_stream &stream, http::message<isRequest, Body, Fields> &&msg,
                     bool &close)
{
  close = msg.need_eof();
  http::serializer<isRequest, Body, Fields> sr{msg};
  co_await http::async_write(stream, sr, use_awaitable);
}

awaitable<void> handle_request(beast::tcp_stream &stream, const std::string &doc_root,
                               http::request<http::string_body> &&req, bool &close)
{
  auto const bad_request = [&req](const std::string &why) {
    http::response<http::string_body> res{http::status::bad_request, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = why;
    res.prepare_payload();
    return res;
  };

  auto const not_found = [&req](const std::string &target) {
    http::response<http::string_body> res{http::status::not_found, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = "The resource '" + target + "' was not found.";
    res.prepare_payload();
    return res;
  };

  auto const server_error = [&req](const std::string &what) {
    http::response<http::string_body> res{http::status::internal_server_error, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = "An error occurred: '" + what + "'";
    res.prepare_payload();
    return res;
  };

  if (req.method() == http::verb::options)
  {
    http::response<http::empty_body> res{http::status::no_content, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::access_control_allow_headers, "authorization");
    res.set(http::field::access_control_allow_methods, "GET,HEAD,PUT,PATCH,POST,DELETE");
    res.set(http::field::access_control_allow_origin, "*");
    res.content_length(0);
    res.keep_alive(req.keep_alive());
    co_return co_await send(stream, std::move(res), close);
  }

  if (req.method() == http::verb::get)
  {
    if (co_await authorize(req))
    {
      http::response<http::string_body> res{http::status::ok, req.version()};
      res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
      res.set(http::field::content_type, "text/html");
      res.set(http::field::access_control_allow_origin, "*");
      res.keep_alive(req.keep_alive());
      res.body() = "Hello C++!";
      res.prepare_payload();
      co_return co_await send(stream, std::move(res), close);
    }
    else
      co_return co_await send(stream, bad_request("Unauthorized"), close);
  }

  co_return co_await send(stream, bad_request("Unknown method"), close);
}

awaitable<void> session(beast::tcp_stream stream, const std::string &doc_root)
{
  bool close = false;

  beast::flat_buffer buffer;

  try
  {
    for (;;)
    {
      stream.expires_after(std::chrono::seconds(10));

      http::request<http::string_body> req;

      boost::system::error_code ec;
      co_await http::async_read(stream, buffer, req,
                                boost::asio::redirect_error(use_awaitable, ec));
      if (ec != boost::system::error_code())
        std::printf("ERROR: %s\n", ec.what().c_str());
      if (ec == http::error::end_of_stream)
        break;

      co_await handle_request(stream, doc_root, std::move(req), close);
      if (close)
        break;
    }

    stream.socket().shutdown(tcp::socket::shutdown_send);
  }
  catch (std::exception &e)
  {
    std::printf("session exception: %s\n", e.what());
  }
}

awaitable<void> listen(tcp::endpoint endpoint, const std::string &doc_root)
{
  try
  {
    auto executor = co_await this_coro::executor;

    tcp::acceptor acceptor(executor);

    acceptor.open(endpoint.protocol());
    acceptor.set_option(net::socket_base::reuse_address(true));
    acceptor.bind(endpoint);
    acceptor.listen(net::socket_base::max_listen_connections);

    for (;;)
    {
      auto socket = co_await acceptor.async_accept(use_awaitable);
      co_spawn(executor, session(beast::tcp_stream(std::move(socket)), doc_root), detached);
    }
  }
  catch (std::exception &e)
  {
    std::printf("listener exception: %s\n", e.what());
  }
}

int main(int argc, char *argv[])
{
  auto const address = net::ip::make_address("0.0.0.0");
  auto const port = static_cast<unsigned short>(std::atoi("4100"));
  auto const doc_root = std::string(".");
  auto const threads = std::max<int>(1, std::atoi("1"));

  net::io_context ioc{threads};

  boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
  signals.async_wait([&](auto, auto) { ioc.stop(); });

  co_spawn(ioc, listen(tcp::endpoint{address, port}, doc_root), detached);

  std::vector<std::thread> v;
  v.reserve(threads - 1);
  for (auto i = threads - 1; i > 0; --i)
    v.emplace_back([&ioc] { ioc.run(); });
  ioc.run();

  return EXIT_SUCCESS;
}