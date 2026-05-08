#include <dhcoin/net/peer.hpp>
#include <iostream>

namespace dhcoin::net {

Peer::Peer(asio::ip::tcp::socket socket)
    : socket_(std::move(socket)) {
    try {
        address_ = socket_.remote_endpoint().address().to_string() + ":" +
                   std::to_string(socket_.remote_endpoint().port());
    } catch (...) {
        address_ = "unknown";
    }
}

Peer::~Peer() {
    close();
}

void Peer::start(MessageHandler on_msg, CloseHandler on_close) {
    on_msg_   = std::move(on_msg);
    on_close_ = std::move(on_close);
    read_header();
}

void Peer::read_header() {
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(header_buf_),
        [self](std::error_code ec, size_t) {
            if (ec) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            uint32_t len = (static_cast<uint32_t>(self->header_buf_[0]) << 24)
                         | (static_cast<uint32_t>(self->header_buf_[1]) << 16)
                         | (static_cast<uint32_t>(self->header_buf_[2]) << 8)
                         |  static_cast<uint32_t>(self->header_buf_[3]);
            if (len == 0 || len > 16 * 1024 * 1024) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            self->read_body(len);
        });
}

void Peer::read_body(uint32_t len) {
    body_buf_.resize(len);
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(body_buf_),
        [self](std::error_code ec, size_t) {
            if (ec) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            try {
                auto msg = Message::deserialize(self->body_buf_.data(), self->body_buf_.size());
                if (self->on_msg_) self->on_msg_(self, msg);
            } catch (std::exception& e) {
                std::cerr << "[peer] message parse error from " << self->address_
                          << ": " << e.what() << "\n";
            }
            self->read_header();
        });
}

void Peer::send(const Message& msg) {
    auto bytes = msg.serialize();
    std::lock_guard<std::mutex> lock(write_mutex_);
    bool idle = write_queue_.empty();
    write_queue_.push_back(std::move(bytes));
    if (idle) do_write();
}

void Peer::do_write() {
    auto self = shared_from_this();
    asio::async_write(socket_, asio::buffer(write_queue_.front()),
        [self](std::error_code ec, size_t) {
            std::lock_guard<std::mutex> lock(self->write_mutex_);
            self->write_queue_.pop_front();
            if (ec) {
                if (self->on_close_) self->on_close_(self);
                return;
            }
            if (!self->write_queue_.empty()) self->do_write();
        });
}

void Peer::close() {
    std::error_code ec;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

void async_connect(asio::io_context& io,
                   const std::string& host, uint16_t port,
                   std::function<void(std::shared_ptr<Peer>)> on_connect,
                   std::function<void(const std::string&)>    on_error) {
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(io);
    resolver->async_resolve(host, std::to_string(port),
        [resolver, &io, on_connect, on_error](std::error_code ec,
                                               asio::ip::tcp::resolver::results_type results) {
            if (ec) { on_error(ec.message()); return; }
            auto socket = std::make_shared<asio::ip::tcp::socket>(io);
            asio::async_connect(*socket, results,
                [socket, resolver, on_connect, on_error](std::error_code ec2, auto) {
                    if (ec2) { on_error(ec2.message()); return; }
                    on_connect(std::make_shared<Peer>(std::move(*socket)));
                });
        });
}

} // namespace dhcoin::net
