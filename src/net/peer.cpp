// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/net/peer.hpp>
#include <iostream>

namespace determ::net {

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
            // S-022: framing-layer ceiling (kMaxFrameBytes = 16 MB). The
            // per-message-type cap fires AFTER deserialize in read_body.
            if (len == 0 || len > kMaxFrameBytes) {
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
                // S-022: per-message-type cap. The framing layer accepted
                // up to kMaxFrameBytes (16 MB) so the only types with a
                // legitimate need for that ceiling get it; everything else
                // is bounded much tighter here. Oversize messages indicate
                // either a peer-side bug or an active flooding attempt;
                // drop the message and close the connection (same
                // disposition the framing layer applies).
                if (self->body_buf_.size() > max_message_bytes(msg.type)) {
                    std::cerr << "[peer] oversize message from " << self->address_
                              << " type=" << static_cast<int>(msg.type)
                              << " size=" << self->body_buf_.size()
                              << " cap=" << max_message_bytes(msg.type) << "\n";
                    if (self->on_close_) self->on_close_(self);
                    return;
                }
                if (self->on_msg_) self->on_msg_(self, msg);
            } catch (std::exception& e) {
                std::cerr << "[peer] message parse error from " << self->address_
                          << ": " << e.what() << "\n";
            }
            self->read_header();
        });
}

void Peer::send(const Message& msg) {
    // A3 / S8: pick the wire format based on the per-peer negotiated
    // version. HELLO is always JSON regardless — both sides need to be
    // able to parse it pre-negotiation, and the JSON encoding is also
    // what carries the `wire_version` advertisement field.
    std::vector<uint8_t> bytes;
    if (wire_version_ >= kWireVersionBinary && msg.type != MsgType::HELLO) {
        try {
            bytes = msg.serialize_binary();
        } catch (...) {
            // Fallback to JSON if binary encoding rejects this message
            // (e.g. encoder doesn't yet support a particular type). Keeps
            // the connection alive; caller still gets the message through.
            bytes = msg.serialize();
        }
    } else {
        bytes = msg.serialize();
    }
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

} // namespace determ::net
