#include <dhcoin/net/messages.hpp>
#include <stdexcept>

namespace dhcoin::net {

std::vector<uint8_t> Message::serialize() const {
    nlohmann::json envelope;
    envelope["type"]    = static_cast<uint8_t>(type);
    envelope["payload"] = payload;
    std::string s = envelope.dump();

    uint32_t len = static_cast<uint32_t>(s.size());
    std::vector<uint8_t> out(4 + s.size());
    out[0] = (len >> 24) & 0xFF;
    out[1] = (len >> 16) & 0xFF;
    out[2] = (len >> 8)  & 0xFF;
    out[3] =  len        & 0xFF;
    std::copy(s.begin(), s.end(), out.begin() + 4);
    return out;
}

Message Message::deserialize(const uint8_t* data, size_t len) {
    nlohmann::json envelope = nlohmann::json::parse(data, data + len);
    Message m;
    m.type    = static_cast<MsgType>(envelope["type"].get<uint8_t>());
    m.payload = envelope["payload"];
    return m;
}

} // namespace dhcoin::net
