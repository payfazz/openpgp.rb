module OpenPGP
  ##
  # Alias for {OpenPGP::Armor.encode}.
  def self.enarmor(data, marker = :message, options = {})
    Armor.encode(data, marker, options)
  end

  ##
  # Alias for {OpenPGP::Armor.decode}.
  def self.dearmor(text, marker = nil, options = {})
    Armor.decode(text, marker, options)
  end

  ##
  # Alias for {OpenPGP::Message.encrypt}.
  def self.encrypt(data, options = {})
    (msg = Message.encrypt(data, options)) ? msg.to_s : nil
  end

  ##
  # Alias for {OpenPGP::Message.decrypt}.
  def self.decrypt(data, options = {})
    raise NotImplementedError # TODO
  end

  ##
  # Alias for {OpenPGP::Message.sign}.
  def self.sign
    raise NotImplementedError # TODO
  end

  ##
  # Alias for {OpenPGP::Message.verify}.
  def self.verify
    raise NotImplementedError # TODO
  end

  ##
  # @see http://tools.ietf.org/html/rfc4880#section-6.1
  CRC24_INIT = 0x00b704ce
  CRC24_POLY = 0x01864cfb

  ##
  # @param  [String] data
  # @return [Integer]
  # @see    http://tools.ietf.org/html/rfc4880#section-6
  # @see    http://tools.ietf.org/html/rfc4880#section-6.1
  def self.crc24(data)
    crc = CRC24_INIT
    data.each_byte do |octet|
      crc ^= octet << 16
      8.times do
        crc <<= 1
        crc ^= CRC24_POLY if (crc & 0x01000000).nonzero?
      end
    end
    crc &= 0x00ffffff
  end

  ##
  # Returns the bit length of a multiprecision integer (MPI).
  #
  # @param  [String] data
  # @return [Integer]
  # @see    http://tools.ietf.org/html/rfc4880#section-3.2
  def self.bitlength(data)
    data.empty? ? 0 : (data.size - 1) * 8 + (Math.log(data[0].ord) / Math.log(2)).floor + 1
  end

  # Should I deal with multi literal
  def self.collect_literal(message)
    ret = ""

    message.each do |p|
      case p
      when OpenPGP::Packet::LiteralData
        ret += p.data
      when OpenPGP::Packet::CompressedData
        ret += collect_literal(p.decompress)
      end
    end
    ret
  end

  def self.xor_strings(a, b)
    a, b = [b, a] if a.length < b.length
    a = a[0...b.length] if b.length != a.length
    a.unpack("c*").zip(b.unpack("c*")).map { |v| v[0] ^ v[1] }.pack("c*")
  end

  def self.addtrailer(data, sig)
    trailer = sig.hashed_data_for_signing

    case sig.version
    when 3
      data + trailer[1..-1]
    when 4
      OpenPGP::Buffer.write do |b|
        b.write(data)
        b.write(trailer)
        b.write("\x04\xff")
        b.write_number(trailer.size, 4)
      end.force_encoding("ASCII-8BIT")
    end
  end

  def self.openpgp_cipher_cfb_decrypt(cipher_ecb, key, data, integrity_packet = false, bs = 16)
    cipher_ecb.encrypt
    cipher_ecb.key = key

    fr = "\x00" * bs
    fre = cipher_ecb.update(fr)

    fr = data[0...bs]

    prefix = xor_strings(fre, fr)

    fre = cipher_ecb.update(fr)

    p = ""
    x = integrity_packet ? 2 : 0

    while x + bs < data.length
      substr = data[x...x + bs]
      p += xor_strings(fre, substr)

      fre = cipher_ecb.update(substr)
      x += bs
    end

    p += xor_strings(fre, data[x...x + bs])
    p = p[bs..-1]

    prefix + (integrity_packet ? prefix[bs - 2...bs] : "") + p
  end
end
