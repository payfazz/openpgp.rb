module OpenPGP
  module PKCS1
    def self.eme_pkcs_1_5_decode(m)
      if m.length > 11 && (m[0] == "\x00") && (m[1] == "\x02")
        x = 2
        x += 1 while x < m.length && m[x] != "\x00"

        return m[x + 1..-1]
      end

      raise
    end

    def self.eme_pkcs_1_5_encode(m, k)
      raise if m.length > (k - 11)

      em = "\x00\x02".force_encoding("ASCII-8BIT")
      while em.size < k - m.size - 1
        c = OpenSSL::Random.random_bytes(1)

        em += c if c != "\x00"
      end

      em + "\x00" + m
    end

    def self.esma_pkcs1_1_5(hash, data, key_length)
      asn1_der = {
        OpenPGP::Constant::Hash::SHA1 => "3021300906052B0E03021A05000414",
        OpenPGP::Constant::Hash::SHA256 => "3031300d060960864801650304020105000420",
        OpenPGP::Constant::Hash::SHA384 => "3041300d060960864801650304020205000430",
        OpenPGP::Constant::Hash::SHA512 => "3051300d060960864801650304020305000440",
      }

      cls = OpenPGP::Hash.get_class(hash)

      OpenPGP::Buffer.write do |b|
        b.write("\x00\x01")
        b.write("\xff" * (key_length - (asn1_der[hash].size >> 1) - (cls.const_get("LENGTH") >> 3) - 3))
        b.write_byte(0)
        b.write([asn1_der[hash]].pack("H*"))
        b.write(data)
      end.force_encoding("ASCII-8BIT")
    end
  end
end