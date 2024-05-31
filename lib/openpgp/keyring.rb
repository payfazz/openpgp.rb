module OpenPGP
  class KeyRing
    def initialize
      @keys = {}
    end

    # TODO: Support multiple key import by reading Signature Packet
    # Current state: Can import multiple key from same email
    def import(key_pgp, passphrase: nil)
      key_pgp = OpenPGP::Message.parse(OpenPGP.dearmor(key_pgp)) if key_pgp.is_a?(String)

      name = ""
      email = ""
      key_pgp.packets.each do |p|
        next unless p.is_a?(OpenPGP::Packet::UserID)

        name = p.name
        email = p.email
      end
      # find out secret key and register

      found_keys = []
      key_pgp.packets.each do |p|
        next unless p.is_a?(OpenPGP::Packet::PublicKey)

        @keys[p.key_id] = {
          type: p.is_a?(OpenPGP::Packet::SecretKey) ? :secret_key : :public_key,
          name: name,
          email: email,
          packet: p,
          key: passphrase.nil? ? nil : p.calculate_key(passphrase),
        }

        found_keys << p.key_id
      end

      found_keys
    end

    def fetch(key_id, secret_key: false)
      entry = @keys[key_id]
      raise KeyNotFoundError, "Key #{key_id} not found" if entry.nil?

      if entry[:type] == :secret_key
        if entry[:key].nil?
          raise "Not decrypt key yet"
        else
          OpenSSL::PKey::RSA.new(entry[:packet].to_der(sym_key: entry[:key]))
        end
      else
        raise "Expected secret key, only public key found" if secret_key

        OpenSSL::PKey::RSA.new(entry[:packet].to_der)
      end
    end

    def decrypt_key(key_id, passphrase:, validate: true)
      entry = @keys[key_id]
      if entry[:type] == :secret_key
        sym_key = entry[:packet].calculate_key(passphrase)

        if validate
          begin
            key = OpenSSL::PKey::RSA.new(entry[:packet].to_der(sym_key: sym_key))
            raise unless key.verify(OpenSSL::Digest.new("SHA256"), key.sign(OpenSSL::Digest.new("SHA256"), "hi"), "hi")
          rescue SandardError
            raise DecryptKeyError, "passphrase may be wrong"
          end
        end

        entry[:key] = sym_key
      end
    end

    # return array
    def find_key(email:, secret_key: false)
      ret = []
      @keys.each do |k, entry|
        ret << k if entry[:email] == email && (!secret_key || entry[:type] == :secret_key)
      end
      ret
    end

    # highest level API
    def encrypt(data, recipient:, signer: nil, cipher_algo: :aes256, digest_algo: :sha1, compress_algo: :zip)
      recipient_key_id = find_key(email: recipient).first

      signer_key_id = nil
      signer_key_id = find_key(email: signer, secret_key: true).first unless signer.nil?

      encrypt_by_key(data,
        recipient_key_id: recipient_key_id,
        cipher_algo: cipher_algo,
        digest_algo: digest_algo,
        compress_algo: compress_algo,
        signer_key_id: signer_key_id,)
    end

    def encrypt_by_key(data, recipient_key_id:, cipher_algo: :aes256, digest_algo: :sha1, compress_algo: :zip, signer_key_id: nil)
      recipient_key = fetch(recipient_key_id)
      data = data.force_encoding("ASCII-8BIT")
      msg = OpenPGP::Message.new

      digest_algo_map = {
        sha1: OpenPGP::Constant::Hash::SHA1,
        sha256: OpenPGP::Constant::Hash::SHA256,
        sha384: OpenPGP::Constant::Hash::SHA384,
        sha512: OpenPGP::Constant::Hash::SHA512,
      }

      cipher_algo_map = {
        aes128: 7,
        aes192: 8,
        aes256: 9,
      }

      tag1 = OpenPGP::Packet::AsymmetricSessionKey.generate(
        pub: recipient_key,
        pub_key_id: recipient_key_id,
      )

      msg << tag1

      literal = OpenPGP::Packet::LiteralData.new(
        data: data,
      )

      to_encrypted = if signer_key_id.nil?
                       literal.build
                     else
                       signed_data = sign_binary(data, signer_key_id: signer_key_id, algo: digest_algo_map[digest_algo])
                       signed_data[0].build + literal.build + signed_data[1].build
                     end

      compress_algo_map = {
        no: 0,
        zip: 1,
        zlib: 2,
        bzip: 3,
      }

      unless compress_algo == :no
        to_encrypted = OpenPGP::Packet::CompressedData.compress(
          compress_algo_map[compress_algo],
          to_encrypted,
        ).build
      end

      msg << OpenPGP::Packet::IntegrityProtectedData.encrypt(to_encrypted, cipher_algorithm: cipher_algo_map[cipher_algo],
                                                                           session_key: tag1.session_key,)

      msg
    end

    # @decompress: return decompressed data?
    def decrypt(data, decompress: true, verify: true)
      data = OpenPGP::Message.parse(OpenPGP.dearmor(data)) unless data.is_a?(OpenPGP::Message)

      session_key_msg, protected_msg = data.packets

      pri = fetch(session_key_msg.key_id, secret_key: true)

      session_key_msg.extract_session_key(pri)
      algo = session_key_msg.cipher_algorithm
      session_key = session_key_msg.session_key

      cipher_map = {
        7 => "AES-128",
        8 => "AES-192",
        9 => "AES-256",
      }
      block_size_map = {
        OpenPGP::Constant::SymmetricKeyAlgorithm::AES128 => 16,
        OpenPGP::Constant::SymmetricKeyAlgorithm::AES192 => 16,
        OpenPGP::Constant::SymmetricKeyAlgorithm::AES256 => 16,
      }

      # here is --cipher-algo 'aes-256'
      dec = case protected_msg
            when OpenPGP::Packet::EncryptedData
              # add --rfc2440 to use EncryptedData packet during encryption
              # I will not implement rfc2440 encrypt.
              OpenPGP.openpgp_cipher_cfb_decrypt(OpenSSL::Cipher.new("#{cipher_map[algo]}-ECB"), session_key, protected_msg.data,
                true,)
            when OpenPGP::Packet::IntegrityProtectedData
              cipher = OpenSSL::Cipher.new("#{cipher_map[algo]}-CFB")
              cipher.decrypt
              cipher.iv = "\x00" * block_size_map[algo]
              cipher.key = session_key
              cipher.update(protected_msg.data) + cipher.final
            end

      # Do extra integrity check for mdc
      if protected_msg.is_a?(OpenPGP::Packet::IntegrityProtectedData)
        raise MDCCheckError, "sha1 checksum failed for decrypted data" unless OpenPGP::Hash::SHA1.new(dec[0...-20]).digest == dec[-20..-1]

        dec = dec[0...-20]
        dec = dec[0...-2] # strip d314
      end

      dec = dec[16 + 2..-1] # strip prefix

      decrypted = OpenPGP::Message.parse(dec)

      # decompress and verify

      # verify if signature present
      decompressed = if decrypted.packets.first.is_a?(OpenPGP::Packet::CompressedData)
                       decrypted.packets.first.decompress
                     else
                       decrypted
                     end
      sig = decompressed.select { |v| v.is_a?(OpenPGP::Packet::Signature) }.first
      # has signature?
      raise SignatureValificationError if !sig.nil? && verify && !verify_signature(decompressed)

      decompress ? decompressed : decrypted
    end

    def detached_sign(data, signer:, digest_algo: :sha256)
      signer_key_id = find_key(email: signer, secret_key: true).first
      raise KeyNotFoundError if signer_key_id.nil?

      digest_algo_map = {
        sha1: OpenPGP::Constant::Hash::SHA1,
        sha256: OpenPGP::Constant::Hash::SHA256,
        sha384: OpenPGP::Constant::Hash::SHA384,
        sha512: OpenPGP::Constant::Hash::SHA512,
      }

      _, sig = sign_binary(data, signer_key_id: signer_key_id, algo: digest_algo_map[digest_algo])

      msg = Message.new(marker: :signature)
      msg << sig
      msg
    end

    private

    def verify_signature(decrypted)
      onepass = decrypted.select { |v| v.is_a?(OpenPGP::Packet::OnePassSignature) }.first
      sig = decrypted.select { |v| v.is_a?(OpenPGP::Packet::Signature) }.first
      literal = decrypted.select { |v| v.is_a?(OpenPGP::Packet::LiteralData) }.first
      sdata = OpenPGP.addtrailer(literal.data, sig)
      digest = OpenPGP::Hash.get_class(onepass.hash_algorithm).new(sdata).digest

      signer = fetch(onepass.key_id)

      # we may need to check digest prefix as well
      # sig.digest_prefix == digest[0...2]
      signer.public_encrypt(sig.fields[0],
        OpenSSL::PKey::RSA::NO_PADDING,) == OpenPGP::PKCS1.esma_pkcs1_1_5(onepass.hash_algorithm, digest,
          signer.n.to_s(2).size,)
    end

    def sign_binary(data, signer_key_id:, timestamp: Time.now.to_i, algo: OpenPGP::Constant::Hash::SHA1)
      signer = fetch(signer_key_id, secret_key: true)
      tag4 = OpenPGP::Packet::OnePassSignature.new(
        version: 3,
        type: 0,
        hash_algorithm: algo,
        key_algorithm: OpenPGP::Constant::AsymmetricKeyAlgorithm::RSAEncryptOrSign,
        key_id: signer_key_id,
        nested_flag: 1,
      )
      # tag length payload
      sig = OpenPGP::Packet::Signature.new(
        version: 4,
        type: 0,
        key_algorithm: OpenPGP::Constant::AsymmetricKeyAlgorithm::RSAEncryptOrSign,
        hash_algorithm: algo,
        hashed: [
          OpenPGP::Packet::Signature::Subpacket::SignatureCreationTime.new(
            timestamp: timestamp,
          ),
        ],
        unhashed: [
          OpenPGP::Packet::Signature::Subpacket::Issuer.new(
            key_id: signer_key_id,
          ),
        ],
      )

      # add trailer
      sdata  = OpenPGP.addtrailer(data, sig)
      digest = OpenPGP::Hash.get_class(algo).new(sdata).digest

      sig.digest_prefix = digest[0...2]

      sig.fields = [
        signer.private_decrypt(OpenPGP::PKCS1.esma_pkcs1_1_5(algo, digest, signer.n.to_s(2).size),
          OpenSSL::PKey::RSA::NO_PADDING,)]

      [tag4, sig]
    end
  end
end
