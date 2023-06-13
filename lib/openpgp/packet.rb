require_relative "./constant.rb"

module OpenPGP
  ##
  # OpenPGP packet.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-4.1
  # @see http://tools.ietf.org/html/rfc4880#section-4.3
  class Packet
    attr_accessor :tag, :size, :data

    ##
    # Returns the implementation class for a packet tag.
    #
    # @param  [Integer, #to_i] tag
    # @return [Class]
    def self.for(tag)
      @@tags[tag.to_i] || self
    end

    def self.ifor(cls)
      @@tags.invert[cls]
    end


    ##
    # Returns the packet tag for this class.
    #
    # @return [Integer]
    def self.tag
      @@tags.index(self)
    end

    ##
    # Parses an OpenPGP packet.
    #
    # @param  [Buffer, #to_str] data
    # @return [Packet]
    # @see    http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      data = Buffer.new(data.to_str) if data.respond_to?(:to_str)

      unless data.eof?
	new = ((tag = data.getbyte) & 64).nonzero? # bit 6 indicates new packet format if set
	data.ungetbyte(tag) rescue data.ungetc(tag.ord) # FIXME in backports/1.8.7
	send(new ? :parse_new_format : :parse_old_format, data)
      end
    end

    ##
    # Parses a new-format (RFC 4880) OpenPGP packet.
    #
    # @param  [Buffer, #to_str] data
    # @return [Packet]
    # @see    http://tools.ietf.org/html/rfc4880#section-4.2.2
    def self.parse_new_format(data)
      tag = data.getbyte & 63
      len = data.getbyte

      case len
      when 0..191   # 4.2.2.1. One-Octet Lengths
	data_length = len
      when 192..223 # 4.2.2.2. Two-Octet Lengths
	data_length = ((len - 192) << 8) + data.getbyte + 192
      when 224..254 # 4.2.2.4. Partial Body Lengths
	data_length = 1 << (len & 0x1f)
      when 255      # 4.2.2.3. Five-Octet Lengths
	data_length = (data.getbyte << 24) | (data.getbyte << 16) | (data.getbyte << 8) | data.getbyte
      end

      Packet.for(tag).parse_body(Buffer.new(data.read(data_length)), :tag => tag)
    end

    ##
    # Parses an old-format (PGP 2.6.x) OpenPGP packet.
    #
    # @param  [Buffer, #to_str] data
    # @return [Packet]
    # @see    http://tools.ietf.org/html/rfc4880#section-4.2.1
    def self.parse_old_format(data)
      len = (tag = data.getbyte) & 3
      tag = (tag >> 2) & 15

      case len
      when 0 # The packet has a one-octet length. The header is 2 octets long.
	data_length = data.getbyte
      when 1 # The packet has a two-octet length. The header is 3 octets long.
	data_length = data.read(2).unpack('n').first
      when 2 # The packet has a four-octet length. The header is 5 octets long.
	data_length = data.read(4).unpack('N').first
      when 3 # The packet is of indeterminate length. The header is 1 octet long.
	data_length = false # read to EOF
      else
	raise "Invalid OpenPGP packet length-type: expected 0..3 but got #{len}"
      end

      Packet.for(tag).parse_body(Buffer.new(data_length ? data.read(data_length) : data.read), :tag => tag)
    end

    def build_old_format
      out = Buffer.new
      tag = Packet.ifor(self.class)
      b = body()

      case b.length
      when 0..0xFF
	out.write_byte((tag << 2) | 0 | 128)
	out.write_byte(b.length)
      when 0xFF+1..0xFFFF
	out.write_byte((tag << 2) | 1 | 128)
	out.write([b.length].pack("S>"))
      else
	out.write_byte((tag << 2) | 2 | 128)
	out.write([b.length].pack("L>"))
      end

      out.write(b)
      out.rewind
      out.read.force_encoding("ASCII-8BIT")
    end

    def build_new_format
      out = Buffer.new
      tag = Packet.ifor(self.class) | 64 | 128
      out.write_byte(tag)
      b = body()

      case b.length
      when 0..191
	out.write_byte(b.length)
      else
	out.write_byte(255)
	out.write_number(b.length, 4)
      end

      out.write(b)
      out.rewind
      out.read.force_encoding("ASCII-8BIT")
    end

    def build
      if Packet.ifor(self.class) <= 15
        build_old_format
      else
        build_new_format
      end
    end

    ##
    # @param  [Buffer]                 body
    # @param  [Hash{Symbol => Object}] options
    # @return [Packet]
    def self.parse_body(body, options = {})
      self.new(options)
    end

    ##
    # @param  [Hash{Symbol => Object}] options
    def initialize(options = {}, &block)
      options.each { |k, v| send("#{k}=", v) }
      block.call(self) if block_given?
    end

    #def to_s() body end

    ##
    # @return [Integer]
    def size() body.size end

    ##
    # @return [String]
    def body
      respond_to?(:write_body) ? Buffer.write { |buffer| write_body(buffer) }.force_encoding('ASCII-8BIT') : ""
    end

    ##
    # OpenPGP Public-Key Encrypted Session Key packet (tag 1).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.1
    # @see http://tools.ietf.org/html/rfc4880#section-13.1
    class AsymmetricSessionKey < Packet
      attr_accessor :version, :key_id, :algorithm
      attr_accessor :mpis

      def self.parse_body(body, options = {})
	case version = body.read_byte
	when 3
	  # TODO: Support other algorithm
	  instance = self.new(:version => version, :key_id => body.read_number(8, 16), :algorithm => body.read_byte, :mpis => [])
	  while !body.eof?
	    instance.mpis << body.read_mpi
	  end
	  instance
	else
	  raise "Invalid OpenPGP public-key ESK packet version: #{version}"
	end
      end

      def write_body(buffer)
	buffer.write_byte(version)
        buffer.write_number(key_id, 8)
	buffer.write_byte(algorithm)
	mpis.each do |mpi|
	  buffer.write_mpi(mpi)
	end
      end

    end

    ##
    # OpenPGP Signature packet (tag 2).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.2
    class Signature < Packet
      attr_accessor :version, :type
      attr_accessor :key_algorithm, :hash_algorithm
      attr_accessor :key_id
      attr_accessor :fields

      def self.parse_body(body, options = {})
	case version = body.read_byte
	when 3 then self.new(:version => 3).send(:read_v3_signature, body)
	when 4 then self.new(:version => 4).send(:read_v4_signature, body)
	else raise "Invalid OpenPGP signature packet version: #{version}"
	end
      end

      protected

      ##
      # @see http://tools.ietf.org/html/rfc4880#section-5.2.2
      def read_v3_signature(body)
	raise "Invalid OpenPGP signature packet V3 header" if body.read_byte != 5
	@type, @timestamp, @key_id = body.read_byte, body.read_number(4), body.read_number(8, 16)
	@key_algorithm, @hash_algorithm = body.read_byte, body.read_byte
	body.read_bytes(2)
	read_signature(body)
	self
      end

      ##
      # @see http://tools.ietf.org/html/rfc4880#section-5.2.3
      def read_v4_signature(body)
	@type = body.read_byte
	@key_algorithm, @hash_algorithm = body.read_byte, body.read_byte
	body.read_bytes(hashed_count = body.read_number(2))
	body.read_bytes(unhashed_count = body.read_number(2))
	body.read_bytes(2)
	read_signature(body)
	self
      end

      ##
      # @see http://tools.ietf.org/html/rfc4880#section-5.2.2
      def read_signature(body)
	case key_algorithm
	when Algorithm::Asymmetric::RSA
	  @fields = [body.read_mpi]
	when Algorithm::Asymmetric::DSA
	  @fields = [body.read_mpi, body.read_mpi]
	else
	  raise "Unknown OpenPGP signature packet public-key algorithm: #{key_algorithm}"
	end
      end
    end

    ##
    # OpenPGP Symmetric-Key Encrypted Session Key packet (tag 3).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.3
    class SymmetricSessionKey < Packet
      attr_accessor :version, :algorithm, :s2k

      def self.parse_body(body, options = {})
	case version = body.read_byte
	when 4
	  self.new({:version => version, :algorithm => body.read_byte, :s2k => body.read_s2k}.merge(options))
	else
	  raise "Invalid OpenPGP symmetric-key ESK packet version: #{version}"
	end
      end

      def initialize(options = {}, &block)
	defaults = {
	  :version   => 4,
	  :algorithm => Cipher::DEFAULT.to_i,
	  :s2k       => S2K::DEFAULT.new,
	}
	super(defaults.merge(options), &block)
      end

      def write_body(buffer)
	buffer.write_byte(version)
	buffer.write_byte(algorithm.to_i)
	buffer.write_s2k(s2k)
      end
    end

    ##
    # OpenPGP One-Pass Signature packet (tag 4).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.4
    class OnePassSignature < Packet
      # TODO
    end

    ##
    # OpenPGP Public-Key packet (tag 6).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.1
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class PublicKey < Packet
      attr_accessor :size
      attr_accessor :version, :timestamp, :algorithm
      attr_accessor :key, :key_fields

      #def parse(data) # FIXME
      def self.parse_body(body, options = {})
	case version = body.read_byte
	when 2, 3
	  # TODO
	when 4
	  packet = self.new(:version => version, :timestamp => body.read_timestamp, :algorithm => body.read_byte, :key => {}, :size => body.size)
	  packet.read_key_material(body)
	  packet
	else
	  raise "Invalid OpenPGP public-key packet version: #{version}"
	end
      end

      ##
      # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
      def read_key_material(body)
	@key_fields = case algorithm
		      when Algorithm::Asymmetric::RSA   then [:n, :e]
		      when Algorithm::Asymmetric::ELG_E then [:p, :g, :y]
		      when Algorithm::Asymmetric::DSA   then [:p, :q, :g, :y]
		      else raise "Unknown OpenPGP key algorithm: #{algorithm}"
		      end
	@key_fields.each { |field| key[field] = body.read_mpi }
      end

      ##
      # @see http://tools.ietf.org/html/rfc4880#section-12.2
      # @see http://tools.ietf.org/html/rfc4880#section-3.3
      def fingerprint
	case version
	when 2, 3
	  Digest::MD5.digest([key[:n], key[:e]].join)
	when 4
	  packet = Buffer.write do |b|
	    b.write_byte(version)
	    b.write([timestamp].pack('N'))
	    b.write_byte(algorithm)

	    key_fields.each do |key_field|
	      b.write_mpi(key[key_field])
	    end
	  end.force_encoding("ASCII-8BIT")

	  material = Buffer.write do |b|
	    b.write_byte(0x99)
	    b.write_number(packet.size, 2)
	    b.write(packet)
	  end.force_encoding("ASCII-8BIT")

	  Digest::SHA1.digest(material)
	end
      end

      def key_id
	case version
        when 2, 3
          raise "Unimplemented"
	when 4
          fingerprint[12...12+8].unpack("H*").last.upcase
        else
          raise "No such version"
	end
      end

      def to_der
	n = OpenSSL::BN.new(key[:n], 2)
	e = OpenSSL::BN.new(key[:e], 2)
	seq = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(n), OpenSSL::ASN1::Integer.new(e)])
	seq.to_der
      end
    end

    ##
    # OpenPGP Public-Subkey packet (tag 14).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.2
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class PublicSubkey < PublicKey
      # TODO
    end

    ##
    # OpenPGP Secret-Key packet (tag 5).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.3
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.3
    # @see http://tools.ietf.org/html/rfc4880#section-11.2
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class SecretKey < PublicKey
      attr_accessor :sym, :s2k, :iv
      attr_accessor :secret_fields

      def self.parse_body(body, options = {})
	instance = super(body, options)

	s2k_con = body.read_byte 

	if s2k_con != 0 && s2k_con != 254 && s2k_con != 255
	  instance.sym = s2k_con
	elsif s2k_con == 254 || s2k_con == 255
	  instance.sym = body.read_byte
	  instance.s2k = body.read_s2k

	elsif s2k_con == 0
	  # ignore
	else
	  raise "Something wrong when reading secret key"
	end

	# unless no sym encryption, read IV
	if s2k_con != 0
	  # 128bit = AES BLOCK SIZE
	  instance.iv = body.read_bytes(128 / 8) 
	end
	instance.secret_fields = body.read
	instance
      end

      def calculate_key(passphrase)
	return passphrase if s2k.nil?
	# TODO: Dont hard code to 16(all AES)
	s2k.run(passphrase, 16)
      end

      def decrypt_keys(passphrase: "", sym_key: nil, validate: true)
	sym_key = calculate_key(passphrase) if sym_key.nil?

	cipher = get_cipher(sym_key, decrypt: true)

	decrypted = cipher.update(secret_fields) + cipher.final

	decrypted, sha1 = decrypted[0...decrypted.length-20], decrypted[-20..-1]
	b = OpenPGP::Buffer.new(decrypted)

	priv_keys = {}
	[:d, :p, :q, :u].each do |v|
	  priv_keys[v] = b.read_mpi
	end

	raise "secret field format error" unless b.eof?

	if validate
	  raise "Private block validate failed" if OpenPGP::Hash::SHA1.new(decrypted).digest != sha1
	end

	priv_keys
      end

      def encrypt_keys(priv_keys, passphrase: "", sym_key: nil)

	sym_key = calculate_key(passphrase) if sym_key.nil?
	cipher = get_cipher(sym_key)

	b = OpenPGP::Buffer.new
	priv_keys.each do |k, v|
	  b.write_mpi(v)
	end
	b.rewind
	block = b.read.force_encoding("ASCII-8BIT")
	block += OpenPGP::Hash::SHA1.new(block).digest

	encrypted = cipher.update(block) + cipher.final

	self.secret_fields = encrypted
      end

      def get_cipher(key, decrypt: false)
	# TODO: Don't hardcode this
	cipher = OpenSSL::Cipher.new("AES-128-CFB")

	if decrypt
	  cipher.decrypt
	else
	  cipher.encrypt
	end
	cipher.iv = iv
	cipher.key = key

	cipher
      end

      def to_der(passphrase:)
	priv_keys = decrypt_keys(passphrase: passphrase)

	n = OpenSSL::BN.new(key[:n], 2)
	e = OpenSSL::BN.new(key[:e], 2)
	d = OpenSSL::BN.new(priv_keys[:d], 2)
	p = OpenSSL::BN.new(priv_keys[:p], 2)
	q = OpenSSL::BN.new(priv_keys[:q], 2)
	u = OpenSSL::BN.new(priv_keys[:u], 2)

	seq = OpenSSL::ASN1::Sequence.new([
	  OpenSSL::ASN1::Integer.new(0),
	  OpenSSL::ASN1::Integer.new(n),
	  OpenSSL::ASN1::Integer.new(e),
	  OpenSSL::ASN1::Integer.new(d),
	  OpenSSL::ASN1::Integer.new(p),
	  OpenSSL::ASN1::Integer.new(q),
	  OpenSSL::ASN1::Integer.new(d % (p-1)),
	  OpenSSL::ASN1::Integer.new(d % (q-1)),
	  OpenSSL::ASN1::Integer.new(q.mod_inverse(p)),
	])
	seq.to_der
      end
    end

    ##
    # OpenPGP Secret-Subkey packet (tag 7).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.4
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.3
    # @see http://tools.ietf.org/html/rfc4880#section-11.2
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class SecretSubkey < SecretKey
      # TODO
    end

    ##
    # OpenPGP Compressed Data packet (tag 8).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.6
    class CompressedData < Packet

      attr_accessor :algorithm, :compressed_data

      def self.parse_body(body, options = {})
	self.new(:algorithm => body.read_byte, :compressed_data => body.read)
      end

      def self.compress(algorithm, data)
	data = Compressor.get_class(algorithm).new.compress(data)
	self.new(:algorithm => algorithm, :compressed_data => data)
      end

      def decompress
	data = Compressor.get_class(algorithm).new.decompress(compressed_data)
	Message.parse(data)
      end

      def write_body(buffer)
	buffer.write_byte(algorithm)
	buffer.write(compressed_data)
      end
    end

    ##
    # OpenPGP Symmetrically Encrypted Data packet (tag 9).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.7
    class EncryptedData < Packet
      attr_accessor :data

      def self.parse_body(body, options = {})
	self.new({:data => body.read}.merge(options))
      end

      def initialize(options = {}, &block)
	super(options, &block)
      end

      def write_body(buffer)
	buffer.write(data)
      end
    end

    ##
    # OpenPGP Marker packet (tag 10).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.8
    class Marker < Packet
      # TODO
    end

    ##
    # OpenPGP Literal Data packet (tag 11).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.9
    class LiteralData < Packet
      attr_accessor :format, :filename, :timestamp, :data

      def self.parse_body(body, options = {})
	defaults = {
	  :format    => body.read_byte.chr.to_sym,
	  :filename  => body.read_string,
	  :timestamp => body.read_timestamp,
	  :data      => body.read,
	}
	self.new(defaults.merge(options))
      end

      def initialize(options = {}, &block)
	defaults = {
	  :format    => :b,
	  :filename  => "",
	  :timestamp => 0,
	  :data      => "",
	}
	super(defaults.merge(options), &block)
      end

      def write_body(buffer)
	buffer.write_byte(format)
	buffer.write_string(filename)
	buffer.write_timestamp(timestamp)
	buffer.write(data.to_s)
      end

      EYES_ONLY = '_CONSOLE'

      def eyes_only!() filename = EYES_ONLY end
      def eyes_only?() filename == EYES_ONLY end
    end

    ##
    # OpenPGP Trust packet (tag 12).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.10
    class Trust < Packet
      attr_accessor :data

      def self.parse_body(body, options = {})
	self.new({:data => body.read}.merge(options))
      end

      def write_body(buffer)
	buffer.write(data)
      end
    end

    ##
    # OpenPGP User ID packet (tag 13).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.11
    # @see http://tools.ietf.org/html/rfc2822
    class UserID < Packet
      attr_accessor :name, :comment, :email

      def self.parse_body(body, options = {})
	case body.read
	  # User IDs of the form: "name (comment) <email>"
	when /^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$/
	  self.new(:name => $1.strip, :comment => $2.strip, :email => $3.strip)
	  # User IDs of the form: "name <email>"
	when /^([^<]+)\s+<([^>]+)>$/
	  self.new(:name => $1.strip, :comment => nil, :email => $2.strip)
	  # User IDs of the form: "name"
	when /^([^<]+)$/
	  self.new(:name => $1.strip, :comment => nil, :email => nil)
	  # User IDs of the form: "<email>"
	when /^<([^>]+)>$/
	  self.new(:name => nil, :comment => nil, :email => $1.strip)
	else
	  self.new(:name => nil, :comment => nil, :email => nil)
	end
      end

      def write_body(buffer)
	buffer.write(to_s)
      end

      def to_s
	text = []
	text << name if name
	text << "(#{comment})" if comment
	text << "<#{email}>" if email
	text.join(' ')
      end
    end

    ##
    # OpenPGP User Attribute packet (tag 17).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.12
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    class UserAttribute < Packet
      attr_accessor :packets

      # TODO
    end

    ##
    # OpenPGP Sym. Encrypted Integrity Protected Data packet (tag 18).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.13
    class IntegrityProtectedData < Packet
      attr_accessor :version, :data

      def self.parse_body(body, options = {})
	case version = body.read_byte
	when 1
	  self.new(:version => version, :data => body.read) # TODO: read the encrypted data.
	else
	  raise "Invalid OpenPGP integrity-protected data packet version: #{version}"
	end
      end

      def write_body(buffer)
	buffer.write_byte(version)
	buffer.write(data)
      end
    end

    ##
    # OpenPGP Modification Detection Code packet (tag 19).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.14
    class ModificationDetectionCode < Packet
      # TODO
    end

    ##
    # OpenPGP Private or Experimental packet (tags 60..63).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.3
    class Experimental < Packet; end

    protected
    ##
    # @see http://tools.ietf.org/html/rfc4880#section-4.3
    @@tags = {
      1 => AsymmetricSessionKey,      # Public-Key Encrypted Session Key
      2 => Signature,                 # Signature Packet
      3 => SymmetricSessionKey,       # Symmetric-Key Encrypted Session Key Packet
      4 => OnePassSignature,          # One-Pass Signature Packet
      5 => SecretKey,                 # Secret-Key Packet
      6 => PublicKey,                 # Public-Key Packet
      7 => SecretSubkey,              # Secret-Subkey Packet
      8 => CompressedData,            # Compressed Data Packet
      9 => EncryptedData,             # Symmetrically Encrypted Data Packet
      10 => Marker,                    # Marker Packet
      11 => LiteralData,               # Literal Data Packet
      12 => Trust,                     # Trust Packet
      13 => UserID,                    # User ID Packet
      14 => PublicSubkey,              # Public-Subkey Packet
      17 => UserAttribute,             # User Attribute Packet
      18 => IntegrityProtectedData,    # Sym. Encrypted and Integrity Protected Data Packet
      19 => ModificationDetectionCode, # Modification Detection Code Packet
      60 => Experimental,              # Private or Experimental Values
      61 => Experimental,              # Private or Experimental Values
      62 => Experimental,              # Private or Experimental Values
      63 => Experimental,              # Private or Experimental Values
    }
  end
end
