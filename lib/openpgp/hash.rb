require 'openssl'

module OpenPGP
  class Hash
    def initialize(data)
      update(data)
    end

    def self.get_class(algorithm)
      @@tags[algorithm]
    end

    def update(data)
      @hash.update(data)
    end

    def digest
      @hash.digest
    end

    class SHA1 < Hash
      LENGTH = OpenSSL::Digest::SHA1.new.digest.length * 8

      def initialize(data)
	@hash = OpenSSL::Digest::SHA1.new
	super(data)
      end
    end

    @@tags = {
      2 => SHA1
    }
  end


end
