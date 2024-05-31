require 'openssl'
require_relative "./constant.rb"

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

    class SHA256 < Hash
      LENGTH = OpenSSL::Digest::SHA256.new.digest.length * 8

      def initialize(data)
	      @hash = OpenSSL::Digest::SHA256.new
	      super(data)
      end
    end

    class SHA384 < Hash
      LENGTH = OpenSSL::Digest::SHA384.new.digest.length * 8

      def initialize(data)
	      @hash = OpenSSL::Digest::SHA384.new
	      super(data)
      end
    end

    class SHA512 < Hash
      LENGTH = OpenSSL::Digest::SHA512.new.digest.length * 8

      def initialize(data)
	      @hash = OpenSSL::Digest::SHA512.new
	      super(data)
      end
    end



    @@tags = {
      Constant::Hash::SHA1 => SHA1,
      Constant::Hash::SHA256  => SHA256,
      Constant::Hash::SHA384  => SHA384,
      Constant::Hash::SHA512  => SHA512
    }
  end


end
