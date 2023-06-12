require 'zlib'

module OpenPGP
  class Compressor
    require 'zlib'

    def self.get_class(algorithm)
      @@tags[algorithm]
    end

    def decompress
      raise "Unimplemented"
    end

    def compress
      raise "Unimplemented"
    end

    class PassThru < Compressor
      def decompress(data)
        data
      end

      def compress(data)
        data
      end
    end

    class Zip < Compressor
      def decompress(data)
        zlib = ::Zlib::Inflate.new(-Zlib::MAX_WBITS)
        zlib.inflate(data)
      ensure
        zlib.finish
        zlib.close
      end
    end

    class Zlib < Compressor
      def decompress(data)
        zlib = ::Zlib::Inflate.new
        zlib.inflate(data)
      ensure
        zlib.finish
        zlib.close
      end
    end

    class BZip < Compressor
      # TODO
    end

    @@tags = {
      Constants::Compression::No => PassThru,
      Constants::Compression::Zip => Zip,
      Constants::Compression::Zlib => Zlib
      Constants::Compression::BZip => BZip
    }
  end
end


