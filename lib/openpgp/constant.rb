
module OpenPGP
  module Constant

    module AsymmetricKeyAlgorithm
      RSAEncryptOrSign = 1
    end

    module SymmetricKeyAlgorithm
      No = 0
      AES128 = 7
      AES192 = 8
      AES256 = 9
    end


    module Compression
      No = 0
      Zip = 1
      Zlib = 2
      BZip = 3
    end

    module Hash
      MD5 = 1
      SHA1 = 2
      SHA256 = 8
      SHA384 = 9
      SHA512 = 10
    end
  end

end
