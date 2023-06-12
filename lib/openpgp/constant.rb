
module OpenPGP
  module Constant

    module AsymmetricKeyAlgorithm
      RSAEncryptOrSign = 1
    end

    module SymmetricKeyAlgorithm
      NO = 0
      AES128 = 7
      AES192 = 8
      AES256 = 9
    end


    module Compression
      NO = 0
      ZIP = 1
      ZLIB = 2
      BZIP = 3
    end
  end

end
