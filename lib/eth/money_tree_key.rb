require 'openssl'

module Eth
  class MoneyTreeKey
    include OpenSSL
    include Support
    extend Support
    
    class KeyInvalid < StandardError; end
    class KeyGenerationFailure < StandardError; end
    class KeyImportFailure < StandardError; end
    class KeyFormatNotFound < StandardError; end
    class InvalidWIFFormat < StandardError; end
    class InvalidBase64Format < StandardError; end

    attr_reader :options, :key, :raw_key
    attr_accessor :ec_key

    GROUP_NAME = 'secp256k1'
    ORDER = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".to_i(16)

    def valid?(eckey = nil)
      eckey ||= ec_key
      eckey.nil? ? false : eckey.check_key
    end

    def to_bytes
      hex_to_bytes to_hex
    end

    def to_i
      bytes_to_int to_bytes
    end
  end
end
