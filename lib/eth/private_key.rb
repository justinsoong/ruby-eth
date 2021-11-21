require 'openssl'

class PrivateKey < Eth::MoneyTreeKey

    def initialize(opts = {})
      @options = opts
      @ec_key = PKey::EC.new GROUP_NAME
      if @options[:key]
        @raw_key = @options[:key]
        @key = parse_raw_key
        import
      else
        generate
        @key = to_hex
      end
    end

    def generate
      ec_key.generate_key
    end

    def import
      ec_key.private_key = BN.new(key, 16)
      set_public_key
    end

    def calculate_public_key(opts = {})
      opts[:compressed] = true unless opts[:compressed] == false
      group = ec_key.group
      group.point_conversion_form = opts[:compressed] ? :compressed : :uncompressed
      point = group.generator.mul ec_key.private_key
    end

    def set_public_key(opts = {})
      ec_key.public_key = calculate_public_key(opts)
    end

    def parse_raw_key
      result = if raw_key.is_a?(Integer) then from_integer
      elsif hex_format? then from_hex
      elsif base64_format? then from_base64
      elsif compressed_wif_format? then from_wif
      elsif uncompressed_wif_format? then from_wif
      else
        raise KeyFormatNotFound
      end
      result.downcase
    end

    def from_integer(bignum = raw_key)
      # TODO: does this need a byte size specification?
      int_to_hex(bignum)
    end

    def from_hex(hex = raw_key)
      hex
    end

    def from_wif(wif = raw_key)
      compressed = wif.length == 52
      validate_wif(wif)
      hex = decode_base58(wif)
      last_char = compressed ? -11 : -9
      hex.slice(2..last_char)
    end

    def from_base64(base64_key = raw_key)
      raise InvalidBase64Format unless base64_format?(base64_key)
      decode_base64(base64_key)
    end

    def compressed_wif_format?
      wif_format?(:compressed)
    end

    def uncompressed_wif_format?
      wif_format?(:uncompressed)
    end

    def wif_format?(compression)
      length = compression == :compressed ? 52 : 51
      wif_prefixes = MoneyTree::NETWORKS.map {|k, v| v["#{compression}_wif_chars".to_sym]}.flatten
      raw_key.length == length && wif_prefixes.include?(raw_key.slice(0))
    end

    def base64_format?(base64_key = raw_key)
      base64_key.length == 44 && base64_key =~ /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/
    end

    def hex_format?
      raw_key.length == 64 && !raw_key[/\H/]
    end

    def to_hex
      int_to_hex @ec_key.private_key, 64
    end

    def to_wif(compressed: true, network: :bitcoin)
      source = NETWORKS[network][:privkey_version] + to_hex
      source += NETWORKS[network][:privkey_compression_flag] if compressed
      hash = sha256(source)
      hash = sha256(hash)
      checksum = hash.slice(0..7)
      source_with_checksum = source + checksum
      encode_base58(source_with_checksum)
    end

    def wif_valid?(wif)
      hex = decode_base58(wif)
      checksum = hex.chars.to_a.pop(8).join
      source = hex.slice(0..-9)
      hash = sha256(source)
      hash = sha256(hash)
      hash_checksum = hash.slice(0..7)
      checksum == hash_checksum
    end

    def validate_wif(wif)
      raise InvalidWIFFormat unless wif_valid?(wif)
    end

    def to_base64
      encode_base64(to_hex)
    end

    def to_s(network: :bitcoin)
      to_wif(network: network)
    end

  end