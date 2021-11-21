require 'openssl'

class PublicKey < Eth::MoneyTreeKey
    attr_reader :private_key, :point, :group, :key_int

    def initialize(p_key, opts = {})
      @options = opts
      @options[:compressed] = true if @options[:compressed].nil?
      if p_key.is_a?(PrivateKey)
        @private_key = p_key
        @point = @private_key.calculate_public_key(@options)
        @group = @point.group
        @key = @raw_key = to_hex
      else
        @raw_key = p_key
        @group = PKey::EC::Group.new GROUP_NAME
        @key = parse_raw_key
      end

      raise ArgumentError, "Must initialize with a MoneyTree::PrivateKey or a public key value" if @key.nil?
    end

    def compression
      @group.point_conversion_form
    end

    def compression=(compression_type = :compressed)
      @group.point_conversion_form = compression_type
    end

    def compressed
      compressed_key = self.class.new raw_key, options # deep clone
      compressed_key.set_point to_i, compressed: true
      compressed_key
    end

    def uncompressed
      uncompressed_key = self.class.new raw_key, options # deep clone
      uncompressed_key.set_point to_i, compressed: false
      uncompressed_key
    end

    def set_point(int = to_i, opts = {})
      opts = options.merge(opts)
      opts[:compressed] = true if opts[:compressed].nil?
      self.compression = opts[:compressed] ? :compressed : :uncompressed
      bn = BN.new int_to_hex(int), 16
      @point = PKey::EC::Point.new group, bn
      raise KeyInvalid, 'point is not on the curve' unless @point.on_curve?
    end

    def parse_raw_key
      result = if raw_key.is_a?(Integer)
        set_point raw_key
      elsif hex_format?
        set_point hex_to_int(raw_key), compressed: false
      elsif compressed_hex_format?
        set_point hex_to_int(raw_key), compressed: true
      else
        raise KeyFormatNotFound
      end
      to_hex
    end

    def hex_format?
      raw_key.length == 130 && !raw_key[/\H/]
    end

    def compressed_hex_format?
      raw_key.length == 66 && !raw_key[/\H/]
    end

    def to_hex
      int_to_hex to_i, 66
    end

    def to_i
      point.to_bn.to_i
    end

    def to_ripemd160
      hash = sha256 to_hex
      ripemd160 hash
    end

    def to_address(network: :bitcoin)
      hash = to_ripemd160
      address = NETWORKS[network][:address_version] + hash
      to_serialized_base58 address
    end
    alias :to_s :to_address

    def to_fingerprint
      hash = to_ripemd160
      hash.slice(0..7)
    end

    def to_bytes
      int_to_bytes to_i
    end
  end