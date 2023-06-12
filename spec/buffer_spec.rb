require File.join(File.dirname(__FILE__), 'spec_helper')
require "openssl"

describe OpenPGP::Buffer do
  it "#write_mpi" do
    values = ([0] * 100).map{ OpenSSL::BN.new(OpenSSL::Random.random_bytes(100), 2) }
    b = described_class.new
    values.each do |v|
      b.write_mpi v.to_s(2)
    end

    b.rewind
    
    mpis = []
    while !b.eof?
      mpis << OpenSSL::BN.new(b.read_mpi, 2)
    end

    expect(values.length).to eq(mpis.length)
    expect(values).to eq(mpis)
  end

  it "#read_number" do
    bn = OpenSSL::BN.new(OpenSSL::Random.random_bytes(16), 2)
    b = described_class.new(bn.to_s(2))
    expect(b.read_number(16)).to eq(bn.to_i)
  end

  it "#write_number" do
    bn = OpenSSL::BN.new(OpenSSL::Random.random_bytes(16), 2)
    str = described_class.write do |b|
      b.write_number(bn.to_i, 20)
    end

    expect(str.force_encoding("ASCII-8BIT")).to eq("\x00"*4+bn.to_s(2))
  end
end
