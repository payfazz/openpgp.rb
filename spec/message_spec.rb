require 'spec_helper'
require 'pry'

describe OpenPGP::Message, " at <http://ar.to/pgp.txt>" do

  let(:ascii) { File.read(File.join(__dir__, 'data', 'pgp.txt')).tap { |s| s.force_encoding(Encoding::ASCII) if s.respond_to?(:force_encoding) } }
  context "when dearmored" do
    subject { OpenPGP.dearmor(ascii) }

    it "returns a binary string of 1,939 bytes" do
      expect { subject }.not_to raise_error
      expect(subject).not_to be_empty
      expect(subject).to be_a_kind_of(String)
      expect(subject.size).to eq(1_939)
    end

    it "has the CRC24 checksum of 0x3B1080" do
      expect { OpenPGP.dearmor(ascii, nil, crc: true) }.not_to raise_error
    end
  end

  context "when parsed" do
    subject { OpenPGP::Message.parse(OpenPGP.dearmor(ascii)) }

    it "returns a sequence of packets" do
      expect { subject }.not_to raise_error
      expect(subject).to be_a_kind_of(OpenPGP::Message)
      expect(subject.packets.size).to eq(9)
    end

    it "contains a public key packet" do
      expect(subject.map(&:class)).to include(OpenPGP::Packet::PublicKey)
    end

    it "contains a public subkey packet" do
      expect(subject.map(&:class)).to include(OpenPGP::Packet::PublicSubkey)
    end

    it "contains three user ID packets" do
      expect(subject.select { |packet| packet.is_a?(OpenPGP::Packet::UserID) }.size).to eq(3)
    end

    it "loads real message" do
      msg = described_class.parse(OpenPGP.dearmor(File.read(File.join(__dir__, 'data', 'msg.pgp'))))
      # Assertions for 'msg' if needed
    end

    it "loads real message with unknown length" do
      msg = described_class.parse(OpenPGP.dearmor(File.read(File.join(__dir__, 'data', 'unknown_length.pgp'))))
      expect(msg.packets[1]).to be_a(OpenPGP::Packet::LiteralData)
      expect(msg.packets[1].data).to eq(File.read(File.join(__dir__, 'data', 'unknown_length')))

      # Assertions for 'msg' if needed
    end

    it "loads real message with decompressed" do
      msg = described_class.parse(OpenPGP.dearmor(File.read(File.join(__dir__, 'data', 'decompressed.pgp'))))
    end
  end
end

