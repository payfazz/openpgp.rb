require File.join(File.dirname(__FILE__), 'spec_helper')
require 'pry'

describe OpenPGP::Message, " at <http://ar.to/pgp.txt>" do
  before :each do
    @ascii = File.read(File.join(File.dirname(__FILE__), 'data', 'pgp.txt'))
    @ascii.force_encoding(Encoding::ASCII) if @ascii.respond_to?(:force_encoding)
  end

  context "when dearmored" do
    it "should return a binary string of 1,939 bytes" do
      lambda { @binary = OpenPGP.dearmor(@ascii) }.should_not raise_error
      @binary.should_not be_empty
      @binary.should be_a_kind_of(String)
      @binary.should have(1_939).characters
    end

    it "should have the CRC24 checksum of 0x3B1080" do
      lambda { @binary = OpenPGP.dearmor(@ascii, nil, :crc => true) }.should_not raise_error
    end
  end

  context "when parsed" do
    it "should return a sequence of packets" do
      lambda { @message = OpenPGP::Message.parse(OpenPGP.dearmor(@ascii)) }.should_not raise_error
      @message.should be_a_kind_of(OpenPGP::Message)
      @message.packets.should have(9).items
    end

    it "should contain a public key packet" do
      @message = OpenPGP::Message.parse(OpenPGP.dearmor(@ascii))
      @message.map(&:class).should include(OpenPGP::Packet::PublicKey)
    end

    it "should contain a public subkey packet" do
      @message = OpenPGP::Message.parse(OpenPGP.dearmor(@ascii))
      @message.map(&:class).should include(OpenPGP::Packet::PublicSubkey)
    end

    it "should contain three user ID packets" do
      @message = OpenPGP::Message.parse(OpenPGP.dearmor(@ascii))
      @message.map(&:class).should include(OpenPGP::Packet::UserID)
      @message.find_all { |packet| packet.is_a?(OpenPGP::Packet::UserID) }.should have(3).items
    end

    it "loads real message" do
      msg = described_class.parse(OpenPGP.dearmor(File.read(File.join(File.dirname(__FILE__), 'data', 'msg.pgp'))))
    end
  end
end
