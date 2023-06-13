require File.join(File.dirname(__FILE__), 'spec_helper')
require 'pry'

describe OpenPGP::Packet, " at <http://ar.to/pgp.txt>" do
  context "Signature Packet" do
    it "loads signature message" do
      
      msg = OpenPGP::Message.parse(OpenPGP.dearmor(File.read(File.join(File.dirname(__FILE__), 'data', 'decompressed.pgp')))) 


      binding.pry
      msg.packets[2]
    end
  end
end

