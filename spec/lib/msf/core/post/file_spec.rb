require 'rspec'

RSpec.describe Msf::Post::File do
  subject do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin
    end
    klass.allocate
  end

  describe '#mkdir' do
    let(:path) { '/tmp/test_dir' }

    subject do
      described_mixin = described_class
      klass = Class.new do
        include described_mixin
        attr_accessor :session
        def cmd_exec(_cmd); ''; end
        def vprint_status(_msg); end
        def register_dir_for_cleanup(_path); end
      end
      obj = klass.allocate
      obj.session = double('session', type: 'shell', platform: 'linux')
      obj
    end

    before(:each) do
      allow(subject).to receive(:register_dir_for_cleanup)
    end

    it 'registers the directory for cleanup by default' do
      subject.mkdir(path)
      expect(subject).to have_received(:register_dir_for_cleanup).with(path)
    end

    it 'does not register the directory for cleanup when cleanup is false' do
      subject.mkdir(path, cleanup: false)
      expect(subject).not_to have_received(:register_dir_for_cleanup)
    end
  end

  describe '#_can_echo?' do
    [
      # printable examples
      { input: '', expected: true },
      { input: 'hello world', expected: true },
      { input: "hello 'world'", expected: true },
      { input: "!@^&*()_+[]{}:|<>?,./;'\\[]1234567890-='", expected: true },

      # non-printable character examples, or breaking characters such as new line or quotes etc
      { input: "a\nb\nc", expected: false },
      { input: "\xff\x00", expected: false },
      { input: "\x00\x01\x02\x03\x04\x1f", expected: false },
      { input: "hello \"world\"", expected: false },
      { input: "🐂", expected: false },
      { input: "%APPDATA%", expected: false },
      { input: "$HOME", expected: false }
    ].each do |test|
      it "should return #{test[:expected]} for #{test[:input].inspect}" do
        expect(subject.send(:_can_echo?, test[:input])).to eql(test[:expected])
      end
    end
  end
end
