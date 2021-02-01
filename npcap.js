var binding       = require("./build/Release/pcap_binding");


exports.lib_version = binding.lib_version();
exports.default_device = binding.default_device();
exports.findalldevs = function () {
    
    return binding.findalldevs();
};
exports.warningHandler = function warningHandler(x) {
    console.warn('warning: %s - this may not actually work', x);
};
function PcapSession(is_live, device_name, filter, buffer_size, snap_length, outfile, is_monitor, buffer_timeout, promiscuous) {
    this.session = new binding.PcapSession();
    this.link_type = this.session.open_offline("C:\\Work\\doc\\AVB\\1722\\1722.pcap","",10 * 1024 * 1024,65535,"",on_packet_ready,false,5000,exports.warningHandler,true);
    console.log(this.link_type);
    this.buf = Buffer.alloc(65535);
    this.header = Buffer.alloc(16);
    
    this.read_callback = () => {
        var packets_read = this.session.dispatch(this.buf, this.header);
        console.log(packets_read)
        this.read_callback();
    };
    this.read_callback();
    console.log("done")
}

function PacketWithHeader(buf, header, link_type) {
    this.buf = buf;
    this.header = header;
    this.link_type = link_type;
}

var on_packet_ready = function () {
    console.log("11")
    // var full_packet = new PacketWithHeader(this.buf, this.header, this.link_type);
    // this.emit("packet", full_packet);
};

exports.PcapSession = PcapSession;