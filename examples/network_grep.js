var pcap = require("../pcap"), 
    pcap_session = pcap.createSession("\\Device\\NPF_{18BA04A9-6792-4E15-8B20-2F15FD6D4A36}", { filter: "tcp" })

console.log("Listening on " + pcap_session.device_name);

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet),
        data = packet.payload.payload.payload.data;
    console.log(packet);
    // console.log(data.toString('hex'));
});
