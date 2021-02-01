var npcap = require("../npcap")

console.log(npcap.lib_version)
console.log(npcap.default_device)
console.log(JSON.stringify(npcap.findalldevs()))
console.log(npcap.PcapSession())
//npcap.PcapSession()