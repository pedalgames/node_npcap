#ifndef NPCAP_SESSION_H
#define NPCAP_SESSION_H
#include <napi.h>
#include <pcap/pcap.h>

class PcapSession : public Napi::ObjectWrap<PcapSession>{
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  PcapSession(const Napi::CallbackInfo& info);

 private:
  static Napi::FunctionReference constructor;

  Napi::Value PcapSession::New(const Napi::CallbackInfo& info);
  Napi::Value PcapSession::Open(bool,const Napi::CallbackInfo& info);
  Napi::Value PcapSession::OpenLive(const Napi::CallbackInfo& info);
  Napi::Value PcapSession::OpenOffline(const Napi::CallbackInfo& info);
  Napi::Value PcapSession::Dispatch(const Napi::CallbackInfo& info);
  //Napi::Value PcapSession::StartPolling(const Napi::CallbackInfo& info);
  //Napi::Value PcapSession::Close(const Napi::CallbackInfo& info);
  ////Napi::Value PcapSession::Stats(const Napi::CallbackInfo& info);
  //Napi::Value PcapSession::Inject(const Napi::CallbackInfo& info);
  static void PcapSession::PacketReady(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet);
  //Napi::Value PcapSession::FinalizeClose(PcapSession *session);


  pcap_t * session;
  Napi::ThreadSafeFunction  tsFn;
  
  struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dump_handle;
    char *buffer_data;
    size_t buffer_length;
    size_t snap_length;
    char *header_data;
};

#endif