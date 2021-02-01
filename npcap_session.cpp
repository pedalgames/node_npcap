#include "npcap_session.h"
#include "stdio.h"

Napi::Object PcapSession::Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);

  Napi::Function func =
      DefineClass(env,
                  "PcapSession",
                  {
                   InstanceMethod("open_live", &PcapSession::OpenLive),
                   InstanceMethod("open_offline", &PcapSession::OpenOffline),
                   InstanceMethod("dispatch", &PcapSession::Dispatch),
                   //InstanceMethod("start_polling",&PcapSession::StartPolling),
                   //InstanceMethod("close",&PcapSession::Close),
                   //InstanceMethod("stats",&PcapSession::Stats),
                   //InstanceMethod("inject",&PcapSession::Inject),
                   });
    Napi::FunctionReference* constructor = new Napi::FunctionReference();  
    *constructor = Napi::Persistent(func);
    //env.SetInstanceData(constructor);
    //constructor.SuppressDestruct();

    exports.Set("PcapSession", func);
    return exports;
}

PcapSession::PcapSession(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<PcapSession>(info) {
  
    return;
}

void PcapSession::PacketReady(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PcapSession* session = (PcapSession *)s;

    printf("##:%d",(uint32_t)session);

    if (session->pcap_dump_handle != NULL) {
        pcap_dump((u_char *) session->pcap_dump_handle, pkthdr, packet);
    }

    size_t copy_len = pkthdr->caplen;

    if (copy_len > session->buffer_length) {
        copy_len = session->buffer_length;
    }

    memcpy(session->buffer_data, packet, copy_len);
    
    // copy header data to fixed offsets in second buffer from user
    memcpy(session->header_data, &(pkthdr->ts.tv_sec), 4);
    memcpy(session->header_data + 4, &(pkthdr->ts.tv_usec), 4);
    memcpy(session->header_data + 8, &(pkthdr->caplen), 4);
    memcpy(session->header_data + 12, &(pkthdr->len), 4);

    //call js callback
    session->tsFn.BlockingCall();
    
}


Napi::Value PcapSession::Dispatch(const Napi::CallbackInfo& info){
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
        Napi::TypeError::New(env, "Dispatch takes exactly two arguments").ThrowAsJavaScriptException();
        return Napi::Number::New(info.Env(),-1);
    }

    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "First argument must be a buffer").ThrowAsJavaScriptException();
        return Napi::Number::New(info.Env(),-1);
    }

    if (!info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Second argument must be a buffer").ThrowAsJavaScriptException();
        return Napi::Number::New(info.Env(),-1);
    }

    Napi::Buffer<char> buffer_obj=info[0].As<Napi::Buffer<char>>();
    this->buffer_data = buffer_obj.Data();
    this->buffer_length = buffer_obj.Length();
    Napi::Buffer<char> header_obj=info[1].As<Napi::Buffer<char>>();
    this->header_data = header_obj.Data();

    int packet_count;
    do {
        packet_count = pcap_dispatch(this->pcap_handle, 1, PcapSession::PacketReady, (u_char *)this);
        
        if (packet_count == -2) {
            //this->FinalizeClose();
        }
    } while (packet_count > 0);

    return Napi::Number::New(info.Env(),packet_count);
}

Napi::Value PcapSession::Open(bool live, const Napi::CallbackInfo& info)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    Napi::Env env = info.Env();

    if (info.Length() == 10) {
        if (!info[0].IsString()) {
            Napi::TypeError::New(env, "pcap Open: info[0] must be a String").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[1].IsString()) {
            Napi::TypeError::New(env, "pcap Open: info[1] must be a String").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[2].IsNumber()) {
            Napi::TypeError::New(env, "pcap Open: info[2] must be a Number").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[3].IsNumber()) {
            Napi::TypeError::New(env, "pcap Open: info[3] must be a Number").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[4].IsString()) {
            Napi::TypeError::New(env, "pcap Open: info[4] must be a String").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[5].IsFunction()) {
            Napi::TypeError::New(env, "pcap Open: info[5] must be a Function").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[6].IsBoolean()) {
            Napi::TypeError::New(env, "pcap Open: info[6] must be a Boolean").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[7].IsNumber()) {
            Napi::TypeError::New(env, "pcap Open: info[7] must be a Number").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[8].IsFunction()) { // warning function
            Napi::TypeError::New(env, "pcap Open: info[8] must be a Function").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
        if (!info[9].IsBoolean()) {
            Napi::TypeError::New(env, "pcap Open: info[9] must be a Boolean").ThrowAsJavaScriptException();
            return Napi::Number::New(env,-1);
        }
    } else {
        Napi::TypeError::New(env, "pcap Open: expecting 8 arguments").ThrowAsJavaScriptException();
        return Napi::Number::New(env,-1);
    }
    std::string device = info[0].As<Napi::String>().Utf8Value().data();
    std::string filter = info[1].As<Napi::String>().Utf8Value().data();

    int buffer_size =info[2].As<Napi::Number>().Int32Value();
    
    int snap_length = info[3].As<Napi::Number>().Int32Value();
    int buffer_timeout = info[7].As<Napi::Number>().Int32Value();
    std::string pcap_output_filename = info[4].As<Napi::String>().Utf8Value().data();

    this->tsFn=Napi::ThreadSafeFunction::New(env,info[5].As<Napi::Function>(),"callback",0,1);


    this->pcap_dump_handle = NULL;

    if (live) {
        if (pcap_lookupnet(device.c_str(), &this->net, &this->mask, errbuf) == -1) {
            this->net = 0;
            this->mask = 0;
            info[8].As<Napi::Function>().Call(env.Global(),{Napi::String::New(env,errbuf)});
        }

        this->pcap_handle = pcap_create(device.c_str(),errbuf);
        if (this->pcap_handle == NULL) {
            Napi::TypeError::New(env, errbuf).ThrowAsJavaScriptException();
        }

        // 64KB is the max IPv4 packet size
        if (pcap_set_snaplen(this->pcap_handle, snap_length) != 0) {
            Napi::TypeError::New(env, "error setting snaplen").ThrowAsJavaScriptException();
        }

        if (info[9].As<Napi::Boolean>()) {
            if (pcap_set_promisc(this->pcap_handle, 1) != 0) {
                Napi::TypeError::New(env, "error setting promiscuous mode").ThrowAsJavaScriptException();
            }
        }

        // Try to set buffer size.  Sometimes the OS has a lower limit that it will silently enforce.
        if (pcap_set_buffer_size(this->pcap_handle, buffer_size) != 0) {
            Napi::TypeError::New(env, "error setting buffer size").ThrowAsJavaScriptException();
        }

        if (buffer_timeout > 0) {
            // set "timeout" on read, even though we are also setting nonblock below.  On Linux this is required.
            if (pcap_set_timeout(this->pcap_handle, buffer_timeout) != 0) {
                Napi::TypeError::New(env, "error setting read timeout").ThrowAsJavaScriptException();
            }
        }

        // timeout <= 0 is undefined behaviour, we'll set immediate mode instead. (timeout is ignored in immediate mode)
        if (pcap_set_immediate_mode(this->pcap_handle, (buffer_timeout <= 0)) != 0) {
            Napi::TypeError::New(env, "error setting immediate mode").ThrowAsJavaScriptException();
        }

        if (info[6].As<Napi::Boolean>()) {
            if (pcap_set_rfmon(this->pcap_handle, 1) != 0) {
                Napi::TypeError::New(env, pcap_geterr(this->pcap_handle)).ThrowAsJavaScriptException();
            }
        }

        if (pcap_activate(this->pcap_handle) != 0) {
            Napi::TypeError::New(env, pcap_geterr(this->pcap_handle)).ThrowAsJavaScriptException();
        }

        if (pcap_output_filename.length() > 0) {
            this->pcap_dump_handle = pcap_dump_open(this->pcap_handle, (char *) pcap_output_filename.c_str());
            if (this->pcap_dump_handle == NULL) {
                Napi::TypeError::New(env, "error opening dump").ThrowAsJavaScriptException();
            }
        }

        if (pcap_setnonblock(this->pcap_handle, 1, errbuf) == -1) {
            Napi::TypeError::New(env, errbuf).ThrowAsJavaScriptException();
        }
    } else {
        // Device is the path to the savefile
        this->pcap_handle = pcap_open_offline(device.c_str(), errbuf);
        if (this->pcap_handle == NULL) {
            Napi::TypeError::New(env, errbuf).ThrowAsJavaScriptException();
        }
    }

    if (filter.length() > 0) {
      if (pcap_compile(this->pcap_handle, &this->fp, filter.c_str(), 1, this->net) == -1) {
        Napi::TypeError::New(env, pcap_geterr(this->pcap_handle)).ThrowAsJavaScriptException();
      }

      if (pcap_setfilter(this->pcap_handle, &this->fp) == -1) {
        Napi::TypeError::New(env, pcap_geterr(this->pcap_handle)).ThrowAsJavaScriptException();
      }
      pcap_freecode(&this->fp);
    }

    int link_type = pcap_datalink(this->pcap_handle);

    Napi::String ret;
    switch (link_type) {
    case DLT_NULL:
        ret = Napi::String::New(info.Env(),"LINKTYPE_NULL");
        break;
    case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
        ret = Napi::String::New(info.Env(),"LINKTYPE_ETHERNET");
        break;
    case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
        ret = Napi::String::New(info.Env(),"LINKTYPE_IEEE802_11_RADIO");
        break;
    case DLT_RAW: // "raw IP"
        ret = Napi::String::New(info.Env(),"LINKTYPE_RAW");
        break;
    case DLT_LINUX_SLL: // "Linux cooked capture"
        ret = Napi::String::New(info.Env(),"LINKTYPE_LINUX_SLL");
        break;
    default:
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
        ret = Napi::String::New(info.Env(),errbuf);
        break;
    }
    
    return ret;
}

Napi::Value PcapSession::OpenLive(const Napi::CallbackInfo& info){
    return this->Open(true, info);
}

Napi::Value PcapSession::OpenOffline(const Napi::CallbackInfo& info){
    return this->Open(false, info);
}