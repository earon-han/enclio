# 网络实现说明（本轮设计与验收输入）

网络边界为精确DNS域名和端口，不是HTTP方法/URL/TLS内容策略。`--allow-host HOST`保持TCP443兼容语义；`--allow HOST:PORT`授权该精确公网TCP端点，可通过以下任一协议使用。默认仍无代理出口；UDP/QUIC、SOCKS BIND/UDP ASSOCIATE与TLS解密明确不支持。

## 入口与接口

可信init在本任务netns监听127.0.0.1:18080，将监听FD经私有SCM_RIGHTS控制通道交给宿主proxy，由其直接accept。proxy识别首字节0x05作为SOCKS5，其余按严格HTTP解析。无relay和挂载的Unix代理入口；所有协议共用策略和DNS校验。

C接口在`src/proxy.h`：规则解析接口不变；CLI使用`enclio_proxy_send_listener(control,port,timeout_ms)`交付监听FD和`enclio_proxy_serve_control(control,rules,count,timeout_ms)`接收/直接服务。发送者调用方负责关闭control；接收服务拥有并关闭control。旧`enclio_proxy_serve_rules(path,rules,count)`与host:443包装保留供既有模块调用及受控fixture，CLI不再调用路径型服务。交付协议、错误关闭和确认边界见[listener-fd-handoff.md](listener-fd-handoff.md)。

## HTTP/CONNECT与SOCKS

- HTTP仅支持absolute-form的`http://hostname[:port]/path`，默认80；转origin-form，并依据URI生成Host。显式Host必须与URI端点一致，HTTP/1.1必须有Host，重复Host拒绝。OPTIONS无path/query按RFC9112 3.2.4转换为`*`。
- 一连接一请求，强制上游`Connection: close`。移除hop-by-hop、Connection提名字段和Proxy-Authorization等代理认证字段；Connection不得提名Host/Content-Length/Transfer-Encoding。
- 支持最多64MiB的Content-Length或严格chunked请求体，16KiB固定缓冲流式转发。重复CL/TE、CL+TE、非十进制/溢出CL、非chunked TE、HTTP/1.0 TE、折叠/非法字段、userinfo、fragment、IP文字、chunk extension/trailer均拒绝。Expect/Upgrade不支持并明确拒绝，不宣称完整透明HTTP兼容。
- HTTP上传由受同一过滤器与PDEATHSIG约束的辅助子进程完成；连接worker同时读取并转发origin响应，以处理提前413/4xx/1xx。正常HTTP上传通过CL/chunked/零长度framing结束，不主动发送上游TCP FIN；origin结束后终止并回收上传者，不把额外客户端流水请求转给上游。
- CONNECT要求显式hostname:port，拒绝请求体framing；隧道建立后双向传输任意TCP字节，支持半关闭与背压。不检查TLS/SNI或证书。
- SOCKS5仅NOAUTH、CONNECT、DOMAIN地址类型；DOMAIN单独验证，不能夹带`:port`或IP文字。BIND/UDP命令、IPv4/IPv6地址类型及非允许端点明确返回失败。SOCKS客户端应远端解析域名（如`socks5h`）。

## DNS、时限与进程

逐连接解析DNS，任何一个返回地址非公网即拒绝整个结果；仅对已检查的sockaddr执行connect，不做第二次域名解析。失败无直连回退。DNS及连接阶段alarm20s；每地址connect10s；头部接收10s；隧道idle30s、阶段lifetime300s。头缓冲8192bytes，最多128字段。HTTP请求体64MiB；响应与隧道按固定缓冲流转，不整包缓存。

proxy最多32连接workers；每个HTTP连接可再有一个上传辅助进程，因此proxy最多32个worker加32个uploader。根监督器和namespace初始化器另计；pids配额必须覆盖这些可信辅助进程及目标程序。所有worker/uploader均校验父PID并设置PDEATHSIG，proxy设non-dumpable。

proxy在接收并校验listener后加载独立libseccomp拒绝清单，worker继承：拒绝exec、namespace/挂载切换、跨进程内存、BPF/io_uring/keyring等，以及新写入open、文件创建/修改。保留DNS/NSS需要的只读配置/动态模块读取、UNIX/IP/NETLINK socket；它不能独立限定connect指针里的地址，网络策略仍由解析器和已验证sockaddr保证。动态NSS模块及系统解析配置属于可信依赖；依赖被过滤导致失败则拒绝请求，不降级过滤器。

## 验证

生产构建没有私网绕过开关。独立fixture用测试链接`--wrap=getaddrinfo/connect`提供可控DNS和上游peer，记录被验证的connect地址再映射至本地测试端口。`ENCLIO_PROXY_TESTING`只在测试构建导出parser fuzz入口，并缩短时限/worker数便于重现边界，不进入正式CLI。

本模块自验证包含Linux严格编译、地址/规则/HTTP与SOCKS负例unit，以及ASan/UBSan下25万次确定性parser变异。独立验证Agent另测试混合/私网/失败DNS、实际HTTP GET/HEAD/POST与chunked、提前响应、SOCKS、双向大流量、半关闭、慢头和饱和。具体真实运行证据以最终验证报告为准。

协议主来源：[RFC9112](https://www.rfc-editor.org/rfc/rfc9112.html)、[RFC9110](https://www.rfc-editor.org/rfc/rfc9110.html)、[RFC1928](https://www.rfc-editor.org/rfc/rfc1928.html)。实现为项目自主代码，无复制RFC代码组件。
