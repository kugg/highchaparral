"""Pure synthetic Asterisk 20 WebRTC→ARI fixture. No disk or network IO.

Derived from the successful isolated V26 research run. This profile is
strictly a local regression fixture, never a device/office configuration.
"""

import re


SECRET = re.compile(r"[A-Za-z0-9_-]{32,64}\Z")
MODULES = (
    "res_pjproject", "res_stasis", "res_sorcery_config", "res_sorcery_memory",
    "res_sorcery_astdb", "res_http_websocket", "res_websocket_client",
    "res_pjsip", "res_pjsip_session", "res_pjsip_pubsub", "res_pjsip_sdp_rtp",
    "res_pjsip_nat", "res_pjsip_endpoint_identifier_ip",
    "res_pjsip_transport_websocket", "res_rtp_asterisk", "res_rtp_multicast",
    "res_crypto", "res_srtp", "res_pjsip_authenticator_digest",
    "res_pjsip_endpoint_identifier_user", "res_pjsip_registrar",
    "res_ari_model", "res_ari", "res_stasis_recording", "res_stasis_answer",
    "res_stasis_playback", "res_stasis_snoop", "res_ari_events",
    "res_ari_channels", "res_ari_bridges", "chan_rtp", "codec_ulaw",
    "codec_alaw", "res_timing_timerfd", "pbx_config", "app_dial",
    "app_echo", "app_stasis", "bridge_simple", "bridge_softmix",
    "res_pjsip_header_funcs", "chan_pjsip",
)


def render(browser_password: str, ari_password: str) -> dict[str, str]:
    if (not isinstance(browser_password, str) or not isinstance(ari_password, str) or
            not SECRET.fullmatch(browser_password) or not SECRET.fullmatch(ari_password) or
            browser_password == ari_password):
        raise ValueError("independent generated synthetic credentials required")
    configs = {
        "asterisk.conf": (
            "[directories]\nastetcdir => /etc/asterisk\n"
            "astmoddir => /usr/local/lib/asterisk/modules\n"
            "astvarlibdir => /var/lib/asterisk\nastdatadir => /var/lib/asterisk\n"
            "astcachedir => /run/asterisk\nastdbdir => /run/asterisk\n"
            "astkeydir => /etc/asterisk/keys\nastlogdir => /var/log/asterisk\n"
            "astspooldir => /var/spool/asterisk\nastrundir => /run/asterisk\n"
            "[options]\nverbose = 0\ndebug = 0\n"),
        "modules.conf": "[modules]\nautoload=no\n" + "".join("load => " + m + ".so\n" for m in MODULES),
        "pjsip.conf": (
            "[transport-wss]\ntype=transport\nprotocol=wss\nbind=0.0.0.0:8089\n"
            "[transport-udp]\ntype=transport\nprotocol=udp\nbind=0.0.0.0:5060\n"
            "[webrtc-lan]\ntype=endpoint\ntransport=transport-wss\ncontext=from-webrtc\n"
            "disallow=all\nallow=ulaw,alaw\nauth=browser-auth\naors=180\n"
            "identify_by=ip,username\nmedia_encryption=dtls\ndtls_auto_generate_cert=no\n"
            "dtls_cert_file=/etc/asterisk/keys/home.crt\n"
            "dtls_private_key=/etc/asterisk/keys/home.key\n"
            "dtls_verify=no\ndtls_setup=actpass\nuse_avpf=yes\nice_support=yes\nrtcp_mux=yes\n"
            "rtp_symmetric=yes\nforce_rport=yes\nrewrite_contact=yes\ndirect_media=no\n"
            "media_address=127.0.0.1\n"
            "[browser-auth]\ntype=auth\nauth_type=userpass\nusername=180\npassword="
            + browser_password + "\n"
            "[180]\ntype=aor\nmax_contacts=1\nremove_existing=yes\n"
            "[webrtc-lan-identify]\ntype=identify\nendpoint=webrtc-lan\nmatch=127.0.0.1/32\n"),
        "http.conf": (
            "[general]\nenabled=yes\nbindaddr=127.0.0.1\nbindport=8088\n"
            "enablestatic=yes\ntlsenable=yes\ntlsbindaddr=0.0.0.0:8089\n"
            "tlscertfile=/etc/asterisk/keys/home.crt\n"
            "tlsprivatekey=/etc/asterisk/keys/home.key\n"),
        "ari.conf": (
            "[general]\nenabled=yes\npretty=no\n[home-control]\ntype=user\n"
            "read_only=no\npassword=" + ari_password + "\n"),
        "extensions.conf": (
            "[from-webrtc]\nexten => e-1234,1,Stasis(eventphone-vgw-browser,browser-demo)\n"
            " same => n,Hangup()\n"),
        "rtp.conf": "[general]\nrtpstart=20000\nrtpend=20100\n",
        "logger.conf": "[general]\n[logfiles]\nconsole => warning,error\n",
    }
    if set(configs) != {"asterisk.conf", "modules.conf", "pjsip.conf", "http.conf",
                        "ari.conf", "extensions.conf", "rtp.conf", "logger.conf"}:
        raise ValueError("synthetic config set changed")
    return configs


if __name__ == "__main__":
    print("DRY RUN: synthetic browser ARI profile; no Docker, SIP or files")
