"""Offline contract for the disposable WebRTC/ARI fixture."""

import unittest

import profile


class ProfileTests(unittest.TestCase):
    def test_only_synthetic_authenticated_browser_and_one_stasis_target(self):
        files = profile.render("B" * 32, "R" * 32)
        pjsip = files["pjsip.conf"]
        self.assertIn("[webrtc-lan]\ntype=endpoint", pjsip)
        self.assertIn("identify_by=ip,username\n", pjsip)
        self.assertIn("ice_support=yes\nrtcp_mux=yes\n", pjsip)
        self.assertIn("match=127.0.0.1/32\n", pjsip)
        self.assertIn("username=180\npassword=" + "B" * 32, pjsip)
        self.assertEqual(files["extensions.conf"].count("Stasis(eventphone-vgw-browser,browser-demo)"), 1)
        self.assertNotIn("eventphone.de", "".join(files.values()).lower())
        self.assertIn("bindaddr=127.0.0.1\n", files["http.conf"])
        self.assertIn("[home-control]\ntype=user", files["ari.conf"])
        self.assertLess(files["modules.conf"].index("res_http_websocket.so"),
                        files["modules.conf"].index("res_pjsip_transport_websocket.so"))
        self.assertLess(files["modules.conf"].index("res_pjsip_header_funcs.so"),
                        files["modules.conf"].index("chan_pjsip.so"))

    def test_injected_or_reused_secrets_refused_without_rendering(self):
        for browser, ari in (("B" * 32 + "\ncontext=outbound", "R" * 32),
                             ("B" * 32, "B" * 32), ("", "R" * 32),
                             ("B" * 32, "R" * 31 + "\r")):
            with self.subTest(browser_len=len(browser)), self.assertRaises(ValueError):
                profile.render(browser, ari)


if __name__ == "__main__":
    unittest.main()
