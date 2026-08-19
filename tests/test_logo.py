def test_logo_renders():
    html = render_html()
    assert '<img src="https://da2n5gsm5bf5f1tcj6ughzohsarpexyjj.oast.me/v4-logo.png"' in html
