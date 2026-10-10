package carrier

import "testing"

func TestParse(t *testing.T) {
	d, err := Parse("tcp://127.0.0.1:9440#lab")
	if err != nil {
		t.Fatal(err)
	}
	if tcp, ok := d.(*TCP); !ok || tcp.Addr != "127.0.0.1:9440" || d.Name() != "lab" {
		t.Fatalf("tcp parsed as %#v", d)
	}

	d, err = Parse("socks5://u:p@127.0.0.1:10808/127.0.0.1:9440#reality")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := d.(*SOCKS5)
	if !ok || s.Proxy != "127.0.0.1:10808" || s.Target != "127.0.0.1:9440" || s.Auth == nil || s.Auth.Password != "p" || d.Name() != "reality" {
		t.Fatalf("socks5 parsed as %#v", d)
	}
	if FamilyOf(d) != FamilyUnknown {
		t.Fatalf("unlabeled SOCKS5 family = %q", FamilyOf(d))
	}
	d, err = Parse("socks5://127.0.0.1:10808/127.0.0.1:9440?family=udp#hysteria2")
	if err != nil || FamilyOf(d) != FamilyUDP {
		t.Fatalf("explicit UDP family = %q, err = %v", FamilyOf(d), err)
	}
	d, err = Parse("socks5://127.0.0.1:10808/127.0.0.1:9440#hy2")
	if err != nil || FamilyOf(d) != FamilyUDP {
		t.Fatalf("inferred UDP family = %q, err = %v", FamilyOf(d), err)
	}

	d, _ = Parse("tcp://10.0.0.1:1")
	if d.Name() != "tcp://10.0.0.1:1" {
		t.Fatalf("default label %q", d.Name())
	}

	for _, bad := range []string{
		"udp://1.2.3.4:5",
		"tcp://nohost",
		"tcp://1.2.3.4:5/path",
		"socks5://127.0.0.1:10808",
		"socks5://127.0.0.1:10808/missingport",
		"socks5://127.0.0.1:10808/127.0.0.1:9440?family=quic",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
