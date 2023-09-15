package embapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httputil"
	"net/netip"
	"os"
	"strings"

	"github.com/vpngen/ministry"
	"golang.org/x/crypto/ssh"
)

const (
	fakeSeedPrefix    = "етитьколотить"
	fakeKeydeskPrefix = "fc00::beaf:0/112"
	fakeEndpointNet   = "182.31.10.0/24"
	fakeCGNAT         = "100.64.0.0/10"
	fakeULA           = "fd00::/8"
	testPrefix        = "DoNotUse "
)

func callMinistry(dgst string, conf *ssh.ClientConfig, addr netip.AddrPort) (*grantPkg, error) {
	pkg := &grantPkg{}

	cmd := fmt.Sprintf("createbrigade -ch -j %s", dgst)

	fmt.Fprintf(os.Stderr, "%s#%s -> %s\n", conf.User, addr, cmd)

	client, err := ssh.Dial("tcp", addr.String(), conf)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	var b, e bytes.Buffer

	session.Stdout = &b
	session.Stderr = &e

	LogTag := "embapi"
	defer func() {
		switch errstr := e.String(); errstr {
		case "":
			fmt.Fprintf(os.Stderr, "%s: SSH Session StdErr: empty\n", LogTag)
		default:
			fmt.Fprintf(os.Stderr, "%s: SSH Session StdErr:\n", LogTag)
			for _, line := range strings.Split(errstr, "\n") {
				fmt.Fprintf(os.Stderr, "%s: | %s\n", LogTag, line)
			}
		}
	}()

	if err := session.Run(cmd); err != nil {
		return nil, fmt.Errorf("ssh run: %w", err)
	}

	r := bufio.NewReader(httputil.NewChunkedReader(&b))

	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("chunk read: %w", err)
	}

	wgconf := &ministry.Answer{}
	if err := json.Unmarshal(payload, &wgconf); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	if wgconf.Configs.WireguardConfig == nil ||
		wgconf.Configs.WireguardConfig.FileContent == nil ||
		wgconf.Configs.WireguardConfig.FileName == nil ||
		wgconf.Configs.WireguardConfig.TonnelName == nil {
		return nil, fmt.Errorf("wgconf read: %w", err)
	}

	pkg.fullname = wgconf.Name
	pkg.person = wgconf.Person.Name
	pkg.desc = wgconf.Person.Desc
	pkg.wiki = wgconf.Person.URL
	pkg.mnemo = wgconf.Mnemo
	pkg.keydesk = wgconf.KeydeskIPv6.String()
	pkg.filename = *wgconf.Configs.WireguardConfig.FileName
	pkg.wgconf = *wgconf.Configs.WireguardConfig.FileContent

	return pkg, nil
}

func genGrants(dgst string, conf *ssh.ClientConfig, addr netip.AddrPort) (*grantPkg, error) {
	// base64name := base64.StdEncoding.EncodeToString([]byte("Веселый Кеттерле"))
	// base64words := base64.StdEncoding.EncodeToString([]byte("несчастный подводный бывать победа долг дядя"))
	// cmd := fmt.Sprintf("restorebrigadier -ch -j %s %s", base64name, base64words)
	cmd := fmt.Sprintf("createbrigade -ch -j %s", dgst)

	fmt.Fprintf(os.Stderr, "%s#%s -> %s\n", conf.User, addr, cmd)

	client, err := ssh.Dial("tcp", addr.String(), conf)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	var b, e bytes.Buffer

	session.Stdout = &b
	session.Stderr = &e

	LogTag := "embapi"
	defer func() {
		switch errstr := e.String(); errstr {
		case "":
			fmt.Fprintf(os.Stderr, "%s: SSH Session StdErr: empty\n", LogTag)
		default:
			fmt.Fprintf(os.Stderr, "%s: SSH Session StdErr:\n", LogTag)
			for _, line := range strings.Split(errstr, "\n") {
				fmt.Fprintf(os.Stderr, "%s: | %s\n", LogTag, line)
			}
		}
	}()

	if err := session.Run(cmd); err != nil {
		return nil, fmt.Errorf("ssh run: %w", err)
	}

	r := bufio.NewReader(httputil.NewChunkedReader(&b))

	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("chunk read: %w", err)
	}

	wgconf := &ministry.Answer{}
	if err := json.Unmarshal(payload, &wgconf); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	if wgconf.Configs.WireguardConfig == nil ||
		wgconf.Configs.WireguardConfig.FileContent == nil ||
		wgconf.Configs.WireguardConfig.FileName == nil ||
		wgconf.Configs.WireguardConfig.TonnelName == nil {
		return nil, fmt.Errorf("wgconf read: %w", err)
	}

	pkg := &grantPkg{}

	pkg.fullname = wgconf.Name
	pkg.person = wgconf.Person.Name
	pkg.desc = wgconf.Person.Desc
	pkg.wiki = wgconf.Person.URL
	pkg.mnemo = wgconf.Mnemo
	pkg.keydesk = wgconf.KeydeskIPv6.String()
	pkg.filename = *wgconf.Configs.WireguardConfig.FileName
	pkg.wgconf = *wgconf.Configs.WireguardConfig.FileContent

	return pkg, nil

	// ------------------------

	/*fullname, person, err := namesgenerator.PhysicsAwardeeShort()
		if err != nil {
			return nil, fmt.Errorf("physics gen: %w", err)
		}

		pkg.fullname = testPrefix + fullname
		pkg.person = person.Name
		pkg.desc = person.Desc
		pkg.wiki = person.URL

		pkg.mnemo, _, _, err = seedgenerator.Seed(seedgenerator.ENT64, fakeSeedPrefix)
		if err != nil {
			return nil, fmt.Errorf("gen seed6: %w", err)
		}

		pkg.keydesk = kdlib.RandomAddrIPv6(netip.MustParsePrefix(fakeKeydeskPrefix)).String()

		numbered := fmt.Sprintf("%03d %s", rand.Int31n(256), fullname)
		pkg.filename = ilib.SanitizeFilename(numbered) + ".conf"

		wgkey, err := wgtypes.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("gen wg psk: %w", err)
		}

		wgpriv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("gen wg psk: %w", err)
		}

		wgpub := wgpriv.PublicKey()

		tmpl := `[Interface]
	Address = %s
	PrivateKey = %s
	DNS = %s

	[Peer]
	Endpoint = %s:51820
	PublicKey = %s
	PresharedKey = %s
	AllowedIPs = 0.0.0.0/0,::/0
	`

		ipv4 := kdlib.RandomAddrIPv4(netip.MustParsePrefix(fakeCGNAT))
		ipv6 := kdlib.RandomAddrIPv6(netip.MustParsePrefix(fakeULA))
		ep := kdlib.RandomAddrIPv4(netip.MustParsePrefix(fakeEndpointNet))

		pkg.wgconf = fmt.Sprintf(
			tmpl,
			netip.PrefixFrom(ipv4, 32).String()+","+netip.PrefixFrom(ipv6, 128).String(),
			base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgpriv[:]),
			ipv4.String()+","+ipv6.String(),
			ep.String(),
			base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgpub[:]),
			base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgkey[:]),
		)

		return pkg, nil*/
}
