package embapi

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http/httputil"
	"net/netip"
	"os"
	"strings"

	"github.com/vpngen/keydesk/kdlib"
	"github.com/vpngen/wordsgens/namesgenerator"
	"github.com/vpngen/wordsgens/seedgenerator"
	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

	cmd := fmt.Sprintf("createbrigade -ch %s", dgst)

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

	fullname, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("fullname read: %w", err)
	}

	pkg.fullname = strings.Trim(fullname, "\r\n\t ")

	person, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("person read: %w", err)
	}

	pkg.person = strings.Trim(person, "\r\n\t ")

	desc64, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("desc64 read: %w", err)
	}

	desc, err := base64.StdEncoding.DecodeString(desc64)
	if err != nil {
		return nil, fmt.Errorf("desc64 decoding: %w", err)
	}

	pkg.desc = string(desc)

	url64, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("url64 read: %w", err)
	}

	wiki, err := base64.StdEncoding.DecodeString(url64)
	if err != nil {
		return nil, fmt.Errorf("url64 decoding: %w", err)
	}

	pkg.wiki = string(wiki)

	mnemo, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("mnemo read: %w", err)
	}

	pkg.mnemo = strings.Trim(mnemo, "\r\n\t ")

	keydesk, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("keydesk read: %w", err)
	}

	pkg.keydesk = strings.Trim(keydesk, "\r\n\t ")

	filename, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("filename read: %w", err)
	}

	pkg.filename = strings.Trim(filename, "\r\n\t ")

	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("chunk read: %w", err)
	}

	pkg.wgconf = string(buf)

	return pkg, nil
}

func genGrants() (*grantPkg, error) {
	pkg := &grantPkg{}

	fullname, person, err := namesgenerator.PhysicsAwardeeShort()
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
	pkg.filename = kdlib.SanitizeFilename(numbered)

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

	return pkg, nil
}
