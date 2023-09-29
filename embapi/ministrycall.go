package embapi

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/google/uuid"
	"github.com/vpngen/keydesk/gen/models"
	klib "github.com/vpngen/keydesk/kdlib"
	"github.com/vpngen/keydesk/keydesk"
	"github.com/vpngen/ministry"
	"github.com/vpngen/partner-api/internal/kdlib"
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

	pkg.keydesk = klib.RandomAddrIPv6(netip.MustParsePrefix(fakeKeydeskPrefix)).String()

	numbered := fmt.Sprintf("%03d %s", rand.Int31n(256), fullname)
	pkg.filename = kdlib.SanitizeFilename(numbered) + ".conf"

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

	ipv4 := klib.RandomAddrIPv4(netip.MustParsePrefix(fakeCGNAT))
	ipv6 := klib.RandomAddrIPv6(netip.MustParsePrefix(fakeULA))
	ep := klib.RandomAddrIPv4(netip.MustParsePrefix(fakeEndpointNet))

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

func callMinistryV2(dgst string, conf *ssh.ClientConfig, addr netip.AddrPort) (*ministry.Answer, error) {
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

	return wgconf, nil
}

func genGrantsV2() (*ministry.Answer, error) {
	// opts := &grantPkg{}
	wgconf := &ministry.Answer{}

	fullname, person, err := namesgenerator.PhysicsAwardeeShort()
	if err != nil {
		return nil, fmt.Errorf("physics gen: %w", err)
	}

	wgconf.Name = fullname
	wgconf.Person = person

	wgconf.Mnemo, _, _, err = seedgenerator.Seed(seedgenerator.ENT64, fakeSeedPrefix)
	if err != nil {
		return nil, fmt.Errorf("gen seed6: %w", err)
	}

	wgconf.KeydeskIPv6 = klib.RandomAddrIPv6(netip.MustParsePrefix(fakeKeydeskPrefix))

	numbered := fmt.Sprintf("%03d %s", rand.Int31n(256), fullname)
	tunname := kdlib.SanitizeFilename(numbered)
	filename := tunname + ".conf"

	wgconf.Configs = models.Newuser{
		UserName: &numbered,
		WireguardConfig: &models.NewuserWireguardConfig{
			FileName:   &filename,
			TonnelName: &tunname,
		},
	}

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

	ipv4 := klib.RandomAddrIPv4(netip.MustParsePrefix(fakeCGNAT))
	ipv6 := klib.RandomAddrIPv6(netip.MustParsePrefix(fakeULA))
	ep := klib.RandomAddrIPv4(netip.MustParsePrefix(fakeEndpointNet))

	text := fmt.Sprintf(
		tmpl,
		netip.PrefixFrom(ipv4, 32).String()+","+netip.PrefixFrom(ipv6, 128).String(),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgpriv[:]),
		ipv4.String()+","+ipv6.String(),
		ep.String(),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgpub[:]),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgkey[:]),
	)

	wgconf.Configs.WireguardConfig.FileContent = &text

	secretRand := make([]byte, keydesk.OutlineSecretLen)
	if _, err := crand.Read(secretRand); err != nil {
		return nil, fmt.Errorf("secret rand: %w", err)
	}

	outlineSecret := base58.Encode(secretRand)

	if len(outlineSecret) < keydesk.IPSecPasswordLen {
		return nil, fmt.Errorf("encoded len err")
	}

	outlineSecret = outlineSecret[:keydesk.OutlineSecretLen]

	accessKey := "ss://" + base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(
		fmt.Appendf([]byte{}, "chacha20-ietf-poly1305:%s@%s:%d", outlineSecret, ep, 46789),
	) + "#" + url.QueryEscape(numbered)
	wgconf.Configs.OutlineConfig = &models.NewuserOutlineConfig{
		AccessKey: &accessKey,
	}

	cloakByPassUID := uuid.New()

	cloakConfig, err := keydesk.NewCloackConfig(
		ep.String(),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgpub[:]),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(cloakByPassUID[:]),
		"chrome",
		"openvpn",
		"vk.com",
	)
	if err != nil {
		return nil, fmt.Errorf("marshal cloak config: %w", err)
	}

	certOvcCA, _, err := klib.NewOvCA()
	if err != nil {
		return nil, fmt.Errorf("ov new ca: %w", err)
	}

	certOvcU, keyOvcU, err := klib.NewOvCA()
	if err != nil {
		return nil, fmt.Errorf("ov new user: %w", err)
	}

	keyOvcUPKCS8, err := x509.MarshalPKCS8PrivateKey(keyOvcU)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	openvpnConfig, err := keydesk.NewOpenVPNConfigJson(
		"10.0.0.1",
		ep.String(),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certOvcCA})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certOvcU})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyOvcUPKCS8})),
	)
	if err != nil {
		return nil, fmt.Errorf("marshal openvpn config: %w", err)
	}

	amneziaConfig := keydesk.NewAmneziaConfig(ep.String(), numbered, "1.1.1.1,8.8.8.8")
	amneziaConfig.AddContainer(keydesk.NewAmneziaContainerWithOvc(cloakConfig, openvpnConfig, "{}"))
	amneziaConfig.SetDefaultContainer("amnezia-openvpn-cloak")

	amnzConf, err := amneziaConfig.Marshal()
	if err != nil {
		return nil, fmt.Errorf("amnz marshal: %w", err)
	}

	amneziaConfString := string(amnzConf)
	afilename := tunname + ".vpn"

	wgconf.Configs.AmnzOvcConfig = &models.NewuserAmnzOvcConfig{
		FileContent: &amneziaConfString,
		TonnelName:  &numbered,
		FileName:    &afilename,
	}

	return wgconf, nil
}
