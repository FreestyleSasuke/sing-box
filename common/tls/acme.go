//go:build with_acme

package tls

import (
	"context"
	"crypto/tls"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/acmedns"
	"github.com/libdns/alidns"
	"github.com/libdns/cloudflare"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type acmeWrapper struct {
	ctx               context.Context
	cfg               *certmagic.Config
	cache             *certmagic.Cache
	zapLogger         *zap.Logger
	dataDirectory     string
	staticDomain      []string
	domain            []string
	checkIP           bool
	checkIPURL        string
	checkIPInterval   time.Duration
	checkIPVersion    option.ACMEIPCheckVersion
	configuredDefault string
	access            sync.Mutex
}

func (w *acmeWrapper) Start() error {
	if w.dataDirectory != "" {
		err := filemanager.MkdirAll(w.ctx, w.dataDirectory, 0o700)
		if err != nil {
			return E.Cause(err, "create ACME data directory")
		}
	}
	config := w.cfg
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certificate certmagic.Certificate) (*certmagic.Config, error) {
			return config, nil
		},
		Logger: w.zapLogger,
	})
	config = certmagic.New(cache, *config)
	w.cfg = config
	w.cache = cache
	if w.checkIP {
		err := w.refreshWANIPCertificates(true)
		if err != nil {
			return err
		}
		go w.loopWANIPCheck()
		return nil
	}
	return w.cfg.ManageSync(w.ctx, w.domain)
}

func (w *acmeWrapper) loopWANIPCheck() {
	interval := w.checkIPInterval
	if interval <= 0 {
		interval = ACMERenewalWatchInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if w.checkIPInterval <= 0 {
				w.access.Lock()
				managed := append([]string{}, w.domain...)
				w.access.Unlock()
				if !ManagedCertificatesNeedRenewal(w.cache, w.cfg, managed) {
					continue
				}
			}
			err := w.refreshWANIPCertificates(false)
			if err != nil {
				w.zapLogger.Warn("refresh WAN IP certificates: " + err.Error())
			}
		}
	}
}

func (w *acmeWrapper) refreshWANIPCertificates(initial bool) error {
	discovery, err := DiscoverWANIPsDetailed(w.ctx, w.checkIPURL, w.checkIPVersion)
	if err != nil {
		return err
	}
	for i, family := range discovery.FailedFamilies {
		msg := "WAN IP lookup failed for address family " + family + "; keeping any stored certificate for that family"
		if i < len(discovery.FamilyErrors) && discovery.FamilyErrors[i] != nil {
			w.zapLogger.Warn(msg + ": " + discovery.FamilyErrors[i].Error())
		} else {
			w.zapLogger.Warn(msg)
		}
	}
	w.access.Lock()
	previous := append([]string{}, w.domain...)
	stored := MergeACMESubjects(previous, StoredIPSubjects(w.ctx, w.cfg.Storage))
	wanIPs := FillMissingWANIPFamilies(discovery.IPs, stored, w.checkIPVersion)
	next := MergeACMESubjects(w.staticDomain, wanIPs)
	if !initial && SameACMESubjectSet(previous, next) {
		w.access.Unlock()
		return nil
	}
	w.domain = next
	if w.configuredDefault == "" {
		if ipName := FirstIPSubject(next); ipName != "" {
			w.cfg.DefaultServerName = ipName
		}
	}
	w.access.Unlock()
	err = w.cfg.ManageAsync(w.ctx, next)
	if err != nil {
		return err
	}
	stale := StaleACMESubjects(previous, next)
	if len(stale) == 0 {
		return nil
	}
	return CleanupStaleACMECertificates(w.ctx, w.cfg.Storage, w.cache, stale)
}

func (w *acmeWrapper) Close() error {
	if w.cache != nil {
		w.cache.Stop()
	}
	return nil
}

func (w *acmeWrapper) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	w.access.Lock()
	managed := append([]string{}, w.domain...)
	w.access.Unlock()
	if name := ManagedNameForHello(hello, managed); name != "" {
		hello = HelloWithCertificateName(hello, name)
	}
	return w.cfg.GetCertificate(hello)
}

func startACME(ctx context.Context, logger logger.Logger, options option.InboundACMEOptions) (*tls.Config, adapter.SimpleLifecycle, error) {
	checkIPURL, checkIPInterval, err := NormalizeACMECheckIPOptions(options.CheckIP, options.CheckIPURL, options.CheckIPInterval, options.Domain)
	if err != nil {
		return nil, nil, err
	}
	var acmeServer string
	switch options.Provider {
	case "", "letsencrypt":
		acmeServer = certmagic.LetsEncryptProductionCA
	case "zerossl":
		acmeServer = certmagic.ZeroSSLProductionCA
	default:
		if !strings.HasPrefix(options.Provider, "https://") {
			return nil, nil, E.New("unsupported acme provider: " + options.Provider)
		}
		acmeServer = options.Provider
	}
	var (
		storage       certmagic.Storage
		dataDirectory string
	)
	if options.DataDirectory != "" {
		dataDirectory = filemanager.BasePath(ctx, os.ExpandEnv(options.DataDirectory))
		storage = &certmagic.FileStorage{
			Path: dataDirectory,
		}
	} else {
		storage = certmagic.Default.Storage
	}
	zapLogger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(ACMEEncoderConfig()),
		&ACMELogWriter{Logger: logger},
		zap.DebugLevel,
	))
	config := &certmagic.Config{
		DefaultServerName: options.DefaultServerName,
		Storage:           storage,
		Logger:            zapLogger,
	}
	profile := options.Profile
	if profile == "" && acmeServer == certmagic.LetsEncryptProductionCA && (options.CheckIP || slices.ContainsFunc(options.Domain, certmagic.SubjectIsIP)) {
		profile = "shortlived"
	}

	acmeConfig := certmagic.ACMEIssuer{
		CA:                      acmeServer,
		Email:                   options.Email,
		Agreed:                  true,
		Profile:                 profile,
		DisableHTTPChallenge:    options.DisableHTTPChallenge,
		DisableTLSALPNChallenge: options.DisableTLSALPNChallenge,
		AltHTTPPort:             int(options.AlternativeHTTPPort),
		AltTLSALPNPort:          int(options.AlternativeTLSPort),
		Logger:                  zapLogger,
	}
	if dnsOptions := options.DNS01Challenge; dnsOptions != nil && dnsOptions.Provider != "" {
		var solver certmagic.DNS01Solver
		switch dnsOptions.Provider {
		case C.DNSProviderAliDNS:
			solver.DNSProvider = &alidns.Provider{
				CredentialInfo: alidns.CredentialInfo{
					AccessKeyID:     dnsOptions.AliDNSOptions.AccessKeyID,
					AccessKeySecret: dnsOptions.AliDNSOptions.AccessKeySecret,
					RegionID:        dnsOptions.AliDNSOptions.RegionID,
					SecurityToken:   dnsOptions.AliDNSOptions.SecurityToken,
				},
			}
		case C.DNSProviderCloudflare:
			solver.DNSProvider = &cloudflare.Provider{
				APIToken:  dnsOptions.CloudflareOptions.APIToken,
				ZoneToken: dnsOptions.CloudflareOptions.ZoneToken,
			}
		case C.DNSProviderACMEDNS:
			solver.DNSProvider = &acmedns.Provider{
				Username:  dnsOptions.ACMEDNSOptions.Username,
				Password:  dnsOptions.ACMEDNSOptions.Password,
				Subdomain: dnsOptions.ACMEDNSOptions.Subdomain,
				ServerURL: dnsOptions.ACMEDNSOptions.ServerURL,
			}
		default:
			return nil, nil, E.New("unsupported ACME DNS01 provider type: " + dnsOptions.Provider)
		}
		acmeConfig.DNS01Solver = &solver
	}
	if options.ExternalAccount != nil && options.ExternalAccount.KeyID != "" {
		acmeConfig.ExternalAccount = (*acme.EAB)(options.ExternalAccount)
	}
	config.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(config, acmeConfig)}
	wrapper := &acmeWrapper{
		ctx:               ctx,
		cfg:               config,
		zapLogger:         zapLogger,
		dataDirectory:     dataDirectory,
		staticDomain:      append([]string{}, options.Domain...),
		domain:            append([]string{}, options.Domain...),
		checkIP:           options.CheckIP,
		checkIPURL:        checkIPURL,
		checkIPInterval:   checkIPInterval,
		checkIPVersion:    options.CheckIPVersion,
		configuredDefault: options.DefaultServerName,
	}
	var tlsConfig *tls.Config
	if acmeConfig.DisableTLSALPNChallenge || acmeConfig.DNS01Solver != nil {
		tlsConfig = &tls.Config{
			GetCertificate: wrapper.GetCertificate,
		}
	} else {
		tlsConfig = &tls.Config{
			GetCertificate: wrapper.GetCertificate,
			NextProtos:     []string{C.ACMETLS1Protocol},
		}
	}
	return tlsConfig, wrapper, nil
}
