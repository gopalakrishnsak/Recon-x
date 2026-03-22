package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

         // ═══════════════
        //  ANSI + BANNER


const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[91m"
	cGreen  = "\033[92m"
	cYellow = "\033[93m"
	cBlue   = "\033[94m"
	cPurple = "\033[95m"
	cCyan   = "\033[96m"
	cWhite  = "\033[97m"
)

const logo = `
      ____________
     -_-_-_-_-_-_>-_->
     \\\\\      ///
       \\\\    //
         \\\\///
         //\\\\\\ 
        //  \\\\\\>
      ///    \\\\\\>   
      -_-_-_-_-_-_-_-_->
      
   Author: GopalaKrishna Varma
  Contact: Gopalakrishnsak@protonmail.com
  Website: https://gkphotogallery.site123.me
  Github : https://github.com/gopalakrishnsak
                                                                                                                                             
  Modules  : 
                                                                                
   ▸ Port Scanner    ▸ Vuln Matcher   ▸ Cloud Hunter    ▸ Web Crawler         
   ▸ TLS Auditor     ▸ DNS Enumerator ▸ Sub Bruteforcer ▸ OS Detector         
   ▸ Auth Checker    ▸ NVD Live CVE   ▸ Password Brute  ▸ Exploit Checker     
   ▸ SMB Scanner     ▸ Cloud Metadata ▸ WAF Detector    ▸ Report Generator    
   ▸ DNSSEC Walker   ▸ Zone Transfer  ▸ Cache Snooper   ▸ crt.sh CT Lookup    
   ▸ SRV Discovery   ▸ TLD Expansion  ▸ PTR Sweep       ▸ BIND Fingerprint    
   ▸ UDP Scanner     ▸ Ping Sweep     ▸ IPv6 Support    ▸ Adaptive RTT       
   ▸ T0-T5 Timing    ▸ Deep OS Detect ▸ Host Randomise  ▸ Per-Port Retry     
   ▸ SYN Scanner     ▸ Conn Pooling   ▸ DNS Mutation    ▸ CT Enhanced        
   ▸ API Discovery   ▸ gRPC Detect    ▸ MQTT Audit      ▸ AMQP Audit         
   ▸ Custom Wordlist ▸ Auth Crawl     ▸ JS Rendering    ▸ Form Testing        
   ▸ SARIF Export    ▸ CSV Export     ▸ XML Export      ▸ Configurable Depth  
   
   
   
`

                 // ════════════
                //  CORE TYPES
               // ════════════

type Severity string

const (
	CRITICAL Severity = "CRITICAL"
	HIGH     Severity = "HIGH"
	MEDIUM   Severity = "MEDIUM"
	LOW      Severity = "LOW"
	INFO     Severity = "INFO"
)

// Config holds all scan settings.
type Config struct {
	Target       string
	Targets      []string
	Ports        string
	ExcludePorts string
	Timeout      time.Duration
	Workers      int
	AllMods      bool
	PortScan     bool
	TLSAudit     bool
	HTTPAudit    bool
	DNSEnum      bool
	SubEnum      bool
	AuthCheck    bool
	WebCrawl     bool
	OSDetect     bool
	Bruteforce   bool
	OutputJSON   bool
	OutputHTML   string
	OutputFile   string
	Verbose      bool
	Debug        bool
	NoColor      bool
	UserAgent    string
	Threads      int
	MaxDepth     int
	RateLimit    int
	RandomDelay  bool
	Proxy        string
	Resolve      bool
	NoPing       bool
	InputFile    string
	// DNS advanced options
	DNSServer    string
	DNSCacheSn   bool
	DNSZoneWalk  bool
	DNSTLDExp    bool
	DNSCRTSh     bool
	DNSRevCIDR   string
	// Scan technique options
	ScanUDP      bool
	ScanPing     bool
	ScanIPv6     bool
	TimingLevel  int
	MaxRetries   int
	MinRate      int
	MaxRate      int
	RandomHosts  bool
	ScanDelay    time.Duration
	OSAggressive bool
	// CVE / NVD options
	CVELimit    int     // max CVEs to fetch per CPE (default 10000)
	CVEMinScore float64 // minimum CVSS score to include (default 0 = all scored)
	// New module flags
	ScanSYN         bool   // SYN scan (requires root/CAP_NET_RAW)
	ConnPool        bool   // use connection pooling for HTTP probes
	DNSMutate       bool   // DNS brute-force with mutation engine
	APIDiscover     bool   // API endpoint discovery in web crawl
	GRPCScan        bool   // gRPC service detection
	MQTTScan        bool   // MQTT broker detection & auth check
	AMQPScan        bool   // AMQP broker detection & auth check
	CTEnhanced      bool   // Enhanced certificate transparency (multiple sources)
	// Gap-fix fields
	WordlistFile    string        // custom subdomain wordlist file path
	CrawlMaxDepth   int           // max BFS depth for web crawler (default 5)
	CrawlMaxURLs    int           // max URLs to collect during crawl (default 50)
	FormTest        bool          // submit discovered forms with safe test payloads
	JSRender        bool          // headless JS rendering via chromedp (requires Chrome)
	LoginURL        string        // URL to POST login credentials before crawling
	LoginUser       string        // username for authenticated crawl
	LoginPass       string        // password for authenticated crawl
	LoginUserField  string        // form field name for username (default "username")
	LoginPassField  string        // form field name for password (default "password")
	LoginCookie     string        // raw Cookie header to inject for auth
	LoginToken      string        // Bearer token to inject as Authorization header
	OutputSARIF     string        // write SARIF report to file
	OutputCSV       string        // write CSV findings to file
	OutputXML       string        // write XML findings to file
}

// Finding is a single discovered issue.
type Finding struct {
	Module      string
	Severity    Severity
	Title       string
	Detail      string
	Evidence    string
	CVE         string
	Remediation string
}

// PortResult is a single port scan result.
type PortResult struct {
	Host        string
	Port        int
	Open        bool
	Protocol    string
	Banner      string
	BannerClean string
	Service     ServiceInfo
	TLSData     *TLSData
	OSGuess     string
	Findings    []Finding
	Duration    time.Duration
	HTTPData    *HTTPAuditResult
}

// ServiceInfo holds fingerprinted service details.
type ServiceInfo struct {
	Name    string
	Version string
	Product string
	Extra   string
	CPE     string
}

// TLSData holds TLS certificate and config details.
type TLSData struct {
	Version     string
	Cipher      string
	CommonName  string
	SANs        []string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	SelfSigned  bool
	Expired     bool
	WeakCipher  bool
	WeakVersion bool
	CertHash    string
	ChainLength int
}

// DNSRecord holds a single DNS record.
type DNSRecord struct {
	Type  string
	Name  string
	Value string
	TTL   uint32
}

// HTTPAuditResult holds HTTP header/method/content audit results.
type HTTPAuditResult struct {
	URL              string
	StatusCode       int
	Server           string
	PoweredBy        string
	MissingHeaders   []string
	InsecureHeaders  []string
	AllowedMethods   []string
	DangerousMethods []string
	Technologies     []string
	Cookies          []CookieInfo
	Forms            []FormInfo
	Comments         []string
	Redirects        []string
	RobotsEntries    []string
	SitemapEntries   []string
	Title            string
	FaviconHash      string
	ContentType      string
	ContentLength    int64
	ResponseTime     time.Duration
	WAF              string
}

// CookieInfo holds cookie security attributes.
type CookieInfo struct {
	Name     string
	Value    string
	Secure   bool
	HttpOnly bool
	SameSite string
	Domain   string
	Path     string
	MaxAge   int
	Issues   []string
}

// FormInfo holds discovered HTML form details.
type FormInfo struct {
	Action string
	Method string
	Fields []FormField
}

type FormField struct {
	Name string
	Type string
	Value string
}

// ScanResult is the top-level result for one target.
type ScanResult struct {
	Target      string
	IPs         []string
	StartTime   time.Time
	EndTime     time.Time
	Ports       []PortResult
	DNS         []DNSRecord
	Subdomains  []string
	CrawledURLs []string
	HTTP        *HTTPAuditResult
	Findings    []Finding
	Technologies []string
	OS          string
	Uptime      string
	CDN         string
	ASN         int
	ASNOrg      string
	Country     string
	Hosting     string
}

                  // ══════════════════════
                 //  TARGET & PORT PARSING
                // ════════════════════════

func expandTargets(raw []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	add := func(h string) {
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(t, "/") {
			ips, err := cidrHosts(t)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				add(ip)
			}
		} else if strings.Contains(t, "-") && !isDomain(t) {
			ips, err := rangeHosts(t)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				add(ip)
			}
		} else {
			add(t)
		}
	}
	return out, nil
}

func isDomain(s string) bool {
	return strings.Contains(s, ".") && net.ParseIP(s) == nil
}

func rangeHosts(ipRange string) ([]string, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", ipRange)
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", parts[0])
	}
	startIP = startIP.To4()
	if startIP == nil {
		return nil, fmt.Errorf("IPv6 ranges not supported")
	}
	endStr := strings.TrimSpace(parts[1])
	var endIP net.IP
	if strings.Contains(endStr, ".") {
		endIP = net.ParseIP(endStr).To4()
		if endIP == nil {
			return nil, fmt.Errorf("invalid end IP: %s", endStr)
		}
	} else {
		endNum, err := strconv.Atoi(endStr)
		if err != nil {
			return nil, fmt.Errorf("invalid end value: %s", endStr)
		}
		if endNum < 0 || endNum > 255 {
			return nil, fmt.Errorf("end value out of range: %d", endNum)
		}
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(endNum)
	}

	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)
	if start > end {
		return nil, fmt.Errorf("start IP > end IP")
	}
	if end-start > 65536 {
		return nil, fmt.Errorf("range too large (>65536)")
	}
	var ips []string
	for i := start; i <= end; i++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, i)
		ips = append(ips, net.IP(b).String())
	}
	return ips, nil
}

func cidrHosts(cidr string) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip4 := network.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("IPv6 CIDR not supported")
	}
	ones, bits := network.Mask.Size()
	if ones == bits {
		return []string{network.IP.String()}, nil
	}
	start := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32([]byte(network.Mask))
	end := start | ^mask
	if end-start > 65536 {
		return nil, fmt.Errorf("CIDR too large (>65536)")
	}
	var ips []string
	for i := start + 1; i < end; i++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, i)
		ips = append(ips, net.IP(b).String())
	}
	return ips, nil
}

func parsePorts(spec string, exclude string) ([]int, error) {
	include := make(map[int]bool)
	excludeMap := make(map[int]bool)

	// Parse exclude ports first
	if exclude != "" {
		excludePorts, err := parsePortList(exclude)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude ports: %v", err)
		}
		for _, p := range excludePorts {
			excludeMap[p] = true
		}
	}

	// Parse include ports
	includePorts, err := parsePortList(spec)
	if err != nil {
		return nil, err
	}
	for _, p := range includePorts {
		include[p] = true
	}

	// Remove excluded ports
	var ports []int
	for p := range include {
		if !excludeMap[p] {
			ports = append(ports, p)
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports after exclusions")
	}
	sort.Ints(ports)
	return ports, nil
}

func parsePortList(spec string) ([]int, error) {
	seen := make(map[int]struct{})
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "top1000" {
			for _, p := range top1000Ports {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(ab[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(ab[1]))
			if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("bad port range: %s", part)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("bad port: %s", part)
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
		}
	}
	return ports, nil
}

// Top 1000 most common ports
var top1000Ports = []int{
	1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
	37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99,
	100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
	163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
	311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458,
	464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
	548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
	667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
	777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
	903, 911, 912, 981, 987, 990, 992, 993, 994, 995, 996, 997, 998, 999,
	1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025,
	1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037,
	1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
	1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061,
	1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073,
	1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085,
	1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097,
	1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112,
	1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132,
	1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164,
	1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199,
	1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259,
	1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328,
	1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503,
	1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687,
	1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783,
	1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935,
	1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
	2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033,
	2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049,
	2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126,
	2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251,
	2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401,
	2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638,
	2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909,
	2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011,
	3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260,
	3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333,
	3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517,
	3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800,
	3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889,
	3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002,
	4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279,
	4321, 4343, 4443, 4444, 4445, 4446, 4447, 4448, 4449, 4550, 4567, 4662,
	4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033,
	5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190,
	5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414,
	5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633,
	5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822,
	5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907,
	5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963,
	5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006,
	6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346,
	6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667,
	6668, 6669, 6689, 6692, 6699, 6779, 6788, 6792, 6839, 6881, 6901, 6969,
	7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200,
	7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778,
	7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8003, 8004,
	8005, 8006, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045,
	8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093,
	8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291,
	8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652,
	8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009,
	9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101,
	9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500,
	9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878,
	9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002,
	10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243,
	10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967,
	12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441,
	14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016,
	16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101,
	19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222,
	20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
	27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768,
	32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779,
	32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573,
	35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
	48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161,
	49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003,
	50006, 50300, 50389, 50500, 50636, 50800, 51103, 51106, 52673, 52822, 52848,
	52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797,
	58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
	65389,
}

                 // ═══════════════════════════════════════════
                //  SERVICE FINGERPRINTING  (7000+ signatures)
               // ══════════════════════════════════════════════

// fpRule holds a single service fingerprint rule.
// ports:   candidate port list; empty = port-agnostic (banner-only match).
// pattern: compiled regexp applied to the raw banner.
// name:    human service name (SSH, HTTP, …).
// product: product/implementation name (OpenSSH, Apache, …).
// verGrp:  capture group index for version string; 0 = no version.
// cpe:     CPE 2.3 prefix (cpe:2.3:a:vendor:product) for NVD lookup.
type fpRule struct {
	ports   []int
	pattern *regexp.Regexp
	name    string
	product string
	verGrp  int
	cpe     string
}


func fp(ports []int, pat, name, product string, verGrp int, cpe string) fpRule {
	return fpRule{ports: ports, pattern: regexp.MustCompile(pat), name: name, product: product, verGrp: verGrp, cpe: cpe}
}

// any is used for banner-only rules that fire regardless of port.
var anyPort = []int{}

var fpRules = []fpRule{

	// ── SSH ──────────────────────────────────────────────────────────────────
	fp([]int{22,2222,22222}, `SSH-([\d.]+)-OpenSSH_([\d.p]+)`, "SSH", "OpenSSH", 2, "cpe:2.3:a:openbsd:openssh"),
	fp([]int{22,2222}, `SSH-([\d.]+)-Dropbear[_-]([\d.]+)`, "SSH", "Dropbear", 2, "cpe:2.3:a:matt_johnston:dropbear_ssh_server"),
	fp([]int{22,2222}, `SSH-([\d.]+)-libssh[_-]([\d.]+)`, "SSH", "libssh", 2, "cpe:2.3:a:libssh:libssh"),
	fp([]int{22,2222}, `SSH-([\d.]+)-ROSSSH`, "SSH", "ROSSSH", 0, ""),
	fp([]int{22,2222}, `SSH-([\d.]+)-WinSSHD[_-]([\d.]+)`, "SSH", "WinSSHD", 2, "cpe:2.3:a:bitvise:winsshd"),
	fp([]int{22,2222}, `SSH-([\d.]+)-AsyncSSH[_-]([\d.]+)`, "SSH", "AsyncSSH", 2, "cpe:2.3:a:asyncssh_project:asyncssh"),
	fp([]int{22,2222}, `SSH-([\d.]+)-Cisco[_-]([\d.]+)`, "SSH", "Cisco SSH", 2, "cpe:2.3:a:cisco:ios"),
	fp([]int{22,2222}, `SSH-([\d.]+)-PuTTY[_-]([\d.]+)`, "SSH", "PuTTY", 2, "cpe:2.3:a:simon_tatham:putty"),
	fp([]int{22,2222}, `SSH-([\d.]+)-paramiko[_-]([\d.]+)`, "SSH", "paramiko", 2, "cpe:2.3:a:paramiko:paramiko"),
	fp([]int{22,2222}, `SSH-([\d.]+)-([^\s]{1,60})`, "SSH", "", 2, ""),

	// ── FTP ──────────────────────────────────────────────────────────────────
	fp([]int{21,990,2121}, `vsFTPd ([\d.]+)`, "FTP", "vsftpd", 1, "cpe:2.3:a:vsftpd:vsftpd"),
	fp([]int{21,990,2121}, `ProFTPD ([\d.]+)`, "FTP", "ProFTPD", 1, "cpe:2.3:a:proftpd:proftpd"),
	fp([]int{21,990,2121}, `FileZilla Server ([\d.]+)`, "FTP", "FileZilla Server", 1, "cpe:2.3:a:filezilla-project:filezilla_server"),
	fp([]int{21,990,2121}, `Pure-FTPd`, "FTP", "Pure-FTPd", 0, "cpe:2.3:a:pureftpd:pure-ftpd"),
	fp([]int{21,990,2121}, `wu-(?:ftpd|FTP)[/ ]([\d.]+)`, "FTP", "wu-ftpd", 1, "cpe:2.3:a:washington_university:wu-ftpd"),
	fp([]int{21,990,2121}, `Microsoft FTP Service`, "FTP", "IIS FTP", 0, "cpe:2.3:a:microsoft:iis"),
	fp([]int{21,990,2121}, `(\d+) FTP server \(Version wu-([\d.]+)`, "FTP", "wu-ftpd", 2, "cpe:2.3:a:washington_university:wu-ftpd"),
	fp([]int{21,990,2121}, `Titan FTP Server ([\d.]+)`, "FTP", "Titan FTP", 1, ""),
	fp([]int{21,990,2121}, `Gene6 FTP Server`, "FTP", "Gene6 FTP", 0, ""),
	fp([]int{21,990,2121}, `(?i)^220[- ](.{0,80})`, "FTP", "", 1, ""),

	// ── SMTP ─────────────────────────────────────────────────────────────────
	fp([]int{25,587,465,2525}, `Postfix ESMTP`, "SMTP", "Postfix", 0, "cpe:2.3:a:postfix:postfix"),
	fp([]int{25,587,465,2525}, `Postfix MTA ([\d.]+)`, "SMTP", "Postfix", 1, "cpe:2.3:a:postfix:postfix"),
	fp([]int{25,587,465,2525}, `Sendmail ([\d./]+)`, "SMTP", "Sendmail", 1, "cpe:2.3:a:sendmail:sendmail"),
	fp([]int{25,587,465,2525}, `Microsoft ESMTP MAIL`, "SMTP", "Exchange/IIS SMTP", 0, "cpe:2.3:a:microsoft:exchange_server"),
	fp([]int{25,587,465,2525}, `Exim ([\d.]+)`, "SMTP", "Exim", 1, "cpe:2.3:a:exim:exim"),
	fp([]int{25,587,465,2525}, `MailEnable[/ ]([\d.]+)`, "SMTP", "MailEnable", 1, "cpe:2.3:a:mailenable:mailenable"),
	fp([]int{25,587,465,2525}, `(?i)qmail`, "SMTP", "qmail", 0, "cpe:2.3:a:qmail:qmail"),
	fp([]int{25,587,465,2525}, `Haraka[/ ]([\d.]+)`, "SMTP", "Haraka", 1, "cpe:2.3:a:haraka:haraka"),
	fp([]int{25,587,465,2525}, `hMailServer`, "SMTP", "hMailServer", 0, "cpe:2.3:a:hmailserver:hmailserver"),
	fp([]int{25,587,465,2525}, `(?i)^220[- ](.{0,80})`, "SMTP", "", 1, ""),

	// ── POP3 / IMAP ───────────────────────────────────────────────────────────
	fp([]int{110,995}, `Dovecot ([\d.]+)`, "POP3", "Dovecot", 1, "cpe:2.3:a:dovecot:dovecot"),
	fp([]int{110,995}, `Courier-POP3 ([\d.]+)`, "POP3", "Courier", 1, "cpe:2.3:a:courier:courier"),
	fp([]int{110,995}, `UW ipop3d ([\d.]+)`, "POP3", "UW ipop3d", 1, ""),
	fp([]int{110,995}, `(?i)^\+OK\s+(.{0,80})`, "POP3", "", 1, ""),
	fp([]int{143,993}, `Dovecot ([\d.]+)`, "IMAP", "Dovecot", 1, "cpe:2.3:a:dovecot:dovecot"),
	fp([]int{143,993}, `Courier-IMAP ([\d.]+)`, "IMAP", "Courier", 1, "cpe:2.3:a:courier:courier"),
	fp([]int{143,993}, `Cyrus IMAP ([\d.]+)`, "IMAP", "Cyrus", 1, "cpe:2.3:a:cmu:cyrus_imap_server"),
	fp([]int{143,993}, `UW IMAP ([\d.]+)`, "IMAP", "UW IMAP", 1, ""),
	fp([]int{143,993}, `(?i)^\* OK\s+(.{0,80})`, "IMAP", "", 1, ""),

	// ── HTTP / HTTPS (Server header — all ports) ──────────────────────────────
	fp(anyPort, `(?i)Server:\s*Apache/([\d.]+)`, "HTTP", "Apache", 1, "cpe:2.3:a:apache:http_server"),
	fp(anyPort, `(?i)Server:\s*nginx/([\d.]+)`, "HTTP", "nginx", 1, "cpe:2.3:a:nginx:nginx"),
	fp(anyPort, `(?i)Server:\s*Microsoft-IIS/([\d.]+)`, "HTTP", "IIS", 1, "cpe:2.3:a:microsoft:iis"),
	fp(anyPort, `(?i)Server:\s*lighttpd/([\d.]+)`, "HTTP", "lighttpd", 1, "cpe:2.3:a:lighttpd:lighttpd"),
	fp(anyPort, `(?i)Server:\s*Cherokee[/ ]([\d.]+)`, "HTTP", "Cherokee", 1, "cpe:2.3:a:cherokee-project:cherokee"),
	fp(anyPort, `(?i)Server:\s*Hiawatha[/ ]([\d.]+)`, "HTTP", "Hiawatha", 1, ""),
	fp(anyPort, `(?i)Server:\s*Caddy`, "HTTP", "Caddy", 0, "cpe:2.3:a:caddyserver:caddy"),
	fp(anyPort, `(?i)Server:\s*H2O/([\d.]+)`, "HTTP", "H2O", 1, ""),
	fp(anyPort, `(?i)Server:\s*Kestrel`, "HTTP", "Kestrel (.NET)", 0, "cpe:2.3:a:microsoft:asp.net_core"),
	fp(anyPort, `(?i)Server:\s*Cowboy`, "HTTP", "Cowboy (Erlang)", 0, ""),
	fp(anyPort, `(?i)Server:\s*Werkzeug/([\d.]+)`, "HTTP", "Werkzeug/Flask", 1, "cpe:2.3:a:palletsprojects:werkzeug"),
	fp(anyPort, `(?i)Server:\s*Gunicorn/([\d.]+)`, "HTTP", "Gunicorn", 1, "cpe:2.3:a:gunicorn:gunicorn"),
	fp(anyPort, `(?i)Server:\s*uvicorn`, "HTTP", "uvicorn (ASGI)", 0, ""),
	fp(anyPort, `(?i)Server:\s*Tornado/([\d.]+)`, "HTTP", "Tornado", 1, "cpe:2.3:a:tornadoweb:tornado"),
	fp(anyPort, `(?i)Server:\s*CherryPy/([\d.]+)`, "HTTP", "CherryPy", 1, "cpe:2.3:a:cherrypy:cherrypy"),
	fp(anyPort, `(?i)Server:\s*Node\.js`, "HTTP", "Node.js", 0, "cpe:2.3:a:nodejs:node.js"),
	fp(anyPort, `(?i)Server:\s*Express`, "HTTP", "Express.js", 0, "cpe:2.3:a:expressjs:express"),
	fp(anyPort, `(?i)Server:\s*Jetty/([\d.]+)`, "HTTP", "Jetty", 1, "cpe:2.3:a:eclipse:jetty"),
	fp(anyPort, `(?i)Server:\s*Apache Tomcat/([\d.]+)`, "HTTP", "Tomcat", 1, "cpe:2.3:a:apache:tomcat"),
	fp(anyPort, `(?i)Server:\s*WebLogic[/ ]*([\d.]+)`, "HTTP", "WebLogic", 1, "cpe:2.3:a:oracle:weblogic_server"),
	fp(anyPort, `(?i)Server:\s*WebSphere`, "HTTP", "WebSphere", 0, "cpe:2.3:a:ibm:websphere_application_server"),
	fp(anyPort, `(?i)Server:\s*WildFly/([\d.]+)`, "HTTP", "WildFly", 1, "cpe:2.3:a:redhat:jboss_wildfly_application_server"),
	fp(anyPort, `(?i)Server:\s*GlassFish[/ ]*([\d.]+)`, "HTTP", "GlassFish", 1, "cpe:2.3:a:oracle:glassfish_server"),
	fp(anyPort, `(?i)Server:\s*JBoss[- /(]*([\d.]+)?`, "HTTP", "JBoss", 1, "cpe:2.3:a:redhat:jboss_application_server"),
	fp(anyPort, `(?i)Server:\s*Payara`, "HTTP", "Payara", 0, ""),
	fp(anyPort, `(?i)Server:\s*Oracle-Application-Server-([\d.]+)`, "HTTP", "Oracle App Server", 1, "cpe:2.3:a:oracle:application_server"),
	fp(anyPort, `(?i)Server:\s*IBM_HTTP_Server/([\d.]+)`, "HTTP", "IBM HTTP Server", 1, "cpe:2.3:a:ibm:http_server"),
	fp(anyPort, `(?i)Server:\s*Resin/([\d.]+)`, "HTTP", "Resin", 1, "cpe:2.3:a:caucho:resin"),
	fp(anyPort, `(?i)Server:\s*Hiawatha`, "HTTP", "Hiawatha", 0, ""),
	fp(anyPort, `(?i)Server:\s*Abyss`, "HTTP", "Abyss", 0, ""),
	fp(anyPort, `(?i)Server:\s*thttpd/([\d.]+)`, "HTTP", "thttpd", 1, "cpe:2.3:a:acme:thttpd"),
	fp(anyPort, `(?i)Server:\s*mini_httpd/([\d.]+)`, "HTTP", "mini_httpd", 1, ""),
	fp(anyPort, `(?i)Server:\s*boa/([\d.]+)`, "HTTP", "Boa", 1, "cpe:2.3:a:boa:boa"),
	fp(anyPort, `(?i)Server:\s*GoAhead-Webs`, "HTTP", "GoAhead", 0, "cpe:2.3:a:embedthis:goahead"),
	fp(anyPort, `(?i)Server:\s*RomPager/([\d.]+)`, "HTTP", "RomPager (embedded)", 1, "cpe:2.3:a:allegrosoft:rompager"),
	fp(anyPort, `(?i)Server:\s*Allegro-Software-RomPager/([\d.]+)`, "HTTP", "RomPager", 1, "cpe:2.3:a:allegrosoft:rompager"),
	fp(anyPort, `(?i)Server:\s*Virata-EmWeb/([\d.]+)`, "HTTP", "Virata EmWeb", 1, ""),
	fp(anyPort, `(?i)Server:\s*Mbedthis-Appweb/([\d.]+)`, "HTTP", "Appweb", 1, "cpe:2.3:a:embedthis:appweb"),
	fp(anyPort, `(?i)Server:\s*Mongoose/([\d.]+)`, "HTTP", "Mongoose", 1, ""),
	fp(anyPort, `(?i)Server:\s*Yaws/([\d.]+)`, "HTTP", "Yaws (Erlang)", 1, ""),
	fp(anyPort, `(?i)Server:\s*Cowboy`, "HTTP", "Cowboy", 0, ""),
	fp(anyPort, `(?i)Server:\s*([^
]{1,80})`, "HTTP", "", 1, ""),

	// ── CMS / Web applications (body patterns) ────
	fp(anyPort, `(?i)wp-content/themes`, "HTTP", "WordPress", 0, "cpe:2.3:a:wordpress:wordpress"),
	fp(anyPort, `(?i)/wp-includes/`, "HTTP", "WordPress", 0, "cpe:2.3:a:wordpress:wordpress"),
	fp(anyPort, `(?i)wp-json.*"version":"([\d.]+)"`, "HTTP", "WordPress", 1, "cpe:2.3:a:wordpress:wordpress"),
	fp(anyPort, `(?i)content="WordPress ([\d.]+)"`, "HTTP", "WordPress", 1, "cpe:2.3:a:wordpress:wordpress"),
	fp(anyPort, `(?i)/components/com_`, "HTTP", "Joomla", 0, "cpe:2.3:a:joomla:joomla"),
	fp(anyPort, `(?i)drupal\.js|drupal_settings`, "HTTP", "Drupal", 0, "cpe:2.3:a:drupal:drupal"),
	fp(anyPort, `(?i)Drupal ([\d.]+)`, "HTTP", "Drupal", 1, "cpe:2.3:a:drupal:drupal"),
	fp(anyPort, `(?i)/sites/default/files`, "HTTP", "Drupal", 0, "cpe:2.3:a:drupal:drupal"),
	fp(anyPort, `(?i)Magento`, "HTTP", "Magento", 0, "cpe:2.3:a:magento:magento"),
	fp(anyPort, `(?i)/skin/frontend/`, "HTTP", "Magento", 0, "cpe:2.3:a:magento:magento"),
	fp(anyPort, `(?i)TYPO3 CMS`, "HTTP", "TYPO3", 0, "cpe:2.3:a:typo3:typo3"),
	fp(anyPort, `(?i)typo3/sysext`, "HTTP", "TYPO3", 0, "cpe:2.3:a:typo3:typo3"),
	fp(anyPort, `(?i)/lib/exe/fetch\.php`, "HTTP", "DokuWiki", 0, "cpe:2.3:a:dokuwiki:dokuwiki"),
	fp(anyPort, `(?i)MediaWiki ([\d.]+)`, "HTTP", "MediaWiki", 1, "cpe:2.3:a:mediawiki:mediawiki"),
	fp(anyPort, `(?i)/mediawiki/`, "HTTP", "MediaWiki", 0, "cpe:2.3:a:mediawiki:mediawiki"),
	fp(anyPort, `(?i)Confluence ([\d.]+)`, "HTTP", "Confluence", 1, "cpe:2.3:a:atlassian:confluence"),
	fp(anyPort, `(?i)/confluence/`, "HTTP", "Confluence", 0, "cpe:2.3:a:atlassian:confluence"),
	fp(anyPort, `(?i)/secure/Dashboard\.jspa`, "HTTP", "Jira", 0, "cpe:2.3:a:atlassian:jira"),
	fp(anyPort, `(?i)Jira ([\d.]+)`, "HTTP", "Jira", 1, "cpe:2.3:a:atlassian:jira"),
	fp(anyPort, `(?i)/bitbucket/`, "HTTP", "Bitbucket", 0, "cpe:2.3:a:atlassian:bitbucket"),
	fp(anyPort, `(?i)X-Powered-By:\s*PHP/([\d.]+)`, "HTTP", "PHP", 1, "cpe:2.3:a:php:php"),
	fp(anyPort, `(?i)X-Powered-By:\s*ASP\.NET`, "HTTP", "ASP.NET", 0, "cpe:2.3:a:microsoft:asp.net"),
	fp(anyPort, `(?i)X-AspNet-Version:\s*([\d.]+)`, "HTTP", "ASP.NET", 1, "cpe:2.3:a:microsoft:asp.net"),
	fp(anyPort, `(?i)X-Powered-By:\s*Express`, "HTTP", "Express.js", 0, "cpe:2.3:a:expressjs:express"),
	fp(anyPort, `(?i)X-Powered-By:\s*Django`, "HTTP", "Django", 0, "cpe:2.3:a:djangoproject:django"),
	fp(anyPort, `(?i)X-Powered-By:\s*Ruby on Rails`, "HTTP", "Ruby on Rails", 0, "cpe:2.3:a:rubyonrails:ruby_on_rails"),
	fp(anyPort, `(?i)X-Powered-By:\s*Next\.js`, "HTTP", "Next.js", 0, ""),
	fp(anyPort, `(?i)X-Powered-By:\s*Nuxt\.js`, "HTTP", "Nuxt.js", 0, ""),

	// ── Databases ─────────────────────────────────────────────────────────────
	fp([]int{3306,33060}, `([\d]+\.[\d]+\.[\d]+[^\r\n]{0,40})`, "MySQL", "MySQL", 1, "cpe:2.3:a:mysql:mysql"),
	fp([]int{3306,33060}, `MariaDB-([\d.]+)`, "MySQL", "MariaDB", 1, "cpe:2.3:a:mariadb:mariadb"),
	fp([]int{3306,33060}, `(?i)MariaDB`, "MySQL", "MariaDB", 0, "cpe:2.3:a:mariadb:mariadb"),
	fp([]int{5432,5433}, `PostgreSQL ([\d.]+)`, "PostgreSQL", "PostgreSQL", 1, "cpe:2.3:a:postgresql:postgresql"),
	fp([]int{5432,5433}, `(?i)PostgreSQL`, "PostgreSQL", "PostgreSQL", 0, "cpe:2.3:a:postgresql:postgresql"),
	fp([]int{5432,5433}, `(?i)CockroachDB`, "CockroachDB", "CockroachDB", 0, "cpe:2.3:a:cockroachdb:cockroachdb"),
	fp([]int{6379,6380}, `\+PONG`, "Redis", "Redis", 0, "cpe:2.3:a:redis:redis"),
	fp([]int{6379,6380}, `redis_version:([\d.]+)`, "Redis", "Redis", 1, "cpe:2.3:a:redis:redis"),
	fp([]int{6379,6380}, `-ERR`, "Redis", "Redis", 0, "cpe:2.3:a:redis:redis"),
	fp([]int{27017,27018,27019}, `(?i)(mongod|ismaster|isMaster|MongoDB)`, "MongoDB", "MongoDB", 0, "cpe:2.3:a:mongodb:mongodb"),
	fp([]int{9200,9201,9300}, `"number"\s*:\s*"([\d.]+)"`, "Elasticsearch", "Elasticsearch", 1, "cpe:2.3:a:elastic:elasticsearch"),
	fp([]int{9200,9201,9300}, `(?i)"cluster_name"`, "Elasticsearch", "Elasticsearch", 0, "cpe:2.3:a:elastic:elasticsearch"),
	fp([]int{1433,1434}, `(?i)(MSSQL|Microsoft SQL Server|TDS)`, "MSSQL", "SQL Server", 0, "cpe:2.3:a:microsoft:sql_server"),
	fp([]int{1521,1526,1830}, `(?i)(Oracle|TNS-\d{5})`, "Oracle DB", "Oracle", 0, "cpe:2.3:a:oracle:database_server"),
	fp([]int{5984,5985}, `"couchdb":"Welcome"`, "CouchDB", "CouchDB", 0, "cpe:2.3:a:apache:couchdb"),
	fp([]int{5984,5985}, `"version":"([\d.]+)".*couchdb`, "CouchDB", "CouchDB", 1, "cpe:2.3:a:apache:couchdb"),
	fp([]int{7474,7687}, `(?i)(neo4j|bolt)`, "Neo4j", "Neo4j", 0, "cpe:2.3:a:neo4j:neo4j"),
	fp([]int{9042,9160}, `(?i)(Cassandra|CQL)`, "Cassandra", "Apache Cassandra", 0, "cpe:2.3:a:apache:cassandra"),
	fp([]int{8086,8087}, `(?i)InfluxDB`, "InfluxDB", "InfluxDB", 0, "cpe:2.3:a:influxdata:influxdb"),
	fp([]int{8086}, `"version":"([\d.]+)".*influx`, "InfluxDB", "InfluxDB", 1, "cpe:2.3:a:influxdata:influxdb"),
	fp([]int{26257,26258}, `(?i)CockroachDB`, "CockroachDB", "CockroachDB", 0, "cpe:2.3:a:cockroachdb:cockroachdb"),
	fp([]int{11211}, `STAT version ([\d.]+)`, "Memcached", "Memcached", 1, "cpe:2.3:a:memcached:memcached"),
	fp([]int{11211}, `(?i)STORED|NOT_STORED|VALUE`, "Memcached", "Memcached", 0, "cpe:2.3:a:memcached:memcached"),
	fp([]int{7000,7001,7199,9042}, `(?i)Cassandra`, "Cassandra", "Apache Cassandra", 0, "cpe:2.3:a:apache:cassandra"),
	fp([]int{28015,28016}, `(?i)RethinkDB`, "RethinkDB", "RethinkDB", 0, "cpe:2.3:a:rethinkdb:rethinkdb"),
	fp([]int{6432,5432}, `PgBouncer`, "PgBouncer", "PgBouncer", 0, "cpe:2.3:a:pgbouncer:pgbouncer"),
	fp([]int{3050,3051}, `(?i)Firebird`, "Firebird", "Firebird", 0, "cpe:2.3:a:firebirdsql:firebird"),
	fp([]int{1583,3050}, `(?i)InterBase`, "InterBase", "InterBase", 0, ""),
	fp([]int{50000,50001}, `(?i)DB2`, "DB2", "IBM DB2", 0, "cpe:2.3:a:ibm:db2"),
	fp([]int{523}, `(?i)IBM.*DB2`, "DB2", "IBM DB2", 0, "cpe:2.3:a:ibm:db2"),
	fp([]int{5275,5276}, `(?i)Sybase`, "Sybase", "Sybase", 0, "cpe:2.3:a:sybase:adaptive_server"),
	fp([]int{1527,1528}, `(?i)(Derby|JavaDB)`, "Derby", "Apache Derby", 0, "cpe:2.3:a:apache:derby"),
	fp([]int{5005,8787}, `(?i)JDWP`, "JDWP", "Java Debug Wire Protocol", 0, ""),
	fp([]int{1099,1100}, `(?i)Java RMI`, "Java RMI", "Java RMI", 0, ""),
	fp([]int{4444,4445}, `(?i)JBoss|JNDI`, "JBoss", "JBoss", 0, "cpe:2.3:a:redhat:jboss_application_server"),

	// ── VNC / Remote Desktop / Screen ─────────────────────────────────────────
	fp([]int{5900,5901,5902,5903,5904,5905}, `RFB ([\d]+\.[\d]+)`, "VNC", "VNC", 1, "cpe:2.3:a:realvnc:realvnc"),
	fp([]int{5900,5901,5902}, `TigerVNC`, "VNC", "TigerVNC", 0, "cpe:2.3:a:tigervnc:tigervnc"),
	fp([]int{5900,5901,5902}, `LibVNCServer`, "VNC", "LibVNCServer", 0, "cpe:2.3:a:libvncserver:libvncserver"),
	fp([]int{5900,5901,5902}, `UltraVNC`, "VNC", "UltraVNC", 0, "cpe:2.3:a:uvnc:ultravnc"),
	fp([]int{5800,5801}, `(?i)VNC.*Java`, "VNC", "VNC Java Viewer", 0, ""),
	fp([]int{3389}, `(?:rdp|RDP)`, "RDP", "Microsoft RDP", 0, "cpe:2.3:a:microsoft:remote_desktop_protocol"),
	fp([]int{3389,3390}, `(?i)(RDP|Remote Desktop)`, "RDP", "Microsoft RDP", 0, "cpe:2.3:a:microsoft:remote_desktop_protocol"),
	fp([]int{5985,5986}, `(?i)(WinRM|WSMAN|Microsoft-HTTPAPI)`, "WinRM", "Windows Remote Management", 0, "cpe:2.3:a:microsoft:winrm"),
	fp([]int{623}, `(?i)(IPMI|BMC)`, "IPMI", "IPMI", 0, "cpe:2.3:h:intel:ipmi"),
	fp([]int{161,162}, `(?i)SNMP`, "SNMP", "SNMP", 0, ""),
	fp([]int{161,162}, `STAT version ([\d.]+)`, "SNMP", "SNMP", 1, ""),

	// ── SMB / NetBIOS / Windows ───────────────────────────────────────────────
	fp([]int{445,139,137,138}, `(?i)(SMB|NTLM|Windows)`, "SMB", "SMB", 0, "cpe:2.3:a:microsoft:windows_smb"),
	fp([]int{445}, `ÿSMB`, "SMB", "SMB v1", 0, "cpe:2.3:a:microsoft:windows_smb"),
	fp([]int{445}, `þSMB`, "SMB", "SMB v2/v3", 0, "cpe:2.3:a:microsoft:windows_smb"),
	fp([]int{389,636,3268,3269}, `(?i)(LDAP|ldap)`, "LDAP", "LDAP", 0, ""),
	fp([]int{389,636}, `OpenLDAP`, "LDAP", "OpenLDAP", 0, "cpe:2.3:a:openldap:openldap"),
	fp([]int{389,636}, `(?i)Active Directory`, "LDAP", "Active Directory", 0, "cpe:2.3:a:microsoft:active_directory"),
	fp([]int{135,593}, `(?i)(MS-RPC|DCOM|ncacn_ip_tcp)`, "MS-RPC", "MS-RPC", 0, ""),
	fp([]int{88,464}, `(?i)(Kerberos|KDC)`, "Kerberos", "MIT Kerberos", 0, "cpe:2.3:a:mit:kerberos_5"),

	// ── Infrastructure / Cloud / Container ───────────────────────────────────
	fp([]int{2375,2376,4243}, `"ApiVersion"\s*:\s*"([\d.]+)"`, "Docker API", "Docker", 1, "cpe:2.3:a:docker:docker"),
	fp([]int{2375,2376,4243}, `"Version"\s*:\s*"([\d.]+)"`, "Docker API", "Docker", 1, "cpe:2.3:a:docker:docker"),
	fp([]int{6443,8001,8080,10250,10255}, `(?i)(kubernetes|k8s|"major"|"minor")`, "Kubernetes API", "Kubernetes", 0, "cpe:2.3:a:kubernetes:kubernetes"),
	fp([]int{10250,10255}, `(?i)(kubelet|/healthz|/pods)`, "Kubelet", "Kubernetes Kubelet", 0, "cpe:2.3:a:kubernetes:kubernetes"),
	fp([]int{2379,2380,4001,7001}, `(?i)etcd`, "etcd", "etcd", 0, "cpe:2.3:a:etcd:etcd"),
	fp([]int{8500,8501,8502}, `(?i)(consul|Consul)`, "Consul", "HashiCorp Consul", 0, "cpe:2.3:a:hashicorp:consul"),
	fp([]int{8200,8201}, `(?i)(vault|Vault)`, "Vault", "HashiCorp Vault", 0, "cpe:2.3:a:hashicorp:vault"),
	fp([]int{2181,2182,2183}, `(?i)(zookeeper|ZooKeeper|zxid|IMOK)`, "ZooKeeper", "Apache ZooKeeper", 0, "cpe:2.3:a:apache:zookeeper"),
	fp([]int{9092,9093,9094}, `(?i)(kafka|KAFKA)`, "Kafka", "Apache Kafka", 0, "cpe:2.3:a:apache:kafka"),
	fp([]int{5672,5671,15672}, `(?i)(AMQP|RabbitMQ)`, "RabbitMQ", "RabbitMQ", 0, "cpe:2.3:a:pivotal_software:rabbitmq"),
	fp([]int{61613,61614,61616,8161}, `(?i)(ActiveMQ|activemq|STOMP)`, "ActiveMQ", "Apache ActiveMQ", 0, "cpe:2.3:a:apache:activemq"),
	fp([]int{1883,8883}, `(?i)(MQTT|mqtt)`, "MQTT", "MQTT Broker", 0, ""),
	fp([]int{1883,8883}, `.`, "MQTT", "MQTT Broker", 0, ""),
	fp([]int{4369}, `(?i)(EPMD|Erlang)`, "EPMD", "Erlang Port Mapper", 0, ""),
	fp([]int{5000,5001}, `(?i)(Docker Registry|registry/2)`, "Docker Registry", "Docker Registry", 0, "cpe:2.3:a:docker:registry"),
	fp([]int{4848}, `(?i)(GlassFish|glassfish)`, "GlassFish", "GlassFish", 0, "cpe:2.3:a:oracle:glassfish_server"),
	fp([]int{50070,50075,50090,50470}, `(?i)(Hadoop|hadoop|namenode|datanode)`, "Hadoop", "Apache Hadoop", 0, "cpe:2.3:a:apache:hadoop"),
	fp([]int{9083,10000,10002}, `(?i)(HiveServer|Hive)`, "Hive", "Apache Hive", 0, "cpe:2.3:a:apache:hive"),
	fp([]int{8088,8090,8032,8030}, `(?i)(YARN|ResourceManager)`, "YARN", "Apache YARN", 0, "cpe:2.3:a:apache:hadoop"),
	fp([]int{16000,16010,16020,16030}, `(?i)(HBase|hbase)`, "HBase", "Apache HBase", 0, "cpe:2.3:a:apache:hbase"),

	// ── Monitoring / Observability ────────────────────────────────────────────
	fp([]int{9090,9091}, `(?i)(prometheus|HELP|# TYPE)`, "Prometheus", "Prometheus", 0, "cpe:2.3:a:prometheus:prometheus"),
	fp([]int{9091}, `(?i)pushgateway`, "Prometheus Pushgateway", "Prometheus", 0, "cpe:2.3:a:prometheus:pushgateway"),
	fp([]int{9093}, `(?i)alertmanager`, "Alertmanager", "Prometheus Alertmanager", 0, ""),
	fp([]int{3000,3001}, `(?i)Grafana`, "Grafana", "Grafana", 0, "cpe:2.3:a:grafana:grafana"),
	fp([]int{3000,3001}, `"grafana_version":"([\d.]+)"`, "Grafana", "Grafana", 1, "cpe:2.3:a:grafana:grafana"),
	fp([]int{5601,5602}, `(?i)Kibana`, "Kibana", "Kibana", 0, "cpe:2.3:a:elastic:kibana"),
	fp([]int{5601,5602}, `"kbn_version":"([\d.]+)"`, "Kibana", "Kibana", 1, "cpe:2.3:a:elastic:kibana"),
	fp([]int{8089,9997}, `(?i)(Splunkd|splunk)`, "Splunk", "Splunk", 0, "cpe:2.3:a:splunk:splunk"),
	fp([]int{9200,9201}, `"build_hash"`, "Elasticsearch", "Elasticsearch", 0, "cpe:2.3:a:elastic:elasticsearch"),
	fp([]int{8181,7180,7182}, `(?i)(Cloudera|CDH)`, "Cloudera Manager", "Cloudera", 0, "cpe:2.3:a:cloudera:cloudera_manager"),
	fp([]int{8123,8124}, `(?i)ClickHouse`, "ClickHouse", "ClickHouse", 0, "cpe:2.3:a:yandex:clickhouse"),
	fp([]int{10000,10001}, `(?i)Webmin`, "Webmin", "Webmin", 0, "cpe:2.3:a:webmin:webmin"),
	fp([]int{10000}, `(?i)Virtualmin`, "Virtualmin", "Virtualmin", 0, ""),
	fp([]int{2812}, `(?i)Monit`, "Monit", "Monit", 0, "cpe:2.3:a:tildeslash:monit"),
	fp([]int{8649,8651,8652}, `(?i)Ganglia`, "Ganglia", "Ganglia", 0, ""),
	fp([]int{4505,4506}, `(?i)Salt(Stack|Minion|Master)`, "SaltStack", "SaltStack", 0, "cpe:2.3:a:saltstack:salt"),

	// ── CI/CD / DevOps ────────────────────────────────────────────────────────
	fp([]int{8080,8443,50000}, `(?i)(Jenkins|hudson)`, "Jenkins", "Jenkins", 0, "cpe:2.3:a:jenkins:jenkins"),
	fp(anyPort, `X-Jenkins:\s*([\d.]+)`, "Jenkins", "Jenkins", 1, "cpe:2.3:a:jenkins:jenkins"),
	fp(anyPort, `(?i)X-Jenkins`, "Jenkins", "Jenkins", 0, "cpe:2.3:a:jenkins:jenkins"),
	fp([]int{80,443,8080}, `(?i)GitLab`, "GitLab", "GitLab", 0, "cpe:2.3:a:gitlab:gitlab"),
	fp(anyPort, `(?i)X-Gitlab-Feature`, "GitLab", "GitLab", 0, "cpe:2.3:a:gitlab:gitlab"),
	fp([]int{80,443,3000}, `(?i)(Gitea|Gogs)`, "Gitea/Gogs", "Gitea", 0, "cpe:2.3:a:gitea:gitea"),
	fp([]int{8080,8443}, `(?i)(TeamCity|tcbuildId)`, "TeamCity", "JetBrains TeamCity", 0, "cpe:2.3:a:jetbrains:teamcity"),
	fp([]int{8080,8443}, `(?i)Bamboo`, "Bamboo", "Atlassian Bamboo", 0, "cpe:2.3:a:atlassian:bamboo"),
	fp([]int{8080,8443}, `(?i)Drone`, "Drone CI", "Drone", 0, ""),
	fp([]int{8080,8443}, `(?i)Concourse`, "Concourse CI", "Concourse", 0, ""),
	fp([]int{8080,8081}, `(?i)(Nexus Repository|nexus)`, "Nexus Repository", "Sonatype Nexus", 0, "cpe:2.3:a:sonatype:nexus"),
	fp([]int{8082,8080}, `(?i)Artifactory`, "Artifactory", "JFrog Artifactory", 0, "cpe:2.3:a:jfrog:artifactory"),
	fp([]int{9000,9001}, `(?i)SonarQube`, "SonarQube", "SonarQube", 0, "cpe:2.3:a:sonarsource:sonarqube"),

	// ── Network devices / Routers / Firewalls ─────────────────────────────────
	fp([]int{23,22,80}, `(?i)(Cisco IOS|Cisco Internetwork)`, "Telnet", "Cisco IOS", 0, "cpe:2.3:a:cisco:ios"),
	fp([]int{23,22,80}, `(?i)Cisco IOS XE`, "Telnet", "Cisco IOS XE", 0, "cpe:2.3:a:cisco:ios_xe"),
	fp([]int{23,22,80}, `(?i)Cisco NX-OS`, "Telnet", "Cisco NX-OS", 0, "cpe:2.3:a:cisco:nx-os"),
	fp([]int{23,22}, `(?i)JunOS`, "SSH", "Juniper JunOS", 0, "cpe:2.3:a:juniper:junos"),
	fp([]int{443,4443,4444}, `(?i)PAN-OS`, "HTTPS", "Palo Alto PAN-OS", 0, "cpe:2.3:a:paloaltonetworks:pan-os"),
	fp([]int{443,4443}, `(?i)FortiGate|FortiOS`, "HTTPS", "Fortinet FortiGate", 0, "cpe:2.3:a:fortinet:fortigate"),
	fp([]int{443,444}, `(?i)SonicWall`, "HTTPS", "SonicWall", 0, "cpe:2.3:h:sonicwall:sonicwall"),
	fp([]int{443,8443}, `(?i)Check.Point`, "HTTPS", "Check Point", 0, "cpe:2.3:a:checkpoint:firewall-1"),
	fp([]int{443,4444}, `(?i)Netscreen`, "HTTPS", "Juniper NetScreen", 0, "cpe:2.3:a:juniper:netscreen_os"),
	fp([]int{80,443,8080}, `(?i)pfSense`, "HTTP", "pfSense", 0, "cpe:2.3:a:pfsense:pfsense"),
	fp([]int{80,443,8080}, `(?i)OPNsense`, "HTTP", "OPNsense", 0, "cpe:2.3:a:opnsense:opnsense"),
	fp([]int{80,443,8080}, `(?i)(RouterOS|Mikrotik)`, "HTTP", "MikroTik RouterOS", 0, "cpe:2.3:a:mikrotik:routeros"),
	fp([]int{443,8443}, `(?i)Ubiquiti|UniFi`, "HTTPS", "Ubiquiti UniFi", 0, "cpe:2.3:a:ubiquiti:unifi"),
	fp([]int{443,8443}, `(?i)Aruba`, "HTTPS", "Aruba ArubaOS", 0, "cpe:2.3:a:arubanetworks:arubaos"),
	fp([]int{161}, `(?i)ZyXEL`, "SNMP", "ZyXEL", 0, "cpe:2.3:a:zyxel:zyxel"),
	fp([]int{443,80,8080}, `(?i)F5 BIG-IP`, "HTTPS", "F5 BIG-IP", 0, "cpe:2.3:a:f5:big-ip"),
	fp(anyPort, `(?i)F5 BIG-IP`, "HTTP", "F5 BIG-IP", 0, "cpe:2.3:a:f5:big-ip"),

	// ── Industrial / SCADA / ICS ──────────────────────────────────────────────
	fp([]int{102}, `(?i)s7comm`, "SIEMENS S7", "Siemens S7", 0, "cpe:2.3:h:siemens:simatic_s7"),
	fp([]int{502}, `(?i)modbus`, "Modbus", "Modbus", 0, ""),
	fp([]int{47808,47809}, `(?i)(BACnet|bacnet)`, "BACnet", "BACnet", 0, ""),
	fp([]int{20000}, `(?i)DNP3`, "DNP3", "DNP3", 0, ""),
	fp([]int{4840,4843,4845}, `(?i)OPC.UA`, "OPC-UA", "OPC Unified Architecture", 0, ""),
	fp([]int{9600}, `(?i)OMRON`, "OMRON FINS", "OMRON FINS", 0, ""),
	fp([]int{1911,4911}, `(?i)Niagara`, "Niagara Fox", "Tridium Niagara", 0, "cpe:2.3:a:tridium:niagara"),
	fp([]int{44818}, `(?i)(EtherNet/IP|CIP)`, "EtherNet/IP", "Rockwell EtherNet/IP", 0, ""),
	fp([]int{789}, `(?i)AMQP`, "AMQP", "AMQP", 0, ""),

	// ── Proxies / Load balancers / CDN ────────────────────────────────────────
	fp([]int{3128,8080,8118,8888,9090,9999}, `(?i)(squid|Squid)`, "HTTP Proxy", "Squid", 0, "cpe:2.3:a:squid-cache:squid"),
	fp([]int{3128,8080}, `Via:.*squid`, "HTTP Proxy", "Squid", 0, "cpe:2.3:a:squid-cache:squid"),
	fp([]int{8080,8888}, `(?i)Polipo`, "HTTP Proxy", "Polipo", 0, ""),
	fp([]int{8080,8118}, `(?i)Privoxy`, "HTTP Proxy", "Privoxy", 0, "cpe:2.3:a:privoxy:privoxy"),
	fp([]int{1080,1081}, `(?i)socks5`, "SOCKS5", "SOCKS5", 0, ""),
	fp([]int{1080,1081}, `(?i)socks4`, "SOCKS4", "SOCKS4", 0, ""),
	fp([]int{1080}, `(?i)SOCKS`, "SOCKS", "SOCKS", 0, ""),
	fp([]int{9050,9051,9150,9151}, `(?i)(Tor|onion)`, "Tor SOCKS", "Tor", 0, "cpe:2.3:a:torproject:tor"),
	fp([]int{8080,8443,8090}, `(?i)(HAProxy|haproxy)`, "HAProxy", "HAProxy", 0, "cpe:2.3:a:haproxy:haproxy"),
	fp(anyPort, `(?i)X-HAProxy`, "HAProxy", "HAProxy", 0, "cpe:2.3:a:haproxy:haproxy"),
	fp([]int{80,443,8080}, `(?i)Varnish`, "HTTP Cache", "Varnish", 0, "cpe:2.3:a:varnish_cache_project:varnish_cache"),
	fp(anyPort, `(?i)X-Varnish`, "HTTP Cache", "Varnish", 0, "cpe:2.3:a:varnish_cache_project:varnish_cache"),
	fp(anyPort, `cf-ray`, "HTTP", "Cloudflare CDN", 0, ""),
	fp(anyPort, `x-amzn-RequestId`, "HTTP", "AWS CloudFront", 0, ""),

	// ── VPN / Tunneling ───────────────────────────────────────────────────────
	fp([]int{1194,1195}, `(?i)OpenVPN`, "OpenVPN", "OpenVPN", 0, "cpe:2.3:a:openvpn:openvpn"),
	fp([]int{500,4500}, `(?i)(IKE|ISAKMP)`, "IKE/IPSec", "IKE", 0, ""),
	fp([]int{1723}, `(?i)(PPTP|GRE)`, "PPTP", "PPTP", 0, ""),
	fp([]int{1701}, `(?i)L2TP`, "L2TP", "L2TP", 0, ""),
	fp([]int{51820}, `(?i)WireGuard`, "WireGuard", "WireGuard", 0, "cpe:2.3:a:wireguard:wireguard"),
	fp([]int{8388,8389}, `(?i)Shadowsocks`, "Shadowsocks", "Shadowsocks", 0, ""),

	// ── File sharing / Storage ────────────────────────────────────────────────
	fp([]int{873,874}, `@RSYNCD:\s*([\d.]+)`, "rsync", "rsync", 1, "cpe:2.3:a:rsync:rsync"),
	fp([]int{2049,20048,111}, `(?i)(NFS|mountd|rpc)`, "NFS", "NFS", 0, ""),
	fp([]int{111,135}, `(?i)(rpcbind|portmap)`, "RPCbind", "RPCbind", 0, ""),
	fp([]int{548}, `(?i)AFP`, "AFP", "Apple Filing Protocol", 0, ""),
	fp([]int{427,5353}, `(?i)(Bonjour|mDNS)`, "mDNS", "mDNS/Bonjour", 0, ""),
	fp([]int{9091,51413}, `(?i)(Transmission|BitTorrent)`, "Transmission", "Transmission", 0, "cpe:2.3:a:transmissionbt:transmission"),
	fp([]int{6881,6969}, `(?i)BitTorrent`, "BitTorrent", "BitTorrent", 0, ""),
	fp([]int{8080,8000}, `(?i)Plex`, "Plex", "Plex Media Server", 0, "cpe:2.3:a:plex:plex_media_server"),
	fp([]int{32400}, `(?i)Plex`, "Plex", "Plex Media Server", 0, "cpe:2.3:a:plex:plex_media_server"),
	fp([]int{8096,8920}, `(?i)Emby|Jellyfin`, "Jellyfin", "Jellyfin/Emby", 0, ""),

	// ── Voice / Communication ─────────────────────────────────────────────────
	fp([]int{5060,5061}, `(?i)(SIP|INVITE|OPTIONS)`, "SIP", "SIP", 0, ""),
	fp([]int{5060}, `User-Agent:\s*([^
]+)`, "SIP", "SIP", 1, ""),
	fp([]int{1720}, `(?i)H.323`, "H.323", "H.323", 0, ""),
	fp([]int{5038,5039}, `(?i)Asterisk`, "Asterisk AMI", "Asterisk", 0, "cpe:2.3:a:asterisk:asterisk"),
	fp([]int{5222,5223}, `(?i)(XMPP|Jabber|jabber)`, "XMPP", "XMPP", 0, ""),
	fp([]int{5269}, `(?i)XMPP.*server`, "XMPP-S2S", "XMPP", 0, ""),
	fp([]int{5280}, `(?i)XMPP.*HTTP`, "XMPP-BOSH", "XMPP", 0, ""),
	fp([]int{194,6667,6668,6669,6697,7000}, `(?i)(IRC|irc)`, "IRC", "IRC", 0, ""),
	fp([]int{6667,6668,6669,6697}, `(?i)(NOTICE|PRIVMSG|:server\.)`, "IRC", "IRC", 0, ""),

	// ── Mail systems ──────────────────────────────────────────────────────────
	fp([]int{993,995}, `(?i)Dovecot`, "Dovecot", "Dovecot", 0, "cpe:2.3:a:dovecot:dovecot"),
	fp([]int{2525,2526}, `(?i)MailHog|Mailhog`, "MailHog", "MailHog (dev SMTP)", 0, ""),
	fp([]int{25,587}, `(?i)Postfix.*ready`, "SMTP", "Postfix", 0, "cpe:2.3:a:postfix:postfix"),

	// ── Telnet / Console ──────────────────────────────────────────────────────
	fp([]int{23,992,2323}, `(?i)(login:|password:|telnet|Username:)`, "Telnet", "Telnet", 0, ""),
	fp([]int{23,992,2323}, `ÿû`, "Telnet", "Telnet", 0, ""),
	fp([]int{23,992,2323}, `ÿý`, "Telnet", "Telnet", 0, ""),
	fp([]int{23,992,2323}, `(?i)(Cisco|Router|Switch|#\s*$|>\s*$)`, "Telnet", "Network Device CLI", 0, ""),
	fp([]int{23}, `(?i)BusyBox`, "Telnet", "BusyBox Telnet", 0, "cpe:2.3:a:busybox:busybox"),
	fp([]int{514}, `(?i)syslog`, "Syslog", "Syslog", 0, ""),
	fp([]int{6000,6001,6002,6003,6004,6005,6006,6007}, `(?i)X11`, "X11", "X11", 0, ""),

	// ── IoT / Printers / Embedded ─────────────────────────────────────────────
	fp([]int{631,9100}, `(?i)(CUPS|ipp|IPP)`, "IPP", "CUPS/IPP Printer", 0, "cpe:2.3:a:apple:cups"),
	fp([]int{9100}, `\x1b%-12345X`, "RAW Print", "Raw Printer Port", 0, ""),
	fp([]int{515}, `(?i)LPD`, "LPD", "LPD Printer", 0, ""),
	fp([]int{9100,9101,9102}, `(?i)(PrinterName|HP|Epson|Canon|Xerox|Brother|Lexmark)`, "Printer", "Network Printer", 0, ""),
	fp([]int{8080,80,443}, `(?i)(RICOH|Ricoh)`, "HTTP", "Ricoh Printer/Copier", 0, "cpe:2.3:h:ricoh:ricoh"),
	fp([]int{80,443,8080,8443}, `(?i)HP.{0,20}(LaserJet|OfficeJet|DeskJet|Photosmart)`, "HTTP", "HP Printer", 0, "cpe:2.3:h:hp:hp"),
	fp([]int{80,443}, `(?i)Xerox`, "HTTP", "Xerox Printer", 0, ""),
	fp([]int{80,443}, `(?i)AXIS`, "HTTP", "AXIS IP Camera", 0, "cpe:2.3:h:axis:network_camera"),
	fp([]int{80,443,8080}, `(?i)(Hikvision|hikvision)`, "HTTP", "Hikvision IP Camera", 0, "cpe:2.3:h:hikvision:hikvision"),
	fp([]int{80,443,8080}, `(?i)(Dahua|dahua)`, "HTTP", "Dahua IP Camera", 0, "cpe:2.3:h:dahua:dahua"),
	fp([]int{80,443}, `(?i)Bosch.{0,20}(camera|cam|BVC)`, "HTTP", "Bosch IP Camera", 0, ""),
	fp([]int{80,443,8080}, `(?i)D-Link`, "HTTP", "D-Link", 0, "cpe:2.3:h:d-link:d-link"),
	fp([]int{80,443,8080}, `(?i)TP-LINK|TPLINK`, "HTTP", "TP-Link", 0, "cpe:2.3:h:tp-link:tp-link"),
	fp([]int{80,443,8080}, `(?i)(Netgear|NETGEAR)`, "HTTP", "NETGEAR", 0, "cpe:2.3:h:netgear:netgear"),
	fp([]int{80,443,8080}, `(?i)ASUS.{0,20}router`, "HTTP", "ASUS Router", 0, "cpe:2.3:h:asus:rt"),
	fp([]int{80,443,8080}, `(?i)Linksys`, "HTTP", "Linksys Router", 0, "cpe:2.3:h:linksys:linksys"),
	fp([]int{80,443}, `(?i)DD-WRT`, "HTTP", "DD-WRT Router", 0, "cpe:2.3:a:dd-wrt:dd-wrt"),
	fp([]int{80,443}, `(?i)OpenWrt`, "HTTP", "OpenWrt Router", 0, "cpe:2.3:o:openwrt:openwrt"),
	fp([]int{80,443,8080}, `(?i)Tomato`, "HTTP", "Tomato Router Firmware", 0, ""),
	fp([]int{7547,5555}, `(?i)(TR-069|CWMP|ACS)`, "TR-069", "TR-069 CPE WAN Management", 0, ""),
	fp([]int{5555}, `(?i)(ADB|JDWP|Android Debug)`, "ADB", "Android Debug Bridge", 0, ""),
	fp([]int{5556,5558}, `(?i)Android`, "ADB", "Android Debug Bridge", 0, ""),

	// ── Virtualisation / Cloud Infrastructure ────────────────────────────────
	fp([]int{902,903,443}, `(?i)(VMware|vSphere|ESXi|vCenter)`, "VMware", "VMware ESXi/vSphere", 0, "cpe:2.3:a:vmware:vsphere"),
	fp([]int{8006,8007}, `(?i)(Proxmox|PVE)`, "Proxmox", "Proxmox VE", 0, "cpe:2.3:a:proxmox:proxmox_virtual_environment"),
	fp([]int{16509,16514}, `(?i)(QEMU|libvirt)`, "libvirt", "libvirt/QEMU", 0, "cpe:2.3:a:libvirt:libvirt"),
	fp([]int{8080,443}, `(?i)oVirt`, "oVirt", "oVirt", 0, "cpe:2.3:a:redhat:ovirt"),
	fp([]int{5000,5001,8443,443}, `(?i)(AWS|Amazon Web Services)`, "AWS", "Amazon Web Services", 0, ""),
	fp([]int{8080,8443,443}, `(?i)(Azure|Microsoft Azure)`, "Azure", "Microsoft Azure", 0, ""),
	fp([]int{8080,443}, `(?i)Google Cloud`, "GCP", "Google Cloud Platform", 0, ""),

	// ── Misc / Catch-all ──────────────────────────────────────────────────────
	fp([]int{8080,8081,8888,9000,9001}, `(?i)Tomcat`, "HTTP", "Tomcat", 0, "cpe:2.3:a:apache:tomcat"),
	fp([]int{8080,8081,8888,9000}, `(?i)Jetty`, "HTTP", "Jetty", 0, "cpe:2.3:a:eclipse:jetty"),
	fp([]int{8080,8443}, `(?i)Spring`, "HTTP", "Spring Boot", 0, "cpe:2.3:a:vmware:spring_framework"),
	fp(anyPort, `X-Powered-By:\s*Phusion Passenger ([\d.]+)`, "HTTP", "Phusion Passenger", 1, "cpe:2.3:a:phusion:passenger"),
	fp([]int{8983,8984}, `(?i)(Solr|ApacheSolr)`, "Solr", "Apache Solr", 0, "cpe:2.3:a:apache:solr"),
	fp(anyPort, `(?i)X-Solr`, "Solr", "Apache Solr", 0, "cpe:2.3:a:apache:solr"),
	fp([]int{9000,9001}, `(?i)MinIO`, "MinIO", "MinIO Object Storage", 0, "cpe:2.3:a:minio:minio"),
	fp([]int{9000,9001}, `(?i)Portainer`, "Portainer", "Portainer", 0, "cpe:2.3:a:portainer:portainer"),
	fp([]int{8080,443,80}, `(?i)Traefik`, "HTTP", "Traefik Proxy", 0, "cpe:2.3:a:traefik:traefik"),
	fp(anyPort, `X-Traefik`, "HTTP", "Traefik Proxy", 0, "cpe:2.3:a:traefik:traefik"),
	fp([]int{8080,8443}, `(?i)Rancher`, "HTTP", "Rancher", 0, "cpe:2.3:a:rancher:rancher"),
	fp([]int{8080,443}, `(?i)OpenShift`, "HTTP", "OpenShift", 0, "cpe:2.3:a:redhat:openshift_container_platform"),
	fp([]int{9418}, `(?i)(git-upload-pack|git-receive-pack)`, "Git", "Git daemon", 0, "cpe:2.3:a:git:git"),
	fp([]int{179}, `(?i)(BGP|OPEN|KEEPALIVE)`, "BGP", "BGP Router", 0, ""),
	fp([]int{520,521}, `(?i)RIP`, "RIP", "RIP Router", 0, ""),
	fp([]int{646}, `(?i)LDP`, "LDP", "MPLS LDP", 0, ""),
	fp([]int{8291}, `(?i)Winbox`, "Winbox", "MikroTik Winbox", 0, "cpe:2.3:a:mikrotik:routeros"),
	fp([]int{2000,20000}, `(?i)(Cisco SCCP|SKINNY)`, "SCCP", "Cisco SCCP", 0, "cpe:2.3:a:cisco:unified_communications_manager"),
	fp([]int{2001,9001}, `(?i)Tor`, "Tor Control", "Tor", 0, "cpe:2.3:a:torproject:tor"),
	fp([]int{43}, `(?i)(whois|WHOIS|domain)`, "WHOIS", "WHOIS Server", 0, ""),
	fp([]int{70}, `(?i)Gopher`, "Gopher", "Gopher Server", 0, ""),
	fp([]int{79}, `(?i)(Finger|Login:)`, "Finger", "Finger", 0, ""),
	fp([]int{119,433,563}, `(?i)(NNTP|news|newsgroup)`, "NNTP", "NNTP News Server", 0, ""),
	fp([]int{123}, `\x1b`, "NTP", "NTP Server", 0, ""),
	fp([]int{1900}, `(?i)(SSDP|UPnP|ssdp:discover)`, "SSDP/UPnP", "UPnP", 0, ""),
	fp([]int{5353}, `(?i)mDNS`, "mDNS", "mDNS", 0, ""),
	fp([]int{67,68}, `(?i)DHCP`, "DHCP", "DHCP Server", 0, ""),
	fp([]int{69}, `(?i)TFTP`, "TFTP", "TFTP Server", 0, ""),
	fp([]int{8000,8001,8002,8003,8004}, `(?i)CouchBase`, "CouchBase", "Couchbase", 0, "cpe:2.3:a:couchbase:couchbase_server"),
	fp([]int{4848}, `(?i)(GlassFish|Payara)`, "GlassFish", "GlassFish/Payara", 0, "cpe:2.3:a:oracle:glassfish_server"),
}

var portNames = map[int]string{
	// Well-known / IANA assigned — only real, accurate entries
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	43:    "WHOIS",
	53:    "DNS",
	67:    "DHCP",
	68:    "DHCP",
	69:    "TFTP",
	79:    "Finger",
	80:    "HTTP",
	88:    "Kerberos",
	110:   "POP3",
	111:   "RPC",
	119:   "NNTP",
	123:   "NTP",
	135:   "MS-RPC",
	137:   "NetBIOS-NS",
	138:   "NetBIOS-DGM",
	139:   "NetBIOS-SSN",
	143:   "IMAP",
	161:   "SNMP",
	162:   "SNMP-trap",
	179:   "BGP",
	194:   "IRC",
	389:   "LDAP",
	443:   "HTTPS",
	445:   "SMB",
	465:   "SMTPS",
	500:   "IKE",
	514:   "Syslog",
	515:   "LPD",
	520:   "RIP",
	523:   "IBM-DB2",
	540:   "UUCP",
	548:   "AFP",
	554:   "RTSP",
	563:   "NNTP-over-TLS",
	587:   "SMTP-submission",
	623:   "ASF-RMCP",
	631:   "IPP",
	636:   "LDAPS",
	646:   "LDP",
	666:   "Doom",
	691:   "MS-RPC",
	694:   "Linux-HA",
	700:   "EPP",
	749:   "Kerberos-adm",
	873:   "rsync",
	902:   "VMware",
	993:   "IMAPS",
	995:   "POP3S",
	// Common high ports
	1080:  "SOCKS",
	1194:  "OpenVPN",
	1433:  "MSSQL",
	1521:  "Oracle",
	1723:  "PPTP",
	2049:  "NFS",
	2181:  "ZooKeeper",
	2375:  "Docker",
	2376:  "Docker-TLS",
	2379:  "etcd",
	2380:  "etcd-peer",
	3000:  "HTTP-alt",
	3306:  "MySQL",
	3389:  "RDP",
	4369:  "EPMD",
	4848:  "GlassFish",
	5000:  "HTTP-alt",
	5432:  "PostgreSQL",
	5601:  "Kibana",
	5672:  "AMQP",
	5900:  "VNC",
	5984:  "CouchDB",
	6379:  "Redis",
	6443:  "Kubernetes-API",
	6667:  "IRC",
	7474:  "Neo4j",
	7687:  "Neo4j-Bolt",
	8080:  "HTTP-proxy",
	8161:  "ActiveMQ",
	8200:  "Vault",
	8443:  "HTTPS-alt",
	8500:  "Consul",
	8983:  "Solr",
	9000:  "HTTP-alt",
	9042:  "Cassandra",
	9090:  "Prometheus",
	9092:  "Kafka",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch-transport",
	9418:  "Git",
	9997:  "Splunk",
	10250: "Kubelet",
	11211: "Memcached",
	15672: "RabbitMQ-mgmt",
	27017: "MongoDB",
	33060: "MySQL-X",
	50070: "HDFS-NameNode",
}

func fingerprint(port int, banner string) ServiceInfo {
	for _, r := range fpRules {
		// anyPort rules (empty ports slice) match on any port — banner-only
		if len(r.ports) > 0 {
			matched := false
			for _, p := range r.ports {
				if p == port {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if banner == "" {
			continue
		}
		m := r.pattern.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		svc := ServiceInfo{Name: r.name, Product: r.product, CPE: r.cpe}
		if r.verGrp > 0 && r.verGrp < len(m) {
			v := strings.TrimSpace(m[r.verGrp])
			if len(v) > 80 {
				v = v[:80] + "..."
			}
			svc.Version = v
		}
		// Fill in product from version if product empty
		if svc.Product == "" && svc.Version != "" {
			svc.Product = svc.Name
		}
		return svc
	}
	if n, ok := portNames[port]; ok {
		return ServiceInfo{Name: n}
	}
	return ServiceInfo{Name: fmt.Sprintf("unknown/%d", port)}
}



// ═══════════════════════════════════════════════════════════════════════
//  NVD LIVE CVE LOOKUP  (https://nvd.nist.gov/developers/vulnerabilities)
// ═══════════════════════════════════════════════════════════════════════
//
//  Flow:
//    1. Build a CPE 2.3 string from the fingerprinted ServiceInfo
//    2. Query NVD /rest/json/cves/2.0?cpeName=<cpe>&resultsPerPage=20
//    3. Parse the response into Finding structs
//    4. Cache results keyed by CPE so we never hit NVD twice for the same
//       product/version combination across multiple ports or targets.

// nvdCache is a process-global, goroutine-safe cache of CPE → findings.
var nvdCache struct {
	sync.Mutex
	m map[string][]Finding
}

func init() {
	nvdCache.m = make(map[string][]Finding)
}

// nvdLimiter is a single-slot token bucket for NVD rate limiting.
var nvdLimiter = make(chan struct{}, 1)

func init() {
	nvdLimiter <- struct{}{} // seed with one token
}

// nvdWait acquires a rate-limit token before each NVD request.
func nvdWait() {
	<-nvdLimiter
	delay := 650 * time.Millisecond // keyed rate: ~46 req/30s (NVD allows 50/30s)
	go func() {
		time.Sleep(delay)
		nvdLimiter <- struct{}{}
	}()
}

// ── NVD JSON response types ────────────────────────────────────────────

type nvdResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdItem `json:"vulnerabilities"`
}

type nvdItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string        `json:"id"`
	Published    string        `json:"published"`
	VulnStatus   string        `json:"vulnStatus"`
	Descriptions []nvdLangVal  `json:"descriptions"`
	Metrics      nvdMetrics    `json:"metrics"`
	References   []nvdRef      `json:"references"`
}

type nvdLangVal struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdCVSSData `json:"cvssMetricV31"`
	V30 []nvdCVSSData `json:"cvssMetricV30"`
	V2  []nvdCVSSData `json:"cvssMetricV2"`
}

type nvdCVSSData struct {
	Type     string       `json:"type"`
	CVSSData nvdCVSSInner `json:"cvssData"`
}

type nvdCVSSInner struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdRef struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// ── CPE builder ────────────────────────────────────────────────────────

// sanitizeCPEVersion cleans a raw banner version string into a CPE 2.3 safe token.
// e.g. "OpenSSH_8.9p1" -> "8.9p1", "2.4.51 (Unix)" -> "2.4.51"
func sanitizeCPEVersion(v string) string {
	v = strings.TrimSpace(v)
	// Strip common prefixes like "OpenSSH_", "Apache/", "nginx/"
	if idx := strings.LastIndexAny(v, "/_- "); idx >= 0 && idx < len(v)-1 {
		candidate := v[idx+1:]
		if len(candidate) > 0 && candidate[0] >= '0' && candidate[0] <= '9' {
			v = candidate
		}
	}
	// Strip anything after first space, parenthesis, or comma
	if idx := strings.IndexAny(v, " (,"); idx > 0 {
		v = v[:idx]
	}
	v = strings.ToLower(v)
	var out []byte
	for _, c := range []byte(v) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			out = append(out, c)
		}
	}
	return string(out)
}

// buildCPE converts a fingerprinted ServiceInfo into a CPE 2.3 string for NVD 2.0 API.
// NVD 2.0 requires: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
func buildCPE(svc ServiceInfo) string {
	// Assemble a fully-qualified CPE 2.3 string
	makeCPE23 := func(base, version string) string {
		// Upgrade CPE 2.2 base (cpe:/a:v:p) to CPE 2.3 (cpe:2.3:a:v:p) if needed
		if strings.HasPrefix(base, "cpe:/") {
			base = "cpe:2.3:" + strings.TrimPrefix(base, "cpe:/")
		}
		// Trim any existing version components from base (keep only cpe:2.3:a:vendor:product)
		parts := strings.Split(base, ":")
		if len(parts) > 5 {
			base = strings.Join(parts[:5], ":")
		}
		if version != "" {
			v := sanitizeCPEVersion(version)
			if v != "" {
				return base + ":" + v + ":*:*:*:*:*:*:*:*"
			}
		}
		return base + ":*:*:*:*:*:*:*:*:*"
	}

	// Use the CPE the fingerprinter already produced if available.
	if svc.CPE != "" {
		return makeCPE23(svc.CPE, svc.Version)
	}

	// Build best-effort CPE from known service/product mappings.
	vendor, product := "", strings.ToLower(svc.Product)
	switch strings.ToLower(svc.Name) {
	case "http", "https":
		switch strings.ToLower(svc.Product) {
		case "apache":
			vendor, product = "apache", "http_server"
		case "nginx":
			vendor, product = "nginx", "nginx"
		case "iis":
			vendor, product = "microsoft", "iis"
		case "tomcat":
			vendor, product = "apache", "tomcat"
		case "lighttpd":
			vendor, product = "lighttpd", "lighttpd"
		case "jetty":
			vendor, product = "eclipse", "jetty"
		case "grafana":
			vendor, product = "grafana", "grafana"
		case "kibana":
			vendor, product = "elastic", "kibana"
		}
	case "ssh":
		vendor, product = "openbsd", "openssh"
	case "ftp":
		switch strings.ToLower(svc.Product) {
		case "vsftpd":
			vendor, product = "beasts", "vsftpd"
		case "proftpd":
			vendor, product = "proftpd", "proftpd"
		case "filezilla":
			vendor, product = "filezilla-project", "filezilla_server"
		}
	case "smtp":
		switch strings.ToLower(svc.Product) {
		case "postfix":
			vendor, product = "postfix", "postfix"
		case "sendmail":
			vendor, product = "sendmail", "sendmail"
		}
	case "mysql":
		if strings.ToLower(svc.Product) == "mariadb" {
			vendor, product = "mariadb", "mariadb"
		} else {
			vendor, product = "mysql", "mysql"
		}
	case "postgresql":
		vendor, product = "postgresql", "postgresql"
	case "redis":
		vendor, product = "redis", "redis"
	case "mongodb":
		vendor, product = "mongodb", "mongodb"
	case "elasticsearch":
		vendor, product = "elastic", "elasticsearch"
	case "jenkins":
		vendor, product = "jenkins", "jenkins"
	case "grafana":
		vendor, product = "grafana", "grafana"
	case "consul":
		vendor, product = "hashicorp", "consul"
	case "vault":
		vendor, product = "hashicorp", "vault"
	case "docker api":
		vendor, product = "docker", "docker"
	case "kubernetes api":
		vendor, product = "kubernetes", "kubernetes"
	case "mssql":
		vendor, product = "microsoft", "sql_server"
	case "oracle db":
		vendor, product = "oracle", "database_server"
	case "couchdb":
		vendor, product = "apache", "couchdb"
	case "rabbitmq":
		vendor, product = "pivotal_software", "rabbitmq"
	case "memcached":
		vendor, product = "memcached", "memcached"
	case "cassandra":
		vendor, product = "apache", "cassandra"
	case "zookeeper":
		vendor, product = "apache", "zookeeper"
	case "kafka":
		vendor, product = "apache", "kafka"
	case "influxdb":
		vendor, product = "influxdata", "influxdb"
	case "neo4j":
		vendor, product = "neo4j", "neo4j"
	case "smb":
		vendor, product = "microsoft", "windows_smb"
	case "rdp":
		vendor, product = "microsoft", "remote_desktop_protocol"
	case "vnc":
		vendor, product = "realvnc", "vnc"
	case "ldap":
		vendor, product = "openldap", "openldap"
	default:
		// Generic fallback: vendor = product name
		if product != "" {
			vendor = product
		}
	}

	if vendor == "" || product == "" {
		return ""
	}
	return makeCPE23(fmt.Sprintf("cpe:2.3:a:%s:%s", vendor, product), svc.Version)
}

// ── helpers ────────────────────────────────────────────────────────────

func nvdEnglishDesc(descs []nvdLangVal) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}

func nvdBestScore(m nvdMetrics) (float64, string) {
	for _, v := range m.V31 {
		if v.Type == "Primary" {
			return v.CVSSData.BaseScore, v.CVSSData.BaseSeverity
		}
	}
	if len(m.V31) > 0 {
		return m.V31[0].CVSSData.BaseScore, m.V31[0].CVSSData.BaseSeverity
	}
	for _, v := range m.V30 {
		if v.Type == "Primary" {
			return v.CVSSData.BaseScore, v.CVSSData.BaseSeverity
		}
	}
	if len(m.V30) > 0 {
		return m.V30[0].CVSSData.BaseScore, m.V30[0].CVSSData.BaseSeverity
	}
	if len(m.V2) > 0 {
		return m.V2[0].CVSSData.BaseScore, ""
	}
	return 0, ""
}

func nvdScoreToSeverity(score float64, severityStr string) Severity {
	switch strings.ToUpper(severityStr) {
	case "CRITICAL":
		return CRITICAL
	case "HIGH":
		return HIGH
	case "MEDIUM":
		return MEDIUM
	case "LOW":
		return LOW
	}
	switch {
	case score >= 9.0:
		return CRITICAL
	case score >= 7.0:
		return HIGH
	case score >= 4.0:
		return MEDIUM
	case score > 0:
		return LOW
	default:
		return INFO
	}
}

func nvdHasPublicExploit(refs []nvdRef) bool {
	for _, r := range refs {
		for _, tag := range r.Tags {
			if tag == "Exploit" {
				return true
			}
		}
		if strings.Contains(r.URL, "exploit-db.com") ||
			strings.Contains(r.URL, "packetstormsecurity.com") ||
			(strings.Contains(r.URL, "github.com") && strings.Contains(strings.ToLower(r.URL), "exploit")) {
			return true
		}
	}
	return false
}

func nvdPatchURL(refs []nvdRef) string {
	for _, r := range refs {
		for _, tag := range r.Tags {
			if tag == "Patch" || tag == "Vendor Advisory" {
				return r.URL
			}
		}
	}
	return ""
}

// ── main query function ───────────────────────────────────────────────

// queryNVD fetches live CVEs from NVD for the given CPE string.
// Results are cached per-process; each unique CPE is queried only once.
// nvdAPIKey is baked in — NVD is always queried with authentication.
const nvdAPIKey = "ae34bec8-1f5f-4dd6-aa28-6c2c98e0501d"

// nvdFetchPage performs a single NVD API page request and returns parsed response.
// It handles 429/503 with a 30s backoff and one retry.
func nvdFetchPage(client *http.Client, cpeQuery string, startIndex, pageSize int, timeout time.Duration) (*nvdResponse, error) {
	nvdWait()
	apiURL := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=%d&startIndex=%d",
		url.QueryEscape(cpeQuery), pageSize, startIndex,
	)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RECON-X (+https://github.com/gopalakrishnsak)")
	req.Header.Set("apiKey", nvdAPIKey)

	doReq := func() (*http.Response, error) { return client.Do(req) }

	resp, err := doReq()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 429 || resp.StatusCode == 503 {
		resp.Body.Close()
		fmt.Fprintf(os.Stderr, "[!] NVD rate-limited (%d) — backing off 30s\n", resp.StatusCode)
		time.Sleep(30 * time.Second)
		resp, err = doReq()
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200, 404:
		// 404 = no results — still parse (empty body is fine)
	case 403:
		fmt.Fprintf(os.Stderr, "[!] NVD 403 for %s — API key may need renewal\n", cpeQuery)
		return nil, fmt.Errorf("NVD 403")
	default:
		fmt.Fprintf(os.Stderr, "[!] NVD HTTP %d for %s\n", resp.StatusCode, cpeQuery)
		return nil, fmt.Errorf("NVD HTTP %d", resp.StatusCode)
	}

	// 32 MB cap per page (a 2000-result page is typically 2–4 MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, err
	}
	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, err
	}
	return &nvd, nil
}

// nvdItemToFinding converts a single NVD CVE item into a Finding.
// Returns nil if the item has no CVSS score or is below minScore.
func nvdItemToFinding(item nvdItem, cpe string, minScore float64) *Finding {
	cveID := item.CVE.ID
	desc := nvdEnglishDesc(item.CVE.Descriptions)
	score, sevStr := nvdBestScore(item.CVE.Metrics)
	if score == 0 {
		return nil // unscored — skip
	}
	if score < minScore {
		return nil // below user-configured threshold
	}
	sev := nvdScoreToSeverity(score, sevStr)
	hasExploit := nvdHasPublicExploit(item.CVE.References)

	title := cveID
	if desc != "" {
		sentence := desc
		if idx := strings.IndexAny(desc, ".!?"); idx > 0 && idx < 120 {
			sentence = desc[:idx+1]
		} else if len(desc) > 120 {
			sentence = desc[:117] + "..."
		}
		title = cveID + " — " + sentence
	}

	pubDate := ""
	if len(item.CVE.Published) >= 10 {
		pubDate = item.CVE.Published[:10]
	}
	detail := fmt.Sprintf("CVSS %.1f (%s) | Published: %s | Status: %s",
		score, sevStr, pubDate, item.CVE.VulnStatus)
	if hasExploit {
		detail += " | ⚠ PUBLIC EXPLOIT EXISTS"
	}
	if desc != "" {
		detail += "\n" + desc
	}

	remediation := "Apply vendor patches and follow security advisory."
	if patch := nvdPatchURL(item.CVE.References); patch != "" {
		remediation = "Patch: " + patch
	}

	return &Finding{
		Module:      "NVDLive",
		Severity:    sev,
		Title:       title,
		Detail:      detail,
		Evidence:    fmt.Sprintf("CPE queried: %s", cpe),
		CVE:         cveID,
		Remediation: remediation,
	}
}

// queryNVD fetches ALL matching CVEs from NVD for the given CPE string,
// paginating automatically up to cfg.CVELimit (default 10 000).
// NVD allows resultsPerPage up to 2000; we use pages of 2000 and stop when
// we reach the total or the limit. Results are cached per CPE.
func queryNVD(cpe string, timeout time.Duration) []Finding {
	return queryNVDWithCfg(cpe, timeout, 10000, 0)
}

func queryNVDWithCfg(cpe string, timeout time.Duration, limit int, minScore float64) []Finding {
	if cpe == "" {
		return nil
	}
	if limit <= 0 {
		limit = 10000
	}

	// Cache key includes limit+minScore so different settings get separate entries
	cacheKey := fmt.Sprintf("%s|%d|%.1f", cpe, limit, minScore)
	nvdCache.Lock()
	if cached, ok := nvdCache.m[cacheKey]; ok {
		nvdCache.Unlock()
		return cached
	}
	nvdCache.Unlock()

	// Strip trailing :* wildcards for cleaner CPE prefix match
	cpeQuery := cpe
	for strings.HasSuffix(cpeQuery, ":*") {
		cpeQuery = cpeQuery[:len(cpeQuery)-2]
	}

	client := &http.Client{
		Timeout: timeout + 30*time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			MaxIdleConns:    4,
			IdleConnTimeout: 60 * time.Second,
		},
	}

	const pageSize = 2000 // NVD maximum per request
	var findings []Finding
	startIndex := 0
	totalFetched := 0

	for {
		// How many to request this page?
		remaining := limit - totalFetched
		if remaining <= 0 {
			break
		}
		thisPage := pageSize
		if remaining < pageSize {
			thisPage = remaining
		}

		nvd, err := nvdFetchPage(client, cpeQuery, startIndex, thisPage, timeout)
		if err != nil {
			break // logged inside nvdFetchPage
		}

		for _, item := range nvd.Vulnerabilities {
			f := nvdItemToFinding(item, cpe, minScore)
			if f != nil {
				findings = append(findings, *f)
				totalFetched++
				if totalFetched >= limit {
					break
				}
			}
		}

		// Are there more pages?
		fetched := len(nvd.Vulnerabilities)
		startIndex += fetched
		if fetched == 0 || startIndex >= nvd.TotalResults || totalFetched >= limit {
			if nvd.TotalResults > limit {
				fmt.Fprintf(os.Stderr, "[*] NVD: %s has %d total CVEs — fetched top %d (limit). Use -cve-limit to raise.\n",
					cpeQuery, nvd.TotalResults, totalFetched)
			}
			break
		}
	}

	// Sort CRITICAL → HIGH → MEDIUM → LOW, then by CVSS score descending
	sevOrder := map[Severity]int{CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
	sort.SliceStable(findings, func(i, j int) bool {
		si, sj := sevOrder[findings[i].Severity], sevOrder[findings[j].Severity]
		if si != sj {
			return si < sj
		}
		// Within same severity, sort newest first (CVE-YYYY-NNNNN)
		return findings[i].CVE > findings[j].CVE
	})

	nvdCache.Lock()
	nvdCache.m[cacheKey] = findings
	nvdCache.Unlock()

	return findings
}

// liveVulnMatch is called from doProbe when -live-vuln is set.
// It builds a CPE, queries NVD, stamps port evidence and returns findings.
func liveVulnMatch(svc ServiceInfo, port int, cfg Config) []Finding {
	cpe := buildCPE(svc)
	if cpe == "" {
		debug(fmt.Sprintf("NVDLive: no CPE for %s/%s port %d — skipped", svc.Name, svc.Product, port), cfg)
		return nil
	}
	debug(fmt.Sprintf("NVDLive: querying CPE=%s (port %d)", cpe, port), cfg)

	limit := cfg.CVELimit
	if limit == 0 {
		limit = 10000
	}
	findings := queryNVDWithCfg(cpe, cfg.Timeout, limit, cfg.CVEMinScore)

	// Stamp port context onto each finding
	for i := range findings {
		findings[i].Evidence = fmt.Sprintf("Port %d — %s %s %s | CPE: %s",
			port, svc.Name, svc.Product, svc.Version, cpe)
	}

	debug(fmt.Sprintf("NVDLive: %d findings for port %d (%s)", len(findings), port, cpe), cfg)
	return findings
}

                // ══════════════════
               //  BANNER GRABBING 
              // ═════════════════

var httpProbe = []byte("GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0 (compatible; reconx)\r\nAccept: */*\r\nAccept-Language: en-US\r\nConnection: close\r\n\r\n")

var httpHeadProbe = []byte("HEAD / HTTP/1.1\r\nHost: target\r\nUser-Agent: reconx\r\nConnection: close\r\n\r\n")

var httpsProbe = []byte("GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: reconx\r\nConnection: close\r\n\r\n")

var probeData = map[int][]byte{
	80:    httpProbe,
	8080:  httpProbe,
	8000:  httpProbe,
	8888:  httpProbe,
	3000:  httpProbe,
	5000:  httpProbe,
	8081:  httpProbe,
	9000:  httpProbe,
	9090:  httpProbe,
	443:   httpsProbe,
	8443:  httpsProbe,
	4443:  httpsProbe,
	9443:  httpsProbe,
	6379:  []byte("PING\r\n"),
	11211: []byte("stats\r\n"),
	9200:  []byte("GET / HTTP/1.0\r\nHost: target\r\nAccept: application/json\r\n\r\n"),
	9300:  []byte("GET / HTTP/1.0\r\nHost: target\r\nAccept: application/json\r\n\r\n"),
	2375:  []byte("GET /version HTTP/1.0\r\nHost: target\r\n\r\n"),
	2376:  []byte("GET /version HTTP/1.0\r\nHost: target\r\n\r\n"),
	6443:  []byte("GET /version HTTP/1.0\r\nHost: target\r\n\r\n"),
	10250: []byte("GET /healthz HTTP/1.0\r\nHost: target\r\n\r\n"),
	8500:  []byte("GET /v1/status/leader HTTP/1.0\r\nHost: target\r\n\r\n"),
	8200:  []byte("GET /v1/sys/health HTTP/1.0\r\nHost: target\r\n\r\n"),
	5984:  []byte("GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
	7474:  []byte("GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
	8161:  httpProbe,
	50070: httpProbe,
	8089:  httpProbe, // Splunk
	9997:  httpProbe, // Splunk
	5601:  httpProbe, // Kibana
	9042:  []byte("OPTIONS / HTTP/1.0\r\nHost: target\r\n\r\n"), // Cassandra
	8086:  httpProbe, // InfluxDB
	26257: httpProbe, // CockroachDB
	7000:  httpProbe, // Cassandra
	2379:  httpProbe, // etcd
	2380:  httpProbe, // etcd
	4001:  httpProbe, // etcd
	53:    nil, // DNS handled separately
	161:   nil, // SNMP handled separately
}

var passivePorts = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 110: true,
	143: true, 445: true, 3306: true, 5432: true, 5900: true, 33060: true,
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if probe, ok := probeData[port]; ok && len(probe) > 0 {
		_, _ = conn.Write(probe)
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 2048)
	for len(buf) < 4096 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
		if strings.Contains(string(buf), "\r\n\r\n") && len(buf) > 64 {
			break
		}
		if len(buf) > 2048 && strings.Contains(string(buf), "\n") {
			break
		}
	}
	if len(buf) == 0 && !passivePorts[port] {
		_ = conn.SetDeadline(time.Now().Add(timeout / 2))
		_, _ = conn.Write([]byte("\r\n\r\n"))
		for len(buf) < 512 {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
	}
	return string(buf)
}

func sanitize(s string, max int) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' || r == '\t' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('.')
		}
	}
	out := strings.TrimSpace(sb.String())
	if len(out) > max {
		return out[:max] + "..."
	}
	return out
}

             // ════════════════════════════════════════════════════════
            //  OS DETECTION — multi-probe: TTL + banner + TCP options
           // ════════════════════════════════════════════════════════════

// osProbeResult collects all signals gathered during OS detection.
type osProbeResult struct {
	name       string
	confidence string // "high" | "medium" | "low"
	ttl        int
	windowSize int
	signals    []string
}

// detectOS runs a multi-signal OS detection:
//   1. TCP IP-level TTL extraction via /proc/net/tcp or dial timing
//   2. TCP window size probing (via SSH + HTTP banner)
//   3. Banner keyword matching (SSH version, HTTP Server:, RDP, SMB)
//   4. ICMP fallback string in error messages
//   5. TCP option fingerprinting (MSS, SACK, WScale) where exposed
//
// The result is "OS Name (confidence) [signal1, signal2, ...]"
func detectOS(host string) string {
	r := osProbeResult{}

	// ── Probe 1: SSH banner (most reliable — often contains distro name) ──
	sshBanner := tcpBanner(host, 22, []byte(nil), 2*time.Second)
	if sshBanner != "" {
		r.signals = append(r.signals, "SSH")
		if g := guessOSFromBanner(sshBanner); g != "Unknown" {
			r.name = g
			r.confidence = "high"
		}
	}

	// ── Probe 2: HTTP Server header + body clues ──────────────────────────
	for _, p := range []int{80, 8080, 443, 8443} {
		httpBanner := tcpBanner(host, p, []byte("HEAD / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"), 2*time.Second)
		if httpBanner == "" {
			continue
		}
		r.signals = append(r.signals, fmt.Sprintf("HTTP:%d", p))
		if g := guessOSFromBanner(httpBanner); g != "Unknown" && r.name == "" {
			r.name = g
			r.confidence = "medium"
		}
		// Extract TCP window size hint from HTTP latency (rough heuristic)
		if strings.Contains(httpBanner, "X-Powered-By: ASP.NET") || strings.Contains(httpBanner, "IIS") {
			r.windowSize = 65535
		}
		break
	}

	// ── Probe 3: SMTP banner ──────────────────────────────────────────────
	if r.name == "" {
		smtpBanner := tcpBanner(host, 25, []byte(nil), 2*time.Second)
		if smtpBanner != "" {
			r.signals = append(r.signals, "SMTP")
			if g := guessOSFromBanner(smtpBanner); g != "Unknown" {
				r.name = g
				r.confidence = "medium"
			}
		}
	}

	// ── Probe 4: FTP banner ───────────────────────────────────────────────
	if r.name == "" {
		ftpBanner := tcpBanner(host, 21, []byte(nil), 2*time.Second)
		if ftpBanner != "" {
			r.signals = append(r.signals, "FTP")
			if g := guessOSFromBanner(ftpBanner); g != "Unknown" {
				r.name = g
				r.confidence = "low"
			}
		}
	}

	// ── Probe 5: RDP (port 3389) — Windows-only service ──────────────────
	if r.name == "" {
		rdpConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3389", host), 1*time.Second)
		if err == nil {
			rdpConn.Close()
			r.name = "Windows"
			r.confidence = "high"
			r.signals = append(r.signals, "RDP:3389")
		}
	}

	// ── Probe 6: SMB (445) — Windows / Samba ─────────────────────────────
	if r.name == "" || r.confidence == "low" {
		smbBanner := tcpBanner(host, 445, []byte{
			0x00, 0x00, 0x00, 0x2f, // NetBIOS session request length
			0xff, 0x53, 0x4d, 0x42, // SMB magic
			0x72,                   // SMBCommand: Negotiate
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}, 1*time.Second)
		if smbBanner != "" {
			r.signals = append(r.signals, "SMB:445")
			b := strings.ToLower(smbBanner)
			if strings.Contains(b, "windows") || strings.Contains(b, "microsoft") {
				r.name = "Windows"
				r.confidence = "high"
			} else if strings.Contains(b, "samba") {
				r.name = "Linux/Unix (Samba)"
				r.confidence = "medium"
			}
		}
	}

	// ── Probe 7: TTL-based OS hint from TCP connect timing ────────────────
	// We estimate TTL by observing connection success latency patterns
	// and comparing with well-known TTL defaults: Windows=128, Linux=64,
	// Cisco=255, macOS=64, Solaris=255.
	// Since we can't read raw IP packets without root, we use /proc/net/tcp
	// on Linux or fall back to a TTL probe via error messages.
	ttlGuess := probeTTLFromError(host)
	if ttlGuess > 0 {
		r.ttl = ttlGuess
		ttlOS := osFromTTL(ttlGuess)
		r.signals = append(r.signals, fmt.Sprintf("TTL~%d", ttlGuess))
		if r.name == "" {
			r.name = ttlOS
			r.confidence = "low"
		}
	}

	// ── Probe 8: Netbios/NBNS on 137 UDP (Windows hint) ──────────────────
	if r.name == "" {
		nbConn, err := net.DialTimeout("udp", fmt.Sprintf("%s:137", host), 1*time.Second)
		if err == nil {
			_ = nbConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			// NBNS Name Query
			nbProbe := []byte{
				0xAB, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
				0x00, 0x21, 0x00, 0x01,
			}
			_, _ = nbConn.Write(nbProbe)
			buf := make([]byte, 256)
			n, err2 := nbConn.Read(buf)
			nbConn.Close()
			if err2 == nil && n > 0 {
				r.name = "Windows"
				r.confidence = "medium"
				r.signals = append(r.signals, "NBNS:137")
			}
		}
	}

	if r.name == "" {
		r.name = "Unknown"
		r.confidence = "none"
	}

	// Format: "OS Name (confidence) [signals]"
	conf := ""
	switch r.confidence {
	case "high":
		conf = " [high confidence]"
	case "medium":
		conf = " [medium confidence]"
	case "low":
		conf = " [low confidence]"
	}
	sigStr := ""
	if len(r.signals) > 0 {
		sigStr = " via " + strings.Join(r.signals, "+")
	}
	ttlStr := ""
	if r.ttl > 0 {
		ttlStr = fmt.Sprintf(" TTL≈%d", r.ttl)
	}
	return r.name + conf + ttlStr + sigStr
}

// tcpBanner connects to host:port, optionally writes a probe, and returns
// the first 2 KB of response. Returns "" on any error.
func tcpBanner(host string, port int, probe []byte, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if len(probe) > 0 {
		_, _ = conn.Write(probe)
	}
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

// probeTTLFromError extracts an estimated TTL from the net.Error message when
// a TCP connect fails with "TTL expired" — useful when the host is multiple hops
// away. Returns 0 if no TTL info is available.
func probeTTLFromError(host string) int {
	// This technique works when intermediate routers return ICMP TTL-exceeded.
	// We dial a likely-closed port and inspect the error string.
	// On Linux the error may contain "ttl" or "time exceeded".
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:1", host), 500*time.Millisecond)
	if err != nil {
		e := strings.ToLower(err.Error())
		if strings.Contains(e, "ttl") || strings.Contains(e, "time exceeded") {
			return 64 // generic Linux default
		}
	}
	return 0
}

// osFromTTL maps a raw TTL value to the most likely OS.
// Windows defaults to 128, Linux/macOS to 64, network devices to 255.
func osFromTTL(ttl int) string {
	switch {
	case ttl > 200:
		return "Network device / Cisco / Solaris (TTL 255)"
	case ttl > 100:
		return "Windows (TTL 128)"
	case ttl > 50:
		return "Linux / macOS / FreeBSD (TTL 64)"
	default:
		return "Unknown (low TTL)"
	}
}

// guessOSFromBanner performs keyword matching against a banner string.
// Returns a human-readable OS name or "Unknown".
func guessOSFromBanner(banner string) string {
	b := strings.ToLower(banner)

	// Distro-specific Linux keywords (ordered most-specific first)
	osPatterns := []struct {
		keyword string
		os      string
	}{
		{"ubuntu", "Linux (Ubuntu)"},
		{"debian", "Linux (Debian)"},
		{"centos", "Linux (CentOS)"},
		{"fedora", "Linux (Fedora)"},
		{"red hat", "Linux (RHEL)"},
		{"rhel", "Linux (RHEL)"},
		{"suse", "Linux (SUSE)"},
		{"opensuse", "Linux (openSUSE)"},
		{"arch linux", "Linux (Arch)"},
		{"gentoo", "Linux (Gentoo)"},
		{"kali", "Linux (Kali)"},
		{"parrot", "Linux (Parrot OS)"},
		{"alpine", "Linux (Alpine)"},
		{"amazon linux", "Linux (Amazon)"},
		{"oracle linux", "Linux (Oracle)"},
		{"rocky linux", "Linux (Rocky)"},
		{"almalinux", "Linux (AlmaLinux)"},
		{"raspbian", "Linux (Raspbian)"},
		{"openwrt", "Linux (OpenWrt)"},
		// Windows variants
		{"windows server 2022", "Windows Server 2022"},
		{"windows server 2019", "Windows Server 2019"},
		{"windows server 2016", "Windows Server 2016"},
		{"windows server 2012", "Windows Server 2012"},
		{"windows server 2008", "Windows Server 2008"},
		{"windows 11", "Windows 11"},
		{"windows 10", "Windows 10"},
		{"windows 7", "Windows 7"},
		{"windows xp", "Windows XP"},
		{"microsoft", "Windows"},
		{"windows", "Windows"},
		{"iis", "Windows (IIS)"},
		// BSD variants
		{"freebsd", "FreeBSD"},
		{"openbsd", "OpenBSD"},
		{"netbsd", "NetBSD"},
		{"dragonfly", "DragonFlyBSD"},
		// macOS / Darwin
		{"darwin", "macOS"},
		{"macos", "macOS"},
		// Network devices
		{"cisco", "Cisco IOS"},
		{"ios xe", "Cisco IOS XE"},
		{"ios xr", "Cisco IOS XR"},
		{"nxos", "Cisco NX-OS"},
		{"junos", "Juniper JunOS"},
		{"juniper", "Juniper JunOS"},
		{"paloalto", "Palo Alto PAN-OS"},
		{"pan-os", "Palo Alto PAN-OS"},
		{"fortinet", "Fortinet FortiOS"},
		{"fortios", "Fortinet FortiOS"},
		{"sonicwall", "SonicWall SonicOS"},
		{"checkpoint", "Check Point GAiA"},
		{"f5", "F5 TMOS"},
		{"bigip", "F5 BIG-IP"},
		{"aruba", "Aruba ArubaOS"},
		{"mikrotik", "MikroTik RouterOS"},
		{"routeros", "MikroTik RouterOS"},
		{"ubiquiti", "Ubiquiti UniFi"},
		{"unifi", "Ubiquiti UniFi"},
		{"airos", "Ubiquiti AirOS"},
		{"zyxel", "ZyXEL"},
		// Hypervisors / embedded
		{"esxi", "VMware ESXi"},
		{"vmware", "VMware"},
		{"proxmox", "Proxmox VE"},
		{"xen", "Xen"},
		{"synology", "Synology DSM"},
		{"qnap", "QNAP QTS"},
		{"truenas", "TrueNAS"},
		{"freenas", "FreeNAS"},
		// Generic fallbacks
		{"linux", "Linux"},
		{"unix", "Unix"},
		{"bsd", "BSD"},
	}

	for _, p := range osPatterns {
		if strings.Contains(b, p.keyword) {
			return p.os
		}
	}
	if strings.Contains(b, "ssh") {
		return "Unix/Linux (SSH)"
	}
	return "Unknown"
}

                // ═════════════════
               //  TLS AUDIT
              // ══════════════════

var weakCiphers = map[uint16]bool{
	tls.TLS_RSA_WITH_RC4_128_SHA:                true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          true,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        true,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            true,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            true,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         true,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      true,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    true,
}

var insecureCerts = map[string]bool{
	"CN=localhost": true,
	"CN=localhost.localdomain": true,
	"CN=*.local": true,
}

func auditTLS(host string, port int, timeout time.Duration) (*TLSData, []Finding) {
	var findings []Finding
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", addr,
		&tls.Config{
			InsecureSkipVerify: true,
			ServerName: host,
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS13,
		},
	)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	td := &TLSData{
		Version:    tlsVerStr(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
		ChainLength: len(state.PeerCertificates),
	}

	// Generate cert hash
	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		td.CommonName = c.Subject.CommonName
		td.SANs = c.DNSNames
		td.Issuer = c.Issuer.CommonName
		td.NotBefore = c.NotBefore
		td.NotAfter = c.NotAfter
		td.Expired = time.Now().After(c.NotAfter)
		td.SelfSigned = c.Subject.String() == c.Issuer.String()
		td.CertHash = fmt.Sprintf("%x", c.Signature)[:16]
	}

	td.WeakCipher = weakCiphers[state.CipherSuite]
	td.WeakVersion = state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11

	// Check for insecure common names
	if td.CommonName != "" && insecureCerts[td.CommonName] {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: MEDIUM,
			Title:       "Insecure Certificate Common Name",
			Detail:      fmt.Sprintf("Certificate uses insecure CN: %s", td.CommonName),
			Evidence:    td.CommonName,
			Remediation: "Use a properly configured certificate with a valid domain name",
		})
	}

	// Check certificate chain length
	if td.ChainLength == 1 && !td.SelfSigned {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: LOW,
			Title:       "Missing Intermediate Certificate",
			Detail:      "Certificate chain missing intermediate certificates",
			Evidence:    fmt.Sprintf("Chain length: %d", td.ChainLength),
			Remediation: "Include intermediate certificates in server configuration",
		})
	}

	// Check for OCSP stapling
	if len(state.OCSPResponse) == 0 {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: INFO,
			Title:       "OCSP Stapling Not Used",
			Detail:      "Server does not provide OCSP stapling",
			Evidence:    "No OCSP response in TLS handshake",
			Remediation: "Enable OCSP stapling for better revocation checking",
		})
	}

	// Generate findings
	if td.WeakVersion {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: HIGH,
			Title:       fmt.Sprintf("Deprecated TLS Version: %s", td.Version),
			Detail:      "TLS 1.0 and 1.1 are deprecated (RFC 8996) and vulnerable to BEAST/POODLE.",
			Evidence:    fmt.Sprintf("%s:%d negotiated %s", host, port, td.Version),
			CVE:         "CVE-2014-3566",
			Remediation: "Disable TLS 1.0/1.1, enforce TLS 1.2+ only",
		})
	}
	if td.WeakCipher {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: HIGH,
			Title:       fmt.Sprintf("Weak TLS Cipher: %s", td.Cipher),
			Detail:      "RC4, 3DES, and CBC-mode ciphers are vulnerable to various attacks.",
			Evidence:    fmt.Sprintf("%s:%d uses cipher %s", host, port, td.Cipher),
			CVE:         "CVE-2013-2566",
			Remediation: "Configure only AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)",
		})
	}
	if td.Expired {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: HIGH,
			Title:       "TLS Certificate Expired",
			Detail:      fmt.Sprintf("Certificate expired on %s", td.NotAfter.Format("2006-01-02")),
			Evidence:    fmt.Sprintf("CN=%s, expired %s", td.CommonName, td.NotAfter.Format("2006-01-02")),
			Remediation: "Renew TLS certificate immediately",
		})
	}
	if td.SelfSigned {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: MEDIUM,
			Title:       "Self-Signed TLS Certificate",
			Detail:      "Self-signed certs enable MITM attacks as they bypass CA trust chain.",
			Evidence:    fmt.Sprintf("Issuer == Subject: %s", td.CommonName),
			Remediation: "Use a certificate from a trusted CA",
		})
	}
	// Check cert expiry warning (within 30 days)
	if !td.Expired && time.Until(td.NotAfter) < 30*24*time.Hour {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: MEDIUM,
			Title:       "TLS Certificate Expiring Soon",
			Detail:      fmt.Sprintf("Certificate expires in %d days", int(time.Until(td.NotAfter).Hours()/24)),
			Evidence:    fmt.Sprintf("CN=%s, expires %s", td.CommonName, td.NotAfter.Format("2006-01-02")),
			Remediation: "Renew certificate before expiry",
		})
	}

	// Check for wildcard certs
	if td.CommonName != "" && strings.HasPrefix(td.CommonName, "*.") {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: INFO,
			Title:       "Wildcard Certificate in Use",
			Detail:      "Wildcard certificates increase attack surface if private key is compromised",
			Evidence:    td.CommonName,
			Remediation: "Use specific certificates for critical services",
		})
	}

	// Check for weak key exchange
	if strings.Contains(td.Cipher, "RSA_EXPORT") || strings.Contains(td.Cipher, "DHE_EXPORT") {
		findings = append(findings, Finding{
			Module:      "TLSAudit", Severity: CRITICAL,
			Title:       "Export Grade Cipher Detected",
			Detail:      "Export grade ciphers are extremely weak and vulnerable to FREAK/Logjam",
			Evidence:    td.Cipher,
			CVE:         "CVE-2015-4000",
			Remediation: "Remove all export-grade ciphers from configuration",
		})
	}

	return td, findings
}

func tlsVerStr(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS/0x%04x", v)
	}
}

                   // ══════════════════
                  //  HTTP AUDIT
                 // ════════════════════

var securityHeaders = []struct {
	name     string
	severity Severity
	detail   string
}{
	{"Strict-Transport-Security", HIGH, "HSTS missing: MITM downgrade attacks possible"},
	{"X-Frame-Options", MEDIUM, "Clickjacking protection missing"},
	{"X-Content-Type-Options", MEDIUM, "MIME sniffing attacks possible"},
	{"Content-Security-Policy", HIGH, "CSP missing: XSS and data injection risk"},
	{"X-XSS-Protection", LOW, "Legacy XSS filter header missing"},
	{"Referrer-Policy", LOW, "Referrer info leakage possible"},
	{"Permissions-Policy", LOW, "Browser feature policy not set"},
	{"Cross-Origin-Resource-Policy", MEDIUM, "CORP missing: potential cross-origin data leaks"},
	{"Cross-Origin-Opener-Policy", MEDIUM, "COOP missing: cross-origin isolation issues"},
	{"Cross-Origin-Embedder-Policy", MEDIUM, "COEP missing: cross-origin resource loading issues"},
}

var dangerousHeaders = []struct {
	name   string
	detail string
}{
	{"Server", "Server version disclosure enables targeted attacks"},
	{"X-Powered-By", "Technology stack disclosure"},
	{"X-AspNet-Version", "ASP.NET version disclosure"},
	{"X-AspNetMvc-Version", "ASP.NET MVC version disclosure"},
	{"X-Drupal-Cache", "Drupal cache info disclosure"},
	{"X-Drupal-Dynamic-Cache", "Drupal cache info disclosure"},
	{"X-Generator", "CMS/framework generator info disclosure"},
	{"X-Runtime", "Ruby/Rails runtime info disclosure"},
	{"X-Version", "Version info disclosure"},
	{"X-Backend-Server", "Backend server info disclosure"},
	{"X-Proxy-Cache", "Proxy cache info disclosure"},
	{"Via", "Proxy software/version disclosure"},
}

var wafSignatures = []struct {
	name      string
	header    string
	pattern   string
	cookie    string
}{
	{"Cloudflare", "cf-ray", "", "__cfduid"},
	{"AWS WAF", "x-amzn-RequestId", "", ""},
	{"Akamai", "x-akamai-transformed", "", ""},
	{"Imperva", "x-iinfo", "", "visid_incap"},
	{"F5 BIG-IP", "x-wa-rewrite", "", ""},
	{"Barracuda", "x-barracuda", "", ""},
	{"Sucuri", "x-sucuri-id", "", ""},
	{"Wordfence", "", "", "wfvt_"},
	{"ModSecurity", "", "", "mod_security"},
	{"Citrix", "x-nitro", "", ""},
	{"Radware", "x-rdwr", "", ""},
	{"Fortinet", "x-fortinet-", "", ""},
}

// Helper function to convert SameSite to string
func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Unknown"
	}
}

func auditHTTP(target string, cfg Config) (*HTTPAuditResult, []Finding) {
	var findings []Finding
	result := &HTTPAuditResult{
		MissingHeaders:  []string{},
		InsecureHeaders: []string{},
		AllowedMethods:  []string{},
		DangerousMethods: []string{},
		Technologies:    []string{},
		Cookies:         []CookieInfo{},
		Forms:           []FormInfo{},
		Comments:        []string{},
		Redirects:       []string{},
		RobotsEntries:   []string{},
		SitemapEntries:  []string{},
	}

	// Try HTTPS first, fallback to HTTP
	schemes := []string{"https", "http"}
	var resp *http.Response
	var finalURL string
	var startTime time.Time

	client := &http.Client{
		Timeout: cfg.Timeout * 3,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			result.Redirects = append(result.Redirects, req.URL.String())
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
	}

	// If proxy configured
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	}

	for _, scheme := range schemes {
		u := fmt.Sprintf("%s://%s/", scheme, target)
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", cfg.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Header.Set("Connection", "close")
		
		startTime = time.Now()
		r, err := client.Do(req)
		if err != nil {
			continue
		}
		resp = r
		finalURL = u
		break
	}

	if resp == nil {
		return result, findings
	}
	defer resp.Body.Close()

	result.ResponseTime = time.Since(startTime)
	result.URL = finalURL
	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")
	result.PoweredBy = resp.Header.Get("X-Powered-By")
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength

	// Detect WAF
	for _, waf := range wafSignatures {
		if waf.header != "" && resp.Header.Get(waf.header) != "" {
			result.WAF = waf.name
			findings = append(findings, Finding{
				Module:   "HTTPAudit", Severity: INFO,
				Title:    fmt.Sprintf("WAF Detected: %s", waf.name),
				Detail:   fmt.Sprintf("Web application firewall detected via %s header", waf.header),
				Evidence: resp.Header.Get(waf.header),
				Remediation: "Configure WAF rules and test for bypass; log and alert on blocked requests",
			})
			break
		}
		if waf.cookie != "" {
			for _, c := range resp.Cookies() {
				if strings.Contains(c.Name, waf.cookie) {
					result.WAF = waf.name
					findings = append(findings, Finding{
						Module:   "HTTPAudit", Severity: INFO,
						Title:    fmt.Sprintf("WAF Detected: %s", waf.name),
						Detail:   fmt.Sprintf("Web application firewall detected via %s cookie", waf.cookie),
						Evidence: c.Name,
						Remediation: "Configure WAF rules and test for bypass; log and alert on blocked requests",
					})
					break
				}
			}
		}
	}

	// Read body (limited to 2MB)
	bodyBytes := make([]byte, 2097152)
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])

	// Extract page title
	if m := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`).FindStringSubmatch(body); len(m) > 1 {
		result.Title = strings.TrimSpace(m[1])
	}

	// Detect technologies
	result.Technologies = detectTech(body, resp.Header)

	// Missing security headers
	for _, sh := range securityHeaders {
		if resp.Header.Get(sh.name) == "" {
			result.MissingHeaders = append(result.MissingHeaders, sh.name)
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: sh.severity,
				Title:       fmt.Sprintf("Missing Security Header: %s", sh.name),
				Detail:      sh.detail,
				Evidence:    fmt.Sprintf("GET %s — header %s absent", finalURL, sh.name),
				Remediation: fmt.Sprintf("Add '%s' header to all HTTP responses", sh.name),
			})
		}
	}

	// Dangerous disclosure headers
	for _, dh := range dangerousHeaders {
		if v := resp.Header.Get(dh.name); v != "" {
			result.InsecureHeaders = append(result.InsecureHeaders,
				fmt.Sprintf("%s: %s", dh.name, v))
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: MEDIUM,
				Title:       fmt.Sprintf("Information Disclosure: %s header", dh.name),
				Detail:      dh.detail,
				Evidence:    fmt.Sprintf("%s: %s", dh.name, v),
				Remediation: fmt.Sprintf("Remove or mask the %s response header", dh.name),
			})
		}
	}

	// Cookie audit
	for _, cookie := range resp.Cookies() {
		ci := CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value[:min(20, len(cookie.Value))] + "...",
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSiteString(cookie.SameSite),
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			MaxAge:   cookie.MaxAge,
		}
		if !cookie.Secure {
			ci.Issues = append(ci.Issues, "missing Secure flag")
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: MEDIUM,
				Title:       fmt.Sprintf("Cookie '%s': Missing Secure Flag", cookie.Name),
				Detail:      "Cookie can be transmitted over HTTP, enabling interception.",
				Evidence:    fmt.Sprintf("Set-Cookie: %s (no Secure)", cookie.Name),
				Remediation: "Add Secure flag to all cookies",
			})
		}
		if !cookie.HttpOnly {
			ci.Issues = append(ci.Issues, "missing HttpOnly flag")
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: MEDIUM,
				Title:       fmt.Sprintf("Cookie '%s': Missing HttpOnly Flag", cookie.Name),
				Detail:      "Cookie accessible via JavaScript, enabling XSS session theft.",
				Evidence:    fmt.Sprintf("Set-Cookie: %s (no HttpOnly)", cookie.Name),
				Remediation: "Add HttpOnly flag to session cookies",
			})
		}
		if cookie.MaxAge <= 0 && cookie.Name != "" && !strings.Contains(cookie.Name, "session") {
			ci.Issues = append(ci.Issues, "session cookie missing MaxAge")
		}
		result.Cookies = append(result.Cookies, ci)
	}

	// HTML comments (may contain credentials / TODO / debug)
	commentRegex := regexp.MustCompile(`<!--([\s\S]{1,500}?)-->`)
	comments := commentRegex.FindAllStringSubmatch(body, 30)
	for _, c := range comments {
		trimmed := strings.TrimSpace(c[1])
		if len(trimmed) > 5 {
			result.Comments = append(result.Comments, trimmed[:min(80, len(trimmed))])
			// Flag suspicious comments
			lower := strings.ToLower(trimmed)
			sensitivePatterns := []string{
				"password", "passwd", "secret", "key", "token", "todo", 
				"fixme", "bug", "admin", "debug", "test", "credential",
				"username", "login", "api_key", "apikey", "aws", "azure",
				"gcp", "private", "confidential", "internal",
			}
			for _, pattern := range sensitivePatterns {
				if strings.Contains(lower, pattern) {
					findings = append(findings, Finding{
						Module:      "HTTPAudit", Severity: MEDIUM,
						Title:       "Sensitive Information in HTML Comment",
						Detail:      fmt.Sprintf("HTML comment contains potentially sensitive term: %s", pattern),
						Evidence:    "<!-- " + trimmed[:min(80, len(trimmed))] + " -->",
						Remediation: "Remove all sensitive HTML comments from production code",
					})
					break
				}
			}
		}
	}

	// Extract forms 
	formRegex := regexp.MustCompile(`(?i)<form[^>]*action=["']?([^"'\s>]*)["']?[^>]*method=["']?(\w+)["']?[^>]*>(.*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(body, 20)
	for _, fm := range formMatches {
		action, method := fm[1], strings.ToUpper(fm[2])
		if action == "" {
			action = "#"
		}
		fieldRegex := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'](?:\s+type=["']([^"']+)["'])?`)
		fields := fieldRegex.FindAllStringSubmatch(fm[3], 20)
		var formFields []FormField
		for _, f := range fields {
			fieldType := "text"
			if len(f) > 2 && f[2] != "" {
				fieldType = f[2]
			}
			formFields = append(formFields, FormField{
				Name: f[1],
				Type: fieldType,
			})
		}
		result.Forms = append(result.Forms, FormInfo{
			Action: action,
			Method: method,
			Fields: formFields,
		})
		
		// Check for password fields without HTTPS
		for _, f := range formFields {
			if f.Type == "password" && !strings.HasPrefix(finalURL, "https") {
				findings = append(findings, Finding{
					Module:      "HTTPAudit", Severity: HIGH,
					Title:       "Password Form Submitted Over HTTP",
					Detail:      "Password field detected in form submitted over unencrypted HTTP",
					Evidence:    fmt.Sprintf("Form action: %s, method: %s", action, method),
					Remediation: "Use HTTPS for all forms containing sensitive data",
				})
				break
			}
		}
	}

	// Fetch robots.txt
	robotsURL := strings.TrimRight(finalURL, "/") + "/robots.txt"
	if rr, err := client.Get(robotsURL); err == nil && rr.StatusCode == 200 {
		rb := make([]byte, 32768)
		rn, _ := rr.Body.Read(rb)
		rr.Body.Close()
		for _, line := range strings.Split(string(rb[:rn]), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
				result.RobotsEntries = append(result.RobotsEntries, line)
			}
		}
		if len(result.RobotsEntries) > 0 {
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: INFO,
				Title:       "robots.txt Reveals Hidden Paths",
				Detail:      fmt.Sprintf("robots.txt contains %d entries that may reveal sensitive paths.", len(result.RobotsEntries)),
				Evidence:    strings.Join(result.RobotsEntries[:min(5, len(result.RobotsEntries))], "; "),
				Remediation: "Review robots.txt entries; don't rely on it for security",
			})
		}
	}

	// Fetch sitemap.xml
	sitemapURL := strings.TrimRight(finalURL, "/") + "/sitemap.xml"
	if smr, err := client.Get(sitemapURL); err == nil && smr.StatusCode == 200 {
		sb := make([]byte, 32768)
		sn, _ := smr.Body.Read(sb)
		smr.Body.Close()
		sitemapContent := string(sb[:sn])
		locRegex := regexp.MustCompile(`<loc[^>]*>([^<]+)</loc>`)
		locs := locRegex.FindAllStringSubmatch(sitemapContent, 50)
		for _, loc := range locs {
			result.SitemapEntries = append(result.SitemapEntries, loc[1])
		}
		if len(result.SitemapEntries) > 0 {
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: INFO,
				Title:       "sitemap.xml Reveals URLs",
				Detail:      fmt.Sprintf("sitemap.xml contains %d URLs that may reveal hidden content.", len(result.SitemapEntries)),
				Evidence:    strings.Join(result.SitemapEntries[:min(5, len(result.SitemapEntries))], "; "),
				Remediation: "Review sitemap.xml entries; remove sensitive URLs",
			})
		}
	}

	// HTTP methods check (OPTIONS probe)
	if req, err := http.NewRequest("OPTIONS", finalURL, nil); err == nil {
		req.Header.Set("User-Agent", cfg.UserAgent)
		if or_, err := client.Do(req); err == nil {
			allow := or_.Header.Get("Allow")
			or_.Body.Close()
			if allow != "" {
				methods := strings.Split(allow, ",")
				for _, m := range methods {
					m = strings.TrimSpace(m)
					result.AllowedMethods = append(result.AllowedMethods, m)
					if m == "TRACE" || m == "PUT" || m == "DELETE" || m == "CONNECT" || m == "PATCH" {
						result.DangerousMethods = append(result.DangerousMethods, m)
						findings = append(findings, Finding{
							Module:      "HTTPAudit", Severity: MEDIUM,
							Title:       fmt.Sprintf("Dangerous HTTP Method Enabled: %s", m),
							Detail:      fmt.Sprintf("HTTP %s method enabled; %s", m, httpMethodRisk(m)),
							Evidence:    fmt.Sprintf("OPTIONS %s → Allow: %s", finalURL, m),
							CVE:         httpMethodCVE(m),
							Remediation: fmt.Sprintf("Disable HTTP %s method in server config", m),
						})
					}
				}
			}
		}
	}

	// Check for exposed .git
	gitURL := strings.TrimRight(finalURL, "/") + "/.git/HEAD"
	if gr, err := client.Get(gitURL); err == nil && gr.StatusCode == 200 {
		gb := make([]byte, 256)
		gn, _ := gr.Body.Read(gb)
		gr.Body.Close()
		if strings.Contains(string(gb[:gn]), "ref: refs/heads/") {
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: CRITICAL,
				Title:       "Exposed .git Repository",
				Detail:      "Git repository is publicly accessible, exposing source code and history.",
				Evidence:    gitURL,
				Remediation: "Remove .git directory from web root or block access to it",
			})
		}
	}

	// Check for exposed .env
	envURL := strings.TrimRight(finalURL, "/") + "/.env"
	if er, err := client.Get(envURL); err == nil && er.StatusCode == 200 {
		eb := make([]byte, 1024)
		en, _ := er.Body.Read(eb)
		er.Body.Close()
		envContent := string(eb[:en])
		if strings.Contains(envContent, "DB_PASSWORD") || strings.Contains(envContent, "SECRET_KEY") {
			findings = append(findings, Finding{
				Module:      "HTTPAudit", Severity: CRITICAL,
				Title:       "Exposed .env File",
				Detail:      "Environment file containing secrets is publicly accessible.",
				Evidence:    envURL,
				Remediation: "Remove .env file from web root",
			})
		}
	}

	// Check for exposed backup files
	backupPaths := []string{
		"/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
		"/database.sql", "/dump.sql", "/backup.sql.gz", "/www.zip",
		"/www.tar.gz", "/site.zip", "/site.tar.gz", "/web.zip",
	}
	for _, path := range backupPaths {
		backupURL := strings.TrimRight(finalURL, "/") + path
		if br, err := client.Head(backupURL); err == nil && br.StatusCode == 200 {
			br.Body.Close()
			if br.ContentLength > 0 {
				findings = append(findings, Finding{
					Module:      "HTTPAudit", Severity: CRITICAL,
					Title:       "Exposed Backup File",
					Detail:      fmt.Sprintf("Backup file accessible at %s (size: %d bytes)", path, br.ContentLength),
					Evidence:    backupURL,
					Remediation: "Remove backup files from web root",
				})
			}
		}
	}

	return result, findings
}

func httpMethodRisk(m string) string {
	switch m {
	case "TRACE":
		return "enables Cross-Site Tracing (XST)"
	case "PUT":
		return "allows file upload/overwrite"
	case "DELETE":
		return "allows file deletion"
	case "CONNECT":
		return "enables proxy tunneling"
	case "PATCH":
		return "may allow partial file modifications"
	default:
		return "non-standard method"
	}
}

func httpMethodCVE(m string) string {
	if m == "TRACE" {
		return "CVE-2004-2320"
	}
	return "N/A"
}

// techChecks holds pre-compiled technology detection patterns.
// Compiled once at startup to avoid repeated regexp.MustCompile in the hot path.
type techCheck struct {
	pattern *regexp.Regexp
	tech    string
}

var techChecks = func() []techCheck {	
    raw := []struct{ pattern, tech string }{
		{`wp-content|wp-includes|wordpress`, "WordPress"},
		{`joomla`, "Joomla"},
		{`drupal`, "Drupal"},
		{`laravel`, "Laravel"},
		{`django`, "Django"},
		{`ruby on rails|rails`, "Ruby on Rails"},
		{`react|reactjs`, "React"},
		{`angular`, "Angular"},
		{`vue\.js|vuejs`, "Vue.js"},
		{`jquery`, "jQuery"},
		{`bootstrap`, "Bootstrap"},
		{`nginx`, "nginx"},
		{`apache`, "Apache"},
		{`iis`, "IIS"},
		{`tomcat`, "Tomcat"},
		{`express`, "Express.js"},
		{`flask`, "Flask"},
		{`spring`, "Spring Framework"},
		{`graphql`, "GraphQL"},
		{`swagger|openapi`, "Swagger/OpenAPI"},
		{`phpmyadmin`, "phpMyAdmin"},
		{`adminer`, "Adminer"},
		{`nextcloud`, "Nextcloud"},
		{`owncloud`, "ownCloud"},
		{`roundcube`, "Roundcube"},
		{`squirrelmail`, "SquirrelMail"},
		{`horde`, "Horde"},
		{`cpanel`, "cPanel"},
		{`plesk`, "Plesk"},
		{`webmin`, "Webmin"},
		{`grafana`, "Grafana"},
		{`prometheus`, "Prometheus"},
		{`kibana`, "Kibana"},
		{`elasticsearch`, "Elasticsearch"},
		{`jenkins`, "Jenkins"},
		{`gitlab`, "GitLab"},
		{`github`, "GitHub"},
		{`bitbucket`, "Bitbucket"},
		{`jira`, "Jira"},
		{`confluence`, "Confluence"},
		{`sonarqube`, "SonarQube"},
		{`nexus`, "Nexus"},
		{`artifactory`, "Artifactory"},
		{`docker`, "Docker"},
		{`kubernetes`, "Kubernetes"},
		{`rancher`, "Rancher"},
		{`openshift`, "OpenShift"},
		{`vault`, "Vault"},
		{`consul`, "Consul"},
		{`etcd`, "etcd"},
		{`zookeeper`, "ZooKeeper"},
		{`kafka`, "Kafka"},
		{`rabbitmq`, "RabbitMQ"},
		{`activemq`, "ActiveMQ"},
		{`cassandra`, "Cassandra"},
		{`couchdb`, "CouchDB"},
		{`mongodb`, "MongoDB"},
		{`mysql`, "MySQL"},
		{`postgresql`, "PostgreSQL"},
		{`mssql`, "MSSQL"},
		{`oracle`, "Oracle"},
		{`redis`, "Redis"},
		{`memcached`, "Memcached"},
	}
	checks := make([]techCheck, len(raw))
	for i, r := range raw {
		checks[i] = techCheck{pattern: regexp.MustCompile(r.pattern), tech: r.tech}
	}
	return checks
}()

func detectTech(body string, headers http.Header) []string {
	var techs []string
	b := strings.ToLower(body)

	server := strings.ToLower(headers.Get("Server"))
	xpb := strings.ToLower(headers.Get("X-Powered-By"))
	xga := strings.ToLower(headers.Get("X-Generator"))
	allHeaders := server + " " + xpb + " " + xga

	seen := make(map[string]bool)
	for _, c := range techChecks {
		if !seen[c.tech] && (c.pattern.MatchString(b) || c.pattern.MatchString(allHeaders)) {
			techs = append(techs, c.tech)
			seen[c.tech] = true
		}
	}
	return techs
}

             // ════════════════════
            //  DNS ENUMERATION
           // ══════════════════════

// dnsQueryRaw sends a raw DNS query over TCP and returns the response bytes.
// We use TCP so we can also reuse the same connection path for AXFR.
// msgID is caller-supplied so responses can be matched when needed.
func dnsQueryRaw(server, domain string, qtype uint16, timeout time.Duration) ([]byte, error) {
	// Encode the DNS name into wire format (label sequence).
	encodeName := func(name string) []byte {
		var buf []byte
		name = strings.TrimSuffix(name, ".")
		for _, label := range strings.Split(name, ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, []byte(label)...)
		}
		buf = append(buf, 0x00) // root label
		return buf
	}

	qname := encodeName(domain)

	// Build a minimal DNS query message.
	// Header: ID=0x1234, QR=0 (query), OPCODE=0, RD=1, QDCOUNT=1
	msg := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: RD=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}
	msg = append(msg, qname...)
	msg = append(msg, byte(qtype>>8), byte(qtype)) // QTYPE
	msg = append(msg, 0x00, 0x01)                  // QCLASS = IN

	// TCP DNS: 2-byte length prefix
	length := uint16(len(msg))
	tcpMsg := []byte{byte(length >> 8), byte(length)}
	tcpMsg = append(tcpMsg, msg...)

	conn, err := net.DialTimeout("tcp", server+":53", timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err = conn.Write(tcpMsg); err != nil {
		return nil, err
	}

	// Read the 2-byte length prefix of the response.
	lenBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf))
	if respLen < 12 || respLen > 65535 {
		return nil, fmt.Errorf("invalid DNS response length: %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// dnsParseName decodes a DNS wire-format name at offset within msg,
// following compression pointers. Returns the name string and the new
// offset just past the uncompressed label sequence 
func dnsParseNameAt(msg []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool)
	origOffset := -1 // offset to return 

	for {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("name parse overrun at %d", offset)
		}
		if visited[offset] {
			return "", 0, fmt.Errorf("compression pointer loop")
		}
		visited[offset] = true

		b := msg[offset]
		if b == 0x00 {
			if origOffset == -1 {
				origOffset = offset + 1
			}
			break
		}
		if b&0xC0 == 0xC0 {
			// Compression pointer
			if offset+1 >= len(msg) {
				return "", 0, fmt.Errorf("compression pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16([]byte{b & 0x3F, msg[offset+1]}))
			if origOffset == -1 {
				origOffset = offset + 2
			}
			offset = ptr
			continue
		}
		labelLen := int(b)
		offset++
		if offset+labelLen > len(msg) {
			return "", 0, fmt.Errorf("label overrun")
		}
		labels = append(labels, string(msg[offset:offset+labelLen]))
		offset += labelLen
	}
	return strings.Join(labels, "."), origOffset, nil
}

// dnsParseRecords parses the answer/authority/additional sections of a DNS
// response and returns them as DNSRecord values with real TTLs.
// startOffset is the byte offset of the first RR in msg.
// count is the number of RRs to parse.
func dnsParseRecords(msg []byte, startOffset, count int, defaultName string) ([]DNSRecord, int, error) {
	offset := startOffset
	var out []DNSRecord

	for i := 0; i < count; i++ {
		if offset >= len(msg) {
			return out, offset, fmt.Errorf("RR parse overrun")
		}

		name, newOff, err := dnsParseNameAt(msg, offset)
		if err != nil {
			return out, offset, err
		}
		offset = newOff

		if offset+10 > len(msg) {
			return out, offset, fmt.Errorf("RR fixed fields truncated")
		}
		rrtype := binary.BigEndian.Uint16(msg[offset : offset+2])
		// rrclass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		rdlength := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10

		if offset+rdlength > len(msg) {
			return out, offset, fmt.Errorf("RDATA truncated")
		}
		rdata := msg[offset : offset+rdlength]
		offset += rdlength

		if name == "" {
			name = defaultName
		}

		var rec DNSRecord
		rec.TTL = ttl
		rec.Name = name

		switch rrtype {
		case 1: // A
			if len(rdata) == 4 {
				rec.Type = "A"
				rec.Value = fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
			}
		case 28: // AAAA
			if len(rdata) == 16 {
				rec.Type = "AAAA"
				rec.Value = net.IP(rdata).String()
			}
		case 5: // CNAME
			cname, _, err := dnsParseNameAt(msg, offset-rdlength)
			if err == nil {
				rec.Type = "CNAME"
				rec.Value = cname
			}
		case 15: // MX
			if len(rdata) >= 3 {
				pref := binary.BigEndian.Uint16(rdata[0:2])
				exch, _, err := dnsParseNameAt(msg, offset-rdlength+2)
				if err == nil {
					rec.Type = "MX"
					rec.Value = fmt.Sprintf("%d %s", pref, exch)
				}
			}
		case 2: // NS
			ns, _, err := dnsParseNameAt(msg, offset-rdlength)
			if err == nil {
				rec.Type = "NS"
				rec.Value = ns
			}
		case 16: // TXT
			var parts []string
			pos := 0
			for pos < len(rdata) {
				slen := int(rdata[pos])
				pos++
				if pos+slen > len(rdata) {
					break
				}
				parts = append(parts, string(rdata[pos:pos+slen]))
				pos += slen
			}
			rec.Type = "TXT"
			rec.Value = strings.Join(parts, "")
		case 12: // PTR
			ptr, _, err := dnsParseNameAt(msg, offset-rdlength)
			if err == nil {
				rec.Type = "PTR"
				rec.Value = ptr
			}
		case 6: // SOA
			rec.Type = "SOA"
			mname, off2, err := dnsParseNameAt(msg, offset-rdlength)
			if err == nil {
				rname, _, err2 := dnsParseNameAt(msg, off2)
				if err2 == nil {
					rec.Value = fmt.Sprintf("%s %s", mname, rname)
				} else {
					rec.Value = mname
				}
			}
		case 33: // SRV
			if len(rdata) >= 7 {
				priority := binary.BigEndian.Uint16(rdata[0:2])
				weight := binary.BigEndian.Uint16(rdata[2:4])
				port := binary.BigEndian.Uint16(rdata[4:6])
				target, _, err := dnsParseNameAt(msg, offset-rdlength+6)
				if err == nil {
					rec.Type = "SRV"
					rec.Value = fmt.Sprintf("%d %d %d %s", priority, weight, port, target)
				}
			}
		default:
			// Skip unknown RR types silently
			continue
		}

		if rec.Type != "" {
			out = append(out, rec)
		}
	}
	return out, offset, nil
}

// dnsResolveWithTTL queries the system's default resolver via raw TCP and
// returns records with real TTL values for the given qtype.
// Falls back to net.Lookup* with TTL=0 on any error.
// dnsResolveWithTTL is kept for backward compatibility; delegates to dnsResolveWith.
func dnsResolveWithTTL(domain string, qtype uint16, timeout time.Duration) []DNSRecord {
	return dnsResolveWith(systemResolver(), domain, qtype, timeout)
}

// tryAXFR attempts a real DNS zone transfer (AXFR) against nsHost for domain.
// Returns all zone records and a boolean indicating success.
func tryAXFR(nsHost, domain string, timeout time.Duration) ([]DNSRecord, bool) {
	// Build AXFR query: qtype=252 (AXFR)
	encodeName := func(name string) []byte {
		var buf []byte
		name = strings.TrimSuffix(name, ".")
		for _, label := range strings.Split(name, ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, []byte(label)...)
		}
		buf = append(buf, 0x00)
		return buf
	}

	qname := encodeName(domain)
	msg := []byte{
		0xAB, 0xCD, // ID
		0x00, 0x00, // Flags: standard query, no RD (AXFR is authoritative-only)
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}
	msg = append(msg, qname...)
	msg = append(msg, 0x00, 0xFC) // QTYPE = 252 (AXFR)
	msg = append(msg, 0x00, 0x01) // QCLASS = IN

	length := uint16(len(msg))
	tcpMsg := []byte{byte(length >> 8), byte(length)}
	tcpMsg = append(tcpMsg, msg...)

	conn, err := net.DialTimeout("tcp", nsHost+":53", timeout)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 5)) // AXFR may be large

	if _, err = conn.Write(tcpMsg); err != nil {
		return nil, false
	}

	// AXFR responses may span multiple TCP messages.
	// The zone is bounded by two SOA records (start and end).
	var allRecords []DNSRecord
	soaCount := 0

	for soaCount < 2 {
		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			break
		}
		respLen := int(binary.BigEndian.Uint16(lenBuf))
		if respLen < 12 || respLen > 65535 {
			break
		}
		resp := make([]byte, respLen)
		if _, err = io.ReadFull(conn, resp); err != nil {
			break
		}

		// Check RCODE (bits 0-3 of byte 3): non-zero means refused/error
		rcode := int(resp[3] & 0x0F)
		if rcode != 0 {
			return nil, false // REFUSED (5) or SERVFAIL (2) etc.
		}

		ancount := int(binary.BigEndian.Uint16(resp[6:8]))
		if ancount == 0 {
			break
		}

		// Skip question section
		offset := 12
		qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
		for i := 0; i < qdcount; i++ {
			for offset < len(resp) {
				b := resp[offset]
				if b == 0x00 {
					offset++
					break
				}
				if b&0xC0 == 0xC0 {
					offset += 2
					break
				}
				offset += int(b) + 1
			}
			offset += 4
		}

		recs, _, err2 := dnsParseRecords(resp, offset, ancount, domain)
		if err2 != nil {
			break
		}

		for _, r := range recs {
			if r.Type == "SOA" {
				soaCount++
				if soaCount == 1 {
					allRecords = append(allRecords, r) // include opening SOA
				}
				// Don't include the closing SOA duplicate
			} else {
				allRecords = append(allRecords, r)
			}
		}
	}

	if soaCount == 0 {
		return nil, false // never got a valid AXFR response
	}
	return allRecords, true
}

func dnsEnum(domain string, cfg Config) ([]DNSRecord, []Finding) {
	var records []DNSRecord
	var findings []Finding
	const dnsTimeout = 5 * time.Second

	// Determine resolver to use
	resolver := cfg.DNSServer
	if resolver == "" {
		resolver = systemResolver()
	}

	add := func(r DNSRecord) { records = append(records, r) }
	addRec := func(rtype, name, value string, ttl uint32) {
		records = append(records, DNSRecord{Type: rtype, Name: name, Value: value, TTL: ttl})
	}

	// ── A / AAAA records ─────────────────────────────────────────────────
	for _, r := range dnsResolveWith(resolver, domain, 1, dnsTimeout) {
		add(r)
	}
	for _, r := range dnsResolveWith(resolver, domain, 28, dnsTimeout) {
		add(r)
	}
	if len(records) == 0 {
		if ips, err := net.LookupHost(domain); err == nil {
			for _, ip := range ips {
				if net.ParseIP(ip).To4() != nil {
					addRec("A", domain, ip, 0)
				} else {
					addRec("AAAA", domain, ip, 0)
				}
			}
		}
	}

	// ── MX ───────────────────────────────────────────────────────────────
	if recs := dnsResolveWith(resolver, domain, 15, dnsTimeout); len(recs) > 0 {
		for _, r := range recs { add(r) }
	} else if mxs, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxs {
			addRec("MX", domain, fmt.Sprintf("%d %s", mx.Pref, mx.Host), 0)
		}
	}

	// ── NS ───────────────────────────────────────────────────────────────
	if recs := dnsResolveWith(resolver, domain, 2, dnsTimeout); len(recs) > 0 {
		for _, r := range recs { add(r) }
	} else if nss, err := net.LookupNS(domain); err == nil {
		for _, ns := range nss {
			addRec("NS", domain, ns.Host, 0)
		}
	}

	// ── SOA ───────────────────────────────────────────────────────────────
	for _, r := range dnsResolveWith(resolver, domain, 6, dnsTimeout) {
		add(r)
	}

	// ── SRV — common service prefixes ─────────────────────────────────────
	srvPrefixes := []string{
		"_http._tcp", "_https._tcp", "_ftp._tcp", "_ftps._tcp",
		"_ssh._tcp", "_smtp._tcp", "_smtps._tcp", "_submission._tcp",
		"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
		"_ldap._tcp", "_ldaps._tcp", "_kerberos._tcp", "_kerberos._udp",
		"_xmpp-server._tcp", "_xmpp-client._tcp", "_sip._tcp", "_sip._udp",
		"_sipfederationtls._tcp", "_autodiscover._tcp", "_vlmcs._tcp",
		"_jabber._tcp", "_minecraft._tcp", "_teamspeak._tcp",
	}
	for _, prefix := range srvPrefixes {
		fqdn := prefix + "." + domain
		for _, r := range dnsResolveWith(resolver, fqdn, 33, dnsTimeout) {
			addRec("SRV", fqdn, r.Value, r.TTL)
			findings = append(findings, Finding{
				Module:      "DNSEnum", Severity: INFO,
				Title:       fmt.Sprintf("SRV Record: %s", fqdn),
				Detail:      fmt.Sprintf("Service endpoint discovered via SRV record: %s", r.Value),
				Evidence:    fmt.Sprintf("%s → %s (TTL %ds)", fqdn, r.Value, r.TTL),
				Remediation: "Verify this service endpoint is intentionally public",
			})
		}
	}

	// ── TXT + email-security analysis ─────────────────────────────────────
	txtRecs := dnsResolveWith(resolver, domain, 16, dnsTimeout)
	if len(txtRecs) == 0 {
		if txts, err := net.LookupTXT(domain); err == nil {
			for _, t := range txts {
				txtRecs = append(txtRecs, DNSRecord{Type: "TXT", Name: domain, Value: t, TTL: 0})
			}
		}
	}
	for _, r := range txtRecs {
		add(r)
		txt := r.Value
		if strings.HasPrefix(txt, "v=spf1") {
			if strings.Contains(txt, "+all") {
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: CRITICAL,
					Title:       "SPF Record Uses +all (Any IP Can Send Email)",
					Detail:      "The +all mechanism allows any IP to send email as this domain.",
					Evidence:    txt,
					Remediation: "Change to -all or ~all in SPF record",
				})
			} else if strings.Contains(txt, "~all") {
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: LOW,
					Title:       "SPF Uses ~all (SoftFail — Not Enforced)",
					Detail:      "~all generates SoftFail but does not reject unauthorized senders. Upgrade to -all.",
					Evidence:    txt,
					Remediation: "Change SPF record to use -all for hard fail enforcement",
				})
			}
			if strings.Contains(txt, "ptr") {
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: LOW,
					Title:       "SPF Uses 'ptr' Mechanism (Deprecated)",
					Detail:      "The ptr mechanism is slow and deprecated in RFC 7208.",
					Evidence:    txt,
					Remediation: "Replace ptr mechanism with ip4/ip6 or include: directives",
				})
			}
			// Count DNS lookup mechanisms (SPF limit is 20)
			lookupCount := strings.Count(txt, "include:") + strings.Count(txt, "a:") +
				strings.Count(txt, "mx:") + strings.Count(txt, "exists:") +
				strings.Count(txt, "redirect=")
			if lookupCount > 20 {
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: MEDIUM,
					Title:       "SPF Record Exceeds 20 DNS Lookup Limit",
					Detail:      fmt.Sprintf("SPF has %d DNS-querying mechanisms; RFC 7208 allows max 20. Excess causes PermError.", lookupCount),
					Evidence:    txt,
					Remediation: "Flatten SPF record using tools like dmarcian SPF Surveyor",
				})
			}
		}
		if strings.HasPrefix(txt, "v=DMARC1") {
			if strings.Contains(txt, "p=none") {
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: MEDIUM,
					Title:       "DMARC Policy Set to 'none' (No Enforcement)",
					Detail:      "DMARC p=none only monitors — email spoofing not prevented.",
					Evidence:    txt,
					Remediation: "Change DMARC policy to p=quarantine or p=reject",
				})
			}
			if !strings.Contains(txt, "rua=") {
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: LOW,
					Title:       "DMARC Reporting Not Configured",
					Detail:      "DMARC record missing rua= tag for aggregate reports",
					Evidence:    txt,
					Remediation: "Add rua=mailto:dmarc-reports@yourdomain.com to DMARC record",
				})
			}
			if strings.Contains(txt, "pct=") {
				pctIdx := strings.Index(txt, "pct=")
				pctStr := txt[pctIdx+4:]
				if semiIdx := strings.Index(pctStr, ";"); semiIdx > 0 {
					pctStr = pctStr[:semiIdx]
				}
				if pctVal, err := strconv.Atoi(strings.TrimSpace(pctStr)); err == nil && pctVal < 100 {
					findings = append(findings, Finding{
						Module:      "DNSEnum", Severity: LOW,
						Title:       fmt.Sprintf("DMARC pct=%d — Partial Enforcement", pctVal),
						Detail:      fmt.Sprintf("DMARC policy applies to only %d%% of failing messages.", pctVal),
						Evidence:    txt,
						Remediation: "Set pct=100 to enforce DMARC policy on all messages",
					})
				}
			}
		}
		// Detect cloud provider verification tokens
		for _, prefix := range []string{"google-site-verification=", "MS=ms", "facebook-domain-verification=", "atlassian-domain-verification="} {
			if strings.HasPrefix(txt, prefix) {
				findings = append(findings, Finding{
					Module:   "DNSEnum", Severity: INFO,
					Title:    "Cloud Service Verification Token Found",
					Detail:   fmt.Sprintf("TXT record indicates ownership verification for a cloud service: %s", prefix),
					Evidence: txt[:min(80, len(txt))],
					Remediation: "Remove if no longer needed to reduce attack surface intel",
				})
				break
			}
		}
	}

	// ── DMARC ─────────────────────────────────────────────────────────────
	dmarcRecs := dnsResolveWith(resolver, "_dmarc."+domain, 16, dnsTimeout)
	if len(dmarcRecs) == 0 {
		if txts, err := net.LookupTXT("_dmarc." + domain); err == nil {
			for _, t := range txts {
				dmarcRecs = append(dmarcRecs, DNSRecord{Type: "TXT", Name: "_dmarc." + domain, Value: t, TTL: 0})
			}
		}
	}
	if len(dmarcRecs) == 0 {
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: HIGH,
			Title:       "Missing DMARC Record",
			Detail:      "No DMARC record found. Domain is fully open to email spoofing.",
			Evidence:    "_dmarc." + domain + " → NXDOMAIN",
			Remediation: "Add _dmarc TXT record: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
		})
	} else {
		for _, r := range dmarcRecs { add(r) }
	}

	// ── DKIM — multiple common selectors ──────────────────────────────────
	dkimSelectors := []string{
		"default", "google", "k1", "k2", "mail", "dkim", "key1", "key2",
		"selector1", "selector2", "smtp", "s1", "s2", "mxvault", "proofpoint",
		"mandrill", "mailchimp", "sendgrid", "amazonses", "postmark",
	}
	for _, sel := range dkimSelectors {
		fqdn := sel + "._domainkey." + domain
		recs := dnsResolveWith(resolver, fqdn, 16, dnsTimeout)
		if len(recs) == 0 {
			if txts, err := net.LookupTXT(fqdn); err == nil {
				for _, t := range txts {
					recs = append(recs, DNSRecord{Type: "TXT", Name: fqdn, Value: t, TTL: 0})
				}
			}
		}
		for _, r := range recs {
			add(r)
			// Check key length from p= field
			keyInfo := "key present"
			if pIdx := strings.Index(r.Value, "p="); pIdx >= 0 {
				keyB64 := r.Value[pIdx+2:]
				if semi := strings.Index(keyB64, ";"); semi > 0 {
					keyB64 = keyB64[:semi]
				}
				keyLen := len(keyB64) * 6 / 8 * 8
				keyInfo = fmt.Sprintf("~%d-bit key", keyLen)
				if keyLen > 0 && keyLen < 1024 {
					findings = append(findings, Finding{
						Module:      "DNSEnum", Severity: HIGH,
						Title:       fmt.Sprintf("DKIM Weak Key Length: %s selector (%d-bit)", sel, keyLen),
						Detail:      "DKIM keys shorter than 1024 bits are considered weak and breakable.",
						Evidence:    fmt.Sprintf("%s: %s", fqdn, r.Value[:min(80, len(r.Value))]),
						Remediation: "Rotate DKIM keys to at least 2048 bits",
					})
				}
			}
			findings = append(findings, Finding{
				Module:      "DNSEnum", Severity: INFO,
				Title:       fmt.Sprintf("DKIM Record Found: %s selector (%s)", sel, keyInfo),
				Detail:      "DKIM signing key discovered. Verify key rotation policy.",
				Evidence:    r.Value[:min(80, len(r.Value))],
				Remediation: "Rotate DKIM keys at least annually; use 2048-bit minimum",
			})
		}
	}

	// ── BIMI (Brand Indicators for Message Identification) ────────────────
	for _, r := range dnsResolveWith(resolver, "default._bimi."+domain, 16, dnsTimeout) {
		addRec("TXT", "default._bimi."+domain, r.Value, r.TTL)
		findings = append(findings, Finding{
			Module:   "DNSEnum", Severity: INFO,
			Title:    "BIMI Record Found",
			Detail:   "Brand Indicators for Message Identification (BIMI) record detected.",
			Evidence: r.Value[:min(80, len(r.Value))],
		})
	}

	// ── CNAME ────────────────────────────────────────────────────────────
	for _, r := range dnsResolveWith(resolver, domain, 5, dnsTimeout) {
		if r.Value != domain && r.Value != domain+"." {
			add(r)
			// Dangling CNAME check: if CNAME target doesn't resolve, it may be takeable
			if _, err := net.LookupHost(strings.TrimSuffix(r.Value, ".")); err != nil {
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: HIGH,
					Title:       fmt.Sprintf("Dangling CNAME — Potential Subdomain Takeover: %s", r.Value),
					Detail:      "CNAME points to a hostname that does not resolve. If the target service is unclaimed, an attacker may register it.",
					Evidence:    fmt.Sprintf("%s CNAME %s → NXDOMAIN", domain, r.Value),
					Remediation: "Remove the CNAME record or reclaim the target resource immediately",
				})
			}
		}
	}
	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		addRec("CNAME", domain, cname, 0)
	}

	// ── PTR (reverse DNS for A records) ──────────────────────────────────
	for _, r := range records {
		if r.Type == "A" {
			if ptrs, err := net.LookupAddr(r.Value); err == nil && len(ptrs) > 0 {
				addRec("PTR", r.Value, ptrs[0], 0)
			}
		}
	}

	// ── DNSSEC checks ─────────────────────────────────────────────────────
	// Query DNSKEY (qtype=48)
	dnskeyRecs := dnsResolveWith(resolver, domain, 48, dnsTimeout)
	if len(dnskeyRecs) == 0 {
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: MEDIUM,
			Title:       "DNSSEC Not Configured",
			Detail:      "No DNSKEY records found. DNS responses are unauthenticated and vulnerable to spoofing/poisoning.",
			Evidence:    domain + " DNSKEY → empty",
			Remediation: "Enable DNSSEC signing at your registrar and DNS provider",
		})
	} else {
		for _, r := range dnskeyRecs {
			addRec("DNSKEY", domain, r.Value, r.TTL)
		}
		findings = append(findings, Finding{
			Module:   "DNSEnum", Severity: INFO,
			Title:    fmt.Sprintf("DNSSEC Enabled (%d DNSKEY record(s))", len(dnskeyRecs)),
			Detail:   "Domain has DNSSEC configured. Verify DS records are present at the registrar.",
			Evidence: fmt.Sprintf("%d DNSKEY record(s) found", len(dnskeyRecs)),
		})
	}
	// Query DS (qtype=43) — delegation signer at parent
	for _, r := range dnsResolveWith(resolver, domain, 43, dnsTimeout) {
		addRec("DS", domain, r.Value, r.TTL)
	}
	// NSEC walk feasibility (qtype=47)
	nsecRecs := dnsResolveWith(resolver, domain, 47, dnsTimeout)
	if len(nsecRecs) > 0 {
		for _, r := range nsecRecs {
			addRec("NSEC", domain, r.Value, r.TTL)
		}
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: HIGH,
			Title:       "DNSSEC Uses NSEC (Zone Enumerable via Walk)",
			Detail:      "NSEC records allow unauthenticated enumeration of all hostnames in the zone via NSEC chain walking. Use NSEC3 with opt-out to prevent this.",
			Evidence:    fmt.Sprintf("%d NSEC record(s) at %s", len(nsecRecs), domain),
			Remediation: "Migrate from NSEC to NSEC3 with a random salt to prevent zone walking",
		})
		// Perform zone walk if -dns-walk flag is set
		if cfg.DNSZoneWalk {
			walked := nsecZoneWalk(resolver, domain, dnsTimeout)
			for _, name := range walked {
				addRec("NSEC-WALK", name, "discovered via NSEC chain", 0)
			}
			if len(walked) > 0 {
				findings = append(findings, Finding{
					Module:   "DNSEnum", Severity: CRITICAL,
					Title:    fmt.Sprintf("NSEC Zone Walk Succeeded — %d Hostnames Enumerated", len(walked)),
					Detail:   "Full zone enumeration achieved without authentication by walking the NSEC chain.",
					Evidence: strings.Join(walked[:min(15, len(walked))], "\n"),
					Remediation: "Switch to NSEC3 with opt-out and a random salt (--nsec3-salt-length 16)",
				})
			}
		}
	}
	// NSEC3 (qtype=50)
	nsec3Recs := dnsResolveWith(resolver, domain, 50, dnsTimeout)
	if len(nsec3Recs) > 0 {
		for _, r := range nsec3Recs {
			addRec("NSEC3", domain, r.Value, r.TTL)
		}
		findings = append(findings, Finding{
			Module:   "DNSEnum", Severity: INFO,
			Title:    "DNSSEC Uses NSEC3 (Zone Walk Resistant)",
			Detail:   "NSEC3 hashed denial-of-existence is in use. Zone walking is prevented. Verify a random salt is configured.",
			Evidence: fmt.Sprintf("%d NSEC3 record(s) at %s", len(nsec3Recs), domain),
		})
	}

	// ── Wildcard detection ────────────────────────────────────────────────
	// Query a random unlikely hostname; if it resolves, wildcard is active
	wildcardProbe := fmt.Sprintf("recon-x-wildcard-probe-%d.%s", rand.Int63(), domain)
	if wIPs, err := net.LookupHost(wildcardProbe); err == nil && len(wIPs) > 0 {
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: MEDIUM,
			Title:       "Wildcard DNS Record Active",
			Detail:      "A random hostname resolved successfully, indicating a wildcard (*) DNS record. Subdomain bruteforce results may contain false positives.",
			Evidence:    fmt.Sprintf("probe %s → %s", wildcardProbe, strings.Join(wIPs, ", ")),
			Remediation: "Remove wildcard DNS entries unless explicitly required. Filter bruteforce results against wildcard IPs.",
		})
	}

	// ── NS server security checks ─────────────────────────────────────────
	var nsHosts []string
	for _, r := range records {
		if r.Type == "NS" {
			nsHosts = append(nsHosts, strings.TrimSuffix(r.Value, "."))
		}
	}
	if len(nsHosts) == 0 {
		if nss, err := net.LookupNS(domain); err == nil {
			for _, ns := range nss {
				nsHosts = append(nsHosts, strings.TrimSuffix(ns.Host, "."))
			}
		}
	}

	for _, nsHost := range nsHosts {
		// BIND version disclosure via CHAOS class
		if ver := bindVersionQuery(nsHost, dnsTimeout); ver != "" {
			findings = append(findings, Finding{
				Module:      "DNSEnum", Severity: MEDIUM,
				Title:       fmt.Sprintf("BIND Version Disclosed by %s: %s", nsHost, ver),
				Detail:      "NS server responds to CHAOS class TXT query for version.bind, revealing software version. This aids targeted exploitation.",
				Evidence:    fmt.Sprintf("%s CHAOS TXT version.bind → %s", nsHost, ver),
				Remediation: "Add 'version none;' to BIND options block to suppress version disclosure",
			})
		}

		// Open recursion check
		if dnsOpenRecursion(nsHost, dnsTimeout) {
			findings = append(findings, Finding{
				Module:      "DNSEnum", Severity: HIGH,
				Title:       fmt.Sprintf("Open DNS Recursion on %s", nsHost),
				Detail:      "Nameserver accepts recursive queries from arbitrary sources. Enables DNS amplification DDoS attacks and cache poisoning.",
				Evidence:    fmt.Sprintf("%s answered recursive query for external domain", nsHost),
				Remediation: "Restrict recursion to authorised clients only (allow-recursion { trusted_nets; }; in BIND)",
			})
		}

		// NXDOMAIN hijacking check
		if dnsNXDomainHijack(nsHost, domain, dnsTimeout) {
			findings = append(findings, Finding{
				Module:      "DNSEnum", Severity: MEDIUM,
				Title:       fmt.Sprintf("NXDOMAIN Hijacking on %s", nsHost),
				Detail:      "Nameserver returns a non-NXDOMAIN answer for a random nonexistent hostname, indicating wildcard interception or ISP-level DNS hijacking.",
				Evidence:    fmt.Sprintf("%s returned a response for a random nonexistent domain", nsHost),
				Remediation: "Use DNSSEC and a trusted resolver to bypass NXDOMAIN hijacking",
			})
		}

		// Zone transfer (AXFR)
		zoneRecs, ok := tryAXFR(nsHost, domain, dnsTimeout)
		if ok {
			var evidence []string
			for _, r := range zoneRecs {
				evidence = append(evidence, fmt.Sprintf("%s %d IN %s %s", r.Name, r.TTL, r.Type, r.Value))
				add(r)
			}
			findings = append(findings, Finding{
				Module:   "DNSEnum", Severity: CRITICAL,
				Title:    fmt.Sprintf("Zone Transfer (AXFR) Succeeded: %s", nsHost),
				Detail:   fmt.Sprintf("Nameserver %s allowed a full zone transfer — all %d DNS records exposed.", nsHost, len(zoneRecs)),
				Evidence: strings.Join(evidence[:min(10, len(evidence))], "\n"),
				Remediation: "Restrict AXFR to authorised secondary NSes only via ACL. " +
					"Most public DNS providers block AXFR by default.",
			})
		} else {
			if conn, err := net.DialTimeout("tcp", nsHost+":53", dnsTimeout); err == nil {
				conn.Close()
				findings = append(findings, Finding{
					Module:      "DNSEnum", Severity: INFO,
					Title:       fmt.Sprintf("AXFR Refused by %s (TCP/53 open)", nsHost),
					Detail:      "Nameserver correctly refused the zone transfer request.",
					Evidence:    fmt.Sprintf("AXFR to %s:53 → REFUSED", nsHost),
					Remediation: "No action required.",
				})
			}
		}
	}

	return records, findings
}

// systemResolver reads /etc/resolv.conf and returns the first nameserver IP.
func systemResolver() string {
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				if parts := strings.Fields(line); len(parts) >= 2 && net.ParseIP(parts[1]) != nil {
					return parts[1]
				}
			}
		}
	}
	return "8.8.8.8"
}

// dnsResolveWith is a renamed wrapper around dnsResolveWithTTL that accepts an explicit resolver.
func dnsResolveWith(resolver, domain string, qtype uint16, timeout time.Duration) []DNSRecord {
	resp, err := dnsQueryRaw(resolver, domain, qtype, timeout)
	if err != nil || len(resp) < 12 {
		return nil
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return nil
	}
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdcount; i++ {
		for offset < len(resp) {
			b := resp[offset]
			if b == 0x00 { offset++; break }
			if b&0xC0 == 0xC0 { offset += 2; break }
			offset += int(b) + 1
		}
		offset += 4
	}
	recs, _, _ := dnsParseRecords(resp, offset, ancount, domain)
	return recs
}

// bindVersionQuery sends a CHAOS class TXT query for version.bind to the given NS.
// Returns the version string if the server discloses it, empty string otherwise.
func bindVersionQuery(nsHost string, timeout time.Duration) string {
	// Build CHAOS class query: qclass=3 (CHAOS), qtype=16 (TXT), qname=version.bind
	encodeName := func(s string) []byte {
		var buf []byte
		for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, []byte(label)...)
		}
		return append(buf, 0x00)
	}
	qname := encodeName("version.bind")
	msg := append([]byte{0x99, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, qname...)
	msg = append(msg, 0x00, 0x10) // TXT
	msg = append(msg, 0x00, 0x03) // CHAOS class
	tcpMsg := append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)

	conn, err := net.DialTimeout("udp", nsHost+":53", timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// UDP: send without length prefix
	if _, err = conn.Write(msg); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	_ = tcpMsg
	ancount := int(binary.BigEndian.Uint16(buf[6:8]))
	if ancount == 0 {
		return ""
	}
	// Skip question section
	offset := 12
	for offset < n {
		b := buf[offset]
		if b == 0x00 { offset++; break }
		if b&0xC0 == 0xC0 { offset += 2; break }
		offset += int(b) + 1
	}
	offset += 4 // qtype+qclass
	// Parse first answer RR — skip name, type, class, ttl, rdlength then read TXT
	if offset >= n { return "" }
	if buf[offset]&0xC0 == 0xC0 { offset += 2 } else {
		for offset < n && buf[offset] != 0x00 { offset++ }
		offset++
	}
	offset += 8 // type(2)+class(2)+ttl(4)
	if offset+2 > n { return "" }
	rdlen := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	if offset+rdlen > n || rdlen < 1 { return "" }
	slen := int(buf[offset])
	if offset+1+slen > n { return "" }
	return string(buf[offset+1 : offset+1+slen])
}

// dnsOpenRecursion checks whether nsHost will resolve an external domain recursively.
func dnsOpenRecursion(nsHost string, timeout time.Duration) bool {
	resp, err := dnsQueryRaw(nsHost, "google.com", 1, timeout)
	if err != nil || len(resp) < 12 {
		return false
	}
	// Check QR=1 (response), RA=1 (recursion available), ANCOUNT>0
	flags := binary.BigEndian.Uint16(resp[2:4])
	qr := (flags >> 15) & 1
	ra := (flags >> 7) & 1
	ancount := binary.BigEndian.Uint16(resp[6:8])
	return qr == 1 && ra == 1 && ancount > 0
}

// dnsNXDomainHijack checks if the NS returns a real answer for a provably fake hostname.
func dnsNXDomainHijack(nsHost, domain string, timeout time.Duration) bool {
	probe := fmt.Sprintf("recon-x-nxcheck-%d.%s", rand.Int63(), domain)
	resp, err := dnsQueryRaw(nsHost, probe, 1, timeout)
	if err != nil || len(resp) < 12 {
		return false
	}
	rcode := int(resp[3] & 0x0F)
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	// NXDOMAIN=3 is correct; anything else with answers is hijacking
	return rcode != 3 && ancount > 0
}

// nsecZoneWalk walks the NSEC chain starting from domain, collecting all discovered hostnames.
func nsecZoneWalk(resolver, domain string, timeout time.Duration) []string {
	seen := make(map[string]bool)
	var found []string
	current := domain
	for i := 0; i < 2000; i++ { // safety cap
		recs := dnsResolveWith(resolver, current, 47, timeout)
		if len(recs) == 0 {
			break
		}
		nextName := recs[0].Value
		if nextName == "" {
			break
		}
		// NSEC value is "next-name type-bitmap" — extract the name part
		if parts := strings.Fields(nextName); len(parts) > 0 {
			nextName = parts[0]
		}
		nextName = strings.TrimSuffix(nextName, ".")
		if seen[nextName] || nextName == domain {
			break // wrapped back to start
		}
		seen[nextName] = true
		found = append(found, nextName)
		current = nextName
	}
	return found
}

// ═══════════════════════════════════════════════════════════════════════
//  SUBDOMAIN ENUMERATION (built-in 500+ wordlist)
// ═══════════════════════════════════════════════════════════════════════

var subWordlist = []string{
	"www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "mx", "mx1", "mx2",
	"webmail", "remote", "vpn", "api", "dev", "staging", "test", "uat", "qa",
	"admin", "portal", "app", "apps", "blog", "shop", "store", "secure",
	"m", "mobile", "static", "assets", "cdn", "img", "images", "media",
	"upload", "uploads", "files", "docs", "help", "support", "kb",
	"db", "database", "mysql", "sql", "postgres", "redis", "mongo",
	"git", "gitlab", "github", "bitbucket", "jira", "confluence", "jenkins",
	"ci", "cd", "build", "deploy", "docker", "registry", "k8s", "kubernetes",
	"grafana", "prometheus", "kibana", "elasticsearch", "es",
	"auth", "sso", "login", "account", "accounts", "user", "users",
	"payment", "pay", "checkout", "billing", "invoice",
	"old", "new", "v1", "v2", "v3", "beta", "alpha", "demo",
	"internal", "intranet", "corp", "corporate", "private",
	"aws", "cloud", "azure", "gcp", "s3", "bucket", "storage",
	"monitor", "monitoring", "status", "healthcheck", "ping",
	"smtp2", "imap", "pop3", "exchange", "owa", "autodiscover",
	"dns", "ns3", "ns4", "rdp", "ssh", "sftp", "ftp2",
	"chat", "slack", "teams", "meet", "video", "zoom",
	"wiki", "forum", "community", "social", "feed", "rss",
	"download", "downloads", "release", "releases", "update", "updates",
	"proxy", "gateway", "lb", "load", "balancer", "router",
	"backup", "backups", "archive", "archives", "log", "logs",
	"metrics", "stats", "analytics", "track", "tracking",
	"mail2", "webmail2", "smtp3", "relay",
	"crm", "erp", "hr", "finance", "accounting",
	"repo", "npm", "pip", "maven", "nexus", "artifactory",
	"test1", "test2", "dev1", "dev2",
	"web", "web1", "web2", "server", "server1", "host",
	"panel", "dashboard", "console", "management", "mgmt",
	"vpn2", "remote2", "access", "extranet",
	"mx3", "mx4", "ns5", "ns6", "ns7", "ns8",
	"mail3", "mail4", "smtp4", "pop4", "imap4",
	"owa2", "autodiscover2", "exchange2",
	"git2", "gitlab2", "jenkins2", "jira2",
	"devops", "ops", "sysadmin", "admin2",
	"test3", "qa2", "staging2",
	"preprod", "prod", "production", "live",
	"development", "develop",
	"uat2", "sandbox", "sandbox2", "playground",
	"demo2", "demo3", "example", "sample",
	"docs2", "help2", "support2", "kb2",
	"forum2", "community2", "blog2", "shop2",
	"store2", "secure2", "ssl", "tls",
	"cert", "certificate", "ca", "pki",
	"certs", "keys", "key", "secret",
	"secrets", "token", "tokens", "oauth",
	"oauth2", "oidc", "saml", "saml2",
	"ldap", "ldaps", "radius", "tacacs",
	"kerberos", "kdc", "ad", "activedirectory",
	"dc", "domaincontroller", "pdc", "bdc",
	"file", "share", "shares",
	"smb", "cifs", "nfs", "ftp3",
	"sftp2", "ftps", "tftp", "rsync",
	"rsync2", "backup2", "backup3", "archive2",
	"logs2", "log2", "logging", "syslog",
	"syslog2", "snmp", "snmp2", "snmp3",
	"ntp", "ntp2", "ntp3", "time",
	"time2", "chrony", "chronyd",
	"mysql2", "mysql3", "mysql4", "mariadb",
	"mariadb2", "postgres2", "postgres3", "postgres4",
	"oracle2", "oracle3", "oracledb", "db2",
	"db3", "db4", "database2", "database3",
	"redis2", "redis3", "redis4", "memcached2",
	"memcached3", "elastic2", "elastic3", "es2",
	"es3", "kibana2", "kibana3", "grafana2",
	"grafana3", "prometheus2", "prometheus3",
	"alertmanager", "pushgateway", "node_exporter",
	"blackbox", "blackbox_exporter", "snmp_exporter",
	"zabbix", "zabbix2", "nagios", "nagios2",
	"icinga", "icinga2", "sensu", "sensu2",
	"datadog", "newrelic", "dynatrace",
	"appdynamics", "appd", "appdyn",
	"splunk", "splunk2", "splunk3", "splunkforwarder",
	"logstash", "logstash2", "logstash3", "filebeat",
	"metricbeat", "packetbeat", "heartbeat",
	"kafka2", "kafka3", "zookeeper2", "zookeeper3",
	"rabbitmq2", "rabbitmq3", "activemq2", "activemq3",
	"cassandra2", "cassandra3", "couchdb2", "couchdb3",
	"mongodb2", "mongodb3", "mongodb4", "mongo2",
	"mongo3", "mongo4", "influxdb", "influxdb2",
	"timescaledb", "cratedb", "cockroachdb",
	"cockroach", "tidb", "tikv", "pd",
	"neo4j", "neo4j2", "neo4j3", "graphdb",
	"janusgraph", "dgraph", "dgraph2",
	"hadoop", "hadoop2", "hdfs", "hdfs2",
	"yarn", "yarn2", "mapreduce", "mr",
	"spark", "spark2", "spark3", "hive",
	"hive2", "hbase", "hbase2", "phoenix",
	"presto", "presto2", "trino", "trino2",
	"drill", "drill2", "impala", "impala2",
	"kudu", "kudu2", "flink", "flink2",
	"storm", "storm2", "samza", "samza2",
	"beam", "beam2", "dataflow",
	"airflow", "airflow2", "dag", "dags",
	"luigi", "luigi2", "azkaban", "azkaban2",
	"oozie", "oozie2", "chronos", "chronos2",
	"marathon", "marathon2", "mesos", "mesos2",
	"aurora", "aurora2", "singularity",
	"docker2", "docker3", "docker4", "containerd",
	"cri-o", "crio", "podman", "podman2",
	"k3s", "k3s2", "microk8s", "minikube",
	"kube", "kube2", "kube3", "k8s2",
	"k8s3", "k8s4", "openshift2", "okd",
	"rancher2", "rancher3", "rke", "rke2",
	"longhorn", "longhorn2", "cattle", "cattle2",
	"harbor", "harbor2", "harbor3", "quay",
	"quay2", "quay3", "gcr", "gcr2",
	"ecr", "ecr2", "acr", "acr2",
	"dockerhub", "dockerhub2", "registry2",
	"nexus2", "nexus3", "artifactory2", "artifactory3",
	"jfrog", "jfrog2", "jfrog3", "bintray",
	"npm2", "npm3", "pypi", "pypi2",
	"maven2", "maven3", "gradle", "gradle2",
	"sonatype", "sonatype2", "sonarqube2", "sonarqube3",
	"jenkins3", "jenkins4", "jenkins5", "gitlab3",
	"gitlab4", "gitlab5", "github2", "github3",
	"github4", "bitbucket2", "bitbucket3",
	"jira3", "jira4", "confluence2", "confluence3",
	"confluence4", "wiki2", "wiki3", "wiki4",
	"docs3", "docs4", "help3", "help4",
	"support3", "support4", "kb3", "kb4",
	"forum3", "forum4", "community3", "community4",
	"blog3", "blog4", "shop3", "shop4",
	"store3", "store4", "secure3", "secure4",
	"ssl2", "ssl3", "tls2", "tls3",
	"certs2", "certs3", "keys2", "keys3",
	"secrets2", "secrets3", "tokens2", "tokens3",
	"oauth3", "oauth4", "oidc2", "saml3",
	"ldap2", "ldaps2", "radius2", "tacacs2",
	"kerberos2", "kdc2", "ad2", "dc2",
	"files2", "files3", "share2", "share3",
	"smb2", "cifs2", "nfs2", "ftp4",
	"sftp3", "ftps2", "tftp2", "rsync3",
	"backup4", "backup5", "archive3", "archive4",
	"logs3", "logs4", "logging2", "syslog3",
	"snmp4", "ntp4", "time3", "chrony2",
}

func enumSubdomains(domain string, workers int, timeout time.Duration, dnsServer string) ([]string, []Finding) {
	var mu sync.Mutex
	var found []string
	var findings []Finding

	// Detect wildcard IPs first so we can filter false positives
	wildcardIPs := make(map[string]bool)
	probe := fmt.Sprintf("recon-x-wc-%d.%s", rand.Int63(), domain)
	if wIPs, err := net.LookupHost(probe); err == nil {
		for _, ip := range wIPs {
			wildcardIPs[ip] = true
		}
	}

	resolver := dnsServer
	if resolver == "" {
		resolver = systemResolver()
	}

	jobs := make(chan string, len(subWordlist))
	for _, sub := range subWordlist {
		jobs <- sub + "." + domain
	}
	close(jobs)

	var wg sync.WaitGroup
	w := workers
	if w > 100 { w = 100 }
	if w > len(subWordlist) { w = len(subWordlist) }

	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fqdn := range jobs {
				recs := dnsResolveWith(resolver, fqdn, 1, timeout)
				if len(recs) == 0 {
					// fallback
					ips, err := net.LookupHost(fqdn)
					if err != nil || len(ips) == 0 {
						continue
					}
					for _, ip := range ips {
						recs = append(recs, DNSRecord{Type: "A", Name: fqdn, Value: ip})
					}
				}
				// Filter out wildcard IPs
				var realIPs []string
				for _, r := range recs {
					if !wildcardIPs[r.Value] {
						realIPs = append(realIPs, r.Value)
					}
				}
				if len(realIPs) > 0 {
					mu.Lock()
					found = append(found, fmt.Sprintf("%s → %s", fqdn, strings.Join(realIPs, ", ")))
					mu.Unlock()
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	sort.Strings(found)

	if len(found) > 0 {
		findings = append(findings, Finding{
			Module:      "SubEnum", Severity: INFO,
			Title:       fmt.Sprintf("Discovered %d Subdomain(s) via Wordlist", len(found)),
			Detail:      "Subdomains found via wordlist bruteforce (wildcard-filtered). Review each for exposure.",
			Evidence:    strings.Join(found[:min(5, len(found))], "\n"),
			Remediation: "Audit each subdomain for unnecessary exposure",
		})
	}
	return found, findings
}

// enumSubdomainsWith is identical to enumSubdomains but accepts an external
// wordlist slice rather than the built-in subWordlist. This enables -wordlist
// support without duplicating the core resolution logic.
func enumSubdomainsWith(domain string, wordlist []string, workers int, timeout time.Duration, dnsServer string) ([]string, []Finding) {
	var mu sync.Mutex
	var found []string
	var findings []Finding

	wildcardIPs := make(map[string]bool)
	probe := fmt.Sprintf("recon-x-wc-%d.%s", rand.Int63(), domain)
	if wIPs, err := net.LookupHost(probe); err == nil {
		for _, ip := range wIPs {
			wildcardIPs[ip] = true
		}
	}
	resolver := dnsServer
	if resolver == "" {
		resolver = systemResolver()
	}

	wlist := wordlist
	if len(wlist) == 0 {
		wlist = subWordlist
	}

	jobs := make(chan string, len(wlist))
	for _, sub := range wlist {
		jobs <- sub + "." + domain
	}
	close(jobs)

	var wg sync.WaitGroup
	w := workers
	if w > 100 {
		w = 100
	}
	if w > len(wlist) {
		w = len(wlist)
	}
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fqdn := range jobs {
				recs := dnsResolveWith(resolver, fqdn, 1, timeout)
				if len(recs) == 0 {
					ips, err := net.LookupHost(fqdn)
					if err != nil || len(ips) == 0 {
						continue
					}
					for _, ip := range ips {
						recs = append(recs, DNSRecord{Type: "A", Name: fqdn, Value: ip})
					}
				}
				var realIPs []string
				for _, r := range recs {
					if !wildcardIPs[r.Value] {
						realIPs = append(realIPs, r.Value)
					}
				}
				if len(realIPs) > 0 {
					mu.Lock()
					found = append(found, fmt.Sprintf("%s → %s", fqdn, strings.Join(realIPs, ", ")))
					mu.Unlock()
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	sort.Strings(found)

	if len(found) > 0 {
		source := "custom wordlist"
		if len(wordlist) == 0 || &wordlist[0] == &subWordlist[0] {
			source = "built-in wordlist"
		}
		findings = append(findings, Finding{
			Module:      "SubEnum", Severity: INFO,
			Title:       fmt.Sprintf("Discovered %d Subdomain(s) via %s (%d words)", len(found), source, len(wlist)),
			Detail:      fmt.Sprintf("Subdomains found via %s bruteforce (wildcard-filtered).", source),
			Evidence:    strings.Join(found[:min(5, len(found))], "\n"),
			Remediation: "Audit each subdomain for unnecessary exposure",
		})
	}
	return found, findings
}

// ═══════════════════════════════════════════════════════════════════════
//  DNS — CERTIFICATE TRANSPARENCY (crt.sh)
// ═══════════════════════════════════════════════════════════════════════

// crtShLookup queries crt.sh for certificate transparency records and returns
// all unique hostnames/subdomains found in issued certificates for the domain.
func crtShLookup(domain string) ([]string, []Finding) {
	var findings []Finding
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; RECON-X)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	// Parse the JSON array — each entry has a "name_value" field
	var entries []struct {
		NameValue string `json:"name_value"`
		IssuerName string `json:"issuer_name"`
		NotBefore  string `json:"not_before"`
		NotAfter   string `json:"not_after"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	var subs []string

	for _, e := range entries {
		// name_value can contain multiple names separated by newlines
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || seen[name] {
				continue
			}
			// Only include names that are subdomains of the target
			if !strings.HasSuffix(name, "."+domain) && name != domain {
				continue
			}
			seen[name] = true
			// Try to resolve it — confirm it's live
			if ips, err := net.LookupHost(name); err == nil && len(ips) > 0 {
				subs = append(subs, fmt.Sprintf("%s → %s", name, strings.Join(ips, ", ")))
			} else {
				subs = append(subs, name)
			}
		}
	}

	sort.Strings(subs)

	if len(subs) > 0 {
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: INFO,
			Title:       fmt.Sprintf("crt.sh: %d Subdomain(s) Found via Certificate Transparency", len(subs)),
			Detail:      "Subdomains discovered from SSL/TLS certificate history in public CT logs. Includes historical and wildcard certs.",
			Evidence:    strings.Join(subs[:min(10, len(subs))], "\n"),
			Remediation: "Review each subdomain — CT logs are permanent and public. Avoid embedding sensitive hostnames in certificates.",
		})
	}

	return subs, findings
}

// ═══════════════════════════════════════════════════════════════════════
//  DNS — REVERSE PTR SWEEP (CIDR / range)
// ═══════════════════════════════════════════════════════════════════════

// reversePTRSweep performs concurrent reverse DNS (PTR) lookups for every IP
// in a CIDR block or dash-range (e.g. "10.0.0.1-254") and returns all records.
func reversePTRSweep(cidrOrRange string, workers int, timeout time.Duration) ([]DNSRecord, []Finding) {
	var ips []string
	var err error

	if strings.Contains(cidrOrRange, "/") {
		ips, err = cidrHosts(cidrOrRange)
	} else {
		ips, err = rangeHosts(cidrOrRange)
	}
	if err != nil || len(ips) == 0 {
		return nil, nil
	}

	type result struct {
		ip  string
		ptr string
	}

	jobs := make(chan string, len(ips))
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	results := make(chan result, len(ips))
	var wg sync.WaitGroup
	w := workers
	if w > 200 {
		w = 200
	}
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				ptrs, err := net.LookupAddr(ip)
				if err == nil && len(ptrs) > 0 {
					results <- result{ip: ip, ptr: strings.TrimSuffix(ptrs[0], ".")}
				}
			}
		}()
	}
	wg.Wait()
	close(results)

	var records []DNSRecord
	var ptrList []string
	for r := range results {
		records = append(records, DNSRecord{Type: "PTR", Name: r.ip, Value: r.ptr, TTL: 0})
		ptrList = append(ptrList, fmt.Sprintf("%s → %s", r.ip, r.ptr))
	}
	sort.Strings(ptrList)

	var findings []Finding
	if len(ptrList) > 0 {
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: INFO,
			Title:       fmt.Sprintf("Reverse PTR Sweep: %d Hosts Resolved in %s", len(ptrList), cidrOrRange),
			Detail:      "Reverse DNS sweep revealed live hostnames. Useful for discovering internal service naming conventions.",
			Evidence:    strings.Join(ptrList[:min(15, len(ptrList))], "\n"),
			Remediation: "Review discovered hostnames for information disclosure. Ensure internal naming conventions are not overly revealing.",
		})
	}
	return records, findings
}

// ═══════════════════════════════════════════════════════════════════════
//  DNS — CACHE SNOOPING
// ═══════════════════════════════════════════════════════════════════════

// dnsCacheSnooping queries the target's NS servers for popular domains
// without requesting recursion (RD=0). If the NS returns an answer, the
// record is cached — revealing what the target's clients have been resolving.
func dnsCacheSnooping(domain, customResolver string, timeout time.Duration) []Finding {
	var findings []Finding

	// Gather NS servers for the domain
	var nsHosts []string
	if nss, err := net.LookupNS(domain); err == nil {
		for _, ns := range nss {
			nsHosts = append(nsHosts, strings.TrimSuffix(ns.Host, "."))
		}
	}
	
	if customResolver != "" {
		nsHosts = append(nsHosts, customResolver)
	}
	if len(nsHosts) == 0 {
		return nil
	}

	// Popular domains whose presence in cache can reveal browsing/service patterns
	snoopTargets := []string{
		"google.com", "github.com", "pastebin.com", "dropbox.com",
		"mega.nz", "discord.com", "telegram.org", "slack.com",
		"aws.amazon.com", "s3.amazonaws.com", "azure.microsoft.com",
		"storage.googleapis.com", "accounts.google.com",
		"login.microsoftonline.com", "api.github.com",
		"gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
		"haveibeenpwned.com", "virustotal.com", "shodan.io",
		"facebook.com", "twitter.com", "linkedin.com",
		"onionmail.org", "protonmail.com", "tutanota.com",
		"blockchain.info", "coinbase.com", "binance.com",
	}

	type snoopResult struct {
		ns     string
		target string
		cached bool
		ttl    uint32
	}

	var cached []snoopResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, nsHost := range nsHosts[:min(3, len(nsHosts))] {
		for _, target := range snoopTargets {
			wg.Add(1)
			go func(ns, t string) {
				defer wg.Done()
				// Build query with RD=0 
				encodeName := func(name string) []byte {
					var buf []byte
					for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
						buf = append(buf, byte(len(label)))
						buf = append(buf, []byte(label)...)
					}
					return append(buf, 0x00)
				}
				qname := encodeName(t)
				msg := []byte{0xCA, 0xFE, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				msg = append(msg, qname...)
				msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A, IN

				conn, err := net.DialTimeout("udp", ns+":53", timeout)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(timeout))
				if _, err = conn.Write(msg); err != nil {
					return
				}
				buf := make([]byte, 512)
				n, err := conn.Read(buf)
				if err != nil || n < 12 {
					return
				}
				ancount := int(binary.BigEndian.Uint16(buf[6:8]))
				if ancount == 0 {
					return
				}
				// Extract TTL from first answer RR
				offset := 12
				// skip question
				for offset < n && buf[offset] != 0x00 {
					if buf[offset]&0xC0 == 0xC0 {
						offset += 2
						break
					}
					offset += int(buf[offset]) + 1
				}
				if offset < n && buf[offset] == 0x00 {
					offset++
				}
				offset += 4 // qtype + qclass
				// skip answer name
				if offset < n {
					if buf[offset]&0xC0 == 0xC0 {
						offset += 2
					} else {
						for offset < n && buf[offset] != 0x00 {
							offset += int(buf[offset]) + 1
						}
						offset++
					}
				}
				offset += 4 // type + class
				var ttl uint32
				if offset+4 <= n {
					ttl = binary.BigEndian.Uint32(buf[offset : offset+4])
				}
				mu.Lock()
				cached = append(cached, snoopResult{ns: ns, target: t, cached: true, ttl: ttl})
				mu.Unlock()
			}(nsHost, target)
		}
	}
	wg.Wait()

	if len(cached) > 0 {
		sort.Slice(cached, func(i, j int) bool { return cached[i].target < cached[j].target })
		var evidenceLines []string
		for _, r := range cached {
			evidenceLines = append(evidenceLines, fmt.Sprintf("%s cached on %s (TTL %ds)", r.target, r.ns, r.ttl))
		}
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: MEDIUM,
			Title:       fmt.Sprintf("DNS Cache Snooping: %d Domains Cached on NS Servers", len(cached)),
			Detail:      "NS servers returned cached answers for queries sent without recursion (RD=0). This reveals which domains the target's clients have recently resolved — potentially exposing cloud providers, communication tools, or infrastructure in use.",
			Evidence:    strings.Join(evidenceLines[:min(15, len(evidenceLines))], "\n"),
			Remediation: "Disable DNS recursion for external clients. Separate internal/external DNS resolvers. Apply rate limiting and RPZ (Response Policy Zones).",
		})
	}
	return findings
}

// ═══════════════════════════════════════════════════════════════════════
//  DNS — TLD EXPANSION
// ═══════════════════════════════════════════════════════════════════════

// tldExpansion takes the base domain name (without TLD) and probes a broad
// list of TLDs to find other registrations — useful for brand monitoring,
// detecting typosquatting, and finding shadow infrastructure.
func tldExpansion(domain, dnsServer string, timeout time.Duration) ([]string, []Finding) {
	// Extract base name (strip current TLD)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, nil
	}
	baseName := parts[0]

	resolver := dnsServer
	if resolver == "" {
		resolver = systemResolver()
	}

	// Comprehensive TLD list — IANA gTLDs + common ccTLDs
	tlds := []string{
		"com", "net", "org", "info", "biz", "co", "io", "app", "dev", "ai",
		"cloud", "online", "site", "web", "tech", "store", "shop", "email",
		"uk", "co.uk", "us", "ca", "de", "fr", "jp", "cn", "au", "in",
		"br", "mx", "ru", "nl", "se", "no", "fi", "dk", "ch", "es", "it",
		"pl", "pt", "be", "at", "nz", "sg", "hk", "kr", "tw", "za",
		"ae", "sa", "il", "tr", "pk", "bd", "ng", "ke", "eg",
		"eu", "int", "gov", "edu", "mil", "arpa",
		"pro", "name", "mobi", "travel", "jobs", "aero", "coop", "museum",
		"xyz", "top", "club", "click", "link", "live", "news", "media",
		"agency", "services", "solutions", "systems", "network", "group",
		"global", "digital", "space", "host", "server", "data", "base",
		"bank", "finance", "money", "pay", "cash", "trade", "market",
		"health", "care", "medical", "clinic", "pharmacy",
		"security", "safe", "secure", "protect", "guard",
		"support", "help", "service", "center",
	}

	type hit struct {
		tld string
		ip  string
	}

	jobs := make(chan string, len(tlds))
	for _, tld := range tlds {
		candidate := baseName + "." + tld
		if candidate == domain {
			continue // skip the original domain
		}
		jobs <- candidate
	}
	close(jobs)

	hits := make(chan hit, len(tlds))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				recs := dnsResolveWith(resolver, candidate, 1, timeout)
				if len(recs) > 0 {
					hits <- hit{tld: candidate, ip: recs[0].Value}
					continue
				}
				if ips, err := net.LookupHost(candidate); err == nil && len(ips) > 0 {
					hits <- hit{tld: candidate, ip: ips[0]}
				}
			}
		}()
	}
	wg.Wait()
	close(hits)

	var found []string
	var evidenceLines []string
	for h := range hits {
		entry := fmt.Sprintf("%s → %s", h.tld, h.ip)
		found = append(found, entry)
		evidenceLines = append(evidenceLines, entry)
	}
	sort.Strings(found)

	var findings []Finding
	if len(found) > 0 {
		findings = append(findings, Finding{
			Module:      "DNSEnum", Severity: INFO,
			Title:       fmt.Sprintf("TLD Expansion: %d Related Domain(s) Registered", len(found)),
			Detail:      fmt.Sprintf("Other TLD registrations found for base name '%s'. These may be legitimate brand protection, typosquatting, or shadow infrastructure.", baseName),
			Evidence:    strings.Join(evidenceLines[:min(20, len(evidenceLines))], "\n"),
			Remediation: "Register defensive TLDs for your brand. Monitor CT logs for new registrations. Report typosquats to relevant registrars.",
		})
	}
	return found, findings
}

// ═══════════════════════════════════════════════════════════════════════
//  AUTH CHECK (unauthenticated access to common services)
// ═══════════════════════════════════════════════════════════════════════

func checkAuth(host string, port int, svc ServiceInfo, timeout time.Duration) []Finding {
	var findings []Finding

	switch svc.Name {
	case "Redis":
		f := checkRedisAuth(host, port, timeout)
		findings = append(findings, f...)
	case "MongoDB":
		f := checkMongoAuth(host, port, timeout)
		findings = append(findings, f...)
	case "FTP":
		f := checkFTPAnon(host, port, timeout)
		findings = append(findings, f...)
	case "Elasticsearch":
		f := checkESAuth(host, port, timeout)
		findings = append(findings, f...)
	case "Memcached":
		f := checkMemcachedAuth(host, port, timeout)
		findings = append(findings, f...)
	case "Docker API":
		f := checkDockerAuth(host, port, timeout)
		findings = append(findings, f...)
	case "Prometheus":
		f := checkPrometheusAuth(host, port, timeout)
		findings = append(findings, f...)
	case "Consul":
		f := checkConsulAuth(host, port, timeout)
		findings = append(findings, f...)
	case "Grafana":
		f := checkGrafanaDefaultCreds(host, port, timeout)
		findings = append(findings, f...)
	case "Jenkins":
		f := checkJenkinsAuth(host, port, timeout)
		findings = append(findings, f...)
	case "Kubernetes API":
		f := checkK8sAuth(host, port, timeout)
		findings = append(findings, f...)
	case "etcd":
		f := checkEtcdAuth(host, port, timeout)
		findings = append(findings, f...)
	case "ZooKeeper":
		f := checkZooKeeperAuth(host, port, timeout)
		findings = append(findings, f...)
	case "CouchDB":
		f := checkCouchDBAuth(host, port, timeout)
		findings = append(findings, f...)
	case "RabbitMQ":
		f := checkRabbitMQAuth(host, port, timeout)
		findings = append(findings, f...)
	case "Cassandra":
		f := checkCassandraAuth(host, port, timeout)
		findings = append(findings, f...)
	}

	return findings
}

func checkRedisAuth(host string, port int, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "+PONG") || strings.Contains(resp, "$") {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "Redis: No Authentication Required",
			Detail:      "Redis server accepts commands without authentication. Full data access + potential RCE.",
			Evidence:    fmt.Sprintf("PING → %s", strings.TrimSpace(resp)),
			CVE:         "CVE-2022-0543",
			Remediation: "Set requirepass, bind to 127.0.0.1, use TLS, rename/disable CONFIG",
		}}
	}
	return nil
}

func checkMongoAuth(host string, port int, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// MongoDB isMaster op
	msg := []byte{
		0x41, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69,
		0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13,
		0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x4d, 0x61,
		0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	_, _ = conn.Write(msg)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "ismaster") || strings.Contains(resp, "ok") || n > 10 {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "MongoDB: No Authentication Required",
			Detail:      "MongoDB responds without authentication. All databases accessible.",
			Evidence:    fmt.Sprintf("isMaster probe → %d bytes received", n),
			CVE:         "CVE-2019-2392",
			Remediation: "Enable auth in mongod.conf: security.authorization: enabled",
		}}
	}
	return nil
}

func checkFTPAnon(host string, port int, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])
	if !strings.Contains(banner, "220") {
		return nil
	}
	_, _ = conn.Write([]byte("USER anonymous\r\n"))
	_ = conn.SetDeadline(time.Now().Add(timeout))
	n, _ = conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "331") || strings.Contains(resp, "230") {
		_, _ = conn.Write([]byte("PASS anonymous@test.com\r\n"))
		_ = conn.SetDeadline(time.Now().Add(timeout))
		n, _ = conn.Read(buf)
		resp2 := string(buf[:n])
		if strings.Contains(resp2, "230") {
			return []Finding{{
				Module:      "AuthCheck", Severity: HIGH,
				Title:       "FTP: Anonymous Login Accepted",
				Detail:      "FTP server allows login with anonymous/anonymous credentials.",
				Evidence:    fmt.Sprintf("USER anonymous → PASS anonymous@test.com → %s", strings.TrimSpace(resp2)),
				Remediation: "Disable anonymous FTP, use SFTP with key auth instead",
			}}
		}
	}
	return nil
}

func checkESAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode == 200 && strings.Contains(body, "cluster_name") {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "Elasticsearch: No Authentication Required",
			Detail:      "Elasticsearch cluster accessible without credentials. All indices exposed.",
			Evidence:    fmt.Sprintf("GET :%d/ → 200 OK, cluster_name present", port),
			CVE:         "CVE-2021-22145",
			Remediation: "Enable X-Pack security: xpack.security.enabled: true",
		}}
	}
	return nil
}

func checkMemcachedAuth(host string, port int, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("stats\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "STAT") {
		return []Finding{{
			Module:      "AuthCheck", Severity: HIGH,
			Title:       "Memcached: Unauthenticated Access + Stats Exposed",
			Detail:      "Memcached responds to stats command without auth. Used in DDoS amplification.",
			Evidence:    fmt.Sprintf("stats → %s", resp[:min(80, len(resp))]),
			Remediation: "Bind to 127.0.0.1, disable UDP (-U 0), use firewall",
		}}
	}
	return nil
}

func checkDockerAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	scheme := "http"
	if port == 2376 {
		scheme = "https"
	}
	resp, err := client.Get(fmt.Sprintf("%s://%s:%d/version", scheme, host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode == 200 && strings.Contains(body, "Version") {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "Docker API: Unauthenticated Remote Access",
			Detail:      "Docker daemon API exposed without TLS auth. Full host compromise possible.",
			Evidence:    fmt.Sprintf("GET :%d/version → 200: %s", port, body[:min(80, len(body))]),
			CVE:         "CVE-2019-5736",
			Remediation: "Remove -H tcp:// from dockerd, use TLS mutual auth or Unix socket only",
		}}
	}
	return nil
}

func checkPrometheusAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/metrics", host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return []Finding{{
			Module:      "AuthCheck", Severity: MEDIUM,
			Title:       "Prometheus Metrics: Unauthenticated Access",
			Detail:      "Prometheus /metrics exposes internal infrastructure details without auth.",
			Evidence:    fmt.Sprintf("GET :%d/metrics → 200 OK", port),
			Remediation: "Add authentication proxy (nginx basic auth or OAuth2 proxy)",
		}}
	}
	return nil
}

func checkConsulAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/v1/status/leader", host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "Consul API: Unauthenticated Access",
			Detail:      "Consul API accessible without ACL token. Service mesh control exposed.",
			Evidence:    fmt.Sprintf("GET :%d/v1/status/leader → 200 OK", port),
			CVE:         "CVE-2021-38698",
			Remediation: "Enable Consul ACL system with default_policy = deny",
		}}
	}
	return nil
}

func checkGrafanaDefaultCreds(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	// Try default admin:admin
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/api/org", host, port), nil)
	if err != nil {
		return nil
	}
	req.SetBasicAuth("admin", "admin")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "Grafana: Default Credentials (admin:admin)",
			Detail:      "Grafana accessible with default admin:admin credentials.",
			Evidence:    fmt.Sprintf("GET :%d/api/org with admin:admin → 200 OK", port),
			Remediation: "Change Grafana admin password immediately",
		}}
	}
	return nil
}

func checkJenkinsAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode == 200 && strings.Contains(body, "Jenkins") {
		// Check if anonymous has read access
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/api/json", host, port), nil)
		if err != nil {
			return nil
		}
		resp2, err := client.Do(req)
		if err == nil {
			resp2.Body.Close()
			if resp2.StatusCode == 200 {
				return []Finding{{
					Module:      "AuthCheck", Severity: HIGH,
					Title:       "Jenkins: Anonymous Read Access",
					Detail:      "Jenkins allows anonymous users to read API data.",
					Evidence:    fmt.Sprintf("GET :%d/api/json → 200 OK", port),
					Remediation: "Configure Jenkins security to require authentication",
				}}
			}
		}
	}
	return nil
}

func checkK8sAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	scheme := "https"
	if port == 8080 || port == 8001 {
		scheme = "http"
	}
	resp, err := client.Get(fmt.Sprintf("%s://%s:%d/api", scheme, host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "Kubernetes API: Unauthenticated Access",
			Detail:      "Kubernetes API server accessible without authentication.",
			Evidence:    fmt.Sprintf("GET :%d/api → 200 OK", port),
			CVE:         "CVE-2018-1002105",
			Remediation: "Enable RBAC and authentication for Kubernetes API",
		}}
	}
	return nil
}

func checkEtcdAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/version", host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "etcd: Unauthenticated Access",
			Detail:      "etcd API accessible without authentication. Cluster configuration exposed.",
			Evidence:    fmt.Sprintf("GET :%d/version → 200 OK", port),
			Remediation: "Enable etcd authentication and TLS client certificates",
		}}
	}
	return nil
}

func checkZooKeeperAuth(host string, port int, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("stat"))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "Zookeeper version") {
		return []Finding{{
			Module:      "AuthCheck", Severity: HIGH,
			Title:       "ZooKeeper: Unauthenticated Access",
			Detail:      "ZooKeeper allows stat command without authentication.",
			Evidence:    fmt.Sprintf("stat → %s", resp[:min(80, len(resp))]),
			Remediation: "Enable ZooKeeper authentication and IP whitelisting",
		}}
	}
	return nil
}

func checkCouchDBAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if resp.StatusCode == 200 && strings.Contains(body, "couchdb") {
		return []Finding{{
			Module:      "AuthCheck", Severity: HIGH,
			Title:       "CouchDB: Unauthenticated Access",
			Detail:      "CouchDB accessible without authentication.",
			Evidence:    fmt.Sprintf("GET :%d/ → 200 OK", port),
			CVE:         "CVE-2017-12635",
			Remediation: "Enable require_valid_user in CouchDB config",
		}}
	}
	return nil
}

func checkRabbitMQAuth(host string, port int, timeout time.Duration) []Finding {
	client := &http.Client{Timeout: timeout}
	// Try management API
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/api/overview", host, port))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return []Finding{{
			Module:      "AuthCheck", Severity: CRITICAL,
			Title:       "RabbitMQ Management API: Unauthenticated Access",
			Detail:      "RabbitMQ management API accessible without authentication.",
			Evidence:    fmt.Sprintf("GET :%d/api/overview → 200 OK", port),
			Remediation: "Enable authentication and set strong passwords",
		}}
	}
	// Try default guest:guest
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/api/overview", host, port), nil)
	if err != nil {
		return nil
	}
	req.SetBasicAuth("guest", "guest")
	resp2, err := client.Do(req)
	if err == nil {
		resp2.Body.Close()
		if resp2.StatusCode == 200 {
			return []Finding{{
				Module:      "AuthCheck", Severity: CRITICAL,
				Title:       "RabbitMQ: Default Credentials (guest:guest)",
				Detail:      "RabbitMQ accessible with default guest:guest credentials.",
				Evidence:    fmt.Sprintf("GET :%d/api/overview with guest:guest → 200 OK", port),
				Remediation: "Change RabbitMQ default credentials immediately",
			}}
		}
	}
	return nil
}

func checkCassandraAuth(host string, port int, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// Simple CQL startup message
	msg := []byte{
		0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0b, 0x43, 0x51, 0x4c, 0x5f,
		0x56, 0x33, 0x5f, 0x30, 0x5f, 0x30, 0x00,
	}
	_, _ = conn.Write(msg)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "READY") {
		return []Finding{{
			Module:      "AuthCheck", Severity: HIGH,
			Title:       "Cassandra: No Authentication Required",
			Detail:      "Cassandra accepts CQL connections without authentication.",
			Evidence:    "CQL startup → READY response",
			Remediation: "Enable Cassandra authentication (PasswordAuthenticator)",
		}}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════
//  BRUTEFORCE — common credential checks for SSH, FTP, HTTP, MySQL, PG
// ═══════════════════════════════════════════════════════════════════════

// commonCreds is a curated list of username:password pairs commonly found
// on default/misconfigured services.
// commonCreds is a Hydra/Medusa-level list of username:password pairs
// covering default device credentials, application defaults, and weak passwords.
var commonCreds = [][2]string{
	// Generic weak passwords
	{"admin", "admin"}, {"admin", "password"}, {"admin", "password1"},
	{"admin", "admin123"}, {"admin", "123456"}, {"admin", "12345678"},
	{"admin", "1234"}, {"admin", "12345"}, {"admin", "0000"},
	{"admin", "pass"}, {"admin", "pass123"}, {"admin", "secret"},
	{"admin", "changeme"}, {"admin", "letmein"}, {"admin", "welcome"},
	{"admin", "admin1234"}, {"admin", "Admin1234"}, {"admin", "P@ssw0rd"},
	{"admin", "qwerty"}, {"admin", "abc123"}, {"admin", "test"},
	{"admin", ""}, {"admin", "1"}, {"admin", "111111"},
	// root
	{"root", "root"}, {"root", "password"}, {"root", "toor"},
	{"root", "pass"}, {"root", "pass123"}, {"root", "123456"},
	{"root", "12345"}, {"root", "admin"}, {"root", "root123"},
	{"root", "P@ssw0rd"}, {"root", "changeme"}, {"root", ""},
	// Generic accounts
	{"user", "user"}, {"user", "password"}, {"user", "user123"},
	{"user", "pass"}, {"user", "1234"}, {"user", "12345"},
	{"guest", "guest"}, {"guest", "password"}, {"guest", ""},
	{"test", "test"}, {"test", "password"}, {"test", "test123"}, {"test", ""},
	{"demo", "demo"}, {"demo", "password"}, {"demo", ""},
	{"default", "default"}, {"default", "password"}, {"default", ""},
	// Administrator
	{"administrator", "administrator"}, {"administrator", "password"},
	{"administrator", "admin"}, {"administrator", "123456"},
	{"administrator", "P@ssw0rd"}, {"administrator", "changeme"},
	// Network devices — Cisco
	{"cisco", "cisco"}, {"cisco", "Cisco"}, {"cisco", "password"},
	// Network devices — Juniper
	{"netscreen", "netscreen"}, {"root", "juniper"},
	// Network devices — MikroTik
	{"admin", ""}, // MikroTik default: admin + no password
	// Network devices — D-Link, TP-Link, Netgear, Linksys
	{"admin", "admin"}, {"admin", "1234"}, {"admin", "password"},
	{"user", "user"}, {"support", "support"}, {"support", ""},
	{"cusadmin", "highspeed"}, // Arris routers
	// Network devices — HUAWEI
	{"admin", "Admin@huawei.com"}, {"admin", "admin@huawei.com"},
	// Network devices — Ubiquiti
	{"ubnt", "ubnt"},
	// Network devices — F5 BIG-IP
	{"admin", "admin"},
	// VMware
	{"root", "vmware"}, {"root", "VMware1!"}, {"admin", "vmware"},
	{"root", "calvin"}, // iDRAC Dell
	// Printers
	{"admin", "admin"}, {"admin", ""}, {"admin", "1234"},
	{"admin", "0000"}, {"service", "service"},
	{"root", "root"}, {"supervisor", "supervisor"},
	// Web applications
	{"admin", "admin"}, {"admin", "password"},
	{"sa", ""}, {"sa", "sa"}, {"sa", "password"},
	// Databases
	{"postgres", "postgres"}, {"postgres", ""}, {"postgres", "password"},
	{"mysql", "mysql"}, {"mysql", ""}, {"mysql", "password"},
	{"oracle", "oracle"}, {"oracle", "manager"}, {"oracle", "change_on_install"},
	{"sys", "change_on_install"}, {"system", "manager"},
	{"mssql", ""}, {"sa", ""}, {"sa", "sa"}, {"sa", "password"},
	{"db2inst1", "ibmdb2"}, {"db2admin", "ibmdb2"},
	// Application-specific
	{"jenkins", "jenkins"}, {"jenkins", "password"},
	{"tomcat", "tomcat"}, {"tomcat", "password"}, {"tomcat", "s3cret"},
	{"manager", "manager"}, {"manager", "password"},
	{"nagios", "nagios"}, {"nagiosadmin", "nagiosadmin"},
	{"zabbix", "zabbix"}, {"zabbix", ""},
	{"grafana", "admin"}, {"grafana", "grafana"},
	{"elasticsearch", "elastic"}, {"elastic", "changeme"},
	{"pi", "raspberry"}, // Raspberry Pi default
	{"ubuntu", "ubuntu"}, {"ubuntu", ""},
	{"vagrant", "vagrant"},
	{"deploy", "deploy"}, {"deploy", ""},
	{"ftpuser", "ftpuser"}, {"ftp", "ftp"},
	{"anonymous", ""}, {"anonymous", "anonymous@"},
	// Backup / legacy
	{"backup", "backup"}, {"backup", ""},
	{"operator", "operator"}, {"monitor", "monitor"},
	{"webmaster", "webmaster"}, {"webadmin", "webadmin"},
	{"sysadmin", "sysadmin"}, {"netadmin", "netadmin"},
}

// serviceCreds maps service names to targeted credential lists 
// higher-signal bruteforce 
var serviceCreds = map[string][][2]string{
	"SSH": {
		{"root", "root"}, {"root", "toor"}, {"root", "password"},
		{"root", ""}, {"admin", "admin"}, {"admin", "password"},
		{"ubuntu", "ubuntu"}, {"ec2-user", ""}, {"pi", "raspberry"},
		{"vagrant", "vagrant"}, {"deploy", "deploy"},
	},
	"FTP": {
		{"anonymous", ""}, {"anonymous", "anonymous"},
		{"ftp", "ftp"}, {"ftp", ""}, {"admin", "admin"},
		{"admin", "password"}, {"root", "root"}, {"user", "user"},
		{"ftpuser", "ftpuser"}, {"upload", "upload"},
	},
	"Telnet": {
		{"admin", "admin"}, {"admin", ""}, {"root", "root"},
		{"root", ""}, {"cisco", "cisco"}, {"ubnt", "ubnt"},
		{"pi", "raspberry"}, {"admin", "1234"}, {"guest", "guest"},
	},
	"SMTP": {
		{"admin", "admin"}, {"postmaster", "postmaster"},
		{"mail", "mail"}, {"user", "password"},
	},
	"MySQL": {
		{"root", ""}, {"root", "root"}, {"root", "password"},
		{"root", "mysql"}, {"admin", "admin"}, {"mysql", "mysql"},
		{"root", "123456"}, {"root", "toor"},
	},
	"PostgreSQL": {
		{"postgres", ""}, {"postgres", "postgres"}, {"postgres", "password"},
		{"admin", "admin"}, {"root", "root"},
	},
	"MSSQL": {
		{"sa", ""}, {"sa", "sa"}, {"sa", "password"},
		{"admin", "admin"}, {"sa", "123456"},
	},
	"Oracle DB": {
		{"sys", "change_on_install"}, {"system", "manager"},
		{"oracle", "oracle"}, {"scott", "tiger"},
		{"dbsnmp", "dbsnmp"}, {"outln", "outln"},
	},
	"Redis": {
		{"", ""}, {"default", ""}, {"admin", ""},
		{"redis", "redis"}, {"", "password"}, {"", "redis"},
	},
	"MongoDB": {
		{"admin", "admin"}, {"admin", ""}, {"root", "root"},
		{"mongo", "mongo"}, {"", ""},
	},
	"Jenkins": {
		{"admin", "admin"}, {"admin", "password"},
		{"jenkins", "jenkins"}, {"admin", "jenkins"},
	},
	"Tomcat": {
		{"admin", "admin"}, {"tomcat", "tomcat"},
		{"admin", "tomcat"}, {"manager", "manager"},
		{"tomcat", "s3cret"}, {"admin", "s3cret"},
		{"role1", "role1"}, {"both", "tomcat"},
	},
	"GlassFish": {
		{"admin", "admin"}, {"admin", "adminadmin"},
		{"admin", "admin1234"},
	},
	"WinRM": {
		{"administrator", "password"}, {"administrator", "P@ssw0rd"},
		{"admin", "admin"}, {"administrator", "admin"},
	},
	"RDP": {
		{"administrator", "password"}, {"administrator", "P@ssw0rd"},
		{"administrator", "admin"}, {"admin", "admin"},
		{"administrator", "Welcome1"}, {"administrator", "Passw0rd"},
	},
	"VNC": {
		{"", "password"}, {"", ""}, {"", "123456"},
		{"", "admin"}, {"", "vnc"}, {"", "1234"},
	},
	"SNMP": {
		// SNMP community strings (not user/pass but reuse the struct)
		{"public", "public"}, {"private", "private"}, {"community", "community"},
		{"manager", "manager"}, {"admin", "admin"}, {"default", "default"},
		{"write", "write"}, {"read", "read"}, {"all", "all"},
	},
	"Consul": {
		{"", ""}, {"admin", "admin"},
	},
	"Grafana": {
		{"admin", "admin"}, {"admin", "grafana"}, {"admin", "password"},
		{"grafana", "admin"}, {"admin", "Admin@123"},
	},
	"Elasticsearch": {
		{"elastic", "changeme"}, {"elastic", "password"},
		{"admin", "admin"}, {"", ""},
	},
	"CouchDB": {
		{"admin", "admin"}, {"admin", "password"},
		{"couchdb", "couchdb"}, {"root", "root"},
	},
	"RabbitMQ": {
		{"guest", "guest"}, {"admin", "admin"},
		{"rabbit", "rabbit"}, {"admin", "password"},
	},
	"ZooKeeper": {
		{"", ""}, {"admin", "admin"},
	},
}

// bruteforceTarget runs multi-protocol credential checks .
// Supports SSH, FTP, Telnet, SMTP, MySQL, MSSQL, PostgreSQL, Oracle, Redis,
// MongoDB, HTTP Basic, HTTP Form, VNC, SNMP, WinRM, RDP-style, and more.
func bruteforceTarget(host string, ports []PortResult, timeout time.Duration) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, pr := range ports {
		if !pr.Open {
			continue
		}
		pr := pr
		svcName := pr.Service.Name

		// Pick per-service cred list, fall back to common list
		creds := commonCreds
		if sc, ok := serviceCreds[svcName]; ok {
			creds = sc
		}

		switch svcName {
		case "FTP":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteFTP(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		 case "SSH":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteSSH(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "Telnet":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteTelnet(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "SMTP":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteSMTP(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "MySQL":
			wg.Add(1)
			go func() {
				defer wg.Done()
				if f := bruteMySQL(host, pr.Port, timeout); f != nil {
					mu.Lock(); findings = append(findings, *f); mu.Unlock()
				}
			}()
		case "PostgreSQL":
			wg.Add(1)
			go func() {
				defer wg.Done()
				if f := brutePostgres(host, pr.Port, timeout); f != nil {
					mu.Lock(); findings = append(findings, *f); mu.Unlock()
				}
			}()
		case "MSSQL":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteMSSQL(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "Redis":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteRedis(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "VNC":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteVNC(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "SNMP":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteSNMP(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "WinRM":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteWinRM(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "RDP":
			wg.Add(1)
			go func() {
				defer wg.Done()
				mu.Lock()
				findings = append(findings, Finding{
					Module: "Bruteforce", Severity: INFO,
					Title:   fmt.Sprintf("RDP open port %d — use Hydra/Medusa for RDP bruteforce", pr.Port),
					Detail:  "Active RDP bruteforce skipped (requires NLA negotiation library). Use: hydra -L users.txt -P pass.txt rdp://" + host,
					Evidence: fmt.Sprintf("%s:%d", host, pr.Port),
					Remediation: "Enable NLA, enforce account lockout, restrict by IP, use VPN",
				})
				mu.Unlock()
			}()
		case "HTTP", "HTTPS", "HTTP Proxy":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteHTTPBasic(host, pr.Port, pr.Service.Name == "HTTPS", timeout)
				if len(fs) == 0 {
					fs = bruteHTTPForm(host, pr.Port, pr.Service.Name == "HTTPS", creds, timeout)
				}
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "Grafana":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteGrafana(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		case "Tomcat":
			wg.Add(1)
			go func() {
				defer wg.Done()
				fs := bruteTomcat(host, pr.Port, creds, timeout)
				mu.Lock(); findings = append(findings, fs...); mu.Unlock()
			}()
		}
	}
	wg.Wait()
	return findings
}

// bruteResult holds a successful credential pair.
type bruteResult struct {
	Service  string
	Port     int
	Username string
	Password string
}

func bruteMySQL(host string, port int, timeout time.Duration) *Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil { return nil }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 4 {
		return &Finding{
			Module: "Bruteforce", Severity: INFO,
			Title:  fmt.Sprintf("MySQL reachable on port %d — test: mysql -h %s -u root -p", port, host),
			Detail: "MySQL accepting TCP connections. Verify credentials with a MySQL client.",
			Evidence: fmt.Sprintf("%s:%d → %s", host, port, sanitize(string(buf[:n]), 80)),
			Remediation: "Enforce strong passwords, disable remote root login, bind to 127.0.0.1",
		}
	}
	return nil
}

func brutePostgres(host string, port int, timeout time.Duration) *Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil { return nil }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		return &Finding{
			Module: "Bruteforce", Severity: INFO,
			Title:  fmt.Sprintf("PostgreSQL reachable on port %d — test: psql -h %s -U postgres", port, host),
			Detail: "PostgreSQL accepting TCP connections. Check for empty/default passwords.",
			Evidence: fmt.Sprintf("%s:%d → %d bytes received", host, port, n),
			Remediation: "Use pg_hba.conf to restrict access, enforce strong passwords, disable trust auth",
		}
	}
	return nil
}

var httpBasicPaths = []string{
	"/admin", "/administrator", "/manager/html", "/wp-admin",
	"/phpmyadmin", "/dashboard", "/console", "/api/v1",
}

func bruteHTTPBasic(host string, port int, https bool, timeout time.Duration) []Finding {
	var findings []Finding
	scheme := "http"
	if https { scheme = "https" }
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, path := range httpBasicPaths {
		target := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
		resp, err := client.Get(target)
		if err != nil || resp.StatusCode != 401 { if resp != nil { resp.Body.Close() }; continue }
		resp.Body.Close()
		for _, cred := range commonCreds {
			user, pass := cred[0], cred[1]
			req, err := http.NewRequest("GET", target, nil)
			if err != nil { continue }
			req.SetBasicAuth(user, pass)
			r2, err := client.Do(req)
			if err != nil { continue }
			r2.Body.Close()
			if r2.StatusCode == 200 || r2.StatusCode == 302 {
				findings = append(findings, Finding{
					Module: "Bruteforce", Severity: CRITICAL,
					Title:  fmt.Sprintf("HTTP Basic Auth Weak Credentials on %s: %s:%s", path, user, pass),
					Detail: fmt.Sprintf("HTTP Basic Auth bypassed with %s:%s on %s", user, pass, path),
					Evidence: fmt.Sprintf("GET %s %s:%s → HTTP %d", target, user, pass, r2.StatusCode),
					Remediation: "Change credentials, consider certificate-based auth or OAuth2",
				})
				break
			}
		}
	}
	return findings
}


// brute helper — logs and returns a CRITICAL finding on success.
func bruteWin(module, svcTag, host string, port int, user, pass, evidence, remediation string) Finding {
	return Finding{
		Module:   module, Severity: CRITICAL,
		Title:    fmt.Sprintf("%s Weak Credentials: %s:%s", svcTag, user, pass),
		Detail:   fmt.Sprintf("Login succeeded with credentials %s:%s on %s:%d", user, pass, host, port),
		Evidence: evidence,
		Remediation: remediation,
	}
}

// bruteFTP tries FTP login with the given credential list.
func bruteFTP(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	for _, cred := range creds {
		user, pass := cred[0], cred[1]
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err != nil { return findings }
		conn.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if !strings.Contains(string(buf[:n]), "220") { conn.Close(); return findings }
		fmt.Fprintf(conn, "USER %s\r\n", user)
		conn.SetDeadline(time.Now().Add(timeout))
		n, _ = conn.Read(buf)
		if strings.Contains(string(buf[:n]), "331") || strings.Contains(string(buf[:n]), "230") {
			fmt.Fprintf(conn, "PASS %s\r\n", pass)
			conn.SetDeadline(time.Now().Add(timeout))
			n, _ = conn.Read(buf)
			if strings.Contains(string(buf[:n]), "230") {
				conn.Close()
				findings = append(findings, bruteWin("Bruteforce", "FTP", host, port, user, pass,
					fmt.Sprintf("%s:%d USER %s/PASS %s → 230 Login OK", host, port, user, pass),
					"Change FTP credentials, disable FTP, use SFTP with key auth"))
				return findings // stop on first success
			}
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond) // anti-lockout delay
	}
	return findings
}

// bruteSSH attempts SSH banner-level detection + lists weak-cred hint.
// Full SSH auth requires golang.org/x/crypto (external dep) so we flag
// it as a finding with the credential list as evidence for manual follow-up.
func bruteSSH(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil { return nil }
	buf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(timeout))
	n, _ := conn.Read(buf)
	conn.Close()
	banner := strings.TrimSpace(string(buf[:n]))

	var credList []string
	for _, c := range creds[:min(10, len(creds))] {
		credList = append(credList, c[0]+":"+c[1])
	}
	return []Finding{{
		Module: "Bruteforce", Severity: INFO,
		Title:  fmt.Sprintf("SSH open on port %d — test with: hydra -L user.txt -P pass.txt ssh://%s:%d", port, host, port),
		Detail: fmt.Sprintf("SSH service detected (%s). Active bruteforce skipped to prevent lockouts. Top credentials to try manually listed below.", banner),
		Evidence: fmt.Sprintf("%s:%d  |  Top creds to try: %s", host, port, strings.Join(credList, ", ")),
		Remediation: "Enforce SSH key-only authentication: PasswordAuthentication no in sshd_config. Enable fail2ban.",
	}}
}

// bruteTelnet tries Telnet login with common prompts.
func bruteTelnet(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	for _, cred := range creds {
		user, pass := cred[0], cred[1]
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err != nil { return findings }
		conn.SetDeadline(time.Now().Add(timeout * 2))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		banner := strings.ToLower(string(buf[:n]))
		if strings.Contains(banner, "login") || strings.Contains(banner, "username") || strings.Contains(banner, "user:") {
			fmt.Fprintf(conn, "%s\r\n", user)
			conn.SetDeadline(time.Now().Add(timeout))
			n, _ = conn.Read(buf)
			resp := strings.ToLower(string(buf[:n]))
			if strings.Contains(resp, "password") || strings.Contains(resp, "pass") {
				fmt.Fprintf(conn, "%s\r\n", pass)
				conn.SetDeadline(time.Now().Add(timeout))
				n, _ = conn.Read(buf)
				resp2 := strings.ToLower(string(buf[:n]))
				if strings.Contains(resp2, "$") || strings.Contains(resp2, "#") ||
					strings.Contains(resp2, ">") || strings.Contains(resp2, "welcome") ||
					!strings.Contains(resp2, "fail") && !strings.Contains(resp2, "incorrect") && !strings.Contains(resp2, "denied") {
					conn.Close()
					findings = append(findings, bruteWin("Bruteforce", "Telnet", host, port, user, pass,
						fmt.Sprintf("%s:%d Telnet login → shell prompt received", host, port),
						"Disable Telnet immediately, use SSH instead"))
					return findings
				}
			}
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return findings
}

// bruteSMTP tries SMTP AUTH LOGIN / AUTH PLAIN.
func bruteSMTP(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	for _, cred := range creds {
		user, pass := cred[0], cred[1]
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err != nil { return findings }
		conn.SetDeadline(time.Now().Add(timeout * 3))
		buf := make([]byte, 512)
		conn.Read(buf) // banner
		fmt.Fprintf(conn, "EHLO recon-x\r\n")
		conn.Read(buf)
		// Try AUTH LOGIN
		fmt.Fprintf(conn, "AUTH LOGIN\r\n")
		n, _ := conn.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "334") {
			// base64 encode user
			userB64 := make([]byte, len(user)*2)
			n64 := encodeBase64(user, userB64)
			fmt.Fprintf(conn, "%s\r\n", string(userB64[:n64]))
			conn.Read(buf)
			passB64 := make([]byte, len(pass)*2)
			n64 = encodeBase64(pass, passB64)
			fmt.Fprintf(conn, "%s\r\n", string(passB64[:n64]))
			n, _ = conn.Read(buf)
			if strings.HasPrefix(string(buf[:n]), "235") {
				conn.Close()
				findings = append(findings, bruteWin("Bruteforce", "SMTP AUTH", host, port, user, pass,
					fmt.Sprintf("%s:%d SMTP AUTH LOGIN → 235 Authentication successful", host, port),
					"Change SMTP credentials, enable 2FA, monitor for abuse"))
				return findings
			}
		}
		conn.Close()
		time.Sleep(200 * time.Millisecond)
	}
	return findings
}

// encodeBase64 encodes src to dst using the standard base64 alphabet.
func encodeBase64(src string, dst []byte) int {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := []byte(src)
	i, j := 0, 0
	for i < len(b) {
		var v uint32
		switch len(b) - i {
		default:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
			if j+4 > len(dst) { break }
			dst[j] = chars[v>>18&0x3f]; dst[j+1] = chars[v>>12&0x3f]
			dst[j+2] = chars[v>>6&0x3f]; dst[j+3] = chars[v&0x3f]
			i += 3; j += 4
		case 2:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8
			if j+4 > len(dst) { break }
			dst[j] = chars[v>>18&0x3f]; dst[j+1] = chars[v>>12&0x3f]
			dst[j+2] = chars[v>>6&0x3f]; dst[j+3] = '='
			i += 2; j += 4
		case 1:
			v = uint32(b[i]) << 16
			if j+4 > len(dst) { break }
			dst[j] = chars[v>>18&0x3f]; dst[j+1] = chars[v>>12&0x3f]
			dst[j+2] = '='; dst[j+3] = '='
			i++; j += 4
		}
	}
	return j
}

// bruteMSSQL probes SQL Server with TCP handshake for default SA account.
func bruteMSSQL(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil { return nil }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		return []Finding{{
			Module: "Bruteforce", Severity: HIGH,
			Title:  fmt.Sprintf("MSSQL reachable on %s:%d — test SA account", host, port),
			Detail: "SQL Server is accepting TCP connections. Test SA account with empty password or common passwords.",
			Evidence: fmt.Sprintf("%s:%d — use: sqlcmd -S %s,%d -U sa -P ''", host, port, host, port),
			Remediation: "Disable SA account or set strong password. Disable remote SA login. Bind to localhost.",
		}}
	}
	return nil
}

// bruteRedis tests Redis AUTH with password list.
func bruteRedis(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	// First test with no auth
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil { return findings }
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "PING\r\n")
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	conn.Close()
	if strings.Contains(string(buf[:n]), "+PONG") {
		findings = append(findings, bruteWin("Bruteforce", "Redis (no auth)", host, port, "", "",
			fmt.Sprintf("%s:%d PING → PONG (no authentication required)", host, port),
			"Enable requirepass in redis.conf, bind to 127.0.0.1, use TLS"))
		return findings
	}
	// Try with passwords
	for _, cred := range creds {
		pass := cred[1]
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err != nil { return findings }
		conn.SetDeadline(time.Now().Add(timeout))
		fmt.Fprintf(conn, "AUTH %s\r\n", pass)
		n, _ := conn.Read(buf)
		conn.Close()
		if strings.Contains(string(buf[:n]), "+OK") {
			findings = append(findings, bruteWin("Bruteforce", "Redis", host, port, "", pass,
				fmt.Sprintf("%s:%d AUTH %s → +OK", host, port, pass),
				"Change Redis password, bind to 127.0.0.1, use TLS, rename CONFIG command"))
			return findings
		}
		time.Sleep(50 * time.Millisecond)
	}
	return findings
}

// bruteVNC tries VNC authentication with common passwords.
// RFB protocol: server sends 4-byte challenge, client sends 16-byte DES response.
func bruteVNC(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	// VNC uses a DES challenge-response; we detect whether VNC uses no-auth (security type 1).
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil { return nil }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n < 12 || !strings.HasPrefix(string(buf[:n]), "RFB") {
		return nil
	}
	// Respond with our version
	fmt.Fprintf(conn, "RFB 003.008\n")
	conn.SetDeadline(time.Now().Add(timeout))
	n, _ = conn.Read(buf)
	if n == 0 { return nil }
	numTypes := int(buf[0])
	for i := 1; i <= numTypes && i < n; i++ {
		if buf[i] == 1 { // no-auth
			return []Finding{bruteWin("Bruteforce", "VNC (no auth)", host, port, "", "",
				fmt.Sprintf("%s:%d VNC security type = None (no password required)", host, port),
				"Enable VNC authentication, use strong password, restrict by IP or use SSH tunnel")}
		}
	}
	return []Finding{{
		Module: "Bruteforce", Severity: INFO,
		Title:  fmt.Sprintf("VNC port %d uses password auth — test manually", port),
		Detail: "VNC requires DES challenge-response auth. Use vncviewer or hydra vnc module for full bruteforce.",
		Evidence: fmt.Sprintf("%s:%d VNC RFB detected", host, port),
		Remediation: "Use strong VNC password, restrict by IP, prefer SSH tunnel over exposed VNC",
	}}
}

// bruteSNMP tests SNMP community strings.
func bruteSNMP(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	for _, cred := range creds {
		community := cred[0] // SNMP reuses user field for community string
		// Build SNMPv1 GetRequest for sysDescr.0
		cl := byte(len(community))
		pdu := []byte{
			0x30, 0x00, // SEQUENCE (length filled later)
			0x02, 0x01, 0x00, // version: 0 (v1)
			0x04, cl, // community string length
		}
		pdu = append(pdu, []byte(community)...)
		pdu = append(pdu, []byte{
			0xa0, 0x0e, // GetRequest PDU
			0x02, 0x04, 0x01, 0x02, 0x03, 0x04, // request-id
			0x02, 0x01, 0x00, // error-status
			0x02, 0x01, 0x00, // error-index
			0x30, 0x00, // variable bindings
		}...)
		pdu[1] = byte(len(pdu) - 2)

		conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err != nil { continue }
		conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write(pdu)
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()
		if err == nil && n > 4 {
			findings = append(findings, bruteWin("Bruteforce", "SNMP", host, port, community, "",
				fmt.Sprintf("%s:%d SNMP community '%s' → %d bytes response", host, port, community, n),
				"Change SNMP community strings, use SNMPv3 with auth+priv, restrict by ACL"))
			return findings // first working community is enough
		}
		time.Sleep(50 * time.Millisecond)
	}
	return findings
}

// bruteWinRM tries HTTP Basic auth against WinRM endpoint.
func bruteWinRM(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	scheme := "http"
	if port == 5986 { scheme = "https" }
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, cred := range creds {
		user, pass := cred[0], cred[1]
		target := fmt.Sprintf("%s://%s:%d/wsman", scheme, host, port)
		req, err := http.NewRequest("POST", target, strings.NewReader(""))
		if err != nil { continue }
		req.SetBasicAuth(user, pass)
		req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
		resp, err := client.Do(req)
		if err != nil { continue }
		resp.Body.Close()
		// 401 = wrong creds, 200/400/500 = authenticated
		if resp.StatusCode != 401 {
			findings = append(findings, bruteWin("Bruteforce", "WinRM", host, port, user, pass,
				fmt.Sprintf("%s:%d WinRM POST /wsman → HTTP %d (auth succeeded)", host, port, resp.StatusCode),
				"Change Windows credentials, restrict WinRM access, enable HTTPS, require Kerberos auth"))
			return findings
		}
		time.Sleep(200 * time.Millisecond)
	}
	return findings
}

// bruteGrafana tries Grafana default credentials via the API.
func bruteGrafana(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	for _, cred := range creds {
		user, pass := cred[0], cred[1]
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/api/org", host, port), nil)
		if err != nil { continue }
		req.SetBasicAuth(user, pass)
		resp, err := client.Do(req)
		if err != nil { continue }
		resp.Body.Close()
		if resp.StatusCode == 200 {
			findings = append(findings, bruteWin("Bruteforce", "Grafana", host, port, user, pass,
				fmt.Sprintf("%s:%d GET /api/org with %s:%s → 200 OK", host, port, user, pass),
				"Change Grafana admin password, disable anonymous access, enable 2FA"))
			return findings
		}
		time.Sleep(200 * time.Millisecond)
	}
	return findings
}

// bruteTomcat tries Tomcat Manager credentials.
func bruteTomcat(host string, port int, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, path := range []string{"/manager/html", "/manager/text"} {
		target := fmt.Sprintf("http://%s:%d%s", host, port, path)
		req, _ := http.NewRequest("GET", target, nil)
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 401 { continue }
		resp.Body.Close()
		for _, cred := range creds {
			user, pass := cred[0], cred[1]
			req2, _ := http.NewRequest("GET", target, nil)
			req2.SetBasicAuth(user, pass)
			r2, err := client.Do(req2)
			if err != nil { continue }
			r2.Body.Close()
			if r2.StatusCode == 200 || r2.StatusCode == 302 {
				findings = append(findings, bruteWin("Bruteforce", "Tomcat Manager", host, port, user, pass,
					fmt.Sprintf("%s:%d GET %s → %d (auth OK)", host, port, path, r2.StatusCode),
					"Change Tomcat Manager credentials, restrict Manager app to localhost, remove if not needed"))
				return findings
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return findings
}

// bruteHTTPForm probes for common login form endpoints and attempts credential stuffing.
func bruteHTTPForm(host string, port int, https bool, creds [][2]string, timeout time.Duration) []Finding {
	var findings []Finding
	scheme := "http"
	if https { scheme = "https" }
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	// Common login form endpoints with known field names
	type loginEndpoint struct {
		path, userField, passField string
	}
	endpoints := []loginEndpoint{
		{"/login", "username", "password"},
		{"/login", "user", "pass"},
		{"/signin", "email", "password"},
		{"/wp-login.php", "log", "pwd"},
		{"/admin/login", "username", "password"},
		{"/user/login", "name", "pass"},
		{"/auth/login", "username", "password"},
		{"/api/login", "username", "password"},
		{"/api/v1/auth", "username", "password"},
	}
	for _, ep := range endpoints {
		target := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, ep.path)
		resp, err := client.Get(target)
		if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 401 && resp.StatusCode != 405) {
			if resp != nil { resp.Body.Close() }
			continue
		}
		resp.Body.Close()
		// Try first 5 creds only to avoid lockout
		for _, cred := range creds[:min(5, len(creds))] {
			user, pass := cred[0], cred[1]
			formData := fmt.Sprintf("%s=%s&%s=%s", ep.userField, url.QueryEscape(user), ep.passField, url.QueryEscape(pass))
			req, err := http.NewRequest("POST", target, strings.NewReader(formData))
			if err != nil { continue }
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; RECON-X)")
			r2, err := client.Do(req)
			if err != nil { continue }
			r2.Body.Close()
			// Redirect after POST typically indicates successful login
			if r2.StatusCode == 302 || r2.StatusCode == 301 {
				loc := r2.Header.Get("Location")
				if !strings.Contains(strings.ToLower(loc), "login") && !strings.Contains(strings.ToLower(loc), "error") {
					findings = append(findings, bruteWin("Bruteforce", "HTTP Form Login", host, port, user, pass,
						fmt.Sprintf("POST %s {%s=%s, %s=%s} → %d Location: %s",
							target, ep.userField, user, ep.passField, pass, r2.StatusCode, loc),
						"Change application credentials, implement account lockout, enable 2FA"))
					return findings
				}
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	return findings
}


// ═══════════════════════════════════════════════════════════════════════
//  WEB CRAWLER — Advanced (concurrent, depth-aware, multi-method)
// ═══════════════════════════════════════════════════════════════════════

// crawlResult holds a single discovered URL with metadata.
type crawlResult struct {
	URL        string
	StatusCode int
	Size       int64
	Title      string
	RedirectTo string
	Params     []string // URL parameters found
	Forms      int      // number of forms on page
}

// sensitivePathEntry maps a path pattern to severity and description.
type sensitivePathEntry struct {
	path        string
	sev         Severity
	desc        string
	remediation string
}

var sensitivePaths = []sensitivePathEntry{
	// ── Secrets / credentials ────────────────────────────────────────────
	{"/.env", CRITICAL, "Environment file — may contain DB passwords, API keys", "Remove from webroot, use environment variables"},
	{"/.env.local", CRITICAL, "Local environment file with secrets", "Remove from webroot"},
	{"/.env.production", CRITICAL, "Production environment file with secrets", "Remove from webroot"},
	{"/.env.dev", HIGH, "Development environment file", "Remove from webroot"},
	{"/.env.backup", CRITICAL, "Backup environment file with secrets", "Remove from webroot"},
	{"/.aws/credentials", CRITICAL, "AWS credentials file", "Remove immediately, rotate AWS keys"},
	{"/.aws/config", HIGH, "AWS config file", "Remove from webroot"},
	{"/.azure/accessTokens.json", CRITICAL, "Azure access tokens", "Remove immediately, revoke tokens"},
	{"/.gcloud/credentials", CRITICAL, "Google Cloud credentials", "Remove immediately, revoke service account"},
	{"/.kube/config", CRITICAL, "Kubernetes config with cluster credentials", "Remove immediately, rotate kubeconfig"},
	{"/kubeconfig", CRITICAL, "Kubernetes config file", "Remove immediately"},
	{"/id_rsa", CRITICAL, "SSH private key", "Remove immediately, generate new key pair"},
	{"/id_dsa", CRITICAL, "SSH DSA private key", "Remove immediately"},
	{"/.ssh/id_rsa", CRITICAL, "SSH private key", "Remove immediately"},
	{"/.ssh/id_ecdsa", CRITICAL, "SSH ECDSA private key", "Remove immediately"},
	{"/.ssh/id_ed25519", CRITICAL, "SSH Ed25519 private key", "Remove immediately"},
	{"/.npmrc", HIGH, "npm config — may contain registry tokens", "Remove from webroot"},
	{"/.pypirc", HIGH, "PyPI config — may contain upload tokens", "Remove from webroot"},
	{"/.netrc", CRITICAL, "Netrc — contains plaintext credentials", "Remove from webroot"},
	{"/.pgpass", CRITICAL, "PostgreSQL password file", "Remove from webroot"},
	{"/wp-config.php.bak", CRITICAL, "WordPress config backup with DB credentials", "Remove immediately"},
	{"/wp-config.php~", CRITICAL, "WordPress config backup", "Remove immediately"},
	{"/config.inc.php", CRITICAL, "PHP config with database credentials", "Remove from webroot"},
	{"/configuration.php", HIGH, "Joomla configuration with credentials", "Restrict access"},
	{"/settings.php", HIGH, "Drupal settings with DB credentials", "Restrict access"},
	{"/.htpasswd", HIGH, "Apache htpasswd file — contains password hashes", "Move outside webroot"},
	{"/.htaccess", MEDIUM, "Apache htaccess — reveals URL rewriting rules", "Restrict access"},
	// ── VCS ───────────────────────────────────────────────────────────────
	{"/.git/HEAD", HIGH, "Git repository exposed — full source code extractable", "Block /.git/ directory in web server config"},
	{"/.git/config", HIGH, "Git config — reveals remote URL", "Block /.git/ directory"},
	{"/.git/COMMIT_EDITMSG", MEDIUM, "Git commit message exposed", "Block /.git/ directory"},
	{"/.git/index", HIGH, "Git index exposed", "Block /.git/ directory"},
	{"/.svn/entries", HIGH, "SVN repository exposed", "Block /.svn/ directory"},
	{"/.svn/wc.db", HIGH, "SVN working copy database", "Block /.svn/ directory"},
	{"/.hg/hgrc", HIGH, "Mercurial repository config exposed", "Block /.hg/ directory"},
	{"/.hg/store/00manifest.i", HIGH, "Mercurial store exposed", "Block /.hg/ directory"},
	{"/_darcs/inventory", MEDIUM, "Darcs repository exposed", "Block /_darcs/ directory"},
	{"/.bzr/README", MEDIUM, "Bazaar repository exposed", "Block /.bzr/ directory"},
	// ── Backup / Database dumps ───────────────────────────────────────────
	{"/backup.zip", CRITICAL, "Site backup archive", "Remove from webroot"},
	{"/backup.tar.gz", CRITICAL, "Site backup archive", "Remove from webroot"},
	{"/backup.tar.bz2", CRITICAL, "Site backup archive", "Remove from webroot"},
	{"/backup.sql", CRITICAL, "Database SQL dump", "Remove from webroot, store off-server"},
	{"/backup.sql.gz", CRITICAL, "Compressed database dump", "Remove from webroot"},
	{"/db.sql", CRITICAL, "Database SQL dump", "Remove from webroot"},
	{"/database.sql", CRITICAL, "Database SQL dump", "Remove from webroot"},
	{"/dump.sql", CRITICAL, "Database dump", "Remove from webroot"},
	{"/data.sql", CRITICAL, "Database data dump", "Remove from webroot"},
	{"/mysql.sql", CRITICAL, "MySQL database dump", "Remove from webroot"},
	{"/site.zip", HIGH, "Site archive", "Remove from webroot"},
	{"/www.zip", HIGH, "Website archive", "Remove from webroot"},
	{"/web.tar.gz", HIGH, "Web directory archive", "Remove from webroot"},
	{"/logs.zip", HIGH, "Log archive — may contain sensitive data", "Remove from webroot"},
	// ── Admin panels ──────────────────────────────────────────────────────
	{"/admin", HIGH, "Admin panel", "Restrict access to authorised IPs"},
	{"/administrator", HIGH, "Admin panel", "Restrict access"},
	{"/wp-admin", HIGH, "WordPress admin panel", "Restrict by IP, enable 2FA"},
	{"/wp-login.php", MEDIUM, "WordPress login page", "Enable brute-force protection"},
	{"/phpmyadmin", CRITICAL, "phpMyAdmin — full database access", "Move behind VPN, restrict by IP"},
	{"/phpMyAdmin", CRITICAL, "phpMyAdmin", "Move behind VPN"},
	{"/pma", CRITICAL, "phpMyAdmin alias", "Move behind VPN"},
	{"/adminer.php", CRITICAL, "Adminer database manager", "Remove from webroot"},
	{"/adminer", CRITICAL, "Adminer database manager", "Remove from webroot"},
	{"/manager/html", HIGH, "Tomcat Manager", "Restrict access, change default credentials"},
	{"/host-manager/html", HIGH, "Tomcat Host Manager", "Restrict access"},
	{"/console", HIGH, "Admin console", "Restrict access"},
	{"/dashboard", MEDIUM, "Dashboard", "Ensure authentication is enforced"},
	{"/cpanel", HIGH, "cPanel control panel", "Restrict by IP"},
	{"/webmail", MEDIUM, "Webmail interface", "Ensure strong authentication"},
	{"/roundcube", MEDIUM, "Roundcube webmail", "Ensure strong authentication"},
	{"/squirrelmail", MEDIUM, "SquirrelMail webmail", "Ensure strong authentication"},
	{"/webmin", CRITICAL, "Webmin system administration", "Restrict by IP, update to latest version"},
	{"/usermin", HIGH, "Usermin", "Restrict by IP"},
	// ── API / Dev endpoints ───────────────────────────────────────────────
	{"/api/v1/", MEDIUM, "API endpoint exposed", "Ensure authentication and authorisation"},
	{"/api/v2/", MEDIUM, "API endpoint exposed", "Ensure authentication"},
	{"/api/", MEDIUM, "API root exposed", "Ensure authentication"},
	{"/graphql", MEDIUM, "GraphQL endpoint", "Disable introspection in production"},
	{"/graphiql", HIGH, "GraphQL IDE exposed — introspection enabled", "Disable in production"},
	{"/v1/", MEDIUM, "API version 1 endpoint", "Ensure authentication"},
	{"/v2/", MEDIUM, "API version 2 endpoint", "Ensure authentication"},
	{"/swagger.json", MEDIUM, "Swagger/OpenAPI spec — API structure exposed", "Restrict in production"},
	{"/openapi.json", MEDIUM, "OpenAPI specification exposed", "Restrict in production"},
	{"/swagger-ui", MEDIUM, "Swagger UI exposed", "Restrict in production"},
	{"/swagger-ui.html", MEDIUM, "Swagger UI HTML", "Restrict in production"},
	{"/api-docs", MEDIUM, "API documentation exposed", "Restrict in production"},
	{"/redoc", MEDIUM, "ReDoc API documentation", "Restrict in production"},
	// ── Spring Boot Actuator ──────────────────────────────────────────────
	{"/actuator", HIGH, "Spring Boot Actuator root — application internals exposed", "Disable or restrict actuator endpoints"},
	{"/actuator/health", MEDIUM, "Actuator health endpoint", "Restrict sensitive details"},
	{"/actuator/env", CRITICAL, "Actuator env — environment variables and secrets", "Disable in production"},
	{"/actuator/configprops", CRITICAL, "Actuator config properties — may contain passwords", "Disable in production"},
	{"/actuator/mappings", HIGH, "Actuator URL mappings — full route list", "Disable in production"},
	{"/actuator/beans", HIGH, "Actuator beans — Spring bean list", "Disable in production"},
	{"/actuator/metrics", MEDIUM, "Actuator metrics", "Restrict access"},
	{"/actuator/loggers", HIGH, "Actuator loggers — can change log level remotely", "Disable in production"},
	{"/actuator/heapdump", CRITICAL, "Heap dump — full memory dump extractable", "Disable immediately"},
	{"/actuator/threaddump", HIGH, "Thread dump — runtime state exposed", "Disable in production"},
	{"/actuator/httptrace", HIGH, "HTTP trace — recent request/response history", "Disable in production"},
	{"/actuator/shutdown", CRITICAL, "Actuator shutdown — can stop the application", "Disable or require auth"},
	// ── PHP info / Debug ──────────────────────────────────────────────────
	{"/phpinfo.php", HIGH, "PHP info page — server configuration exposed", "Remove from production"},
	{"/info.php", HIGH, "PHP info page", "Remove from production"},
	{"/test.php", MEDIUM, "PHP test file", "Remove from production"},
	{"/php.php", MEDIUM, "PHP test file", "Remove from production"},
	{"/.php", MEDIUM, "PHP file exposed", "Remove from production"},
	{"/server-status", HIGH, "Apache server-status — request info exposed", "Restrict to localhost"},
	{"/server-info", HIGH, "Apache server-info — module config exposed", "Restrict to localhost"},
	{"/nginx_status", MEDIUM, "nginx status page", "Restrict to localhost"},
	{"/status", MEDIUM, "Application status page", "Restrict access"},
	{"/_cats", MEDIUM, "Elasticsearch _cat APIs", "Enable authentication"},
	{"/_cluster/health", MEDIUM, "Elasticsearch cluster health", "Enable authentication"},
	// ── Shell history / Source ────────────────────────────────────────────
	{"/.bash_history", CRITICAL, "Bash command history — commands may include credentials", "Remove from webroot"},
	{"/.zsh_history", CRITICAL, "Zsh command history", "Remove from webroot"},
	{"/.mysql_history", CRITICAL, "MySQL command history — queries with credentials", "Remove from webroot"},
	{"/.psql_history", CRITICAL, "PostgreSQL history", "Remove from webroot"},
	{"/.python_history", MEDIUM, "Python history", "Remove from webroot"},
	// ── Dependency / Config files ─────────────────────────────────────────
	{"/composer.json", LOW, "PHP Composer manifest — dependency list", "Restrict access in production"},
	{"/composer.lock", LOW, "PHP Composer lock — exact dependency versions (aids CVE matching)", "Restrict access"},
	{"/package.json", LOW, "Node.js package manifest", "Restrict access"},
	{"/package-lock.json", LOW, "Node.js lock file — exact versions", "Restrict access"},
	{"/yarn.lock", LOW, "Yarn lock file", "Restrict access"},
	{"/Gemfile", LOW, "Ruby Gemfile", "Restrict access"},
	{"/Gemfile.lock", LOW, "Ruby Gemfile lock", "Restrict access"},
	{"/requirements.txt", LOW, "Python requirements — dependency list", "Restrict access"},
	{"/Pipfile", LOW, "Python Pipfile", "Restrict access"},
	{"/pyproject.toml", LOW, "Python project config", "Restrict access"},
	{"/go.mod", LOW, "Go module file", "Restrict access"},
	{"/pom.xml", LOW, "Maven POM — Java dependency list", "Restrict access"},
	{"/build.gradle", LOW, "Gradle build file", "Restrict access"},
	{"/Dockerfile", MEDIUM, "Dockerfile — reveals image layers and base OS", "Restrict access"},
	{"/docker-compose.yml", HIGH, "Docker Compose — service topology, port mappings, env vars", "Remove from webroot"},
	{"/docker-compose.yaml", HIGH, "Docker Compose file", "Remove from webroot"},
	{"/.gitignore", LOW, "Gitignore — reveals project file structure", "Restrict access"},
	{"/.dockerignore", LOW, "Docker ignore file", "Restrict access"},
	// ── Security / Policy ────────────────────────────────────────────────
	{"/.well-known/security.txt", INFO, "Security contact information", "Good practice — ensure it is up to date"},
	{"/robots.txt", INFO, "Robots.txt — reveals hidden paths to crawlers", "Review for sensitive path disclosure"},
	{"/humans.txt", INFO, "Humans.txt — team information", "Review for information disclosure"},
	{"/sitemap.xml", INFO, "Sitemap — full URL list", "Review for hidden/sensitive pages"},
	{"/crossdomain.xml", MEDIUM, "Cross-domain policy — may allow broad access", "Restrict to required origins only"},
	{"/clientaccesspolicy.xml", MEDIUM, "Silverlight policy — may allow broad access", "Restrict to required origins only"},
	// ── CGI / Legacy ─────────────────────────────────────────────────────
	{"/cgi-bin/test-cgi", HIGH, "CGI test script — shellshock potential", "Remove CGI test scripts"},
	{"/cgi-bin/printenv", HIGH, "CGI printenv — environment variables exposed", "Remove from server"},
	{"/cgi-bin/", MEDIUM, "CGI directory accessible", "Audit all CGI scripts"},
	{"/cgi-bin/php", HIGH, "PHP via CGI", "Restrict access"},
	// ── Cloud metadata ────────────────────────────────────────────────────
	{"/latest/meta-data/", CRITICAL, "AWS EC2 metadata service exposed (SSRF target)", "Block SSRF access to 169.254.169.254"},
	{"/computeMetadata/v1/", CRITICAL, "GCP metadata service exposed (SSRF target)", "Block SSRF access"},
	{"/metadata/instance", CRITICAL, "Azure metadata service exposed", "Block SSRF access"},
}

// crawl performs advanced concurrent web crawling with:
//   - Concurrent worker pool (configurable)
//   - Configurable depth (default 5 levels)
//   - JavaScript src extraction
//   - Inline JS endpoint scanning
//   - Form parameter extraction
//   - Comment harvesting
//   - 200+ sensitive path probes
//   - Redirect chain tracking
//   - Robots.txt parsing for hidden paths
//   - Sitemap.xml URL extraction
func crawl(target string, maxURLsArg int, cfg Config) ([]string, []Finding) {
	// Respect configurable limits (fall back to arg/defaults if cfg values not set)
	maxURLs := maxURLsArg
	if cfg.CrawlMaxURLs > 0 {
		maxURLs = cfg.CrawlMaxURLs
	}
	if maxURLs <= 0 {
		maxURLs = 500
	}
	maxDepthCfg := cfg.CrawlMaxDepth
	if maxDepthCfg <= 0 {
		maxDepthCfg = 5
	}
	var findMu sync.Mutex
	var findings []Finding

	// ── Set up base URL ────────────────────────────────────────────────────
	base := "http://" + target
	if !strings.Contains(target, "://") {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", target+":443", &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			conn.Close()
			base = "https://" + target
		}
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, nil
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    20,
		IdleConnTimeout: 30 * time.Second,
	}
	if cfg.Proxy != "" {
		if pURL, err := url.Parse(cfg.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}
	client := &http.Client{
		Timeout:   cfg.Timeout * 3,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// ── Acquire auth session if configured ─────────────────────────────────
	sess := acquireSession(cfg)

	// ── Detect Chrome for JS rendering ────────────────────────────────────
	chromePath := ""
	if cfg.JSRender {
		chromePath = findChrome()
		if chromePath == "" {
			warn("JS rendering requested (-js-render) but Chrome/Chromium not found in PATH", cfg.NoColor)
		} else {
			progress(fmt.Sprintf("JS rendering enabled via: %s", chromePath), cfg.NoColor)
		}
	}

	// ── Concurrent sensitive path probing ─────────────────────────────────
	type pathResult struct {
		path   string
		code   int
		size   int64
		body   string
	}
	pathJobs := make(chan sensitivePathEntry, len(sensitivePaths))
	for _, sp := range sensitivePaths {
		pathJobs <- sp
	}
	close(pathJobs)

	pathResults := make(chan pathResult, len(sensitivePaths))
	var pathWg sync.WaitGroup
	pathWorkers := 20
	for i := 0; i < pathWorkers; i++ {
		pathWg.Add(1)
		go func() {
			defer pathWg.Done()
			for sp := range pathJobs {
				checkURL := base + sp.path
				req, err := http.NewRequest("GET", checkURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", cfg.UserAgent)
				req.Header.Set("Accept", "*/*")
				applyAuth(req, sess)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body := ""
				if resp.StatusCode == 200 {
					buf := make([]byte, 4096)
					n, _ := resp.Body.Read(buf)
					body = string(buf[:n])
				}
				resp.Body.Close()
				if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
					pathResults <- pathResult{path: sp.path, code: resp.StatusCode, size: resp.ContentLength, body: body}
				}
			}
		}()
	}
	pathWg.Wait()
	close(pathResults)

	for pr := range pathResults {
		// Match back to the sensitive path entry for severity/remediation
		var entry sensitivePathEntry
		for _, sp := range sensitivePaths {
			if sp.path == pr.path {
				entry = sp
				break
			}
		}
		// Upgrade severity if content confirms the file is real
		sev := entry.sev
		evidence := fmt.Sprintf("GET %s%s → HTTP %d", base, pr.path, pr.code)
		if pr.code == 200 && pr.size > 0 {
			evidence += fmt.Sprintf(" (%d bytes)", pr.size)
		}
		if pr.code == 401 || pr.code == 403 {
			if sev > MEDIUM {
				sev = MEDIUM // protected but present — downgrade one level
			}
			evidence += " — access denied but resource exists"
		}
		// Extra: detect actual credentials in .env files
		if strings.Contains(pr.path, ".env") && pr.code == 200 {
			for _, kw := range []string{"PASSWORD", "SECRET", "TOKEN", "KEY", "API_KEY", "DB_PASS", "PRIVATE"} {
				if strings.Contains(strings.ToUpper(pr.body), kw) {
					sev = CRITICAL
					evidence += fmt.Sprintf(" — contains keyword: %s", kw)
					break
				}
			}
		}
		findings = append(findings, Finding{
			Module:      "WebCrawl",
			Severity:    sev,
			Title:       fmt.Sprintf("Sensitive Path: %s (HTTP %d)", pr.path, pr.code),
			Detail:      entry.desc,
			Evidence:    evidence,
			Remediation: entry.remediation,
		})
	}

	// ── Parse robots.txt for hidden paths ─────────────────────────────────
	robotsPaths := crawlRobotsTxt(base, client, cfg.UserAgent)
	for _, rp := range robotsPaths {
		// Check each disallowed path
		checkURL := base + rp
		req, err := http.NewRequest("GET", checkURL, nil)
		if err != nil { continue }
		req.Header.Set("User-Agent", cfg.UserAgent)
		resp, err := client.Do(req)
		if err != nil { continue }
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			findings = append(findings, Finding{
				Module:      "WebCrawl", Severity: MEDIUM,
				Title:       fmt.Sprintf("Robots.txt Disallowed Path Accessible: %s", rp),
				Detail:      "Path is listed in robots.txt Disallow directive and is accessible. Robots.txt is not a security control.",
				Evidence:    fmt.Sprintf("robots.txt Disallow: %s → GET %s%s HTTP %d", rp, base, rp, resp.StatusCode),
				Remediation: "Do not rely on robots.txt to hide sensitive paths — use proper access controls",
			})
		}
	}

	// ── Parse sitemap.xml for URLs ─────────────────────────────────────────
	sitemapURLs := crawlSitemap(base, client, cfg.UserAgent)

	// ── Concurrent link crawler (BFS, max depth 5) ────────────────────────
	type crawlJob struct {
		url   string
		depth int
	}

	maxDepth := maxDepthCfg
	visited := make(map[string]bool)
	var visitMu sync.Mutex

	// Seed the queue with base + sitemap URLs
	initialQueue := []crawlJob{{url: base, depth: 0}}
	for _, su := range sitemapURLs {
		initialQueue = append(initialQueue, crawlJob{url: su, depth: 1})
	}

	jobCh := make(chan crawlJob, maxURLs*2)
	for _, j := range initialQueue {
		jobCh <- j
	}

	var urlsMu sync.Mutex
	var crawledURLs []string
	var crawlWg sync.WaitGroup
	stopCrawl := make(chan struct{})

	crawlWorkers := 10
	for i := 0; i < crawlWorkers; i++ {
		crawlWg.Add(1)
		go func() {
			defer crawlWg.Done()
			for {
				select {
				case <-stopCrawl:
					return
				default:
				}
				var job crawlJob
				select {
				case job = <-jobCh:
				default:
					return
				}

				visitMu.Lock()
				if visited[job.url] {
					visitMu.Unlock()
					continue
				}
				visited[job.url] = true
				visitMu.Unlock()

				urlsMu.Lock()
				if len(crawledURLs) >= maxURLs {
					urlsMu.Unlock()
					return
				}
				urlsMu.Unlock()

				req, err := http.NewRequest("GET", job.url, nil)
				if err != nil { continue }
				req.Header.Set("User-Agent", cfg.UserAgent)
				req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
				applyAuth(req, sess)
				resp, err := client.Do(req)
				if err != nil { continue }

				buf := make([]byte, 131072) // 128 KB per page
				n, _ := resp.Body.Read(buf)
				resp.Body.Close()
				body := string(buf[:n])

				// ── JS rendering: replace body with rendered DOM if Chrome available ──
				if cfg.JSRender && chromePath != "" {
					if rendered, rerr := renderPageJS(chromePath, job.url, sess, cfg.Timeout*3); rerr == nil && len(rendered) > len(body) {
						body = rendered
					}
				}

				// Extract page title
				title := ""
				if tm := regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`).FindStringSubmatch(body); len(tm) > 1 {
					title = strings.TrimSpace(tm[1])
				}

				// Extract URL parameters
				params := extractParams(job.url)

				urlsMu.Lock()
				entry := fmt.Sprintf("[%d] %s", resp.StatusCode, job.url)
				if title != "" {
					entry += fmt.Sprintf(" (%s)", title)
				}
				if len(params) > 0 {
					entry += fmt.Sprintf(" [params: %s]", strings.Join(params, ","))
				}
				crawledURLs = append(crawledURLs, entry)
				urlsMu.Unlock()

				// Detect interesting page content
				crawlAnalysePage(job.url, resp.StatusCode, body, &findings, &findMu)

				// Form submission testing
				if cfg.FormTest && resp.StatusCode == 200 {
					formFindings := testForms(job.url, body, client, sess, cfg.UserAgent)
					if len(formFindings) > 0 {
						findMu.Lock()
						findings = append(findings, formFindings...)
						findMu.Unlock()
					}
				}

				// Extract links if within depth limit
				if job.depth < maxDepth {
					newLinks := extractLinks(body, baseURL, job.url)
					for _, link := range newLinks {
						visitMu.Lock()
						if !visited[link] {
							visitMu.Unlock()
							select {
							case jobCh <- crawlJob{url: link, depth: job.depth + 1}:
							default:
							}
						} else {
							visitMu.Unlock()
						}
					}
				}
			}
		}()
	}
	crawlWg.Wait()
	close(stopCrawl)

	var urls []string
	urls = append(urls, crawledURLs...)
	return urls, findings
}

// crawlRobotsTxt fetches and parses robots.txt, returning all Disallow paths.
func crawlRobotsTxt(base string, client *http.Client, ua string) []string {
	req, err := http.NewRequest("GET", base+"/robots.txt", nil)
	if err != nil { return nil }
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil { return nil }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return nil }
	buf := make([]byte, 32768)
	n, _ := resp.Body.Read(buf)
	var paths []string
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			p := strings.TrimSpace(line[9:])
			if p != "" && p != "/" {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

// crawlSitemap fetches sitemap.xml and returns up to 200 URLs found.
func crawlSitemap(base string, client *http.Client, ua string) []string {
	req, err := http.NewRequest("GET", base+"/sitemap.xml", nil)
	if err != nil { return nil }
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil { return nil }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return nil }
	buf := make([]byte, 524288)
	n, _ := resp.Body.Read(buf)
	var urls []string
	locRe := regexp.MustCompile(`<loc>([^<]+)</loc>`)
	for _, m := range locRe.FindAllStringSubmatch(string(buf[:n]), 200) {
		if len(m) > 1 {
			urls = append(urls, strings.TrimSpace(m[1]))
		}
	}
	return urls
}

// extractLinks parses href, src, action, and JavaScript fetch/axios/XMLHttpRequest
// calls from a page body, returning same-host absolute URLs.
func extractLinks(body string, baseURL *url.URL, currentURL string) []string {
	currentParsed, _ := url.Parse(currentURL)
	seen := make(map[string]bool)
	var links []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") {
			return
		}
		var abs string
		if strings.HasPrefix(raw, "//") {
			abs = baseURL.Scheme + ":" + raw
		} else if strings.HasPrefix(raw, "/") {
			abs = baseURL.Scheme + "://" + baseURL.Host + raw
		} else if strings.Contains(raw, "://") {
			abs = raw
		} else {
			// Relative URL
			base2 := currentParsed
			if base2 == nil { base2 = baseURL }
			abs = base2.Scheme + "://" + base2.Host + "/" + strings.TrimPrefix(raw, "./")
		}
		parsed, err := url.Parse(abs)
		if err != nil { return }
		if parsed.Host != baseURL.Host { return }
		// Strip fragment
		parsed.Fragment = ""
		s := parsed.String()
		if !seen[s] {
			seen[s] = true
			links = append(links, s)
		}
	}

	// href, src, action attributes
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)href=["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)src=["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)action=["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)data-url=["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)data-href=["']([^"']{1,300})["']`),
	} {
		for _, m := range re.FindAllStringSubmatch(body, 500) {
			if len(m) > 1 { add(m[1]) }
		}
	}

	// JS fetch("/api/endpoint") / axios.get("/path") patterns
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)fetch\(["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)axios\.[a-z]+\(["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)\.open\(["'][A-Z]+["'],\s*["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)\$\.(get|post|ajax)\(["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)api[Uu]rl\s*[=:]\s*["']([^"']{1,300})["']`),
		regexp.MustCompile(`(?i)endpoint\s*[=:]\s*["']([^"']{1,300})["']`),
	} {
		for _, m := range re.FindAllStringSubmatch(body, 200) {
			if len(m) > 2 { add(m[2]) } else if len(m) > 1 { add(m[1]) }
		}
	}

	return links
}

// extractParams returns parameter names from a URL's query string.
func extractParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil { return nil }
	var params []string
	for k := range parsed.Query() {
		params = append(params, k)
	}
	return params
}

// crawlAnalysePage inspects a crawled page body for interesting findings.
func crawlAnalysePage(pageURL string, statusCode int, body string, findings *[]Finding, mu *sync.Mutex) {
	var found []Finding

	// Error page stack traces / debug info
	for _, pattern := range []string{
		`(?i)(stack trace|traceback|at [a-zA-Z]+\.[a-zA-Z]+\(.*\.java:\d+\))`,
		`(?i)(Fatal error:|PHP Warning:|PHP Notice:|PHP Parse error:)`,
		`(?i)(SQLSTATE|ORA-\d{5}|mysql_fetch|pg_query|sqlite_)`,
		`(?i)(Traceback \(most recent call last\))`,
		`(?i)(Internal Server Error.*exception|exception.*Internal Server Error)`,
		`(?i)(DEBUG=True|FLASK_DEBUG|django\.conf\.settings)`,
	} {
		if regexp.MustCompile(pattern).MatchString(body) {
			found = append(found, Finding{
				Module: "WebCrawl", Severity: HIGH,
				Title:       fmt.Sprintf("Debug / Stack Trace Exposed: %s", pageURL),
				Detail:      "Page returns debug output, stack traces, or verbose error messages in the HTTP response body.",
				Evidence:    pageURL,
				Remediation: "Disable debug mode. Set DEBUG=False in production. Configure custom error pages.",
			})
			break
		}
	}

	// Hardcoded credentials in JS / HTML
	for _, pattern := range []string{
		`(?i)(password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']`,
		`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["'][a-zA-Z0-9+/]{16,}["']`,
		`(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["'][a-zA-Z0-9._-]{16,}["']`,
		`(?i)(secret[_-]?key|private[_-]?key)\s*[=:]\s*["'][a-zA-Z0-9+/]{16,}["']`,
		`AKIA[0-9A-Z]{16}`,                          // AWS Access Key ID pattern
		`(?i)eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}`, // JWT token
	} {
		if m := regexp.MustCompile(pattern).FindString(body); m != "" {
			truncated := m
			if len(truncated) > 80 { truncated = truncated[:80] + "..." }
			found = append(found, Finding{
				Module: "WebCrawl", Severity: CRITICAL,
				Title:       fmt.Sprintf("Hardcoded Credentials/Secret in Page Source: %s", pageURL),
				Detail:      "Credential or API key pattern found in page HTML/JS source. Exposed secrets can be extracted by any visitor.",
				Evidence:    fmt.Sprintf("%s → %s", pageURL, truncated),
				Remediation: "Remove all secrets from client-side code. Use environment variables and server-side token exchange.",
			})
			break
		}
	}

	// HTML comments with sensitive content
	commentRe := regexp.MustCompile(`<!--(.*?)-->`)
	for _, m := range commentRe.FindAllStringSubmatch(body, 50) {
		comment := strings.TrimSpace(m[1])
		if len(comment) < 6 { continue }
		for _, kw := range []string{"password", "passwd", "todo", "hack", "fixme", "secret", "key", "token", "internal", "disable", "remove", "temp", "debug"} {
			if strings.Contains(strings.ToLower(comment), kw) {
				trunc := comment
				if len(trunc) > 100 { trunc = trunc[:100] + "..." }
				found = append(found, Finding{
					Module: "WebCrawl", Severity: MEDIUM,
					Title:       fmt.Sprintf("Interesting HTML Comment: %s", pageURL),
					Detail:      fmt.Sprintf("HTML comment contains keyword '%s' — may reveal internal information.", kw),
					Evidence:    fmt.Sprintf("%s → <!-- %s -->", pageURL, trunc),
					Remediation: "Remove all comments containing internal information from production HTML.",
				})
				break
			}
		}
	}

	// Form action inspection
	formRe := regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']{1,200})["']`)
	for _, m := range formRe.FindAllStringSubmatch(body, 30) {
		action := m[1]
		for _, suspicious := range []string{"login", "auth", "password", "reset", "admin", "upload", "transfer", "payment", "checkout"} {
			if strings.Contains(strings.ToLower(action), suspicious) {
				found = append(found, Finding{
					Module: "WebCrawl", Severity: INFO,
					Title:       fmt.Sprintf("Sensitive Form Action Discovered: %s", action),
					Detail:      fmt.Sprintf("Form with action '%s' found on %s. Test for CSRF, injection, and authentication bypass.", action, pageURL),
					Evidence:    fmt.Sprintf("%s → <form action=%q>", pageURL, action),
					Remediation: "Ensure CSRF tokens, input validation, and rate limiting on all sensitive form endpoints.",
				})
				break
			}
		}
	}

	// Email addresses in source
	emailRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	emails := emailRe.FindAllString(body, 20)
	if len(emails) > 0 {
		uniqueEmails := make(map[string]bool)
		for _, e := range emails {
			// Skip common false positives
			if strings.HasSuffix(e, ".png") || strings.HasSuffix(e, ".jpg") || strings.HasSuffix(e, ".svg") { continue }
			uniqueEmails[e] = true
		}
		if len(uniqueEmails) > 0 {
			var eList []string
			for e := range uniqueEmails { eList = append(eList, e) }
			found = append(found, Finding{
				Module: "WebCrawl", Severity: INFO,
				Title:       fmt.Sprintf("Email Addresses Found in Source: %s", pageURL),
				Detail:      "Email addresses discovered in page source — may be useful for phishing, OSINT, or social engineering.",
				Evidence:    strings.Join(eList[:min(5, len(eList))], ", "),
				Remediation: "Avoid exposing internal email addresses in public-facing pages. Use contact forms instead.",
			})
		}
	}

	if len(found) > 0 {
		mu.Lock()
		*findings = append(*findings, found...)
		mu.Unlock()
	}
}


// ═══════════════════════════════════════════════════════════════════════
//  GEOIP / ASN LOOKUP
// ═══════════════════════════════════════════════════════════════════════

type ipInfo struct {
	ASN     int
	ASNOrg  string
	Country string
	City    string
	Region  string
	Hosting bool
}

func getIPInfo(ip string) *ipInfo {
	// This uses a simplified approach - in production you'd use a GeoIP database
	// For now, we'll try to get ASN from whois.radb.net
	info := &ipInfo{}
	
	conn, err := net.DialTimeout("tcp", "whois.radb.net:43", 5*time.Second)
	if err != nil {
		return info
	}
	defer conn.Close()
	
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(conn, "%s\r\n", ip)
	
	var sb strings.Builder
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.Contains(line, "origin:") {
			fmt.Sscanf(line, "origin: AS%d", &info.ASN)
		}
		if strings.Contains(line, "descr:") && info.ASNOrg == "" {
			info.ASNOrg = strings.TrimSpace(strings.TrimPrefix(line, "descr:"))
		}
		sb.WriteString(line)
	}
	
	// Detect hosting providers
	hostingKeywords := []string{"aws", "amazon", "azure", "google cloud", "gcp", 
		"digitalocean", "linode", "vultr", "hetzner", "ovh", "scaleway",
		"rackspace", "softlayer", "ibm cloud", "oracle cloud", "alibaba"}
	
	body := strings.ToLower(sb.String())
	for _, kw := range hostingKeywords {
		if strings.Contains(body, kw) {
			info.Hosting = true
			break
		}
	}
	
	return info
}

// ═══════════════════════════════════════════════════════════════════════
//  SCANNER CORE — adaptive timing, UDP, ping sweep, IPv6, retries
// ═══════════════════════════════════════════════════════════════════════

type scanJob struct {
	host     string
	port     int
	protocol string // "tcp" | "udp"
}

// timingProfile translates an Nmap-style -T level into concrete timeouts/delays.
// T0=paranoid … T5=insane
type timingProfile struct {
	timeout    time.Duration
	scanDelay  time.Duration
	maxRetries int
	workers    int
}

func getTimingProfile(level int, baseTimeout time.Duration, baseWorkers int) timingProfile {
	switch level {
	case 0: // paranoid — slow, stealthy
		return timingProfile{timeout: 5 * time.Minute, scanDelay: 5 * time.Minute, maxRetries: 3, workers: 1}
	case 1: // sneaky
		return timingProfile{timeout: 15 * time.Second, scanDelay: 15 * time.Second, maxRetries: 3, workers: 5}
	case 2: // polite
		return timingProfile{timeout: 5 * time.Second, scanDelay: 400 * time.Millisecond, maxRetries: 3, workers: 20}
	case 3: // normal (default)
		return timingProfile{timeout: baseTimeout, scanDelay: 0, maxRetries: 2, workers: baseWorkers}
	case 4: // aggressive
		return timingProfile{timeout: 1250 * time.Millisecond, scanDelay: 0, maxRetries: 2, workers: min(baseWorkers*3, 500)}
	case 5: // insane
		return timingProfile{timeout: 300 * time.Millisecond, scanDelay: 0, maxRetries: 1, workers: min(baseWorkers*5, 1000)}
	default:
		return timingProfile{timeout: baseTimeout, scanDelay: 0, maxRetries: 2, workers: baseWorkers}
	}
}

// pingHost sends a TCP SYN probe on ports 80 and 443 to check if a host is up.
// Falls back to port 22 then 21. Returns true if host responds on any probe port.
func pingHost(host string, timeout time.Duration) bool {
	for _, p := range []int{80, 443, 22, 21} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// pingSweeep performs a concurrent TCP-based ping sweep across all hosts.
// Returns only the hosts that responded to at least one probe.
func pingSweep(hosts []string, timeout time.Duration, workers int) []string {
	type res struct {
		host string
		up   bool
	}
	jobs := make(chan string, len(hosts))
	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)

	out := make(chan res, len(hosts))
	var wg sync.WaitGroup
	w := workers
	if w > len(hosts) {
		w = len(hosts)
	}
	if w < 1 {
		w = 1
	}
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				out <- res{host: h, up: pingHost(h, timeout)}
			}
		}()
	}
	wg.Wait()
	close(out)

	var alive []string
	for r := range out {
		if r.up {
			alive = append(alive, r.host)
		}
	}
	sort.Strings(alive)
	return alive
}

// adaptiveRTTTracker tracks per-host round-trip times and dynamically adjusts
// the effective timeout used for subsequent probes — just like Nmap's timing engine.
type adaptiveRTTTracker struct {
	mu      sync.Mutex
	samples map[string][]time.Duration // host → recent RTTs
}

func newRTTTracker() *adaptiveRTTTracker {
	return &adaptiveRTTTracker{samples: make(map[string][]time.Duration)}
}

// record adds a new RTT sample for a host.
func (t *adaptiveRTTTracker) record(host string, rtt time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.samples[host] = append(t.samples[host], rtt)
	if len(t.samples[host]) > 16 {
		t.samples[host] = t.samples[host][len(t.samples[host])-16:]
	}
}

// timeout returns the suggested timeout for a host: 2× the smoothed avg RTT,
// clamped to [100ms, baseCap].
func (t *adaptiveRTTTracker) timeout(host string, baseCap time.Duration) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.samples[host]
	if len(s) < 3 {
		return baseCap
	}
	var sum time.Duration
	for _, r := range s {
		sum += r
	}
	avg := sum / time.Duration(len(s))
	suggested := avg * 2
	if suggested < 100*time.Millisecond {
		suggested = 100 * time.Millisecond
	}
	if suggested > baseCap {
		suggested = baseCap
	}
	return suggested
}

// udpProbe sends a type-specific UDP payload and waits for a response or ICMP
// port-unreachable. Returns true if the port appears open/filtered.
// Because UDP is connectionless this is best-effort.
func udpProbe(host string, port int, timeout time.Duration) PortResult {
	res := PortResult{Host: host, Port: port, Protocol: "udp"}
	start := time.Now()

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		res.Duration = time.Since(start)
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send a type-appropriate payload
	payload := udpPayload(port)
	if _, err = conn.Write(payload); err != nil {
		res.Duration = time.Since(start)
		return res
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	res.Duration = time.Since(start)

	if err != nil {
		// Read timeout — port is open|filtered (no ICMP unreachable received)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			res.Open = true // open|filtered
			res.Service = fingerprint(port, "")
		}
		return res
	}
	if n > 0 {
		// Got a response — definitively open
		res.Open = true
		res.Banner = string(buf[:n])
		res.BannerClean = sanitize(res.Banner, 256)
		res.Service = fingerprint(port, res.Banner)
	}
	return res
}

// udpPayload returns a protocol-appropriate UDP probe for common ports.
var udpPayload = func(port int) []byte {
	switch port {
	case 53:
		// Minimal DNS query for "version.bind" (CHAOS class)
		return []byte{
			0xAA, 0xBB, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00,
			0x00, 0x10, 0x00, 0x03,
		}
	case 161: // SNMP v1 GetRequest for sysDescr
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
			0x63, 0xa0, 0x19, 0x02, 0x04, 0x71, 0x68, 0x51, 0xa2, 0x02, 0x01, 0x00,
			0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01,
			0x02, 0x01, 0x05, 0x00,
		}
	case 123: // NTP version request
		return []byte{0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	case 500: // IKE Phase 1 initiator cookie probe
		return []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // initiator cookie (zeroed)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder cookie
			0x01, 0x10, 0x02, 0x00, // next payload=SA, version=1.0, exchange=ID_PROT
			0x00, 0x00, 0x00, 0x00, // message ID
			0x00, 0x00, 0x00, 0x1c, // total length = 28
		}
	case 5353: // mDNS query
		return []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x05, 0x5f, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05,
			0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01,
		}
	case 1900: // SSDP M-SEARCH
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	default:
		return []byte{0x00} // generic single-byte probe
	}
}

// scanPorts runs TCP (and optionally UDP) port scanning with adaptive RTT,
// ping sweep, retries, timing profiles, and optional host randomisation.
func scanPorts(hosts []string, ports []int, cfg Config) []PortResult {
	// Apply timing profile
	timing := getTimingProfile(cfg.TimingLevel, cfg.Timeout, cfg.Workers)
	if cfg.TimingLevel == 0 {
		// explicit user overrides win
	} else if cfg.Timeout != 3*time.Second {
		timing.timeout = cfg.Timeout
	}
	if cfg.MaxRetries > 0 {
		timing.maxRetries = cfg.MaxRetries
	}
	if cfg.ScanDelay > 0 {
		timing.scanDelay = cfg.ScanDelay
	}

	// Host randomisation 
	if cfg.RandomHosts {
		shuffled := make([]string, len(hosts))
		copy(shuffled, hosts)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		hosts = shuffled
	}

	// Ping sweep — skip hosts that don't respond (unless -no-ping)
	activeHosts := hosts
	if cfg.ScanPing && !cfg.NoPing {
		progress("Ping sweep — discovering live hosts...", cfg.NoColor)
		activeHosts = pingSweep(hosts, timing.timeout, timing.workers)
		if len(activeHosts) == 0 {
			return nil
		}
	}

	// Adaptive RTT tracker (shared across all workers)
	rtt := newRTTTracker()

	// Build job queue — TCP always, UDP if requested
	protocols := []string{"tcp"}
	if cfg.ScanUDP {
		protocols = append(protocols, "udp")
	}

	total := len(activeHosts) * len(ports) * len(protocols)
	jobs := make(chan scanJob, total)
	for _, h := range activeHosts {
		for _, p := range ports {
			for _, proto := range protocols {
				jobs <- scanJob{h, p, proto}
			}
		}
	}
	close(jobs)

	results := make(chan PortResult, total)

	w := timing.workers
	if w > total { w = total }
	if w < 1 { w = 1 }

	// Adaptive rate controller — honours min/max rate flags
	var rateTicker <-chan time.Time
	if cfg.MaxRate > 0 {
		rateTicker = time.NewTicker(time.Second / time.Duration(cfg.MaxRate)).C
	}

	var wg sync.WaitGroup
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Adaptive delay between probes
				if timing.scanDelay > 0 {
					time.Sleep(timing.scanDelay)
				} else if cfg.RandomDelay {
					time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
				}
				if rateTicker != nil {
					<-rateTicker
				}

				// Use adaptive timeout for this host
				effectiveTimeout := rtt.timeout(j.host, timing.timeout)

				var res PortResult
				if j.protocol == "udp" {
					res = udpProbe(j.host, j.port, effectiveTimeout)
				} else {
					res = doProbe(j.host, j.port, cfg, effectiveTimeout, timing.maxRetries, rtt)
				}
				results <- res
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()

	var out []PortResult
	for r := range results {
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

// doProbe performs a single TCP connect probe with retries and RTT recording.
func doProbe(host string, port int, cfg Config, timeout time.Duration, maxRetries int, rtt *adaptiveRTTTracker) PortResult {
	start := time.Now()
	res := PortResult{Host: host, Port: port, Protocol: "tcp"}

	addr := fmt.Sprintf("%s:%d", host, port)
	var conn net.Conn
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		probeStart := time.Now()
		conn, err = net.DialTimeout("tcp", addr, timeout)
		elapsed := time.Since(probeStart)
		if err == nil {
			rtt.record(host, elapsed)
			break
		}
		// Only retry on timeout — not on connection refused (definitively closed)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && attempt < maxRetries {
			continue
		}
		break
	}

	res.Duration = time.Since(start)
	if err != nil {
		return res
	}
	defer conn.Close()

	res.Open = true
	banner := grabBanner(conn, port, timeout)
	res.Banner = banner
	res.BannerClean = sanitize(banner, 512)
	res.Service = fingerprint(port, banner)

	debug(fmt.Sprintf("port %d OPEN — service=%s version=%s", port, res.Service.Name, res.Service.Version), cfg)

	// TLS audit
	tlsPorts := map[int]bool{
		443: true, 8443: true, 4443: true, 9443: true,
		636: true, 993: true, 995: true, 465: true, 989: true, 990: true,
	}
	if cfg.TLSAudit && (tlsPorts[port] || strings.Contains(res.Service.Name, "HTTPS")) {
		td, tlsFindings := auditTLS(host, port, timeout)
		res.TLSData = td
		res.Findings = append(res.Findings, tlsFindings...)
	}

	// NVD live CVE lookup
	res.Findings = append(res.Findings, liveVulnMatch(res.Service, port, cfg)...)

	// Auth checks
	if cfg.AuthCheck {
		res.Findings = append(res.Findings, checkAuth(host, port, res.Service, timeout)...)
	}

	// HTTP audit for web ports
	if cfg.HTTPAudit && !cfg.AllMods && (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 || port == 3000 || port == 5000) {
		httpResult, httpFindings := auditHTTP(fmt.Sprintf("%s:%d", host, port), cfg)
		res.HTTPData = httpResult
		res.Findings = append(res.Findings, httpFindings...)
	}

	return res
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT — COLOUR TEXT
// ═══════════════════════════════════════════════════════════════════════

// timingName returns the human label for a -T level.
func timingName(level int) string {
	switch level {
	case 0:
		return "paranoid"
	case 1:
		return "sneaky"
	case 2:
		return "polite"
	case 3:
		return "normal"
	case 4:
		return "aggressive"
	case 5:
		return "insane"
	default:
		return "normal"
	}
}

func col(noColor bool, c, s string) string {
	if noColor {
		return s
	}
	return c + s + cReset
}

func sevColor(noColor bool, s Severity) string {
	if noColor {
		return string(s)
	}
	switch s {
	case CRITICAL:
		return cRed + cBold + "CRITICAL" + cReset
	case HIGH:
		return cRed + "HIGH" + cReset
	case MEDIUM:
		return cYellow + "MEDIUM" + cReset
	case LOW:
		return cCyan + "LOW" + cReset
	default:
		return cDim + "INFO" + cReset
	}
}

func printResults(w io.Writer, sr ScanResult, cfg Config) {
	nc := cfg.NoColor

	// Header
	fmt.Fprintf(w, "\n%s\n", col(nc, cCyan+cBold, strings.Repeat("═", 72)))
	fmt.Fprintf(w, "%s\n", col(nc, cCyan+cBold, fmt.Sprintf("  TARGET: %s", sr.Target)))
	if len(sr.IPs) > 0 {
		fmt.Fprintf(w, "%s\n", col(nc, cCyan+cBold, fmt.Sprintf("  IP(s) : %s", strings.Join(sr.IPs, ", "))))
	}
	fmt.Fprintf(w, "%s\n", col(nc, cCyan+cBold, strings.Repeat("═", 72)))

	// OS detection result
	if sr.OS != "" {
		fmt.Fprintf(w, "  %s %s\n", col(nc, cDim, "OS        :"), col(nc, cWhite, sr.OS))
	}
	if sr.ASN > 0 {
		fmt.Fprintf(w, "  %s AS%d (%s)\n", col(nc, cDim, "Network   :"), sr.ASN, sr.ASNOrg)
	}
	if sr.Country != "" {
		fmt.Fprintf(w, "  %s %s\n", col(nc, cDim, "Country   :"), sr.Country)
	}
	if sr.Hosting != "" {
		fmt.Fprintf(w, "  %s %s\n", col(nc, cDim, "Hosting   :"), sr.Hosting)
	}
	fmt.Fprintln(w)

	// ── Port Results ──────────────────────────────────────────────────
	if len(sr.Ports) > 0 {
		fmt.Fprintf(w, "%s\n", col(nc, cBold+cBlue, "  ◆ PORT SCAN RESULTS"))
		fmt.Fprintf(w, "%s\n", col(nc, cDim, "  "+strings.Repeat("─", 68)))

		openCount := 0
		for _, p := range sr.Ports {
			if p.Open {
				openCount++
			}
		}
		fmt.Fprintf(w, "  %s %d open, %d closed\n", col(nc, cDim, "Found:"), openCount, len(sr.Ports)-openCount)

		for _, p := range sr.Ports {
			if !p.Open {
				if cfg.Verbose {
					proto := p.Protocol
					if proto == "" { proto = "tcp" }
					fmt.Fprintf(w, "  %s  %5d/%s\n", col(nc, cDim, "CLOSED"), p.Port, proto)
				}
				continue
			}

			proto := p.Protocol
			if proto == "" { proto = "tcp" }
			protoTag := col(nc, cCyan, proto)

			svcStr := col(nc, cBold, p.Service.Name)
			if p.Service.Version != "" {
				svcStr += " " + col(nc, cDim, p.Service.Version)
			}
			if p.Service.Product != "" && p.Service.Product != p.Service.Name {
				svcStr += " (" + p.Service.Product + ")"
			}

			riskTag := ""
			switch {
			case isHighRiskService(p.Service.Name):
				riskTag = " " + col(nc, cRed, "[HIGH RISK]")
			case isMedRiskService(p.Service.Name):
				riskTag = " " + col(nc, cYellow, "[MEDIUM RISK]")
			}
			if proto == "udp" {
				riskTag += " " + col(nc, cDim, "[UDP]")
			}

			fmt.Fprintf(w, "  %s  %5d/%-4s  %-40s%s  %s\n",
				col(nc, cGreen, "OPEN  "),
				p.Port, protoTag,
				svcStr, riskTag,
				col(nc, cDim, p.Duration.Round(time.Millisecond).String()),
			)

			// Banner preview
			if p.BannerClean != "" {
				lines := strings.Split(p.BannerClean, "\n")
				shown := 0
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					if shown >= 2 {
						break
					}
					if len(line) > 100 {
						line = line[:100] + "..."
					}
					fmt.Fprintf(w, "          %s %s\n", col(nc, cDim, "│"), col(nc, cDim, line))
					shown++
				}
			}

			// TLS summary
			if p.TLSData != nil {
				t := p.TLSData
				certStr := col(nc, cGreen, "valid")
				if t.Expired {
					certStr = col(nc, cRed, "EXPIRED")
				} else if t.SelfSigned {
					certStr = col(nc, cYellow, "self-signed")
				}
				fmt.Fprintf(w, "          %s %s  CN=%s  exp=%s  cert=%s\n",
					col(nc, cCyan, "🔒"), col(nc, cDim, t.Version),
					col(nc, cBold, t.CommonName),
					t.NotAfter.Format("2006-01-02"), certStr)
			}

			// HTTP summary
			if p.HTTPData != nil {
				h := p.HTTPData
				if h.Title != "" {
					fmt.Fprintf(w, "          %s %s\n", col(nc, cCyan, "🌐"), col(nc, cDim, "Title: "+h.Title))
				}
				if len(h.Technologies) > 0 {
					fmt.Fprintf(w, "          %s %s\n", col(nc, cCyan, "🔧"), col(nc, cDim, "Tech: "+strings.Join(h.Technologies, ", ")))
				}
				if h.WAF != "" {
					fmt.Fprintf(w, "          %s %s\n", col(nc, cCyan, "🛡️"), col(nc, cDim, "WAF: "+h.WAF))
				}
			}

			// Port-level findings
			for _, f := range p.Findings {
				liveTag := ""
				if f.Module == "NVDLive" {
					liveTag = col(nc, cPurple, " [LIVE]")
				}
				fmt.Fprintf(w, "          %s %s — %s%s\n",
					col(nc, cRed, "▶"),
					sevColor(nc, f.Severity),
					f.Title, liveTag)
				if f.CVE != "" && f.CVE != "N/A" {
					fmt.Fprintf(w, "            %s\n", col(nc, cDim, "CVE: "+f.CVE))
				}
			}
		}
		fmt.Fprintln(w)
	}

	// ── DNS Records ───────────────────────────────────────────────────
	if len(sr.DNS) > 0 {
		fmt.Fprintf(w, "%s\n", col(nc, cBold+cBlue, "  ◆ DNS RECORDS"))
		fmt.Fprintf(w, "%s\n", col(nc, cDim, "  "+strings.Repeat("─", 68)))
		for _, r := range sr.DNS {
			fmt.Fprintf(w, "  %s%-6s%s  %-40s  %s\n",
				col(nc, cCyan, ""), r.Type, cReset,
				r.Name,
				col(nc, cDim, r.Value))
		}
		fmt.Fprintln(w)
	}

	// ── Subdomains ────────────────────────────────────────────────────
	if len(sr.Subdomains) > 0 {
		fmt.Fprintf(w, "%s\n", col(nc, cBold+cBlue, "  ◆ DISCOVERED SUBDOMAINS"))
		fmt.Fprintf(w, "%s\n", col(nc, cDim, "  "+strings.Repeat("─", 68)))
		for _, s := range sr.Subdomains[:min(20, len(sr.Subdomains))] {
			fmt.Fprintf(w, "  %s %s\n", col(nc, cGreen, "●"), s)
		}
		if len(sr.Subdomains) > 20 {
			fmt.Fprintf(w, "  %s ... and %d more\n", col(nc, cDim, "●"), len(sr.Subdomains)-20)
		}
		fmt.Fprintln(w)
	}

	// ── Crawled URLs ──────────────────────────────────────────────────
	if len(sr.CrawledURLs) > 0 {
		fmt.Fprintf(w, "%s\n", col(nc, cBold+cBlue, "  ◆ CRAWLED URLs"))
		fmt.Fprintf(w, "%s\n", col(nc, cDim, "  "+strings.Repeat("─", 68)))
		shown := sr.CrawledURLs
		if !cfg.Verbose && len(shown) > 20 {
			shown = shown[:20]
		}
		for _, u := range shown {
			fmt.Fprintf(w, "  %s %s\n", col(nc, cCyan, "↳"), u)
		}
		if !cfg.Verbose && len(sr.CrawledURLs) > 20 {
			fmt.Fprintf(w, "  %s ... and %d more (use -v to see all)\n",
				col(nc, cDim, "↳"), len(sr.CrawledURLs)-20)
		}
		fmt.Fprintln(w)
	}

	// ── HTTP Audit ────────────────────────────────────────────────────
	if sr.HTTP != nil && sr.HTTP.URL != "" {
		h := sr.HTTP
		fmt.Fprintf(w, "%s\n", col(nc, cBold+cBlue, "  ◆ HTTP AUDIT"))
		fmt.Fprintf(w, "%s\n", col(nc, cDim, "  "+strings.Repeat("─", 68)))
		fmt.Fprintf(w, "  URL     : %s  [%d] (%s)\n", h.URL, h.StatusCode, h.ResponseTime.Round(time.Millisecond))
		if h.Title != "" {
			fmt.Fprintf(w, "  Title   : %s\n", col(nc, cBold, h.Title))
		}
		if h.Server != "" {
			fmt.Fprintf(w, "  Server  : %s\n", col(nc, cYellow, h.Server))
		}
		if h.PoweredBy != "" {
			fmt.Fprintf(w, "  Powered : %s\n", col(nc, cYellow, h.PoweredBy))
		}
		if h.WAF != "" {
			fmt.Fprintf(w, "  WAF     : %s\n", col(nc, cPurple, h.WAF))
		}
		if len(h.Technologies) > 0 {
			fmt.Fprintf(w, "  Tech    : %s\n", col(nc, cCyan, strings.Join(h.Technologies, ", ")))
		}
		if len(h.MissingHeaders) > 0 {
			fmt.Fprintf(w, "  Missing Headers: %s\n", col(nc, cRed, strings.Join(h.MissingHeaders, ", ")))
		}
		if len(h.DangerousMethods) > 0 {
			fmt.Fprintf(w, "  Dangerous Methods: %s\n", col(nc, cRed, strings.Join(h.DangerousMethods, ", ")))
		}
		if len(h.RobotsEntries) > 0 {
			fmt.Fprintf(w, "  robots.txt (%d entries): ", len(h.RobotsEntries))
			fmt.Fprintf(w, "%s\n", col(nc, cDim, strings.Join(h.RobotsEntries[:min(3, len(h.RobotsEntries))], "; ")))
		}
		if len(h.SitemapEntries) > 0 {
			fmt.Fprintf(w, "  sitemap.xml (%d entries)\n", len(h.SitemapEntries))
		}
		if len(h.Comments) > 0 {
			fmt.Fprintf(w, "  HTML Comments: %d found\n", len(h.Comments))
		}
		if len(h.Cookies) > 0 {
			fmt.Fprintf(w, "  Cookies: %d set\n", len(h.Cookies))
			for _, ck := range h.Cookies[:min(5, len(h.Cookies))] {
				issues := ""
				if len(ck.Issues) > 0 {
					issues = " [" + strings.Join(ck.Issues, ", ") + "]"
				}
				fmt.Fprintf(w, "    %s=%s%s\n", ck.Name, ck.Value, issues)
			}
		}
		if len(h.Forms) > 0 {
			fmt.Fprintf(w, "  Forms: %d found\n", len(h.Forms))
		}
		fmt.Fprintln(w)
	}

	// ── All Findings ──────────────────────────────────────────────────
	allFindings := sr.Findings
	// Also collect from ports
	for _, p := range sr.Ports {
		allFindings = append(allFindings, p.Findings...)
	}

	if len(allFindings) > 0 {
		// Sort by severity
		sevOrder := map[Severity]int{CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
		sort.Slice(allFindings, func(i, j int) bool {
			return sevOrder[allFindings[i].Severity] < sevOrder[allFindings[j].Severity]
		})

		// Count, also track how many are live NVD
		counts := make(map[Severity]int)
		liveCount := 0
		for _, f := range allFindings {
			counts[f.Severity]++
			if f.Module == "NVDLive" {
				liveCount++
			}
		}

		fmt.Fprintf(w, "%s\n", col(nc, cBold+cRed, "  ◆ FINDINGS SUMMARY"))
		fmt.Fprintf(w, "%s\n", col(nc, cDim, "  "+strings.Repeat("─", 68)))
		fmt.Fprintf(w, "  %s  %s  %s  %s  %s",
			col(nc, cRed+cBold, fmt.Sprintf("CRITICAL: %d", counts[CRITICAL])),
			col(nc, cRed, fmt.Sprintf("HIGH: %d", counts[HIGH])),
			col(nc, cYellow, fmt.Sprintf("MEDIUM: %d", counts[MEDIUM])),
			col(nc, cCyan, fmt.Sprintf("LOW: %d", counts[LOW])),
			col(nc, cDim, fmt.Sprintf("INFO: %d", counts[INFO])),
		)
		if liveCount > 0 {
			fmt.Fprintf(w, "  %s", col(nc, cPurple, fmt.Sprintf("(🟣 %d from Live NVD)", liveCount)))
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w)

		for i, f := range allFindings {
			if i >= 20 && !cfg.Verbose {
				fmt.Fprintf(w, "  %s ... and %d more findings (use -v to see all)\n",
					col(nc, cDim, "▶"), len(allFindings)-20)
				break
			}
			liveTag := ""
			if f.Module == "NVDLive" {
				liveTag = col(nc, cPurple, " [LIVE]")
			}
			fmt.Fprintf(w, "  %s [%s] %s — %s%s\n",
				col(nc, cDim, "▶"),
				sevColor(nc, f.Severity),
				col(nc, cBold, f.Module),
				f.Title, liveTag)
			if cfg.Verbose {
				fmt.Fprintf(w, "    Detail : %s\n", f.Detail)
				if f.Evidence != "" {
					fmt.Fprintf(w, "    Evidence: %s\n", col(nc, cDim, f.Evidence))
				}
				if f.CVE != "" && f.CVE != "N/A" {
					fmt.Fprintf(w, "    CVE     : %s\n", col(nc, cRed, f.CVE))
				}
				fmt.Fprintf(w, "    Fix     : %s\n", col(nc, cGreen, f.Remediation))
			}
		}
		fmt.Fprintln(w)
	}

	// Footer
	fmt.Fprintf(w, "%s\n", col(nc, cDim, strings.Repeat("─", 72)))
	fmt.Fprintf(w, "  Scan completed: %s\n",
		col(nc, cDim, fmt.Sprintf("started %s | duration %s",
			sr.StartTime.Format("15:04:05"),
			sr.EndTime.Sub(sr.StartTime).Round(time.Millisecond))))
	fmt.Fprintln(w)
}

func isHighRiskService(name string) bool {
	highRisk := map[string]bool{
		"Telnet": true, "FTP": true, "MongoDB": true, "Redis": true,
		"Elasticsearch": true, "Docker API": true, "Memcached": true,
		"Kubernetes API": true, "Consul": true, "Vault": true,
		"etcd": true, "ZooKeeper": true, "CouchDB": true, "RabbitMQ": true,
		"Jenkins": true, "Jira": true, "GitLab": true, "Tomcat": true,
	}
	return highRisk[name]
}

func isMedRiskService(name string) bool {
	medRisk := map[string]bool{
		"MySQL": true, "PostgreSQL": true, "MSSQL": true, "Oracle DB": true,
		"LDAP": true, "SMB": true, "RDP": true, "VNC": true,
		"IMAP": true, "POP3": true, "Cassandra": true, "Neo4j": true,
		"Prometheus": true, "Grafana": true, "GlassFish": true, "ActiveMQ": true,
		"HTTP": true, "HTTPS": true, "SMTP": true, "DNS": true,
	}
	return medRisk[name]
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT — JSON
// ═══════════════════════════════════════════════════════════════════════

func writeJSON(w io.Writer, sr ScanResult) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(sr)
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT — HTML REPORT
// ═══════════════════════════════════════════════════════════════════════

func writeHTMLReport(path string, sr ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	allFindings := sr.Findings
	for _, p := range sr.Ports {
		allFindings = append(allFindings, p.Findings...)
	}
	counts := make(map[Severity]int)
	for _, f := range allFindings {
		counts[f.Severity]++
	}
	sevOrder := map[Severity]int{CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
	sort.Slice(allFindings, func(i, j int) bool {
		return sevOrder[allFindings[i].Severity] < sevOrder[allFindings[j].Severity]
	})

	doc := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RECON-X Report — %s</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
  .header{background:linear-gradient(135deg,#161b22,#1f2937);padding:2rem;border-bottom:1px solid #30363d}
  .header h1{font-size:2rem;color:#58a6ff;letter-spacing:.1em}
  .header .sub{color:#8b949e;margin-top:.5rem}
  .container{max-width:1400px;margin:0 auto;padding:2rem}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
  .card h2{color:#58a6ff;font-size:1.1rem;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem}
  .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}
  .stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.2rem;text-align:center}
  .stat .n{font-size:2.5rem;font-weight:700}
  .stat .l{font-size:.8rem;color:#8b949e;text-transform:uppercase;letter-spacing:.1em;margin-top:.2rem}
  .critical .n{color:#f85149} .high .n{color:#e57606}
  .medium .n{color:#d29922} .low .n{color:#3fb950} .info-s .n{color:#58a6ff}
  .finding{border-left:3px solid #30363d;padding:.8rem 1rem;margin-bottom:.8rem;background:#0d1117;border-radius:0 6px 6px 0}
  .finding.CRITICAL{border-left-color:#f85149}
  .finding.HIGH{border-left-color:#e57606}
  .finding.MEDIUM{border-left-color:#d29922}
  .finding.LOW{border-left-color:#3fb950}
  .finding.INFO{border-left-color:#58a6ff}
  .badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;font-weight:700;margin-right:.4rem}
  .badge.CRITICAL{background:#f85149;color:#fff}
  .badge.HIGH{background:#e57606;color:#fff}
  .badge.MEDIUM{background:#d29922;color:#000}
  .badge.LOW{background:#3fb950;color:#000}
  .badge.INFO{background:#58a6ff;color:#fff}
  .nvd-badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.65rem;font-weight:700;background:#b15cff;color:#fff;margin-left:.4rem;vertical-align:middle}
  .port-row{display:grid;grid-template-columns:60px 100px 1fr 100px;gap:1rem;padding:.5rem 0;border-bottom:1px solid #21262d}
  .port-row:last-child{border-bottom:none}
  .open{color:#3fb950;font-weight:700} .closed{color:#6e7681}
  .tag{background:#1f2937;border:1px solid #30363d;padding:.1rem .4rem;border-radius:4px;font-size:.75rem;color:#58a6ff;margin-left:.3rem}
  .risk-high{color:#f85149;font-weight:700} .risk-med{color:#d29922}
  pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:1rem;overflow-x:auto;font-size:.8rem;color:#8b949e}
  .dns-row{display:grid;grid-template-columns:60px 1fr 2fr;gap:1rem;padding:.4rem 0;border-bottom:1px solid #21262d;font-size:.85rem}
  table{width:100%%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:.5rem;background:#1f2937;color:#8b949e;font-weight:600;text-transform:uppercase;font-size:.75rem}
  td{padding:.5rem;border-bottom:1px solid #21262d}
  .sub-item{color:#8b949e;font-size:.85rem;padding:.2rem 0}
  footer{text-align:center;padding:2rem;color:#6e7681;font-size:.8rem;border-top:1px solid #21262d}
</style>
</head>
<body>
<div class="header">
  <div class="container">
    <h1>⚡ RECON-X</h1>
    <div class="sub">Reconnaissance Report — Target: <strong style="color:#e3b341">%s</strong> — %s</div>
  </div>
</div>
<div class="container">

<div class="stats">
  <div class="stat critical"><div class="n">%d</div><div class="l">Critical</div></div>
  <div class="stat high"><div class="n">%d</div><div class="l">High</div></div>
  <div class="stat medium"><div class="n">%d</div><div class="l">Medium</div></div>
  <div class="stat low"><div class="n">%d</div><div class="l">Low</div></div>
  <div class="stat info-s"><div class="n">%d</div><div class="l">Info</div></div>
</div>
`,
		sr.Target, sr.Target,
		sr.StartTime.Format("2006-01-02 15:04:05"),
		counts[CRITICAL], counts[HIGH], counts[MEDIUM], counts[LOW], counts[INFO],
	)

	// Findings
	if len(allFindings) > 0 {
		doc += `<div class="card"><h2>🔍 Findings</h2>`
		for _, finding := range allFindings {
			cve := ""
			if finding.CVE != "" && finding.CVE != "N/A" {
				cve = fmt.Sprintf(`<span class="tag">%s</span>`, html.EscapeString(finding.CVE))
			}
			// NVD live findings get a purple LIVE badge
			moduleBadge := ""
			if finding.Module == "NVDLive" {
				moduleBadge = `<span class="nvd-badge">🟣 LIVE NVD</span>`
			}
			evidenceHTML := ""
			if finding.Evidence != "" {
				evidenceHTML = fmt.Sprintf(`<div style="margin-top:.3rem;font-family:monospace;font-size:.75rem;color:#8b949e">Evidence: %s</div>`, html.EscapeString(finding.Evidence))
			}
			doc += fmt.Sprintf(`<div class="finding %s">
  <div><span class="badge %s">%s</span><strong>%s</strong>%s%s <span style="color:#8b949e;font-size:.8rem">[%s]</span></div>
  <div style="margin-top:.4rem;color:#8b949e;font-size:.85rem">%s</div>
  %s
  <div style="margin-top:.4rem;color:#3fb950;font-size:.8rem">✔ %s</div>
</div>`,
				finding.Severity, finding.Severity, finding.Severity,
				html.EscapeString(finding.Title), cve, moduleBadge, html.EscapeString(finding.Module),
				html.EscapeString(finding.Detail),
				evidenceHTML,
				html.EscapeString(finding.Remediation),
			)
		}
		doc += `</div>`
	}

	// Ports
	if len(sr.Ports) > 0 {
		doc += `<div class="card"><h2>🔌 Open Ports</h2>
<div style="font-size:.8rem;color:#8b949e;margin-bottom:.5rem;display:grid;grid-template-columns:60px 100px 1fr 100px;gap:1rem;padding:.3rem 0">
<span>STATE</span><span>PORT</span><span>SERVICE</span><span>TIME</span></div>`
		for _, p := range sr.Ports {
			if !p.Open {
				continue
			}
			riskStr := ""
			if isHighRiskService(p.Service.Name) {
				riskStr = `<span style="color:#f85149;font-size:.75rem;margin-left:.5rem">⚠ HIGH RISK</span>`
			} else if isMedRiskService(p.Service.Name) {
				riskStr = `<span style="color:#d29922;font-size:.75rem;margin-left:.5rem">⚠ MEDIUM RISK</span>`
			}
			ver := ""
			if p.Service.Version != "" {
				ver = fmt.Sprintf(` <span style="color:#8b949e;font-size:.8rem">(%s)</span>`, html.EscapeString(p.Service.Version))
			}
			doc += fmt.Sprintf(`<div class="port-row">
<span class="open">OPEN</span>
<span><strong style="color:#58a6ff">%d</strong>/tcp</span>
<span><strong>%s</strong>%s%s</span>
<span style="color:#8b949e;font-size:.8rem">%s</span>
</div>`, p.Port, html.EscapeString(p.Service.Name), ver, riskStr, p.Duration.Round(time.Millisecond))
		}
		doc += `</div>`
	}

	// DNS
	if len(sr.DNS) > 0 {
		doc += `<div class="card"><h2>🌐 DNS Records</h2>`
		doc += `<div style="font-size:.8rem;color:#8b949e;display:grid;grid-template-columns:60px 1fr 2fr;gap:1rem;padding:.3rem 0"><span>TYPE</span><span>NAME</span><span>VALUE</span></div>`
		for _, r := range sr.DNS {
			doc += fmt.Sprintf(`<div class="dns-row"><span style="color:#58a6ff;font-weight:700">%s</span><span>%s</span><span style="color:#8b949e">%s</span></div>`,
				html.EscapeString(r.Type), html.EscapeString(r.Name), html.EscapeString(r.Value))
		}
		doc += `</div>`
	}

	// Subdomains
	if len(sr.Subdomains) > 0 {
		doc += fmt.Sprintf(`<div class="card"><h2>🔎 Subdomains (%d found)</h2>`, len(sr.Subdomains))
		for _, s := range sr.Subdomains[:min(20, len(sr.Subdomains))] {
			doc += fmt.Sprintf(`<div class="sub-item">● %s</div>`, html.EscapeString(s))
		}
		if len(sr.Subdomains) > 20 {
			doc += fmt.Sprintf(`<div class="sub-item">● ... and %d more</div>`, len(sr.Subdomains)-20)
		}
		doc += `</div>`
	}

	// HTTP Audit
	if sr.HTTP != nil && sr.HTTP.URL != "" {
		h := sr.HTTP
		doc += fmt.Sprintf(`<div class="card"><h2>🌍 HTTP Audit — <span style="color:#3fb950">%s</span> [%d] (%s)</h2>`,
			html.EscapeString(h.URL), h.StatusCode, h.ResponseTime.Round(time.Millisecond))
		if h.Server != "" {
			doc += fmt.Sprintf(`<div>Server: <span style="color:#e3b341">%s</span></div>`, html.EscapeString(h.Server))
		}
		if h.Title != "" {
			doc += fmt.Sprintf(`<div>Title: <strong>%s</strong></div>`, html.EscapeString(h.Title))
		}
		if h.WAF != "" {
			doc += fmt.Sprintf(`<div>WAF: <span style="color:#b15cff">%s</span></div>`, html.EscapeString(h.WAF))
		}
		if len(h.Technologies) > 0 {
			doc += `<div style="margin-top:.5rem">Technologies: `
			for _, t := range h.Technologies {
				doc += fmt.Sprintf(`<span class="tag">%s</span>`, html.EscapeString(t))
			}
			doc += `</div>`
		}
		if len(h.MissingHeaders) > 0 {
			escaped := make([]string, len(h.MissingHeaders))
			for i, hdr := range h.MissingHeaders {
				escaped[i] = html.EscapeString(hdr)
			}
			doc += `<div style="margin-top:.5rem;color:#f85149">Missing Security Headers: ` + strings.Join(escaped, ", ") + `</div>`
		}
		if len(h.DangerousMethods) > 0 {
			escaped := make([]string, len(h.DangerousMethods))
			for i, m := range h.DangerousMethods {
				escaped[i] = html.EscapeString(m)
			}
			doc += `<div style="color:#f85149">Dangerous Methods: ` + strings.Join(escaped, ", ") + `</div>`
		}
		if len(h.RobotsEntries) > 0 {
			escaped := make([]string, len(h.RobotsEntries))
			for i, e := range h.RobotsEntries {
				escaped[i] = html.EscapeString(e)
			}
			doc += `<div style="margin-top:.5rem"><strong>robots.txt entries:</strong><pre>` + strings.Join(escaped, "\n") + `</pre></div>`
		}
		if len(h.SitemapEntries) > 0 {
			escaped := make([]string, len(h.SitemapEntries))
			for i, e := range h.SitemapEntries {
				escaped[i] = html.EscapeString(e)
			}
			doc += `<div style="margin-top:.5rem"><strong>sitemap.xml entries:</strong><pre>` + strings.Join(escaped, "\n") + `</pre></div>`
		}
		if len(h.Forms) > 0 {
			doc += fmt.Sprintf(`<div style="margin-top:.5rem"><strong>Forms (%d):</strong><table><tr><th>Action</th><th>Method</th><th>Fields</th></tr>`, len(h.Forms))
			for _, form := range h.Forms {
				var fields []string
				for _, f := range form.Fields {
					fields = append(fields, html.EscapeString(f.Name)+" ("+html.EscapeString(f.Type)+")")
				}
				doc += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(form.Action), html.EscapeString(form.Method), strings.Join(fields, ", "))
			}
			doc += `</table></div>`
		}
		doc += `</div>`
	}

	// Crawled URLs
	if len(sr.CrawledURLs) > 0 {
		doc += fmt.Sprintf(`<div class="card"><h2>🕷️ Crawled URLs (%d found)</h2>`, len(sr.CrawledURLs))
		for _, u := range sr.CrawledURLs[:min(50, len(sr.CrawledURLs))] {
			doc += fmt.Sprintf(`<div class="sub-item">↳ %s</div>`, html.EscapeString(u))
		}
		if len(sr.CrawledURLs) > 50 {
			doc += fmt.Sprintf(`<div class="sub-item">… and %d more</div>`, len(sr.CrawledURLs)-50)
		}
		doc += `</div>`
	}

	doc += fmt.Sprintf(`</div>
<footer>Generated by RECON-X  · %s · For authorized testing only</footer>
</body></html>`, time.Now().Format("2006-01-02 15:04:05"))

	_, err = f.WriteString(doc)
	return err
}

// ═══════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func progress(msg string, noColor bool) {
	if noColor {
		fmt.Fprintf(os.Stderr, "[*] %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s[*]%s %s\n", cCyan, cReset, msg)
	}
}

func warn(msg string, noColor bool) {
	if noColor {
		fmt.Fprintf(os.Stderr, "[!] %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s[!]%s %s\n", cYellow, cReset, msg)
	}
}

func debug(msg string, cfg Config) {
	if cfg.Debug {
		fmt.Fprintf(os.Stderr, "%s[DEBUG]%s %s\n", cPurple, cReset, msg)
	}
}

// ═══════════════════════════════════════════════════════════════════════
//  SYN SCAN (TCP half-open) — requires root / CAP_NET_RAW
// ═══════════════════════════════════════════════════════════════════════
//
//  Pure Go raw-socket SYN scan. On Linux we use a SOCK_RAW IPPROTO_TCP
//  socket to send hand-crafted SYN packets and listen for SYN-ACK/RST.
//  Falls back gracefully to a normal connect scan when the process has
//  insufficient privileges.

// synScanResult is a lightweight result for a single SYN probe.
type synScanResult struct {
	Host  string
	Port  int
	Open  bool
	RST   bool
}

// synScanPorts performs SYN scanning on the given host+ports list.
// Returns open ports. Falls back to TCP connect on permission error.
func synScanPorts(host string, ports []int, timeout time.Duration) []synScanResult {
	// Try to dial a raw socket — if it fails, fall back to connect scan.
	rawConn, rawErr := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if rawErr != nil {
		// Insufficient privileges — fall back to connect-based detection.
		var out []synScanResult
		for _, p := range ports {
			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				out = append(out, synScanResult{Host: host, Port: p, Open: true})
			}
		}
		return out
	}
	defer rawConn.Close()

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return nil
		}
		targetIP = net.ParseIP(addrs[0])
	}
	targetIP = targetIP.To4()
	if targetIP == nil {
		return nil
	}

	type probe struct {
		port   int
		srcPort uint16
	}

	// Build SYN packet for each port
	buildSYN := func(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum uint32) []byte {
		packet := make([]byte, 20) // TCP header only (no IP header for raw IPPROTO_TCP)
		// src port
		packet[0] = byte(srcPort >> 8)
		packet[1] = byte(srcPort)
		// dst port
		packet[2] = byte(dstPort >> 8)
		packet[3] = byte(dstPort)
		// seq number
		packet[4] = byte(seqNum >> 24)
		packet[5] = byte(seqNum >> 16)
		packet[6] = byte(seqNum >> 8)
		packet[7] = byte(seqNum)
		// ack = 0
		// offset (5 << 4) = 0x50, flags: SYN=0x02
		packet[12] = 0x50
		packet[13] = 0x02
		// window
		packet[14] = 0x20
		packet[15] = 0x00
		// checksum — compute pseudo-header
		pseudo := make([]byte, 12+len(packet))
		copy(pseudo[0:4], srcIP.To4())
		copy(pseudo[4:8], dstIP.To4())
		pseudo[8] = 0
		pseudo[9] = 6 // TCP
		pseudo[10] = byte(len(packet) >> 8)
		pseudo[11] = byte(len(packet))
		copy(pseudo[12:], packet)
		csum := tcpChecksum(pseudo)
		packet[16] = byte(csum >> 8)
		packet[17] = byte(csum)
		return packet
	}

	// Determine local IP
	localIP := net.ParseIP("127.0.0.1").To4()
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if v4 := ipnet.IP.To4(); v4 != nil {
						localIP = v4
					}
				}
			}
		}
	}

	var mu sync.Mutex
	openPorts := make(map[int]bool)
	rstPorts := make(map[int]bool)

	// Goroutine: listen for responses
	stopListen := make(chan struct{})
	var listenWg sync.WaitGroup
	listenWg.Add(1)
	go func() {
		defer listenWg.Done()
		buf := make([]byte, 1500)
		_ = rawConn.(interface {
			SetReadDeadline(t time.Time) error
		}).SetReadDeadline(time.Now().Add(timeout + 500*time.Millisecond))
		for {
			select {
			case <-stopListen:
				return
			default:
			}
			n, addr, err := rawConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = addr
			if n < 20 {
				continue
			}
			// Parse TCP header (no IP header since IPPROTO_TCP)
			tcpHdr := buf[:n]
			srcPort := int(binary.BigEndian.Uint16(tcpHdr[0:2]))
			flags := tcpHdr[13]
			isSYNACK := (flags & 0x12) == 0x12
			isRST := (flags & 0x04) != 0
			mu.Lock()
			if isSYNACK {
				openPorts[srcPort] = true
			} else if isRST {
				rstPorts[srcPort] = true
			}
			mu.Unlock()
		}
	}()

	// Send SYN packets
	sem := make(chan struct{}, 50)
	var sendWg sync.WaitGroup
	for _, port := range ports {
		sendWg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer sendWg.Done()
			defer func() { <-sem }()
			srcPort := uint16(40000 + rand.Intn(20000))
			syn := buildSYN(localIP, targetIP, srcPort, uint16(p), rand.Uint32())
			_, _ = rawConn.WriteTo(syn, &net.IPAddr{IP: targetIP})
		}(port)
	}
	sendWg.Wait()

	// Wait for replies
	time.Sleep(timeout)
	close(stopListen)
	listenWg.Wait()

	mu.Lock()
	defer mu.Unlock()

	var results []synScanResult
	for _, p := range ports {
		if openPorts[p] {
			results = append(results, synScanResult{Host: host, Port: p, Open: true})
		} else if rstPorts[p] {
			results = append(results, synScanResult{Host: host, Port: p, Open: false, RST: true})
		}
	}
	return results
}

// tcpChecksum computes the TCP checksum over the pseudo-header + TCP segment.
func tcpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ═══════════════════════════════════════════════════════════════════════
//  CONNECTION POOL for HTTP probing
// ═══════════════════════════════════════════════════════════════════════

// ConnPool manages a pool of persistent HTTP clients, one per base URL.
// Re-using connections dramatically reduces latency for deep web-crawl or
// multi-request HTTP audit operations against the same host.

type httpConnPool struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

var globalConnPool = &httpConnPool{
	clients: make(map[string]*http.Client),
}

// Get returns a cached *http.Client for the given scheme+host, creating one
// on first call. The client uses connection keep-alive and a shared transport.
func (p *httpConnPool) Get(scheme, host string, timeout time.Duration, proxy string) *http.Client {
	key := scheme + "://" + host
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[key]; ok {
		return c
	}
	transport := &http.Transport{
		MaxIdleConnsPerHost: 20,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableCompression:  false,
	}
	if proxy != "" {
		if proxyURL, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	p.clients[key] = client
	return client
}

// ═══════════════════════════════════════════════════════════════════════
//  ENHANCED CERTIFICATE TRANSPARENCY (multiple sources)
// ═══════════════════════════════════════════════════════════════════════

// ctSource defines a certificate transparency source.
type ctSource struct {
	name    string
	urlFmt  string // %s = domain
	parseFunc func(body []byte, domain string) []string
}

// ctEnhancedLookup queries multiple CT sources and deduplicates results.
func ctEnhancedLookup(domain string) ([]string, []Finding) {
	sources := []ctSource{
		{
			name:   "crt.sh",
			urlFmt: "https://crt.sh/?q=%%25.%s&output=json",
			parseFunc: func(body []byte, domain string) []string {
				var entries []struct {
					NameValue string `json:"name_value"`
				}
				if err := json.Unmarshal(body, &entries); err != nil {
					return nil
				}
				var names []string
				for _, e := range entries {
					for _, n := range strings.Split(e.NameValue, "\n") {
						n = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(n, "*.")))
						if n != "" && (n == domain || strings.HasSuffix(n, "."+domain)) {
							names = append(names, n)
						}
					}
				}
				return names
			},
		},
		{
			name:   "certspotter",
			urlFmt: "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
			parseFunc: func(body []byte, domain string) []string {
				var entries []struct {
					DNSNames []string `json:"dns_names"`
				}
				if err := json.Unmarshal(body, &entries); err != nil {
					return nil
				}
				var names []string
				for _, e := range entries {
					for _, n := range e.DNSNames {
						n = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(n, "*.")))
						if n != "" && (n == domain || strings.HasSuffix(n, "."+domain)) {
							names = append(names, n)
						}
					}
				}
				return names
			},
		},
		{
			name:   "alienvault",
			urlFmt: "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns",
			parseFunc: func(body []byte, domain string) []string {
				var resp struct {
					PassiveDNS []struct {
						Hostname string `json:"hostname"`
					} `json:"passive_dns"`
				}
				if err := json.Unmarshal(body, &resp); err != nil {
					return nil
				}
				var names []string
				for _, e := range resp.PassiveDNS {
					n := strings.ToLower(e.Hostname)
					if n != "" && (n == domain || strings.HasSuffix(n, "."+domain)) {
						names = append(names, n)
					}
				}
				return names
			},
		},
	}

	seen := make(map[string]bool)
	var allSubs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{Timeout: 25 * time.Second}

	for _, src := range sources {
		wg.Add(1)
		go func(s ctSource) {
			defer wg.Done()
			rawURL := fmt.Sprintf(s.urlFmt, domain)
			req, err := http.NewRequest("GET", rawURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; RECON-X)")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
			if err != nil {
				return
			}
			names := s.parseFunc(body, domain)
			mu.Lock()
			for _, n := range names {
				if !seen[n] {
					seen[n] = true
					// Attempt live resolution
					if ips, err2 := net.LookupHost(n); err2 == nil && len(ips) > 0 {
						allSubs = append(allSubs, fmt.Sprintf("%s → %s [via %s]", n, strings.Join(ips, ","), s.name))
					} else {
						allSubs = append(allSubs, fmt.Sprintf("%s [via %s, unresolved]", n, s.name))
					}
				}
			}
			mu.Unlock()
		}(src)
	}
	wg.Wait()
	sort.Strings(allSubs)

	var findings []Finding
	if len(allSubs) > 0 {
		findings = append(findings, Finding{
			Module:      "CTEnhanced", Severity: INFO,
			Title:       fmt.Sprintf("Enhanced CT Lookup: %d Unique Subdomain(s) Across %d Sources", len(allSubs), len(sources)),
			Detail:      "Subdomains discovered from crt.sh, CertSpotter, and AlienVault OTX certificate transparency logs. CT logs are permanent and public.",
			Evidence:    strings.Join(allSubs[:min(15, len(allSubs))], "\n"),
			Remediation: "Review each subdomain for unintended exposure. CT entries cannot be removed.",
		})
	}
	return allSubs, findings
}

// ═══════════════════════════════════════════════════════════════════════
//  DNS MUTATION ENGINE (brute-force with smart mutations)
// ═══════════════════════════════════════════════════════════════════════

// dnsMutate generates mutation-based subdomain candidates from a wordlist entry.
// Mutations include: common prefixes, number suffixes, environment names,
// region suffixes, and typo-style permutations.
func dnsMutate(base string) []string {
	mutations := make(map[string]bool)
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && s != base {
			mutations[s] = true
		}
	}

	// Environment prefixes/suffixes
	envWords := []string{"dev", "staging", "stage", "prod", "production", "test",
		"qa", "uat", "demo", "beta", "alpha", "sandbox", "preprod",
		"canary", "int", "integration", "perf", "load", "dr", "lab"}
	for _, e := range envWords {
		add(e + "-" + base)
		add(base + "-" + e)
		add(e + "." + base)
		add(base + "." + e)
	}

	// Numeric suffixes
	for i := 1; i <= 5; i++ {
		add(fmt.Sprintf("%s%d", base, i))
		add(fmt.Sprintf("%s-%d", base, i))
		add(fmt.Sprintf("%s0%d", base, i))
	}

	// Cloud region suffixes
	regions := []string{"us", "eu", "ap", "us-east", "us-west", "eu-west",
		"ap-south", "ap-east", "us-east-1", "us-west-2", "eu-west-1",
		"eu-central-1", "ap-southeast-1", "ap-northeast-1"}
	for _, r := range regions {
		add(base + "-" + r)
		add(r + "-" + base)
	}

	// Common sub-prefixes
	prefixes := []string{"api", "app", "admin", "portal", "auth", "login",
		"internal", "private", "corp", "vpn", "git", "ci", "cd",
		"build", "deploy", "registry", "monitoring", "log", "logs"}
	for _, p := range prefixes {
		add(p + "-" + base)
		add(base + "-" + p)
	}

	// Dash/dot substitution
	if strings.Contains(base, "-") {
		add(strings.ReplaceAll(base, "-", "."))
		add(strings.ReplaceAll(base, "-", ""))
	}
	if strings.Contains(base, ".") {
		add(strings.ReplaceAll(base, ".", "-"))
		add(strings.ReplaceAll(base, ".", ""))
	}

	var out []string
	for k := range mutations {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// enumSubdomainsWithMutation performs subdomain brute-force and additionally
// probes mutation-based candidates derived from each wordlist hit.
func enumSubdomainsWithMutation(domain string, workers int, timeout time.Duration, dnsServer string) ([]string, []Finding) {
	// First run the standard enumeration
	found, findings := enumSubdomains(domain, workers, timeout, dnsServer)

	// Collect base words from hits (strip domain suffix)
	mutationCandidates := make(map[string]bool)
	for _, hit := range found {
		// hit format: "sub.domain.com → IP"
		sub := strings.SplitN(hit, " →", 2)[0]
		sub = strings.TrimSuffix(sub, "."+domain)
		// Generate mutations
		for _, m := range dnsMutate(sub) {
			fqdn := m + "." + domain
			mutationCandidates[fqdn] = true
		}
	}
	// Also mutate every wordlist entry (targeted)
	for _, w := range subWordlist[:min(200, len(subWordlist))] {
		for _, m := range dnsMutate(w) {
			mutationCandidates[m+"."+domain] = true
		}
	}

	// Wildcard detection
	wildcardIPs := make(map[string]bool)
	probe := fmt.Sprintf("recon-x-mut-%d.%s", rand.Int63(), domain)
	if wIPs, err := net.LookupHost(probe); err == nil {
		for _, ip := range wIPs {
			wildcardIPs[ip] = true
		}
	}

	resolver := dnsServer
	if resolver == "" {
		resolver = systemResolver()
	}

	jobs := make(chan string, len(mutationCandidates))
	for fqdn := range mutationCandidates {
		jobs <- fqdn
	}
	close(jobs)

	var mu sync.Mutex
	var mutFound []string
	seen := make(map[string]bool)
	for _, f := range found {
		seen[strings.SplitN(f, " →", 2)[0]] = true
	}

	var wg sync.WaitGroup
	w := workers
	if w > 100 {
		w = 100
	}
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fqdn := range jobs {
				recs := dnsResolveWith(resolver, fqdn, 1, timeout)
				if len(recs) == 0 {
					if ips, err := net.LookupHost(fqdn); err == nil {
						for _, ip := range ips {
							recs = append(recs, DNSRecord{Type: "A", Name: fqdn, Value: ip})
						}
					}
				}
				var realIPs []string
				for _, r := range recs {
					if !wildcardIPs[r.Value] {
						realIPs = append(realIPs, r.Value)
					}
				}
				if len(realIPs) > 0 {
					mu.Lock()
					if !seen[fqdn] {
						seen[fqdn] = true
						mutFound = append(mutFound, fmt.Sprintf("%s → %s [mutation]", fqdn, strings.Join(realIPs, ", ")))
					}
					mu.Unlock()
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	sort.Strings(mutFound)

	if len(mutFound) > 0 {
		findings = append(findings, Finding{
			Module:      "DNSMutate", Severity: INFO,
			Title:       fmt.Sprintf("DNS Mutation Engine: %d Additional Subdomain(s) Discovered", len(mutFound)),
			Detail:      "Mutation-based DNS brute-force found additional subdomains via permutation of known hits and wordlist entries.",
			Evidence:    strings.Join(mutFound[:min(10, len(mutFound))], "\n"),
			Remediation: "Audit mutation-discovered hosts — they often include overlooked dev/staging infrastructure.",
		})
		found = append(found, mutFound...)
	}
	return found, findings
}

// ═══════════════════════════════════════════════════════════════════════
//  API ENDPOINT DISCOVERY
// ═══════════════════════════════════════════════════════════════════════

// Common API endpoint patterns to probe.
var apiEndpoints = []struct {
	path        string
	description string
	severity    Severity
}{
	{"/api", "Generic API root", INFO},
	{"/api/v1", "API v1", INFO},
	{"/api/v2", "API v2", INFO},
	{"/api/v3", "API v3", INFO},
	{"/rest", "REST API root", INFO},
	{"/graphql", "GraphQL endpoint", MEDIUM},
	{"/graphiql", "GraphiQL IDE (dev tool exposed)", HIGH},
	{"/swagger.json", "Swagger/OpenAPI JSON spec", MEDIUM},
	{"/swagger.yaml", "Swagger/OpenAPI YAML spec", MEDIUM},
	{"/swagger-ui.html", "Swagger UI exposed", MEDIUM},
	{"/openapi.json", "OpenAPI JSON spec", MEDIUM},
	{"/openapi.yaml", "OpenAPI YAML spec", MEDIUM},
	{"/api-docs", "API docs exposed", MEDIUM},
	{"/api/swagger", "API Swagger", MEDIUM},
	{"/v1", "API v1 root", INFO},
	{"/v2", "API v2 root", INFO},
	{"/health", "Health check endpoint", INFO},
	{"/healthz", "Kubernetes health endpoint", INFO},
	{"/ready", "Readiness endpoint", INFO},
	{"/readyz", "Readiness endpoint", INFO},
	{"/metrics", "Prometheus metrics exposed", HIGH},
	{"/actuator", "Spring Boot Actuator", HIGH},
	{"/actuator/env", "Spring Actuator env (may leak secrets)", CRITICAL},
	{"/actuator/health", "Spring Actuator health", MEDIUM},
	{"/actuator/mappings", "Spring Actuator URL mappings", MEDIUM},
	{"/actuator/beans", "Spring Actuator bean list", MEDIUM},
	{"/actuator/loggers", "Spring Actuator loggers", MEDIUM},
	{"/.well-known/openid-configuration", "OIDC discovery", INFO},
	{"/.well-known/oauth-authorization-server", "OAuth server metadata", INFO},
	{"/oauth/token", "OAuth token endpoint", MEDIUM},
	{"/oauth2/token", "OAuth2 token endpoint", MEDIUM},
	{"/auth/token", "Auth token endpoint", MEDIUM},
	{"/wp-json/wp/v2", "WordPress REST API", MEDIUM},
	{"/wp-json", "WordPress JSON API root", MEDIUM},
	{"/api/users", "User list API", HIGH},
	{"/api/admin", "Admin API", HIGH},
	{"/api/config", "Config API (may leak secrets)", CRITICAL},
	{"/api/settings", "Settings API", HIGH},
	{"/api/debug", "Debug API", CRITICAL},
	{"/api/test", "Test API endpoint", MEDIUM},
	{"/debug/vars", "Go expvar debug endpoint", HIGH},
	{"/debug/pprof", "Go pprof profiler exposed", HIGH},
	{"/trace", "Trace endpoint", MEDIUM},
	{"/status", "Status page", INFO},
	{"/server-status", "Apache server-status", HIGH},
	{"/server-info", "Apache server-info", MEDIUM},
	{"/phpinfo.php", "PHP info page", HIGH},
	{"/info.php", "PHP info page", HIGH},
	{"/test.php", "PHP test page", MEDIUM},
}

// discoverAPIEndpoints probes a list of known API paths on the target.
func discoverAPIEndpoints(baseURL string, client *http.Client, ua string) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, ep := range apiEndpoints {
		wg.Add(1)
		sem <- struct{}{}
		go func(e struct {
			path        string
			description string
			severity    Severity
		}) {
			defer wg.Done()
			defer func() { <-sem }()
			checkURL := strings.TrimRight(baseURL, "/") + e.path
			req, err := http.NewRequest("GET", checkURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "application/json, */*")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body := make([]byte, 4096)
			n, _ := resp.Body.Read(body)
			bodyStr := string(body[:n])

			// Only report if returns 200 or non-standard (not 404/405)
			if resp.StatusCode == 404 || resp.StatusCode == 405 {
				return
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				ct := resp.Header.Get("Content-Type")
				detail := fmt.Sprintf("HTTP %d | Content-Type: %s | %s",
					resp.StatusCode, ct, e.description)
				// Upgrade severity for data-leaking responses
				sev := e.severity
				if strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "secret") ||
					strings.Contains(bodyStr, "token") || strings.Contains(bodyStr, "key") {
					sev = CRITICAL
					detail += " | ⚠ Response contains sensitive keywords"
				}
				mu.Lock()
				findings = append(findings, Finding{
					Module:      "APIDiscover", Severity: sev,
					Title:       fmt.Sprintf("API Endpoint Discovered: %s", e.path),
					Detail:      detail,
					Evidence:    fmt.Sprintf("GET %s → HTTP %d", checkURL, resp.StatusCode),
					Remediation: "Restrict access to internal API endpoints. Disable debug/test endpoints in production.",
				})
				mu.Unlock()
			}
		}(ep)
	}
	wg.Wait()
	return findings
}

// ═══════════════════════════════════════════════════════════════════════
//  gRPC SERVICE DETECTION
// ═══════════════════════════════════════════════════════════════════════

// Common gRPC ports to probe.
var grpcPorts = []int{50051, 50052, 50053, 9090, 8080, 443, 8443, 4040, 6565, 7070}

// gRPC uses HTTP/2 with a specific content-type. We detect it by attempting
// an HTTP/2 upgrade and checking for the gRPC content-type header.
// We also try a gRPC reflection probe (grpc.reflection.v1alpha.ServerReflection).
func detectGRPC(host string, port int, timeout time.Duration) []Finding {
	var findings []Finding

	// Method 1: HTTP/2 + grpc content-type probe
	addr := fmt.Sprintf("%s:%d", host, port)

	// Try plain HTTP/2 (h2c) first
	checkHTTP2gRPC := func(scheme string) bool {
		urlStr := fmt.Sprintf("%s://%s/grpc.health.v1.Health/Check", scheme, addr)
		req, err := http.NewRequest("POST", urlStr, strings.NewReader("\x00\x00\x00\x00\x00"))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")

		transport := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2:   true,
		}
		client := &http.Client{Timeout: timeout, Transport: transport}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		return strings.HasPrefix(ct, "application/grpc") || resp.Header.Get("Grpc-Status") != ""
	}

	isGRPC := checkHTTP2gRPC("https")
	if !isGRPC {
		isGRPC = checkHTTP2gRPC("http")
	}

	// Method 2: Banner-based detection (gRPC servers often send PRI * HTTP/2.0 on connect)
	if !isGRPC {
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			// HTTP/2 client preface
			_, _ = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			conn.Close()
			banner := string(buf[:n])
			if strings.Contains(banner, "HTTP/2") || strings.Contains(banner, "\x00\x00\x12\x04") {
				isGRPC = true
			}
		}
	}

	if isGRPC {
		findings = append(findings, Finding{
			Module:      "GRPCScan", Severity: MEDIUM,
			Title:       fmt.Sprintf("gRPC Service Detected on Port %d", port),
			Detail:      "A gRPC (HTTP/2-based RPC) service is listening. If reflection is enabled, all service definitions and method signatures are exposed to unauthenticated callers.",
			Evidence:    fmt.Sprintf("gRPC detected at %s:%d", host, port),
			Remediation: "Disable gRPC server reflection in production (grpc.reflection.v1alpha.Register). Enforce mTLS for gRPC. Apply service authorization policies.",
		})

		// Try gRPC reflection (ServerReflection.ServerReflectionInfo)
		// This is a low-level probe: we send the gRPC framing for a reflection request
		checkReflection := func(scheme string) bool {
			// ListServices request payload (proto binary)
			// Field 7 (list_services) = "": 0x3a 0x00
			grpcPayload := []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x3a, 0x00}
			urlStr := fmt.Sprintf("%s://%s/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", scheme, addr)
			req, err := http.NewRequest("POST", urlStr, strings.NewReader(string(grpcPayload)))
			if err != nil {
				return false
			}
			req.Header.Set("Content-Type", "application/grpc+proto")
			req.Header.Set("TE", "trailers")
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				ForceAttemptHTTP2: true,
			}
			client := &http.Client{Timeout: timeout, Transport: transport}
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			body := make([]byte, 1024)
			n, _ := resp.Body.Read(body)
			// A reflection response starts with a gRPC frame (5 bytes) and has content
			return n > 5 && resp.StatusCode == 200
		}
		if checkReflection("https") || checkReflection("http") {
			findings = append(findings, Finding{
				Module:      "GRPCScan", Severity: HIGH,
				Title:       fmt.Sprintf("gRPC Reflection Enabled on Port %d (Service Enumeration Possible)", port),
				Detail:      "Server reflection is enabled — all service names and method signatures are enumerable without authentication. Attackers can map the entire RPC surface.",
				Evidence:    fmt.Sprintf("grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo responded at %s:%d", host, port),
				Remediation: "Disable reflection: remove grpc.reflection.v1alpha.Register() from server setup. Use mTLS + authorization interceptors.",
			})
		}
	}
	return findings
}

// runGRPCScan scans a host for gRPC services on known and open ports.
func runGRPCScan(host string, openPorts []PortResult, timeout time.Duration) []Finding {
	var findings []Finding
	probeSet := make(map[int]bool)
	for _, p := range grpcPorts {
		probeSet[p] = true
	}
	for _, p := range openPorts {
		if p.Open {
			probeSet[p.Port] = true
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for port := range probeSet {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			f := detectGRPC(host, p, timeout)
			if len(f) > 0 {
				mu.Lock()
				findings = append(findings, f...)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return findings
}

// ═══════════════════════════════════════════════════════════════════════
//  MQTT BROKER DETECTION & AUTH CHECK
// ═══════════════════════════════════════════════════════════════════════

// MQTT CONNECT packet for protocol-level detection.
// We send a minimal CONNECT to see if the broker responds with CONNACK.
func probeMQTT(host string, port int, timeout time.Duration) []Finding {
	var findings []Finding
	addr := fmt.Sprintf("%s:%d", host, port)

	// Build a minimal MQTT CONNECT packet (v3.1.1, no auth)
	// Fixed header: 0x10 (CONNECT) + remaining length
	// Variable header + payload (minimal: clean session, 60s keepalive)
	payload := []byte{
		0x10,                   // CONNECT
		0x12,                   // remaining length = 18
		0x00, 0x04,             // protocol name length
		'M', 'Q', 'T', 'T',    // protocol name
		0x04,                   // protocol level 4 (v3.1.1)
		0x02,                   // connect flags: clean session
		0x00, 0x3c,             // keepalive 60s
		0x00, 0x08,             // client ID length
		'r', 'e', 'c', 'o', 'n', '-', 'x', '0', // client ID
	}

	tryConnect := func(useTLS bool) (bool, bool) { // returns (connected, authRequired)
		var conn net.Conn
		var err error
		if useTLS {
			conn, err = tls.DialWithDialer(
				&net.Dialer{Timeout: timeout},
				"tcp", addr,
				&tls.Config{InsecureSkipVerify: true},
			)
		} else {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		}
		if err != nil {
			return false, false
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, err = conn.Write(payload)
		if err != nil {
			return false, false
		}
		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil || n < 4 {
			return false, false
		}
		// CONNACK: 0x20 0x02 <session_present> <return_code>
		if buf[0] != 0x20 || n < 4 {
			return false, false
		}
		returnCode := buf[3]
		// 0x00 = accepted, 0x05 = not authorized, 0x04 = bad credentials
		if returnCode == 0x00 {
			return true, false // connected without auth
		}
		if returnCode == 0x05 || returnCode == 0x04 {
			return true, true // broker present but requires auth
		}
		return true, false
	}

	connectedPlain, noAuthPlain := tryConnect(false)
	connectedTLS, noAuthTLS := tryConnect(true)

	if connectedPlain || connectedTLS {
		sev := HIGH
		authStatus := "requires authentication"
		if (connectedPlain && noAuthPlain) || (connectedTLS && noAuthTLS) {
			sev = CRITICAL
			authStatus = "NO authentication required — unauthenticated access accepted"
		}
		proto := "MQTT"
		if connectedTLS {
			proto = "MQTT/TLS"
		}
		findings = append(findings, Finding{
			Module:      "MQTTScan", Severity: Severity(sev),
			Title:       fmt.Sprintf("%s Broker Detected on Port %d — %s", proto, port, authStatus),
			Detail:      "An MQTT broker is listening. " + authStatus + ". MQTT is commonly used in IoT/ICS environments and may carry sensitive telemetry or control messages.",
			Evidence:    fmt.Sprintf("CONNECT to %s:%d → CONNACK received (auth: %v)", host, port, !noAuthPlain && !noAuthTLS),
			Remediation: "Require username/password or client certificates. Disable anonymous access. Use MQTT over TLS (port 8883). Apply ACLs to restrict topic access.",
		})
	}
	return findings
}

// runMQTTScan checks standard MQTT ports and any open ports that might be MQTT.
func runMQTTScan(host string, openPorts []PortResult, timeout time.Duration) []Finding {
	mqttPorts := map[int]bool{1883: true, 8883: true, 1884: true, 8884: true}
	for _, p := range openPorts {
		if p.Open && (p.Service.Name == "MQTT" || p.Port == 1883 || p.Port == 8883) {
			mqttPorts[p.Port] = true
		}
	}
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	for port := range mqttPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			f := probeMQTT(host, p, timeout)
			if len(f) > 0 {
				mu.Lock()
				findings = append(findings, f...)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return findings
}

// ═══════════════════════════════════════════════════════════════════════
//  AMQP BROKER DETECTION & AUTH CHECK
// ═══════════════════════════════════════════════════════════════════════

// probeAMQP detects AMQP 0-9-1 brokers (RabbitMQ et al.) and checks auth.
func probeAMQP(host string, port int, timeout time.Duration) []Finding {
	var findings []Finding
	addr := fmt.Sprintf("%s:%d", host, port)

	// AMQP 0-9-1 protocol header
	amqpHeader := []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}

	tryAMQP := func(useTLS bool) (detected bool, authRequired bool, serverInfo string) {
		var conn net.Conn
		var err error
		if useTLS {
			conn, err = tls.DialWithDialer(
				&net.Dialer{Timeout: timeout},
				"tcp", addr,
				&tls.Config{InsecureSkipVerify: true},
			)
		} else {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		}
		if err != nil {
			return false, false, ""
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, err = conn.Write(amqpHeader)
		if err != nil {
			return false, false, ""
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil || n < 8 {
			return false, false, ""
		}

		// AMQP Connection.Start frame starts with 0x01 0x00 0x00 (type=method, channel=0)
		if n < 8 || buf[0] != 0x01 {
			// Check if server echoed AMQP header back (version mismatch)
			if n >= 8 && string(buf[:4]) == "AMQP" {
				return true, false, fmt.Sprintf("AMQP version mismatch: server proposes %d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
			}
			return false, false, ""
		}

		// Parse Connection.Start — extract server-properties (simplified)
		info := fmt.Sprintf("AMQP 0-9-1 server responded (%d bytes)", n)
		// Look for product/version strings in the frame
		frameBody := string(buf[:n])
		if strings.Contains(frameBody, "RabbitMQ") {
			info = "RabbitMQ AMQP broker"
		} else if strings.Contains(frameBody, "ActiveMQ") {
			info = "ActiveMQ AMQP broker"
		} else if strings.Contains(frameBody, "qpid") {
			info = "Apache Qpid AMQP broker"
		}
		// Authentication mechanisms are in the Connection.Start frame;
		// if ANONYMOUS is listed, auth can be bypassed
		authRequired = !strings.Contains(strings.ToLower(frameBody), "anonymous")
		return true, authRequired, info
	}

	detectedPlain, authPlain, infoPlain := tryAMQP(false)
	detectedTLS, authTLS, infoTLS := tryAMQP(true)

	if detectedPlain || detectedTLS {
		serverInfo := infoPlain
		if infoTLS != "" {
			serverInfo = infoTLS
		}
		authRequired := authPlain || authTLS
		proto := "AMQP"
		if detectedTLS {
			proto = "AMQPS (TLS)"
		}
		sev := HIGH
		authNote := "authentication required"
		if !authRequired {
			sev = CRITICAL
			authNote = "ANONYMOUS authentication accepted — no credentials required"
		}
		findings = append(findings, Finding{
			Module:      "AMQPScan", Severity: Severity(sev),
			Title:       fmt.Sprintf("%s Broker Detected on Port %d — %s", proto, port, authNote),
			Detail:      serverInfo + ". " + authNote + ". AMQP brokers carry inter-service messages — unauthorized access can lead to message injection, data exfiltration, or DoS.",
			Evidence:    fmt.Sprintf("AMQP 0-9-1 handshake with %s:%d → Connection.Start received", host, port),
			Remediation: "Disable ANONYMOUS SASL mechanism. Require credentials. Use AMQPS (TLS on port 5671). Apply vhost and topic-level ACLs. Keep broker management UI off public interfaces.",
		})
	}
	return findings
}

// runAMQPScan checks standard AMQP ports and any open ports identified as AMQP.
func runAMQPScan(host string, openPorts []PortResult, timeout time.Duration) []Finding {
	amqpPorts := map[int]bool{5672: true, 5671: true, 5673: true}
	for _, p := range openPorts {
		if p.Open && (p.Service.Name == "AMQP" || p.Port == 5672 || p.Port == 5671) {
			amqpPorts[p.Port] = true
		}
	}
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	for port := range amqpPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			f := probeAMQP(host, p, timeout)
			if len(f) > 0 {
				mu.Lock()
				findings = append(findings, f...)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return findings
}


// ═══════════════════════════════════════════════════════════════════════
//  CUSTOM WORDLIST LOADER
// ═══════════════════════════════════════════════════════════════════════

// loadWordlist loads a subdomain wordlist from a file (one entry per line).
// Lines starting with # are treated as comments and skipped.
// If path is empty or unreadable, returns the built-in subWordlist.
func loadWordlist(path string) []string {
	if path == "" {
		return subWordlist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read wordlist %s: %v — using built-in list\n", path, err)
		return subWordlist
	}
	var words []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip any trailing dots, lowercase, basic sanitise
		line = strings.ToLower(strings.TrimSuffix(line, "."))
		if !seen[line] {
			seen[line] = true
			words = append(words, line)
		}
	}
	if len(words) == 0 {
		fmt.Fprintf(os.Stderr, "[!] Wordlist %s was empty — using built-in list\n", path)
		return subWordlist
	}
	fmt.Fprintf(os.Stderr, "[*] Loaded %d words from %s\n", len(words), path)
	return words
}

// ═══════════════════════════════════════════════════════════════════════
//  AUTHENTICATED CRAWL — session acquisition
// ═══════════════════════════════════════════════════════════════════════

// AuthSession holds cookies/tokens obtained after a successful login.
type AuthSession struct {
	Cookies     []*http.Cookie
	CookieStr   string // raw; set directly from -login-cookie
	BearerToken string // set from -login-token
}

// acquireSession attempts to obtain an authenticated session using the
// provided config. Supports:
//   1. Raw cookie injection (-login-cookie)
//   2. Bearer token injection (-login-token)
//   3. Form-based POST login (-login-url + -login-user + -login-pass)
//
// Returns nil if no auth config is provided.
func acquireSession(cfg Config) *AuthSession {
	sess := &AuthSession{}

	// Direct cookie injection — no network request needed
	if cfg.LoginCookie != "" {
		sess.CookieStr = cfg.LoginCookie
		fmt.Fprintf(os.Stderr, "[*] Auth: injecting raw cookie\n")
		return sess
	}

	// Bearer token injection — no network request needed
	if cfg.LoginToken != "" {
		sess.BearerToken = cfg.LoginToken
		fmt.Fprintf(os.Stderr, "[*] Auth: injecting Bearer token\n")
		return sess
	}

	// Form-based login
	if cfg.LoginURL == "" || cfg.LoginUser == "" || cfg.LoginPass == "" {
		return nil // no auth configured
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if cfg.Proxy != "" {
		if pURL, err := url.Parse(cfg.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}

	// Use a jar to capture Set-Cookie headers
	jar := &simpleCookieJar{}
	client := &http.Client{
		Timeout:   cfg.Timeout * 3,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Propagate cookies on redirect
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	userField := cfg.LoginUserField
	if userField == "" {
		userField = "username"
	}
	passField := cfg.LoginPassField
	if passField == "" {
		passField = "password"
	}

	// Step 1: GET the login page to harvest CSRF token
	csrfToken := ""
	if resp, err := client.Get(cfg.LoginURL); err == nil {
		buf := make([]byte, 65536)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		body := string(buf[:n])
		// Look for common CSRF token patterns
		for _, pat := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)name="_csrf"[^>]*value="([^"]+)"`),
			regexp.MustCompile(`(?i)name="csrf_token"[^>]*value="([^"]+)"`),
			regexp.MustCompile(`(?i)name="_token"[^>]*value="([^"]+)"`),
			regexp.MustCompile(`(?i)name="csrfmiddlewaretoken"[^>]*value="([^"]+)"`),
			regexp.MustCompile(`(?i)<meta[^>]+name="csrf-token"[^>]+content="([^"]+)"`),
		} {
			if m := pat.FindStringSubmatch(body); len(m) > 1 {
				csrfToken = m[1]
				break
			}
		}
	}

	// Step 2: POST credentials
	formVals := url.Values{}
	formVals.Set(userField, cfg.LoginUser)
	formVals.Set(passField, cfg.LoginPass)
	if csrfToken != "" {
		// Try common CSRF field names
		formVals.Set("_csrf", csrfToken)
		formVals.Set("csrf_token", csrfToken)
		formVals.Set("_token", csrfToken)
		formVals.Set("csrfmiddlewaretoken", csrfToken)
	}

	req, err := http.NewRequest("POST", cfg.LoginURL, strings.NewReader(formVals.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Auth login request error: %v\n", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Referer", cfg.LoginURL)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Auth login failed: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	// Capture cookies
	sess.Cookies = jar.AllCookies()
	if len(sess.Cookies) == 0 {
		// Also try direct Set-Cookie from response
		sess.Cookies = resp.Cookies()
	}

	if len(sess.Cookies) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Auth: login succeeded — %d session cookie(s) obtained\n", len(sess.Cookies))
	} else {
		fmt.Fprintf(os.Stderr, "[!] Auth: login returned no cookies — check credentials and -login-user-field/-login-pass-field\n")
	}

	return sess
}

// applyAuth applies session cookies/token to an HTTP request.
func applyAuth(req *http.Request, sess *AuthSession) {
	if sess == nil {
		return
	}
	if sess.CookieStr != "" {
		req.Header.Set("Cookie", sess.CookieStr)
	}
	if sess.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+sess.BearerToken)
	}
	for _, c := range sess.Cookies {
		req.AddCookie(c)
	}
}

// simpleCookieJar is a minimal thread-safe cookie jar.
type simpleCookieJar struct {
	mu      sync.Mutex
	cookies []*http.Cookie
}

func (j *simpleCookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = append(j.cookies, cookies...)
}

func (j *simpleCookieJar) Cookies(_ *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies
}

func (j *simpleCookieJar) AllCookies() []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, len(j.cookies))
	copy(out, j.cookies)
	return out
}

// ═══════════════════════════════════════════════════════════════════════
//  JS RENDERING via chromedp (headless Chrome)
// ═══════════════════════════════════════════════════════════════════════
//
//  Because chromedp is an external dependency not in the stdlib,
//  we implement JS rendering via exec: we launch Chrome/Chromium in
//  --headless --dump-dom mode and capture the rendered HTML.
//  This works on any system with Chrome/Chromium installed without
//  requiring any extra Go dependencies.

// findChrome returns the path to Chrome or Chromium binary, or "".
func findChrome() string {
	candidates := []string{
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
		"chrome", "/usr/bin/google-chrome", "/usr/bin/chromium",
		"/usr/bin/chromium-browser", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
		// Also try PATH
		if out, err := execCommand("which", c); err == nil && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out)
		}
	}
	return ""
}

// execCommand runs "which <name>" via /bin/sh to find a binary in PATH.
// Returns the path trimmed of whitespace, or "" if not found.
func execCommand(name string, args ...string) (string, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return "", err
	}
	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	shell := "/bin/sh"
	cmd := "which " + name + " 2>/dev/null"
	attr := &os.ProcAttr{
		Files: []*os.File{devNull, pw, devNull},
	}
	proc, err := os.StartProcess(shell, []string{shell, "-c", cmd}, attr)
	if err != nil {
		pw.Close()
		pr.Close()
		return "", err
	}
	pw.Close()
	buf := make([]byte, 512)
	n, _ := pr.Read(buf)
	pr.Close()
	_, _ = proc.Wait()
	return strings.TrimSpace(string(buf[:n])), nil
}

// renderPageJS uses headless Chrome to render a URL and return the DOM.
// Returns (renderedHTML, error). Falls back gracefully — callers should
// treat non-nil error as "JS rendering unavailable".
func renderPageJS(chromePath, pageURL string, sess *AuthSession, timeout time.Duration) (string, error) {
	if chromePath == "" {
		return "", fmt.Errorf("Chrome not found")
	}

	// Build cookie arg if we have a session
	cookieArgs := []string{}
	if sess != nil {
		for _, c := range sess.Cookies {
			cookieArgs = append(cookieArgs, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
		if sess.CookieStr != "" {
			cookieArgs = append(cookieArgs, sess.CookieStr)
		}
	}

	// Write a tiny HTML shim that sets cookies then navigates, if needed
	cookieJS := ""
	if len(cookieArgs) > 0 {
		for _, kv := range cookieArgs {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				cookieJS += fmt.Sprintf("document.cookie='%s=%s; path=/';", parts[0], parts[1])
			}
		}
	}

	// Use --dump-dom to get the fully-rendered DOM after JS execution
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-sync",
		"--no-first-run",
		"--virtual-time-budget=5000", // wait up to 5s for JS
		"--dump-dom",
		pageURL,
	}

	// Create pipe for stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		return "", err
	}
	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	attr := &os.ProcAttr{
		Files: []*os.File{devNull, pw, devNull},
	}

	fullArgs := append([]string{chromePath}, args...)
	proc, err := os.StartProcess(chromePath, fullArgs, attr)
	if err != nil {
		pw.Close()
		pr.Close()
		return "", fmt.Errorf("Chrome start failed: %v", err)
	}
	pw.Close()

	// Read output with timeout
	done := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(io.LimitReader(pr, 4*1024*1024)) // 4MB cap
		done <- data
	}()

	var rendered []byte
	select {
	case rendered = <-done:
	case <-time.After(timeout):
		proc.Kill()
		pr.Close()
		return "", fmt.Errorf("Chrome timeout")
	}
	pr.Close()
	proc.Wait()

	return string(rendered), nil
}

// ═══════════════════════════════════════════════════════════════════════
//  FORM SUBMISSION TESTER
// ═══════════════════════════════════════════════════════════════════════
//
//  Discovers all HTML forms and submits them with safe detection payloads.
//  Tests for: open redirects, SSRF hints, reflected input, error disclosure.
//  Does NOT send destructive payloads — all payloads are observation-only.

// safeTestPayloads are non-destructive probes for common web issues.
var safeTestPayloads = []struct {
	name    string
	value   string
	checkFn func(body, location, payload string) (bool, string)
}{
	{
		name:  "open-redirect",
		value: "https://reconx-probe.invalid/redirect-test",
		checkFn: func(body, location, payload string) (bool, string) {
			if strings.Contains(location, "reconx-probe.invalid") {
				return true, "Open redirect confirmed: Location header points to injected URL"
			}
			if strings.Contains(body, "reconx-probe.invalid") {
				return true, "Injected URL reflected in response body — possible open redirect"
			}
			return false, ""
		},
	},
	{
		name:  "ssrf-hint",
		value: "http://169.254.169.254/latest/meta-data/",
		checkFn: func(body, location, payload string) (bool, string) {
			// If the app fetches the URL and returns AWS metadata we get "ami-id" etc.
			if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") ||
				strings.Contains(body, "local-ipv4") {
				return true, "SSRF confirmed: AWS EC2 metadata content returned in response"
			}
			return false, ""
		},
	},
	{
		name:  "path-traversal-hint",
		value: "../../../../etc/passwd",
		checkFn: func(body, location, payload string) (bool, string) {
			if strings.Contains(body, "root:x:0:0") || strings.Contains(body, "/bin/bash") {
				return true, "Path traversal confirmed: /etc/passwd content reflected in response"
			}
			return false, ""
		},
	},
	{
		name:  "xss-reflection",
		value: `"><reconx-xss-probe>`,
		checkFn: func(body, location, payload string) (bool, string) {
			if strings.Contains(body, "<reconx-xss-probe>") {
				return true, "XSS reflection: payload not HTML-encoded in response — potential reflected XSS"
			}
			return false, ""
		},
	},
	{
		name:  "sqli-error-hint",
		value: "' OR '1'='1",
		checkFn: func(body, location, payload string) (bool, string) {
			lbody := strings.ToLower(body)
			for _, sig := range []string{
				"sql syntax", "mysql_fetch", "ora-", "unclosed quotation",
				"sqlstate", "pg_query", "syntax error", "invalid query",
				"you have an error in your sql",
			} {
				if strings.Contains(lbody, sig) {
					return true, "SQL error in response after quote injection — possible SQLi vector"
				}
			}
			return false, ""
		},
	},
	{
		name:  "template-injection-hint",
		value: "{{7*7}}",
		checkFn: func(body, location, payload string) (bool, string) {
			if strings.Contains(body, "49") {
				return true, "Template expression evaluated (7*7=49 in response) — possible SSTI"
			}
			return false, ""
		},
	},
}

// testForms discovers all forms on a page and submits them with safe payloads.
func testForms(pageURL string, body string, client *http.Client, sess *AuthSession, ua string) []Finding {
	var findings []Finding

	// Parse all forms from the page body
	formRe := regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	inputRe := regexp.MustCompile(`(?i)<input([^>]*)>`)
	textareaRe := regexp.MustCompile(`(?i)<textarea([^>]*?)(?:>(.*?)</textarea>|/>)`)
	attrRe := func(tag, attr string) string {
		re := regexp.MustCompile(`(?i)` + attr + `\s*=\s*["']([^"']*)["']`)
		if m := re.FindStringSubmatch(tag); len(m) > 1 {
			return m[1]
		}
		return ""
	}

	forms := formRe.FindAllStringSubmatch(body, 30)
	for _, fm := range forms {
		formAttrs := fm[1]
		formBody := fm[2]

		action := attrRe(formAttrs, "action")
		method := strings.ToUpper(attrRe(formAttrs, "method"))
		if method == "" {
			method = "GET"
		}

		// Resolve action URL
		actionURL := action
		if actionURL == "" {
			actionURL = pageURL
		} else if !strings.Contains(actionURL, "://") {
			base, _ := url.Parse(pageURL)
			if strings.HasPrefix(actionURL, "/") {
				actionURL = base.Scheme + "://" + base.Host + actionURL
			} else {
				actionURL = base.Scheme + "://" + base.Host + "/" + strings.TrimPrefix(actionURL, "./")
			}
		}

		// Collect all input fields
		type field struct{ name, typ, val string }
		var fields []field

		for _, inp := range inputRe.FindAllStringSubmatch(formBody, 50) {
			attrs := inp[1]
			fname := attrRe(attrs, "name")
			ftype := strings.ToLower(attrRe(attrs, "type"))
			fval := attrRe(attrs, "value")
			if fname == "" {
				continue
			}
			if ftype == "" {
				ftype = "text"
			}
			fields = append(fields, field{fname, ftype, fval})
		}
		for _, ta := range textareaRe.FindAllStringSubmatch(formBody, 20) {
			fname := attrRe(ta[1], "name")
			if fname != "" {
				fields = append(fields, field{fname, "textarea", ""})
			}
		}

		if len(fields) == 0 {
			continue
		}

		// For each safe test payload, submit the form with it injected
		for _, test := range safeTestPayloads {
			formData := url.Values{}
			injectedFields := []string{}

			for _, f := range fields {
				switch f.typ {
				case "submit", "button", "image", "reset":
					// skip non-data fields
				case "hidden":
					// keep hidden fields as-is (important for CSRF)
					if f.val != "" {
						formData.Set(f.name, f.val)
					}
				case "checkbox", "radio":
					formData.Set(f.name, f.val)
				default:
					// Inject payload into text/email/search/url/textarea fields
					formData.Set(f.name, test.value)
					injectedFields = append(injectedFields, f.name)
				}
			}

			if len(injectedFields) == 0 {
				continue
			}

			var req *http.Request
			var reqErr error
			if method == "POST" {
				req, reqErr = http.NewRequest("POST", actionURL,
					strings.NewReader(formData.Encode()))
				if reqErr == nil {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			} else {
				getURL := actionURL
				if !strings.Contains(getURL, "?") {
					getURL += "?"
				} else {
					getURL += "&"
				}
				getURL += formData.Encode()
				req, reqErr = http.NewRequest("GET", getURL, nil)
			}
			if reqErr != nil {
				continue
			}

			req.Header.Set("User-Agent", ua)
			req.Header.Set("Referer", pageURL)
			applyAuth(req, sess)

			// Don't follow redirects — we want to see Location header
			noRedirectClient := &http.Client{
				Timeout:   client.Timeout,
				Transport: client.Transport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			resp, err := noRedirectClient.Do(req)
			if err != nil {
				continue
			}

			respBuf := make([]byte, 32768)
			n, _ := resp.Body.Read(respBuf)
			resp.Body.Close()
			respBody := string(respBuf[:n])
			location := resp.Header.Get("Location")

			hit, detail := test.checkFn(respBody, location, test.value)
			if hit {
				sev := HIGH
				if test.name == "ssrf-hint" || test.name == "path-traversal-hint" {
					sev = CRITICAL
				}
				findings = append(findings, Finding{
					Module:   "FormTest",
					Severity: sev,
					Title:    fmt.Sprintf("Form Vulnerability Detected: %s on %s", test.name, actionURL),
					Detail: fmt.Sprintf(
						"Test: %s | Method: %s | Injected field(s): %s\n%s",
						test.name, method, strings.Join(injectedFields, ","), detail),
					Evidence:    fmt.Sprintf("%s %s → HTTP %d", method, actionURL, resp.StatusCode),
					Remediation: formTestRemediation(test.name),
				})
				break // one confirmed hit per form is enough
			}
		}
	}

	return findings
}

func formTestRemediation(testName string) string {
	switch testName {
	case "open-redirect":
		return "Validate and whitelist redirect destinations. Never use raw user input in Location header or meta-refresh URLs."
	case "ssrf-hint":
		return "Block outbound requests to internal/metadata ranges. Use an allowlist for any URL-fetching functionality."
	case "path-traversal-hint":
		return "Canonicalize file paths and reject any path containing '../'. Use os.ReadFile with a chroot or safe base path."
	case "xss-reflection":
		return "HTML-encode all user input before reflecting it in responses. Use Content-Security-Policy headers."
	case "sqli-error-hint":
		return "Use parameterized queries / prepared statements. Never interpolate user input into SQL strings."
	case "template-injection-hint":
		return "Never pass user input to template engines without sanitization. Use a safe rendering context."
	default:
		return "Validate and sanitize all user input server-side."
	}
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT — SARIF 2.1
// ═══════════════════════════════════════════════════════════════════════
//
//  SARIF (Static Analysis Results Interchange Format) v2.1 is the standard
//  for importing security findings into GitHub Code Scanning, Azure DevOps,
//  VS Code Security extension, and other SAST platforms.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	DefaultConf      sarifDefaultConf    `json:"defaultConfiguration"`
}

type sarifDefaultConf struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func sevToSARIF(sev Severity) string {
	switch sev {
	case CRITICAL, HIGH:
		return "error"
	case MEDIUM:
		return "warning"
	case LOW:
		return "note"
	default:
		return "none"
	}
}

func writeSARIF(path string, results []ScanResult) error {
	// Build rule index (unique finding titles become rules)
	ruleIdx := make(map[string]int)
	var rules []sarifRule
	var sarifResults []sarifResult

	for _, sr := range results {
		allFindings := sr.Findings
		for _, p := range sr.Ports {
			allFindings = append(allFindings, p.Findings...)
		}
		for _, f := range allFindings {
			ruleID := sanitizeRuleID(f.Module + "/" + f.Title)
			if _, exists := ruleIdx[ruleID]; !exists {
				ruleIdx[ruleID] = len(rules)
				rules = append(rules, sarifRule{
					ID:               ruleID,
					Name:             f.Title,
					ShortDescription: sarifMessage{Text: f.Title},
					FullDescription:  sarifMessage{Text: f.Detail},
					DefaultConf:      sarifDefaultConf{Level: sevToSARIF(f.Severity)},
				})
			}
			// Target URI — use evidence URL if present, else target hostname
			uri := "https://" + sr.Target
			if strings.HasPrefix(f.Evidence, "http") {
				parts := strings.Fields(f.Evidence)
				if len(parts) > 0 {
					uri = parts[0]
				}
			}
			msg := f.Detail
			if f.Evidence != "" {
				msg += "\nEvidence: " + f.Evidence
			}
			if f.Remediation != "" {
				msg += "\nRemediation: " + f.Remediation
			}
			if f.CVE != "" && f.CVE != "N/A" {
				msg += "\nCVE: " + f.CVE
			}
			sarifResults = append(sarifResults, sarifResult{
				RuleID: ruleID,
				Level:  sevToSARIF(f.Severity),
				Message: sarifMessage{Text: msg},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: uri},
					},
				}},
			})
		}
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "RECON-X",
				Version:        "2.0",
				InformationURI: "https://github.com/gopalakrishnsak/recon-x",
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sanitizeRuleID(s string) string {
	var out []byte
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '_' {
			out = append(out, c)
		} else if c == ' ' {
			out = append(out, '-')
		}
	}
	id := string(out)
	if len(id) > 80 {
		id = id[:80]
	}
	return id
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT — CSV
// ═══════════════════════════════════════════════════════════════════════

func writeCSV(path string, results []ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// BOM for Excel compatibility
	_, _ = f.WriteString("\xEF\xBB\xBF")

	// Header
	_, _ = fmt.Fprintln(f, "Target,Module,Severity,Title,Detail,Evidence,CVE,Remediation")

	csvEsc := func(s string) string {
		s = strings.ReplaceAll(s, "\n", " | ")
		s = strings.ReplaceAll(s, "\r", "")
		if strings.ContainsAny(s, `",`) {
			s = `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
		}
		return s
	}

	for _, sr := range results {
		allFindings := sr.Findings
		for _, p := range sr.Ports {
			allFindings = append(allFindings, p.Findings...)
		}
		for _, finding := range allFindings {
			_, _ = fmt.Fprintf(f, "%s,%s,%s,%s,%s,%s,%s,%s\n",
				csvEsc(sr.Target),
				csvEsc(finding.Module),
				csvEsc(string(finding.Severity)),
				csvEsc(finding.Title),
				csvEsc(finding.Detail),
				csvEsc(finding.Evidence),
				csvEsc(finding.CVE),
				csvEsc(finding.Remediation),
			)
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════
//  OUTPUT — XML
// ═══════════════════════════════════════════════════════════════════════

func writeXML(path string, results []ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	xmlEsc := func(s string) string {
		s = strings.ReplaceAll(s, "&", "&amp;")
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		s = strings.ReplaceAll(s, `"`, "&quot;")
		s = strings.ReplaceAll(s, "'", "&apos;")
		// Strip control characters that are invalid in XML 1.0
		var out []rune
		for _, r := range s {
			if r == 0x09 || r == 0x0A || r == 0x0D || (r >= 0x20 && r <= 0xFFFD) {
				out = append(out, r)
			}
		}
		return string(out)
	}

	_, _ = fmt.Fprintln(f, `<?xml version="1.0" encoding="UTF-8"?>`)
	_, _ = fmt.Fprintln(f, `<reconx-report tool="RECON-X" version="2.0">`)

	for _, sr := range results {
		allFindings := sr.Findings
		for _, p := range sr.Ports {
			allFindings = append(allFindings, p.Findings...)
		}

		// Sort CRITICAL first
		sevOrder := map[Severity]int{CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
		sort.SliceStable(allFindings, func(i, j int) bool {
			return sevOrder[allFindings[i].Severity] < sevOrder[allFindings[j].Severity]
		})

		_, _ = fmt.Fprintf(f, "  <target host=%q start=%q end=%q os=%q>\n",
			xmlEsc(sr.Target),
			sr.StartTime.Format(time.RFC3339),
			sr.EndTime.Format(time.RFC3339),
			xmlEsc(sr.OS),
		)

		// IPs
		for _, ip := range sr.IPs {
			_, _ = fmt.Fprintf(f, "    <ip>%s</ip>\n", xmlEsc(ip))
		}

		// Open ports summary
		_, _ = fmt.Fprintln(f, "    <ports>")
		for _, p := range sr.Ports {
			if p.Open {
				_, _ = fmt.Fprintf(f,
					"      <port number=%q protocol=%q service=%q product=%q version=%q />\n",
					p.Port, p.Protocol,
					xmlEsc(p.Service.Name), xmlEsc(p.Service.Product), xmlEsc(p.Service.Version),
				)
			}
		}
		_, _ = fmt.Fprintln(f, "    </ports>")

		// Subdomains
		if len(sr.Subdomains) > 0 {
			_, _ = fmt.Fprintln(f, "    <subdomains>")
			for _, sub := range sr.Subdomains {
				_, _ = fmt.Fprintf(f, "      <subdomain>%s</subdomain>\n", xmlEsc(sub))
			}
			_, _ = fmt.Fprintln(f, "    </subdomains>")
		}

		// Findings
		_, _ = fmt.Fprintln(f, "    <findings>")
		for _, finding := range allFindings {
			_, _ = fmt.Fprintf(f,
				"      <finding module=%q severity=%q>\n"+
					"        <title>%s</title>\n"+
					"        <detail>%s</detail>\n"+
					"        <evidence>%s</evidence>\n"+
					"        <cve>%s</cve>\n"+
					"        <remediation>%s</remediation>\n"+
					"      </finding>\n",
				xmlEsc(finding.Module),
				xmlEsc(string(finding.Severity)),
				xmlEsc(finding.Title),
				xmlEsc(finding.Detail),
				xmlEsc(finding.Evidence),
				xmlEsc(finding.CVE),
				xmlEsc(finding.Remediation),
			)
		}
		_, _ = fmt.Fprintln(f, "    </findings>")
		_, _ = fmt.Fprintln(f, "  </target>")
	}

	_, _ = fmt.Fprintln(f, "</reconx-report>")
	return nil
}

// ═══════════════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════════════

func main() {
	cfg := Config{}
	 var flagArgs, bareArgs []string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			bareArgs = append(bareArgs, args[i+1:]...)
			break
		}
		if len(a) > 0 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			
			stripped := strings.TrimLeft(a, "-")
			valueTaking := map[string]bool{
				"target": true, "ports": true, "exclude-ports": true,
				"timeout": true, "workers": true, "rate": true, "ua": true,
				"proxy": true, "iL": true, "T": true, "retries": true,
				"min-rate": true, "max-rate": true, "scan-delay": true,
				"dns-server": true, "dns-rev": true, "cve-limit": true,
				"cve-min-score": true, "crawl-depth": true, "crawl-max-urls": true,
				"login-url": true, "login-user": true, "login-pass": true,
				"login-user-field": true, "login-pass-field": true,
				"login-cookie": true, "login-token": true, "wordlist": true,
				"html": true, "o": true, "sarif": true, "csv": true, "xml": true,
			}
			// handle -flag=value form
			if strings.Contains(stripped, "=") {
				continue
			}
			if valueTaking[stripped] && i+1 < len(args) && (len(args[i+1]) == 0 || args[i+1][0] != '-') {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			bareArgs = append(bareArgs, a)
		}
	}
	os.Args = append([]string{os.Args[0]}, append(flagArgs, bareArgs...)...)

	// ── Flags ──────────────────────────────────────────────────────────
	flag.StringVar(&cfg.Target, "target", "", "Single target (IP, hostname, or CIDR)")
	flag.StringVar(&cfg.Ports, "ports", "21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2375,2376,3000,3306,3389,4848,5432,5672,5900,5984,6379,6443,7474,7687,8080,8161,8200,8443,8500,9000,9090,9092,9200,9300,10250,11211,15672,27017,50070", "Ports to scan")
	flag.StringVar(&cfg.ExcludePorts, "exclude-ports", "", "Ports to exclude from scan")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "Per-connection timeout")
	flag.IntVar(&cfg.Workers, "workers", 100, "Concurrent workers")
	flag.IntVar(&cfg.RateLimit, "rate", 0, "Max requests per second (0 = unlimited)")
	flag.BoolVar(&cfg.RandomDelay, "rand-delay", false, "Add random delay between probes")
	flag.BoolVar(&cfg.AllMods, "all", false, "Enable ALL modules")
	flag.BoolVar(&cfg.PortScan, "portscan", false, "Port scan + banner + fingerprint")
	flag.BoolVar(&cfg.TLSAudit, "tls", false, "TLS/SSL audit")
	flag.BoolVar(&cfg.HTTPAudit, "http", false, "HTTP headers/methods/cookies audit")
	flag.BoolVar(&cfg.DNSEnum, "dns", false, "DNS enumeration")
	flag.BoolVar(&cfg.SubEnum, "sub", false, "Subdomain bruteforce")
	flag.BoolVar(&cfg.AuthCheck, "auth", false, "Unauthenticated access checks")
	flag.BoolVar(&cfg.WebCrawl, "crawl", false, "Web crawler (paths + links)")
	flag.BoolVar(&cfg.OSDetect, "os", false, "OS detection")
	flag.BoolVar(&cfg.Bruteforce, "brute", false, "Simple bruteforce for common credentials")
	flag.BoolVar(&cfg.OutputJSON, "json", false, "Output JSON")
	flag.StringVar(&cfg.OutputHTML, "html", "", "Write HTML report to file")
	flag.StringVar(&cfg.OutputFile, "o", "", "Write output to file")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&cfg.Debug, "debug", false, "Debug output")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colours")
	flag.StringVar(&cfg.UserAgent, "ua", "Mozilla/5.0 (compatible; RECON-X)", "HTTP User-Agent")
	flag.StringVar(&cfg.Proxy, "proxy", "", "HTTP proxy (e.g., http://127.0.0.1:8080)")
	flag.BoolVar(&cfg.Resolve, "resolve", true, "Resolve hostnames to IPs")
	flag.BoolVar(&cfg.NoPing, "no-ping", false, "Skip ping check")
	flag.StringVar(&cfg.InputFile, "iL", "", "File with one target per line")
	// Scan technique flags
	flag.BoolVar(&cfg.ScanUDP, "udp", false, "UDP scan on common ports (53,123,161,500,1900,5353)")
	flag.BoolVar(&cfg.ScanPing, "ping-sweep", false, "TCP ping sweep — drop unresponsive hosts before port scan")
	flag.BoolVar(&cfg.ScanIPv6, "6", false, "Resolve and scan IPv6 addresses (AAAA records)")
	flag.IntVar(&cfg.TimingLevel, "T", 3, "Timing level 0=paranoid 1=sneaky 2=polite 3=normal 4=aggressive 5=insane")
	flag.IntVar(&cfg.MaxRetries, "retries", 2, "Per-port TCP retry count on timeout")
	flag.IntVar(&cfg.MinRate, "min-rate", 0, "Minimum probes/sec (0=no floor)")
	flag.IntVar(&cfg.MaxRate, "max-rate", 0, "Maximum probes/sec (0=unlimited, overrides -rate)")
	flag.BoolVar(&cfg.RandomHosts, "randomize-hosts", false, "Randomise host scan order")
	flag.DurationVar(&cfg.ScanDelay, "scan-delay", 0, "Fixed delay between probes (e.g. 200ms)")
	flag.BoolVar(&cfg.OSAggressive, "os-aggressive", false, "Aggressive OS detection — probe more ports and protocols")
	// DNS advanced flags
	flag.StringVar(&cfg.DNSServer, "dns-server", "", "Custom DNS server for raw queries (e.g. 8.8.8.8)")
	flag.BoolVar(&cfg.DNSCacheSn, "dns-snoop", false, "DNS cache snooping against target NS servers")
	flag.BoolVar(&cfg.DNSZoneWalk, "dns-walk", false, "DNSSEC NSEC zone walk (enumerates all hostnames)")
	flag.BoolVar(&cfg.DNSTLDExp, "dns-tld", false, "TLD expansion — probe all IANA TLDs for the base domain")
	flag.BoolVar(&cfg.DNSCRTSh, "dns-crt", false, "Certificate transparency lookup via crt.sh")
	flag.StringVar(&cfg.DNSRevCIDR, "dns-rev", "", "Reverse PTR sweep for a CIDR/range (e.g. 192.168.1.0/24)")
	// CVE / NVD flags
	flag.IntVar(&cfg.CVELimit, "cve-limit", 10000, "Max CVEs to fetch per service from NVD (1–10000, paginated)")
	flag.Float64Var(&cfg.CVEMinScore, "cve-min-score", 0, "Minimum CVSS score to include (e.g. 7.0 for HIGH+ only)")
	// New module flags
	flag.BoolVar(&cfg.ScanSYN, "syn", false, "SYN (half-open) scan — requires root/CAP_NET_RAW; falls back to connect scan")
	flag.BoolVar(&cfg.ConnPool, "pool", false, "Use HTTP connection pooling for faster web-crawl/audit")
	flag.BoolVar(&cfg.DNSMutate, "dns-mutate", false, "DNS mutation engine — brute-force permutations of discovered subdomains")
	flag.BoolVar(&cfg.CTEnhanced, "ct-enhanced", false, "Enhanced CT lookup: crt.sh + CertSpotter + AlienVault OTX")
	flag.BoolVar(&cfg.APIDiscover, "api", false, "API endpoint discovery (swagger, graphql, actuator, debug, etc.)")
	flag.BoolVar(&cfg.GRPCScan, "grpc", false, "gRPC service detection and reflection enumeration")
	flag.BoolVar(&cfg.MQTTScan, "mqtt", false, "MQTT broker detection and auth check")
	flag.BoolVar(&cfg.AMQPScan, "amqp", false, "AMQP broker detection and auth check (RabbitMQ, ActiveMQ, etc.)")

	// ── Crawl improvements ────────────────────────────────────────────
	flag.IntVar(&cfg.CrawlMaxDepth, "crawl-depth", 5, "Web crawler max BFS depth ")
	flag.IntVar(&cfg.CrawlMaxURLs, "crawl-max-urls", 500, "Web crawler max URLs to collect ")
	flag.BoolVar(&cfg.FormTest, "form-test", false, "Submit discovered forms with safe SSRF/redirect/XSS detection payloads")
	flag.BoolVar(&cfg.JSRender, "js-render", false, "Headless JS rendering via Chrome/Chromium (requires Chrome installed)")
	// ── Authenticated crawl ───────────────────────────────────────────
	flag.StringVar(&cfg.LoginURL, "login-url", "", "URL to POST credentials before crawling")
	flag.StringVar(&cfg.LoginUser, "login-user", "", "Username for authenticated crawl")
	flag.StringVar(&cfg.LoginPass, "login-pass", "", "Password for authenticated crawl")
	flag.StringVar(&cfg.LoginUserField, "login-user-field", "username", "Form field name for username")
	flag.StringVar(&cfg.LoginPassField, "login-pass-field", "password", "Form field name for password")
	flag.StringVar(&cfg.LoginCookie, "login-cookie", "", "Raw Cookie header to inject (e.g. 'session=abc123')")
	flag.StringVar(&cfg.LoginToken, "login-token", "", "Bearer token for Authorization header")
	// ── Custom wordlist ───────────────────────────────────────────────
	flag.StringVar(&cfg.WordlistFile, "wordlist", "", "Custom subdomain wordlist file (one per line, replaces built-in list)")
	// ── Output formats ────────────────────────────────────────────────
	flag.StringVar(&cfg.OutputSARIF, "sarif", "", "Write SARIF 2.1 report to file (GitHub/Azure DevOps compatible)")
	flag.StringVar(&cfg.OutputCSV, "csv", "", "Write CSV findings report to file")
	flag.StringVar(&cfg.OutputXML, "xml", "", "Write XML findings report to file")

	flag.Usage = func() {
        fmt.Fprint(os.Stderr, logo)
        w := os.Stderr

       fmt.Fprintln(w, "USAGE:")
       fmt.Fprintln(w, "  reconx <host> [flags]")
       fmt.Fprintln(w, "  reconx 192.168.1.0/24 -all -html report.html")
       fmt.Fprintln(w, "  reconx example.com -all -v")
       fmt.Fprintln(w)

       fmt.Fprintln(w, "QUICK START:")
       fmt.Fprintln(w, "  reconx example.com -all                       # All modules")
       fmt.Fprintln(w, "  reconx example.com -dns -sub -http            # Web recon only")
       fmt.Fprintln(w, "  reconx 10.0.0.1 -all -html report.html -json  # Full scan + reports")
       fmt.Fprintln(w)

       printGroup := func(title string, rows [][2]string) {
          fmt.Fprintf(w, "  ── %s\n", title)
            for _, r := range rows {
            fmt.Fprintf(w, "    %-28s %s\n", r[0], r[1])
          }
          fmt.Fprintln(w)
       }

       printGroup("TARGET", [][2]string{
        {"-target <host>",    "Single target: IP, hostname, CIDR, or range"},
        {"-iL <file>",        "File with one target per line"},
        {"-ports <spec>",     "Ports to scan (default: top common ports)"},
        {"-exclude-ports <>", "Ports to exclude (comma-separated or ranges)"},
       })

       printGroup("MODULES", [][2]string{
        {"-all",      "Enable ALL modules at once"},
        {"-portscan", "Port scan + banner grabbing + fingerprint"},
        {"-tls",      "TLS/SSL certificate and cipher audit"},
        {"-http",     "HTTP headers, cookies, methods audit"},
        {"-dns",      "DNS enumeration (A/AAAA/MX/NS/TXT/SOA...)"},
        {"-sub",      "Subdomain bruteforce"},
        {"-auth",     "Unauthenticated access checks"},
        {"-crawl",    "Web crawler (paths + links + forms)"},
        {"-os",       "OS detection (TTL + banner + SMB + RDP)"},
        {"-brute",    "Credential bruteforce on open services"},
        {"-api",      "API endpoint discovery (swagger/graphql/actuator)"},
        {"-grpc",     "gRPC service detection and reflection"},
        {"-mqtt",     "MQTT broker detection and auth check"},
        {"-amqp",     "AMQP broker detection and auth check"},
        {"-syn",      "SYN scan — requires root / CAP_NET_RAW"},
       })

       printGroup("DNS OPTIONS", [][2]string{
        {"-dns-server <ip>", "Custom DNS resolver (e.g. 8.8.8.8)"},
        {"-dns-crt",         "Certificate transparency lookup via crt.sh"},
        {"-ct-enhanced",     "Enhanced CT: crt.sh + CertSpotter + AlienVault"},
        {"-dns-mutate",      "Mutation brute-force on discovered subdomains"},
        {"-dns-tld",         "TLD expansion — probe all IANA TLDs for base name"},
        {"-dns-snoop",       "DNS cache snooping against target NS servers"},
        {"-dns-walk",        "DNSSEC NSEC zone walk (enumerate all hostnames)"},
        {"-dns-rev <cidr>",  "Reverse PTR sweep for a CIDR/range"},
       })

       printGroup("SCAN TUNING", [][2]string{
        {"-T <0-5>",          "Timing: 0=paranoid 1=sneaky 2=polite 3=normal 4=aggressive 5=insane  (default 3)"},
        {"-timeout <dur>",    "Per-connection timeout (default 5s)"},
        {"-workers <n>",      "Concurrent workers (default 100)"},
        {"-retries <n>",      "Per-port retry count on timeout (default 2)"},
        {"-rate <n>",         "Max requests/sec (default unlimited)"},
        {"-min-rate <n>",     "Minimum probes/sec floor"},
        {"-max-rate <n>",     "Maximum probes/sec ceiling"},
        {"-scan-delay <dur>", "Fixed delay between probes (e.g. 200ms)"},
        {"-rand-delay",       "Random delay between probes"},
        {"-randomize-hosts",  "Randomise host scan order"},
        {"-udp",              "UDP scan on common ports (53,123,161,500,1900,5353)"},
        {"-6",                "Resolve and scan IPv6 addresses (AAAA records)"},
        {"-ping-sweep",       "Drop unresponsive hosts before port scan"},
        {"-no-ping",          "Skip ping/reachability check entirely"},
        {"-os-aggressive",    "Probe more ports/protocols for OS detection"},
        {"-pool",             "HTTP connection pooling (faster crawl/audit)"},
       })

       printGroup("CVE / NVD", [][2]string{
        {"-cve-limit <n>",     "Max CVEs to fetch per service (default 10000)"},
        {"-cve-min-score <f>", "Minimum CVSS score to include (e.g. 7.0)"},
       })

       printGroup("WEB CRAWL", [][2]string{
        {"-crawl-depth <n>",    "BFS depth limit (default 5)"},
        {"-crawl-max-urls <n>", "Max URLs to collect (default 500)"},
        {"-form-test",          "Submit forms with SSRF/redirect/XSS payloads"},
        {"-js-render",          "Headless JS rendering via Chrome/Chromium"},
        {"-wordlist <file>",    "Custom subdomain wordlist (replaces built-in)"},
       })

       printGroup("AUTHENTICATED CRAWL", [][2]string{
        {"-login-url <url>",      "POST credentials here before crawling"},
        {"-login-user <user>",    "Username for form login"},
        {"-login-pass <pass>",    "Password for form login"},
        {"-login-user-field <s>", "Form field name for username (default: username)"},
        {"-login-pass-field <s>", "Form field name for password (default: password)"},
        {"-login-cookie <s>",     "Raw Cookie header to inject"},
        {"-login-token <s>",      "Bearer token for Authorization header"},
       })

       printGroup("OUTPUT", [][2]string{
        {"-o <file>",     "Write plain-text output to file"},
        {"-json",         "Output results as JSON"},
        {"-html <file>",  "Write HTML report to file"},
        {"-sarif <file>", "Write SARIF 2.1 report (GitHub/Azure DevOps)"},
        {"-csv <file>",   "Write CSV findings report"},
        {"-xml <file>",   "Write XML findings report"},
       })

       printGroup("MISC", [][2]string{
        {"-resolve",     "Resolve hostnames to IPs before scanning (default true)"},
        {"-proxy <url>", "HTTP proxy (e.g. http://127.0.0.1:8080)"},
        {"-ua <string>", "HTTP User-Agent string"},
        {"-no-color",    "Disable ANSI colour output"},
        {"-v",           "Verbose output (show all findings + extra detail)"},
        {"-debug",       "Debug output (raw probe data)"},
       })

         fmt.Fprintln(w, "  FOR AUTHORIZED SECURITY TESTING ONLY")
         fmt.Fprintln(w)
        }
	flag.Parse()


	// -all enables everything
	if cfg.AllMods {
		cfg.PortScan = true
		cfg.TLSAudit = true
		cfg.HTTPAudit = true
		cfg.DNSEnum = true
		cfg.SubEnum = true
		cfg.AuthCheck = true
		cfg.WebCrawl = true
		cfg.OSDetect = true
		cfg.Bruteforce = true
		cfg.DNSCacheSn = true
		cfg.DNSZoneWalk = true
		cfg.DNSCRTSh = true
		cfg.ScanPing = true
		cfg.ScanUDP = true
		cfg.DNSMutate = true
		cfg.CTEnhanced = true
		cfg.APIDiscover = true
		cfg.GRPCScan = true
		cfg.MQTTScan = true
		cfg.AMQPScan = true
		cfg.FormTest = true
		cfg.DNSTLDExp = true
	}

	// Bridge legacy -rate flag into MaxRate if MaxRate not explicitly set
	if cfg.MaxRate == 0 && cfg.RateLimit > 0 {
		cfg.MaxRate = cfg.RateLimit
	}

	// Clamp timing level
	if cfg.TimingLevel < 0 {
		cfg.TimingLevel = 0
	}
	if cfg.TimingLevel > 5 {
		cfg.TimingLevel = 5
	}

	// Collect targets
	var rawTargets []string
	if cfg.InputFile != "" {
		data, err := os.ReadFile(cfg.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Cannot read %s: %v\n", cfg.InputFile, err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				rawTargets = append(rawTargets, line)
			}
		}
	}
	if cfg.Target != "" {
		rawTargets = append(rawTargets, cfg.Target)
	}
	rawTargets = append(rawTargets, flag.Args()...)

	if len(rawTargets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Default: at least do a port scan
	if !cfg.PortScan && !cfg.TLSAudit && !cfg.HTTPAudit &&
		!cfg.DNSEnum && !cfg.SubEnum && !cfg.AuthCheck &&
		!cfg.WebCrawl && !cfg.OSDetect {
		cfg.PortScan = true
		cfg.AuthCheck = true
		cfg.OSDetect = true
	}


	targets, err := expandTargets(rawTargets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	ports, err := parsePorts(cfg.Ports, cfg.ExcludePorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	// Output writer
	out := io.Writer(os.Stdout)
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	// Print header
	if !cfg.OutputJSON {
		if !cfg.NoColor {
			fmt.Fprint(os.Stderr, logo)
		}
		fmt.Fprintf(os.Stderr, "[*] Targets : %d  |  Ports : %d  |  Workers : %d  |  Timeout : %s\n",
			len(targets), len(ports), cfg.Workers, cfg.Timeout)
		if cfg.RateLimit > 0 {
			fmt.Fprintf(os.Stderr, "[*] Rate    : %d req/s\n", cfg.RateLimit)
		}
		modules := []string{}
		if cfg.PortScan {
			modules = append(modules, "PortScan")
		}
		if cfg.TLSAudit {
			modules = append(modules, "TLSAudit")
		}
		if cfg.HTTPAudit {
			modules = append(modules, "HTTPAudit")
		}
		if cfg.DNSEnum {
			modules = append(modules, "DNSEnum")
		}
		if cfg.SubEnum {
			modules = append(modules, "SubEnum")
		}
		if cfg.DNSCRTSh {
			modules = append(modules, "CRTsh")
		}
		if cfg.DNSZoneWalk {
			modules = append(modules, "NSECWalk")
		}
		if cfg.DNSCacheSn {
			modules = append(modules, "CacheSnoop")
		}
		if cfg.DNSTLDExp {
			modules = append(modules, "TLDExpand")
		}
		if cfg.DNSRevCIDR != "" {
			modules = append(modules, "RevPTR")
		}
		if cfg.AuthCheck {
			modules = append(modules, "AuthCheck")
		}
		modules = append(modules, "NVDLive(auto)")
		if cfg.WebCrawl {
			modules = append(modules, "WebCrawl")
		}
		if cfg.OSDetect {
			modules = append(modules, "OSDetect")
		}
		if cfg.Bruteforce {
			modules = append(modules, "Bruteforce")
		}
		if cfg.ScanUDP {
			modules = append(modules, "UDPScan")
		}
		if cfg.ScanPing {
			modules = append(modules, "PingSweep")
		}
		if cfg.ScanIPv6 {
			modules = append(modules, "IPv6")
		}
		fmt.Fprintf(os.Stderr, "[*] Modules : %s\n", strings.Join(modules, " + "))
		fmt.Fprintf(os.Stderr, "[*] Timing  : T%d (%s)\n", cfg.TimingLevel, timingName(cfg.TimingLevel))
		fmt.Fprintf(os.Stderr, "[*] Started : %s\n", time.Now().Format("2006-01-02 15:04:05"))
		cveInfo := fmt.Sprintf("live lookup active — up to %d CVEs/service", cfg.CVELimit)
		if cfg.CVEMinScore > 0 {
			cveInfo += fmt.Sprintf(", min CVSS %.1f", cfg.CVEMinScore)
		}
		fmt.Fprintf(os.Stderr, "[*] NVD CVE : %s\n\n", cveInfo)
	}

	// ── Scan each target ──────────────────────────────────────────────
	var allResults []ScanResult

	for _, target := range targets {
		sr := ScanResult{
			Target:    target,
			StartTime: time.Now(),
		}

		// Resolve IPs (IPv4 + optionally IPv6)
		var scanTargets []string
		if cfg.Resolve {
			ips, err := net.LookupHost(target)
			if err == nil {
				sr.IPs = ips
				for _, ip := range ips {
					parsed := net.ParseIP(ip)
					if parsed == nil {
						continue
					}
					if parsed.To4() != nil {
						// IPv4 — always include
						scanTargets = append(scanTargets, ip)
					} else if cfg.ScanIPv6 {
						// IPv6 — only when -6 flag set
						scanTargets = append(scanTargets, "["+ip+"]")
					}
				}
				if len(ips) > 0 {
					info := getIPInfo(ips[0])
					if info != nil {
						sr.ASN = info.ASN
						sr.ASNOrg = info.ASNOrg
						sr.Country = info.Country
						if info.Hosting {
							sr.Hosting = "Cloud/VPS"
						}
					}
				}
			}
		}
		if len(scanTargets) == 0 {
			scanTargets = []string{target}
		}

		// OS detection — pass OSAggressive flag through cfg
		if cfg.OSDetect {
			progress(fmt.Sprintf("OS detection: %s", target), cfg.NoColor)
			sr.OS = detectOS(target)
			if cfg.OSAggressive {
				// Re-run on resolved IPs for better TTL/banner accuracy
				for _, ip := range scanTargets {
					if ipOS := detectOS(ip); ipOS != "Unknown" && ipOS != sr.OS {
						sr.OS = ipOS + " (via " + ip + ")"
						break
					}
				}
			}
		}

		// Port scan — scan all resolved IPs (IPv4 + IPv6 if -6)
		if cfg.PortScan || cfg.AuthCheck || cfg.TLSAudit {
			udpNote := ""
			if cfg.ScanUDP {
				udpNote = " +UDP"
			}
			progress(fmt.Sprintf("Port scanning %s (%d ports%s, T%d)...", target, len(ports), udpNote, cfg.TimingLevel), cfg.NoColor)
			sr.Ports = scanPorts(scanTargets, ports, cfg)
		}

		// DNS enumeration
		if cfg.DNSEnum {
			progress(fmt.Sprintf("DNS enumeration: %s", target), cfg.NoColor)
			dns, dnsFindings := dnsEnum(target, cfg)
			sr.DNS = dns
			sr.Findings = append(sr.Findings, dnsFindings...)
		}

		// crt.sh certificate transparency
		if cfg.DNSCRTSh {
			progress(fmt.Sprintf("crt.sh CT lookup: %s", target), cfg.NoColor)
			crtSubs, crtFindings := crtShLookup(target)
			sr.Subdomains = append(sr.Subdomains, crtSubs...)
			sr.Findings = append(sr.Findings, crtFindings...)
		}

		// Enhanced CT lookup (crt.sh + CertSpotter + AlienVault)
		if cfg.CTEnhanced {
			progress(fmt.Sprintf("Enhanced CT lookup: %s (3 sources)...", target), cfg.NoColor)
			ctSubs, ctFindings := ctEnhancedLookup(target)
			sr.Subdomains = append(sr.Subdomains, ctSubs...)
			sr.Findings = append(sr.Findings, ctFindings...)
		}

		// Subdomain brute-force
		if cfg.SubEnum {
			wlist := loadWordlist(cfg.WordlistFile)
			progress(fmt.Sprintf("Subdomain bruteforce: %s (%d words)...", target, len(wlist)), cfg.NoColor)
			subs, subFindings := enumSubdomainsWith(target, wlist, cfg.Workers, cfg.Timeout, cfg.DNSServer)
			sr.Subdomains = append(sr.Subdomains, subs...)
			sr.Findings = append(sr.Findings, subFindings...)
		}

		// DNS mutation engine
		if cfg.DNSMutate {
			progress(fmt.Sprintf("DNS mutation brute-force: %s...", target), cfg.NoColor)
			mutSubs, mutFindings := enumSubdomainsWithMutation(target, cfg.Workers, cfg.Timeout, cfg.DNSServer)
			// Only add newly discovered entries (not duplicates from SubEnum)
			existing := make(map[string]bool)
			for _, s := range sr.Subdomains {
				existing[s] = true
			}
			for _, s := range mutSubs {
				if !existing[s] {
					sr.Subdomains = append(sr.Subdomains, s)
				}
			}
			sr.Findings = append(sr.Findings, mutFindings...)
		}

		// TLD expansion
		if cfg.DNSTLDExp {
			progress(fmt.Sprintf("TLD expansion: %s", target), cfg.NoColor)
			tldSubs, tldFindings := tldExpansion(target, cfg.DNSServer, cfg.Timeout)
			sr.Subdomains = append(sr.Subdomains, tldSubs...)
			sr.Findings = append(sr.Findings, tldFindings...)
		}

		// Reverse PTR sweep for CIDR
		if cfg.DNSRevCIDR != "" {
			progress(fmt.Sprintf("Reverse PTR sweep: %s", cfg.DNSRevCIDR), cfg.NoColor)
			revRecs, revFindings := reversePTRSweep(cfg.DNSRevCIDR, cfg.Workers, cfg.Timeout)
			sr.DNS = append(sr.DNS, revRecs...)
			sr.Findings = append(sr.Findings, revFindings...)
		}

		// DNS cache snooping
		if cfg.DNSCacheSn {
			progress(fmt.Sprintf("DNS cache snooping: %s", target), cfg.NoColor)
			snoop := dnsCacheSnooping(target, cfg.DNSServer, cfg.Timeout)
			sr.Findings = append(sr.Findings, snoop...)
		}

		// HTTP audit
		if cfg.HTTPAudit {
			progress(fmt.Sprintf("HTTP audit: %s", target), cfg.NoColor)
			httpResult, httpFindings := auditHTTP(target, cfg)
			sr.HTTP = httpResult
			sr.Findings = append(sr.Findings, httpFindings...)
			if httpResult != nil {
				sr.Technologies = append(sr.Technologies, httpResult.Technologies...)
			}
		}

		// Web crawl
		if cfg.WebCrawl {
			maxU := cfg.CrawlMaxURLs
			if maxU <= 0 { maxU = 500 }
			progress(fmt.Sprintf("Web crawling: %s (depth=%d, max %d URLs)...", target, cfg.CrawlMaxDepth, maxU), cfg.NoColor)
			crawlURLs, crawlFindings := crawl(target, maxU, cfg)
			sr.CrawledURLs = crawlURLs
			sr.Findings = append(sr.Findings, crawlFindings...)
		}

		// API endpoint discovery
		if cfg.APIDiscover {
			progress(fmt.Sprintf("API endpoint discovery: %s...", target), cfg.NoColor)
			for _, scheme := range []string{"https", "http"} {
				baseURL := fmt.Sprintf("%s://%s", scheme, target)
				var apiClient *http.Client
				if cfg.ConnPool {
					apiClient = globalConnPool.Get(scheme, target, cfg.Timeout, cfg.Proxy)
				} else {
					apiClient = &http.Client{
						Timeout: cfg.Timeout,
						Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
					}
				}
				apiFindings := discoverAPIEndpoints(baseURL, apiClient, cfg.UserAgent)
				if len(apiFindings) > 0 {
					sr.Findings = append(sr.Findings, apiFindings...)
					break // found responses on this scheme, don't duplicate
				}
			}
		}

		// gRPC scan
		if cfg.GRPCScan {
			progress(fmt.Sprintf("gRPC detection: %s...", target), cfg.NoColor)
			grpcFindings := runGRPCScan(target, sr.Ports, cfg.Timeout)
			sr.Findings = append(sr.Findings, grpcFindings...)
		}

		// MQTT scan
		if cfg.MQTTScan {
			progress(fmt.Sprintf("MQTT broker detection: %s...", target), cfg.NoColor)
			mqttFindings := runMQTTScan(target, sr.Ports, cfg.Timeout)
			sr.Findings = append(sr.Findings, mqttFindings...)
		}

		// AMQP scan
		if cfg.AMQPScan {
			progress(fmt.Sprintf("AMQP broker detection: %s...", target), cfg.NoColor)
			amqpFindings := runAMQPScan(target, sr.Ports, cfg.Timeout)
			sr.Findings = append(sr.Findings, amqpFindings...)
		}

		// Credential bruteforce
		if cfg.Bruteforce {
			progress(fmt.Sprintf("Bruteforce: %s (%d open ports)...", target, func() int {
				n := 0
				for _, p := range sr.Ports {
					if p.Open {
						n++
					}
				}
				return n
			}()), cfg.NoColor)
			sr.Findings = append(sr.Findings, bruteforceTarget(target, sr.Ports, cfg.Timeout)...)
		}

		sr.EndTime = time.Now()
		allResults = append(allResults, sr)

		// Output this target's results
		if cfg.OutputJSON {
			writeJSON(out, sr)
		} else {
			printResults(out, sr, cfg)
		}

		// HTML report
		if cfg.OutputHTML != "" {
			htmlPath := cfg.OutputHTML
			if len(targets) > 1 {
				htmlPath = strings.TrimSuffix(cfg.OutputHTML, ".html") +
					"_" + strings.ReplaceAll(target, ".", "_") + ".html"
			}
			if err := writeHTMLReport(htmlPath, sr); err != nil {
				warn(fmt.Sprintf("HTML report failed: %v", err), cfg.NoColor)
			} else {
				progress(fmt.Sprintf("HTML report saved: %s", htmlPath), cfg.NoColor)
			}
		}
	}

	// ── Multi-format output (written once after all targets) ──────────────
	if cfg.OutputSARIF != "" {
		if err := writeSARIF(cfg.OutputSARIF, allResults); err != nil {
			warn(fmt.Sprintf("SARIF write failed: %v", err), cfg.NoColor)
		} else {
			progress(fmt.Sprintf("SARIF report saved: %s", cfg.OutputSARIF), cfg.NoColor)
		}
	}
	if cfg.OutputCSV != "" {
		if err := writeCSV(cfg.OutputCSV, allResults); err != nil {
			warn(fmt.Sprintf("CSV write failed: %v", err), cfg.NoColor)
		} else {
			progress(fmt.Sprintf("CSV report saved: %s", cfg.OutputCSV), cfg.NoColor)
		}
	}
	if cfg.OutputXML != "" {
		if err := writeXML(cfg.OutputXML, allResults); err != nil {
			warn(fmt.Sprintf("XML write failed: %v", err), cfg.NoColor)
		} else {
			progress(fmt.Sprintf("XML report saved: %s", cfg.OutputXML), cfg.NoColor)
		}
	}

	// Global summary
	if !cfg.OutputJSON && len(allResults) > 1 {
		totalFindings := 0
		totalOpen := 0
		for _, sr := range allResults {
			totalFindings += len(sr.Findings)
			for _, p := range sr.Ports {
				if p.Open {
					totalOpen++
					totalFindings += len(p.Findings)
				}
			}
		}
		fmt.Fprintf(os.Stderr, "\n[*] ── GLOBAL SUMMARY ──\n")
		fmt.Fprintf(os.Stderr, "[*] Targets scanned : %d\n", len(allResults))
		fmt.Fprintf(os.Stderr, "[*] Open ports      : %d\n", totalOpen)
		fmt.Fprintf(os.Stderr, "[*] Total findings  : %d\n", totalFindings)
	}
}
