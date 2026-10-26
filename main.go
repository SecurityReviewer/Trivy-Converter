// trivy-converter — converte report Grype o TruffleHog nel formato JSON di Trivy.
//
// Utilizzo:
//
//	trivy-converter [--input <file>] [--output <file>] [--format grype|trufflehog] [--pretty=false]
//	trivy-converter <file>           # forma breve, posizionale
//
// Il formato viene rilevato automaticamente; usa --format per forzarlo.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tipi Grype
// ─────────────────────────────────────────────────────────────────────────────

type GrypeReport struct {
	Matches    []GrypeMatch    `json:"matches"`
	Source     GrypeSource     `json:"source"`
	Distro     GrypeDistro     `json:"distro"`
	Descriptor GrypeDescriptor `json:"descriptor"`
}

type GrypeMatch struct {
	Vulnerability          GrypeVulnerability   `json:"vulnerability"`
	RelatedVulnerabilities []GrypeVulnerability  `json:"relatedVulnerabilities"`
	MatchDetails           []GrypeMatchDetail   `json:"matchDetails"`
	Artifact               GrypeArtifact        `json:"artifact"`
}

type GrypeVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource"`
	Namespace   string      `json:"namespace"`
	Severity    string      `json:"severity"`
	URLs        []string    `json:"urls"`
	Description string      `json:"description"`
	CVSS        []GrypeCVSS `json:"cvss"`
	Fix         GrypeFix    `json:"fix"`
	CWEs        []GrypeCWE  `json:"cwes"`
}

type GrypeCVSS struct {
	Type    string           `json:"type"`
	Version string           `json:"version"`
	Vector  string           `json:"vector"`
	Metrics GrypeCVSSMetrics `json:"metrics"`
}

type GrypeCVSSMetrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type GrypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type GrypeCWE struct {
	CWE    string `json:"cwe"`
	Source string `json:"source"`
	Type   string `json:"type"`
}

type GrypeMatchDetail struct {
	Type    string                 `json:"type"`
	Matcher string                 `json:"matcher"`
	Found   map[string]interface{} `json:"found"`
}

type GrypeArtifact struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Type         string            `json:"type"`
	Language     string            `json:"language"`
	CPEs         []string          `json:"cpes"`
	PURL         string            `json:"purl"`
	MetadataType string            `json:"metadataType"`
	Metadata     GrypeArtifactMeta `json:"metadata"`
}

type GrypeArtifactMeta struct {
	PomArtifactID string `json:"pomArtifactID"`
	PomGroupID    string `json:"pomGroupID"`
}

type GrypeSource struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type GrypeDistro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GrypeDescriptor struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipi TruffleHog (NDJSON — un oggetto JSON per riga)
// ─────────────────────────────────────────────────────────────────────────────

type TruffleHogFinding struct {
	SourceMetadata      TruffleHogSourceMetadata `json:"SourceMetadata"`
	DetectorName        string                   `json:"DetectorName"`
	DetectorDescription string                   `json:"DetectorDescription"`
	DecoderName         string                   `json:"DecoderName"`
	Verified            bool                     `json:"Verified"`
	VerificationFromCache bool                   `json:"VerificationFromCache"`
	Raw                 string                   `json:"Raw"`
}

type TruffleHogSourceMetadata struct {
	Data TruffleHogData `json:"Data"`
}

type TruffleHogData struct {
	Filesystem *TruffleHogFilesystem `json:"Filesystem,omitempty"`
	Git        *TruffleHogGit        `json:"Git,omitempty"`
}

type TruffleHogFilesystem struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type TruffleHogGit struct {
	Commit     string `json:"commit"`
	File       string `json:"file"`
	Repository string `json:"repository"`
	Timestamp  string `json:"timestamp"`
	Line       int    `json:"line"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Tipi Trivy (output)
// ─────────────────────────────────────────────────────────────────────────────

type TrivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Trivy         TrivyMeta     `json:"Trivy"`
	ReportID      string        `json:"ReportID"`
	CreatedAt     string        `json:"CreatedAt"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Results       []TrivyResult `json:"Results"`
}

type TrivyMeta struct {
	Version string `json:"Version"`
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type,omitempty"`
	Packages        []TrivyPackage       `json:"Packages,omitempty"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities,omitempty"`
	Secrets         []TrivySecret        `json:"Secrets,omitempty"`
}

type TrivyPackage struct {
	ID         string          `json:"ID"`
	Name       string          `json:"Name"`
	Identifier TrivyIdentifier `json:"Identifier"`
	Version    string          `json:"Version"`
}

type TrivyIdentifier struct {
	PURL   string `json:"PURL"`
	UID    string `json:"UID"`
	BOMRef string `json:"BOMRef,omitempty"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`
	VendorIDs        []string            `json:"VendorIDs,omitempty"`
	PkgID            string              `json:"PkgID"`
	PkgName          string              `json:"PkgName"`
	PkgIdentifier    TrivyIdentifier     `json:"PkgIdentifier"`
	InstalledVersion string              `json:"InstalledVersion"`
	FixedVersion     string              `json:"FixedVersion,omitempty"`
	Status           string              `json:"Status"`
	SeveritySource   string              `json:"SeveritySource"`
	PrimaryURL       string              `json:"PrimaryURL,omitempty"`
	DataSource       TrivyDataSource     `json:"DataSource"`
	Title            string              `json:"Title,omitempty"`
	Description      string              `json:"Description,omitempty"`
	Severity         string              `json:"Severity"`
	CweIDs           []string            `json:"CweIDs,omitempty"`
	VendorSeverity   map[string]int      `json:"VendorSeverity,omitempty"`
	CVSS             map[string]TrivyCVSS `json:"CVSS,omitempty"`
	References       []string            `json:"References,omitempty"`
}

type TrivyDataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type TrivyCVSS struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Rilevamento formato
// ─────────────────────────────────────────────────────────────────────────────

// detectFormat ispeziona i byte del file e ritorna "grype" o "trufflehog".
func detectFormat(data []byte) (string, error) {
	// Grype: singolo oggetto JSON con chiave "matches" e "descriptor"
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err == nil {
		if _, hasMatches := probe["matches"]; hasMatches {
			if _, hasDesc := probe["descriptor"]; hasDesc {
				return "grype", nil
			}
		}
	}

	// TruffleHog: JSON concatenato (uno o più oggetti separati da whitespace).
	// Decodifico il primo oggetto e verifico la presenza di "DetectorName".
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var first map[string]json.RawMessage
	if err := dec.Decode(&first); err == nil {
		if _, ok := first["DetectorName"]; ok {
			return "trufflehog", nil
		}
	}

	return "", fmt.Errorf("formato non riconosciuto: atteso grype (JSON con 'matches'+'descriptor') o trufflehog (JSON concatenato con 'DetectorName')")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateUID crea uno short UID deterministico da una stringa (per PURL).
func generateUID(seed string) string {
	h := make([]byte, 8)
	for i, c := range []byte(seed) {
		h[i%8] ^= c
	}
	return hex.EncodeToString(h)
}

func severityToInt(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// normalizeStatus mappa lo stato fix di Grype nello stato Trivy.
func normalizeStatus(grypeState string) string {
	switch grypeState {
	case "fixed":
		return "fixed"
	case "not-fixed":
		return "affected"
	case "wont-fix":
		return "will_not_fix"
	case "end-of-life":
		return "end_of_life"
	default:
		return "unknown"
	}
}

// namespaceToSource estrae il tag source da un namespace Grype
// (es. "github:language:java" → "ghsa").
func namespaceToSource(ns string) string {
	ns = strings.ToLower(ns)
	switch {
	case strings.Contains(ns, "github"):
		return "ghsa"
	case strings.Contains(ns, "nvd"):
		return "nvd"
	case strings.Contains(ns, "redhat"):
		return "redhat"
	case strings.Contains(ns, "ubuntu"):
		return "ubuntu"
	case strings.Contains(ns, "debian"):
		return "debian"
	case strings.Contains(ns, "alpine"):
		return "alpine"
	default:
		parts := strings.Split(ns, ":")
		return parts[len(parts)-1]
	}
}

// namespaceToDataSourceName produce il nome human-readable del data source.
func namespaceToDataSourceName(ns string) string {
	ns = strings.ToLower(ns)
	lang := ""
	switch {
	case strings.Contains(ns, "java"):
		lang = "Maven"
	case strings.Contains(ns, "python"):
		lang = "PyPI"
	case strings.Contains(ns, "javascript"):
		lang = "npm"
	case strings.Contains(ns, "golang"), strings.Contains(ns, "go"):
		lang = "Go"
	case strings.Contains(ns, "ruby"):
		lang = "RubyGems"
	case strings.Contains(ns, "dotnet"):
		lang = "NuGet"
	case strings.Contains(ns, "rust"):
		lang = "cargo"
	}
	if strings.Contains(ns, "github") {
		if lang != "" {
			return "GitHub Security Advisory " + lang
		}
		return "GitHub Security Advisory"
	}
	if lang != "" {
		return lang + " Advisory"
	}
	return ns
}

// artifactTypeInfo mappa il tipo Grype al (target, type) Trivy.
func artifactTypeInfo(grypeType, lang string) (target, typ string) {
	switch grypeType {
	case "java-archive":
		return "Java", "jar"
	case "python":
		return "Python", "pip"
	case "npm":
		return "Node.js", "npm"
	case "gem":
		return "Ruby", "gemspec"
	case "go-module":
		return "Go", "gomod"
	case "dotnet":
		return ".NET", "dotnet-core"
	case "rust-crate":
		return "Rust", "cargo"
	case "rpm":
		return "OS Packages", "rpm"
	case "deb":
		return "OS Packages", "dpkg"
	}
	if lang != "" {
		return strings.Title(lang), lang
	}
	return "Unknown", grypeType
}

// pkgFullName restituisce il nome completo di un artefatto (groupId:name per Java).
func pkgFullName(a GrypeArtifact) string {
	if a.Language == "java" && a.Metadata.PomGroupID != "" {
		return a.Metadata.PomGroupID + ":" + a.Name
	}
	return a.Name
}

// pkgFullID restituisce l'ID completo del pacchetto (name:version).
func pkgFullID(a GrypeArtifact) string {
	return pkgFullName(a) + ":" + a.Version
}

// primaryURL sceglie la PrimaryURL nel formato Trivy (preferisce avd.aquasec.com).
func primaryURL(cveID string, urls []string) string {
	avd := "https://avd.aquasec.com/nvd/" + strings.ToLower(cveID)
	for _, u := range urls {
		if strings.Contains(u, "nvd.nist.gov") {
			return avd
		}
	}
	if len(urls) > 0 {
		return urls[0]
	}
	return avd
}

// redactSecret maschera il valore del segreto lasciando visibili solo i primi/ultimi 4 caratteri.
func redactSecret(raw string) string {
	if len(raw) == 0 {
		return ""
	}
	visible := 4
	if len(raw) <= visible*2 {
		return strings.Repeat("*", len(raw))
	}
	return raw[:visible] + strings.Repeat("*", len(raw)-visible*2) + raw[len(raw)-visible:]
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversione Grype → Trivy
// ─────────────────────────────────────────────────────────────────────────────

func convertGrype(data []byte) (*TrivyReport, error) {
	var g GrypeReport
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parsing grype JSON: %w", err)
	}

	timestamp := g.Descriptor.Timestamp
	if timestamp == "" {
		timestamp = time.Now().Format(time.RFC3339Nano)
	}

	report := &TrivyReport{
		SchemaVersion: 2,
		Trivy:         TrivyMeta{Version: "0.70.0"},
		ReportID:      generateUUID(),
		CreatedAt:     timestamp,
		ArtifactName:  g.Source.Target,
		ArtifactType:  g.Source.Type,
	}

	// Raggruppa i match per (target, type) → un TrivyResult per gruppo.
	type resultKey struct{ target, typ string }

	type resultAccumulator struct {
		vulns    []TrivyVulnerability
		pkgsSeen map[string]TrivyPackage // key = pkgFullID
	}

	groups := make(map[resultKey]*resultAccumulator)

	for _, m := range g.Matches {
		target, typ := artifactTypeInfo(m.Artifact.Type, m.Artifact.Language)
		key := resultKey{target, typ}

		if groups[key] == nil {
			groups[key] = &resultAccumulator{pkgsSeen: make(map[string]TrivyPackage)}
		}
		acc := groups[key]

		// Pacchetto
		fullName := pkgFullName(m.Artifact)
		fullID := pkgFullID(m.Artifact)
		if _, exists := acc.pkgsSeen[fullID]; !exists {
			uid := generateUID(m.Artifact.PURL)
			acc.pkgsSeen[fullID] = TrivyPackage{
				ID:   fullID,
				Name: fullName,
				Identifier: TrivyIdentifier{
					PURL: m.Artifact.PURL,
					UID:  uid,
				},
				Version: m.Artifact.Version,
			}
		}

		vuln := m.Vulnerability
		source := namespaceToSource(vuln.Namespace)

		// VendorIDs: alias GHSA se il CVE è il primario
		var vendorIDs []string
		seen := map[string]bool{vuln.ID: true}
		for _, rv := range m.RelatedVulnerabilities {
			if !seen[rv.ID] {
				vendorIDs = append(vendorIDs, rv.ID)
				seen[rv.ID] = true
			}
		}

		// FixedVersion
		fixedVersion := strings.Join(vuln.Fix.Versions, ", ")

		// CWE IDs (deduplicati)
		cweSet := map[string]bool{}
		var cweIDs []string
		for _, c := range vuln.CWEs {
			if !cweSet[c.CWE] {
				cweSet[c.CWE] = true
				cweIDs = append(cweIDs, c.CWE)
			}
		}

		// CVSS: mappa source → TrivyCVSS
		cvssMap := map[string]TrivyCVSS{}
		for _, c := range vuln.CVSS {
			src := source
			if strings.EqualFold(c.Type, "Primary") {
				src = "nvd"
			}
			entry := cvssMap[src]
			ver := strings.TrimSpace(c.Version)
			if strings.HasPrefix(ver, "3") {
				entry.V3Vector = c.Vector
				entry.V3Score = c.Metrics.BaseScore
			} else if strings.HasPrefix(ver, "2") {
				entry.V2Vector = c.Vector
				entry.V2Score = c.Metrics.BaseScore
			}
			cvssMap[src] = entry
		}

		// VendorSeverity
		vendorSeverity := map[string]int{
			source: severityToInt(vuln.Severity),
		}

		uid := generateUID(m.Artifact.PURL)
		trivyVuln := TrivyVulnerability{
			VulnerabilityID:  vuln.ID,
			VendorIDs:        vendorIDs,
			PkgID:            fullID,
			PkgName:          fullName,
			PkgIdentifier:    TrivyIdentifier{PURL: m.Artifact.PURL, UID: uid},
			InstalledVersion: m.Artifact.Version,
			FixedVersion:     fixedVersion,
			Status:           normalizeStatus(vuln.Fix.State),
			SeveritySource:   source,
			PrimaryURL:       primaryURL(vuln.ID, vuln.URLs),
			DataSource: TrivyDataSource{
				ID:   source,
				Name: namespaceToDataSourceName(vuln.Namespace),
				URL:  vuln.DataSource,
			},
			Description:    vuln.Description,
			Severity:       strings.ToUpper(vuln.Severity),
			CweIDs:         cweIDs,
			VendorSeverity: vendorSeverity,
			CVSS:           cvssMap,
			References:     vuln.URLs,
		}

		acc.vulns = append(acc.vulns, trivyVuln)
	}

	// Costruisce i Results nell'ordine di prima comparsa (Java prima, ecc.)
	// Usiamo una slice ordinata delle chiavi per output deterministico.
	type keyedResult struct {
		key resultKey
		acc *resultAccumulator
	}
	ordered := make([]keyedResult, 0, len(groups))
	// Itera sulle corrispondenze originali per preservare l'ordine dei gruppi.
	seen := map[resultKey]bool{}
	for _, m := range g.Matches {
		target, typ := artifactTypeInfo(m.Artifact.Type, m.Artifact.Language)
		key := resultKey{target, typ}
		if !seen[key] {
			seen[key] = true
			ordered = append(ordered, keyedResult{key, groups[key]})
		}
	}

	for _, kr := range ordered {
		acc := kr.acc
		pkgs := make([]TrivyPackage, 0, len(acc.pkgsSeen))
		for _, p := range acc.pkgsSeen {
			pkgs = append(pkgs, p)
		}
		report.Results = append(report.Results, TrivyResult{
			Target:          kr.key.target,
			Class:           "lang-pkgs",
			Type:            kr.key.typ,
			Packages:        pkgs,
			Vulnerabilities: acc.vulns,
		})
	}

	return report, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversione TruffleHog → Trivy
// ─────────────────────────────────────────────────────────────────────────────

func convertTruffleHog(data []byte) (*TrivyReport, error) {
	// Supporta sia NDJSON (un oggetto per riga) sia JSON concatenato multi-line.
	// json.Decoder gestisce entrambi i casi automaticamente.
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var findings []TruffleHogFinding
	for dec.More() {
		var f TruffleHogFinding
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("parsing trufflehog finding: %w", err)
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return nil, fmt.Errorf("nessun finding trovato nel file TruffleHog")
	}

	report := &TrivyReport{
		SchemaVersion: 2,
		Trivy:         TrivyMeta{Version: "0.70.0"},
		ReportID:      generateUUID(),
		CreatedAt:     time.Now().Format(time.RFC3339Nano),
		ArtifactName:  "filesystem",
		ArtifactType:  "filesystem",
	}

	// Raggruppa i segreti per file (mantenendo l'ordine di primo inserimento).
	type fileEntry struct {
		target  string
		secrets []TrivySecret
	}
	fileMap := map[string]*fileEntry{}
	fileOrder := []string{}

	for _, f := range findings {
		var filePath string
		var line int

		switch {
		case f.SourceMetadata.Data.Filesystem != nil:
			filePath = f.SourceMetadata.Data.Filesystem.File
			line = f.SourceMetadata.Data.Filesystem.Line
		case f.SourceMetadata.Data.Git != nil:
			filePath = f.SourceMetadata.Data.Git.File
			line = f.SourceMetadata.Data.Git.Line
		}

		// Normalizza i path separator (Windows → Unix)
		filePath = filepath.ToSlash(filePath)

		// Severity: CRITICAL se verificato, HIGH altrimenti
		severity := "HIGH"
		if f.Verified {
			severity = "CRITICAL"
		}

		ruleID := strings.ToLower(strings.ReplaceAll(f.DetectorName, " ", "-"))

		secret := TrivySecret{
			RuleID:    ruleID,
			Category:  f.DetectorName,
			Severity:  severity,
			Title:     f.DetectorDescription,
			StartLine: line,
			EndLine:   line,
			Match:     redactSecret(f.Raw),
		}

		if _, exists := fileMap[filePath]; !exists {
			fileMap[filePath] = &fileEntry{target: filePath}
			fileOrder = append(fileOrder, filePath)
		}
		fileMap[filePath].secrets = append(fileMap[filePath].secrets, secret)
	}

	for _, fp := range fileOrder {
		fe := fileMap[fp]
		report.Results = append(report.Results, TrivyResult{
			Target:  fe.target,
			Class:   "secret",
			Secrets: fe.secrets,
		})
	}

	return report, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	var (
		inputFile  = flag.String("input", "", "File di input (Grype JSON o TruffleHog NDJSON)")
		outputFile = flag.String("output", "", "File di output (default: stdout)")
		format     = flag.String("format", "", "Forza il formato: grype | trufflehog (default: auto-detect)")
		pretty     = flag.Bool("pretty", true, "Output JSON indentato")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `trivy-converter — converte report Grype/TruffleHog in formato Trivy JSON

Utilizzo:
  trivy-converter --input <file> [--output <file>] [--format grype|trufflehog] [--pretty=false]
  trivy-converter <file>     (forma breve, argomento posizionale)

Flag:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Formati supportati:
  grype       — grype JSON  (chiavi top-level: matches, source, descriptor)
  trufflehog  — TruffleHog NDJSON (un oggetto JSON per riga con DetectorName)

Esempi:
  trivy-converter --input scan.json --output trivy.json
  trivy-converter --input secrets.ndjson --format trufflehog
  trivy-converter scan.json > trivy.json
`)
	}
	flag.Parse()

	// Argomento posizionale come fallback
	if *inputFile == "" && flag.NArg() > 0 {
		*inputFile = flag.Arg(0)
	}
	if *inputFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Errore lettura file %q: %v\n", *inputFile, err)
		os.Exit(1)
	}

	// Auto-detect o formato forzato
	detectedFormat := *format
	if detectedFormat == "" {
		detectedFormat, err = detectFormat(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Rilevamento formato fallito: %v\n", err)
			fmt.Fprintf(os.Stderr, "Usa --format grype|trufflehog per forzare il formato.\n")
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "[trivy-converter] formato rilevato: %s\n", detectedFormat)

	var report *TrivyReport
	switch detectedFormat {
	case "grype":
		report, err = convertGrype(data)
	case "trufflehog":
		report, err = convertTruffleHog(data)
	default:
		fmt.Fprintf(os.Stderr, "Formato sconosciuto: %q\n", detectedFormat)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Errore conversione: %v\n", err)
		os.Exit(1)
	}

	var out []byte
	if *pretty {
		out, err = json.MarshalIndent(report, "", "  ")
	} else {
		out, err = json.Marshal(report)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Errore serializzazione JSON: %v\n", err)
		os.Exit(1)
	}

	if *outputFile == "" {
		fmt.Println(string(out))
	} else {
		if err := os.WriteFile(*outputFile, out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Errore scrittura %q: %v\n", *outputFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[trivy-converter] output scritto in: %s\n", *outputFile)
	}
}
