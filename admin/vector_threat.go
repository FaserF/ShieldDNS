package main

import (
	"fmt"
	"math"
	"strings"
	"sync"
)

// VectorDimension is the fixed size of the character n-gram lexical embedding vector.
const VectorDimension = 128

// ThreatAssessment holds the result of a vector similarity and lexical threat evaluation.
type ThreatAssessment struct {
	Domain          string   `json:"domain"`
	IsThreat        bool     `json:"is_threat"`
	ThreatType      string   `json:"threat_type"` // "dga", "typosquat", "phishing_similarity", "none"
	SimilarityScore float64  `json:"similarity_score"`
	MatchedAnchor   string   `json:"matched_anchor,omitempty"`
	Entropy         float64  `json:"entropy"`
	Confidence      float64  `json:"confidence"`
	Reason          string   `json:"reason"`
	VectorDigest    string   `json:"vector_digest"`
}

var (
	vectorMu      sync.RWMutex
	targetAnchors = []string{
		"paypal.com",
		"apple.com",
		"amazon.de",
		"amazon.com",
		"google.com",
		"microsoft.com",
		"sparkasse.de",
		"deutsche-bank.de",
		"volksbank.de",
		"postbank.de",
		"dhl.de",
		"telekom.de",
		"netflix.com",
		"ebay.de",
		"facebook.com",
		"instagram.com",
		"binance.com",
		"coinbase.com",
		"whatsapp.com",
	}
	anchorVectors = make(map[string][]float64)
)

func init() {
	initAnchorVectors()
}

func initAnchorVectors() {
	vectorMu.Lock()
	defer vectorMu.Unlock()
	for _, a := range targetAnchors {
		anchorVectors[a] = ComputeLexicalVector(a)
	}
}

// ComputeLexicalVector creates an L2-normalized 128-dim character n-gram embedding vector.
func ComputeLexicalVector(s string) []float64 {
	vec := make([]float64, VectorDimension)
	clean := strings.ToLower(strings.TrimSpace(s))
	if len(clean) == 0 {
		return vec
	}

	// 1. Bi-grams & Tri-grams hashing into 128-dim space
	for i := 0; i < len(clean)-1; i++ {
		bg := clean[i : i+2]
		idx := int((uint32(bg[0])*31 + uint32(bg[1])) % uint32(VectorDimension))
		vec[idx] += 1.0
	}
	for i := 0; i < len(clean)-2; i++ {
		tg := clean[i : i+3]
		idx := int((uint32(tg[0])*961 + uint32(tg[1])*31 + uint32(tg[2])) % uint32(VectorDimension))
		vec[idx] += 1.5
	}

	// 2. Character length & structural features in dedicated slots
	vec[0] += float64(len(clean)) * 0.1
	vec[1] += CalculateEntropy(clean)

	// 3. L2 Normalize
	var sumSq float64
	for _, val := range vec {
		sumSq += val * val
	}
	if sumSq > 0 {
		norm := math.Sqrt(sumSq)
		for i := range vec {
			vec[i] /= norm
		}
	}
	return vec
}

// CosineSimilarity calculates the cosine similarity between two normalized vectors.
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}
	var dot float64
	for i := 0; i < len(a); i++ {
		dot += a[i] * b[i]
	}
	// Clamp to [0.0, 1.0] for non-negative feature spaces
	if dot < 0.0 {
		return 0.0
	}
	if dot > 1.0 {
		return 1.0
	}
	return dot
}

// EvaluateDomainVectorThreat performs vector similarity checks against phishing targets and DGA analysis.
func EvaluateDomainVectorThreat(domain string) ThreatAssessment {
	normDomain := NormalizeDomain(domain)
	if normDomain == "" {
		return ThreatAssessment{
			Domain:   domain,
			IsThreat: false,
			Reason:   "Empty domain",
		}
	}

	entropy := CalculateEntropy(normDomain)
	queryVec := ComputeLexicalVector(normDomain)
	digest := fmt.Sprintf("vec128:%08x", uint32(entropy*1000000))

	// 1. Check for DGA (Domain Generation Algorithm) characteristics
	parts := strings.Split(normDomain, ".")
	mainPart := parts[0]
	if len(mainPart) >= 12 && entropy >= 3.85 {
		consonantClustering := countConsonantCluster(mainPart)
		if consonantClustering >= 4 || entropy >= 4.15 {
			return ThreatAssessment{
				Domain:          normDomain,
				IsThreat:        true,
				ThreatType:      "dga",
				SimilarityScore: 0.95,
				Entropy:         math.Round(entropy*100) / 100,
				Confidence:      0.92,
				Reason:          fmt.Sprintf("DGA algorithm pattern detected (entropy: %.2f, cluster: %d)", entropy, consonantClustering),
				VectorDigest:    digest,
			}
		}
	}

	// 2. Vector Cosine Similarity against protected brand anchors
	vectorMu.RLock()
	defer vectorMu.RUnlock()

	var maxSim float64
	var matchedAnchor string

	for anchor, aVec := range anchorVectors {
		// Exact match or legitimate subdomain is clean
		if normDomain == anchor || strings.HasSuffix(normDomain, "."+anchor) {
			continue
		}

		sim := CosineSimilarity(queryVec, aVec)
		if sim > maxSim {
			maxSim = sim
			matchedAnchor = anchor
		}
	}

	if matchedAnchor != "" {
		anchorCore := strings.Split(matchedAnchor, ".")[0]
		isImpersonation := strings.Contains(normDomain, anchorCore) && maxSim >= 0.65
		isDirectTyposquat := maxSim >= 0.80

		if isImpersonation || isDirectTyposquat {
			threatType := "typosquat"
			if isImpersonation && !isDirectTyposquat {
				threatType = "phishing_similarity"
			}
			return ThreatAssessment{
				Domain:          normDomain,
				IsThreat:        true,
				ThreatType:      threatType,
				SimilarityScore: math.Round(maxSim*1000) / 1000,
				MatchedAnchor:   matchedAnchor,
				Entropy:         math.Round(entropy*100) / 100,
				Confidence:      math.Min(0.99, maxSim+0.15),
				Reason:          fmt.Sprintf("Brand impersonation / vector similarity (%.1f%%) to protected anchor %s", maxSim*100, matchedAnchor),
				VectorDigest:    digest,
			}
		}
	}

	return ThreatAssessment{
		Domain:          normDomain,
		IsThreat:        false,
		ThreatType:      "none",
		SimilarityScore: math.Round(maxSim*1000) / 1000,
		MatchedAnchor:   matchedAnchor,
		Entropy:         math.Round(entropy*100) / 100,
		Confidence:      0.90,
		Reason:          "Clean domain profile (within normal lexical distribution)",
		VectorDigest:    digest,
	}
}

func countConsonantCluster(s string) int {
	vowels := map[rune]bool{'a': true, 'e': true, 'i': true, 'o': true, 'u': true, '-': true, '_': true}
	maxCluster := 0
	curr := 0
	for _, r := range strings.ToLower(s) {
		if vowels[r] {
			curr = 0
		} else if r >= 'a' && r <= 'z' {
			curr++
			if curr > maxCluster {
				maxCluster = curr
			}
		}
	}
	return maxCluster
}

// MCP Tool definitions for Vector Threat Intelligence
var mcpVectorTools = []mcpToolDefinition{
	{
		tool: mcpTool{
			Name:        "vector_threat_check",
			Description: "Evaluate a domain using 128-dimensional character n-gram embeddings and pgvector/HNSW-compatible similarity metrics to identify typosquatting, phishing impersonation, and DGA clusters.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{"type": "string", "description": "The domain name to evaluate (e.g. 'paypa1-verify.com', 'xkj892laoqpm.net')"},
				},
				"required": []string{"domain"},
			},
		},
		requiredPerm: "read:logs",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			domain, _ := args["domain"].(string)
			if domain == "" {
				return nil, fmt.Errorf("domain parameter is required")
			}
			assessment := EvaluateDomainVectorThreat(domain)
			return assessment, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "vector_threat_add_anchor",
			Description: "Register a high-value domain anchor to protect against typosquatting and impersonation vector attacks.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"anchor_domain": map[string]interface{}{"type": "string", "description": "Domain to protect (e.g. 'fabiseitz.de', 'internal-corp.net')"},
				},
				"required": []string{"anchor_domain"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			anchor, _ := args["anchor_domain"].(string)
			anchor = NormalizeDomain(anchor)
			if anchor == "" {
				return nil, fmt.Errorf("valid anchor_domain is required")
			}
			vectorMu.Lock()
			targetAnchors = append(targetAnchors, anchor)
			anchorVectors[anchor] = ComputeLexicalVector(anchor)
			vectorMu.Unlock()
			return map[string]interface{}{
				"success":        true,
				"anchor_domain":  anchor,
				"total_anchors":  len(anchorVectors),
				"message":        fmt.Sprintf("Anchor %s registered for vector similarity protection", anchor),
			}, nil
		},
	},
}
