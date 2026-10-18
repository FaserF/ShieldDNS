package main

import (
	"math"
	"testing"
)

func TestComputeLexicalVector(t *testing.T) {
	vec := ComputeLexicalVector("paypal.com")
	if len(vec) != VectorDimension {
		t.Fatalf("Expected vector dimension %d, got %d", VectorDimension, len(vec))
	}

	// Verify L2 normalization: sum(v_i^2) ~= 1.0
	var sumSq float64
	for _, v := range vec {
		sumSq += v * v
	}
	if math.Abs(sumSq-1.0) > 0.001 {
		t.Errorf("Vector not L2 normalized, sum of squares = %f", sumSq)
	}
}

func TestCosineSimilarity(t *testing.T) {
	v1 := ComputeLexicalVector("paypal.com")
	v2 := ComputeLexicalVector("paypal.com")
	sim := CosineSimilarity(v1, v2)
	if math.Abs(sim-1.0) > 0.001 {
		t.Errorf("Self-similarity should be 1.0, got %f", sim)
	}

	v3 := ComputeLexicalVector("wikipedia.org")
	simDiff := CosineSimilarity(v1, v3)
	if simDiff > 0.70 {
		t.Errorf("Unrelated domains should have low similarity, got %f", simDiff)
	}
}

func TestEvaluateDomainVectorThreat(t *testing.T) {
	// 1. Clean domain
	clean := EvaluateDomainVectorThreat("google.com")
	if clean.IsThreat {
		t.Errorf("google.com should not be flagged as threat: %+v", clean)
	}

	// 2. Brand Impersonation / Phishing Similarity
	phish := EvaluateDomainVectorThreat("paypal-security-login.com")
	if !phish.IsThreat || (phish.ThreatType != "phishing_similarity" && phish.ThreatType != "typosquat") {
		t.Errorf("paypal-security-login.com should be flagged as threat: %+v", phish)
	}

	// 3. Direct Typosquat
	typo := EvaluateDomainVectorThreat("paypa1.com")
	if !typo.IsThreat {
		t.Errorf("paypa1.com should be flagged as threat: %+v", typo)
	}

	// 4. DGA (high entropy + consonant cluster)
	dga := EvaluateDomainVectorThreat("xkrpzlqwtmnvb891.com")
	if !dga.IsThreat || dga.ThreatType != "dga" {
		t.Errorf("xkrpzlqwtmnvb891.com should be flagged as DGA: %+v", dga)
	}
}
