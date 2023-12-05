package sboms

import (
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type inTotoStatement struct {
	PredicateType string                     `json:"predicateType"`
	Subject       []inTotoResourceDescriptor `json:"subject"`
	Predicate     json.RawMessage            `json:"predicate"`
}

func (r *inTotoStatement) AppliesTo(digest v1.Hash) bool {
	for _, subject := range r.Subject {
		if subject.Digest[digest.Algorithm] == digest.Hex {
			return true
		}
	}

	return false
}

type inTotoResourceDescriptor struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     []byte `json:"payload"`
}

func (e *dsseEnvelope) UnmarshalStatement() (*inTotoStatement, error) {
	if e.PayloadType != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("unsupported payload type: %s", e.PayloadType)
	}

	stmt := &inTotoStatement{}
	err := json.Unmarshal(e.Payload, stmt)
	if err != nil {
		return nil, err
	}

	return stmt, nil
}
