package hashcash_test

import (
	"crypto/sha1"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/umahmood/hashcash"
)

var (
	validToken       = createValidTestToken(false)
	invalidToken     = "blah"
	expiredToken     = "1:20:040806:foo::65f460d0726f420d:13a6b8"
	spentToken       = createValidTestToken(true)
	noCollisionToken = "1:20:180311205026:someone@gmail.com::2M6FmM7eRvw=:MjU5ODg5"
)

type MockStorage struct {
	store map[string]struct{}
}

func (m *MockStorage) Add(hash string) error {
	if m.store == nil {
		m.store = make(map[string]struct{})
		// add spentToken
		m.store["000006e634cdf7cc404bd5b3d632cc943e09ea29"] = struct{}{}
	}
	m.store[hash] = struct{}{}
	return nil
}

func (m *MockStorage) Spent(hash string) bool {
	_, ok := m.store[hash]
	if ok {
		return true
	}
	return false
}

var storage = &MockStorage{}

var testConfig = &hashcash.Config{
	Bits:    20,
	Future:  time.Now().AddDate(0, 0, 2),
	Expired: time.Now().AddDate(0, 0, -30),
	Storage: storage,
}

func createValidTestToken(addToSpent bool) string {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: nil,
		},
		testConfig,
	)
	if err != nil {
		return ""
	}
	var gotProof bool
	var solution string
	for !gotProof {
		s, err := hc.Compute()
		if err == nil {
			solution = s
			gotProof = true
		}
	}
	if addToSpent {
		hash := sha1.New()
		_, err := io.WriteString(hash, solution)
		if err != nil {
			return ""
		}
		sha1 := fmt.Sprintf("%x", hash.Sum(nil))
		storage.Add(sha1)
	}
	return solution
}

func TestComputeHashcash(t *testing.T) {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: nil,
		},
		testConfig,
	)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	var gotProof bool
	var solution string
	for !gotProof {
		s, err := hc.Compute()
		if err != nil {
			if err != hashcash.ErrSolutionFail {
				t.Errorf("%v\n", err)
			}
		} else {
			solution = s
			gotProof = true
		}
	}
	if !strings.HasPrefix(solution, "1:20:") {
		t.Errorf("bad/invalid hashcash token")
	}
	if !strings.Contains(solution, "someone@gmail.com") {
		t.Errorf("bad/invalid hashcash token")
	}
}

func TestVerifyHashcash(t *testing.T) {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: func(res string) bool { return true },
		},
		testConfig,
	)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	valid, err := hc.Verify(validToken)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	if !valid {
		t.Errorf("hashcash token failed verification\n")
	}
}

func TestHashcashInvalidHeader(t *testing.T) {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: func(res string) bool { return true },
		},
		testConfig,
	)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	_, err = hc.Verify(invalidToken)
	if err != hashcash.ErrInvalidHeader {
		t.Errorf("%v\n", err)
	}
}

func TestHashcashNoCollsion(t *testing.T) {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: func(res string) bool { return true },
		},
		testConfig,
	)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	_, err = hc.Verify(noCollisionToken)
	if err != hashcash.ErrNoCollision {
		t.Errorf("%v\n", err)
	}
}

func TestHashcashInvalidTimestamp(t *testing.T) {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: func(res string) bool { return true },
		},
		testConfig,
	)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	_, err = hc.Verify(expiredToken)
	if err != hashcash.ErrTimestamp {
		t.Errorf("%v\n", err)
	}
}

func TestHashcashResourceFail(t *testing.T) {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: func(res string) bool { return false },
		},
		testConfig,
	)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	_, err = hc.Verify(validToken)
	if err != hashcash.ErrResourceFail {
		t.Errorf("%v\n", err)
	}
}

func TestHashcashSpent(t *testing.T) {
	hc, err := hashcash.New(
		&hashcash.Resource{
			Data:          "someone@gmail.com",
			ValidatorFunc: func(res string) bool { return true },
		},
		testConfig,
	)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	_, err = hc.Verify(spentToken)
	if err != hashcash.ErrSpent {
		t.Errorf("%v\n", err)
	}
}
