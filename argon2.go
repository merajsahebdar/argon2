// Copyright 2023 Meraj Sahebdar
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	iterations  = 3
	memory      = 64 * 1024
	parallelism = 2
	keyLength   = 32

	saltLength = 16

	encodedSlicesCount = 6
)

var (
	// ErrInvalidEncodedHash is returned when the encoded hash is in an invalid format.
	ErrInvalidEncodedHash = errors.New("the encoded hash is not in the correct format")

	// ErrIncompatibleVersion is returned when the encoded hash generated
	// using a different version of argon2.
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")

	// ErrScan is returned when the given value to scanner cannot be represented as a ULID.
	ErrScan = errors.New("cannot scan the given value")
)

// Argon2 provides Argon2 based hashing operations.
type Argon2 struct {
	salt        []byte
	iterations  uint32
	memory      uint32
	parallelism uint8
	keyLength   uint32
	hashed      []byte
	isValid     bool
}

var _ sql.Scanner = (*Argon2)(nil)
var _ driver.Valuer = Argon2{}
var _ fmt.Stringer = Argon2{}

func (a *Argon2) makeSalt() error {
	if a.salt != nil {
		return nil
	}

	salt, err := Bytes(saltLength)
	if err != nil {
		return err
	}

	a.salt = salt

	return nil
}

func (a *Argon2) makeHash(toHash string) {
	a.hashed = argon2.IDKey(
		[]byte(toHash),
		a.salt,
		a.iterations,
		a.memory,
		a.parallelism,
		a.keyLength,
	)
}

// Scan implements sql.Scanner.
func (a *Argon2) Scan(src interface{}) error {
	if src == nil {
		a.isValid = false

		return nil
	}

	s, ok := src.(string)
	if !ok {
		return fmt.Errorf("%w: expected a string", ErrScan)
	}

	var err error
	*a, err = NewByEncoded(s)
	if err != nil {
		return fmt.Errorf("cannot scan due to decode error: %w", err)
	}

	return nil
}

// Value implements driver.Valuer.
func (a Argon2) Value() (driver.Value, error) {
	if !a.isValid {
		return nil, nil
	}

	return a.String(), nil
}

// Encode returns an encoded value of the hash.
func (a Argon2) String() string {
	if !a.isValid {
		return ""
	}

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.memory,
		a.iterations,
		a.parallelism,
		base64.RawStdEncoding.EncodeToString(a.salt),
		base64.RawStdEncoding.EncodeToString(a.hashed),
	)
}

// Compare compares the current hash with the given string.
func (a Argon2) Compare(toCompare string) bool {
	b := &Argon2{
		salt:        a.salt,
		iterations:  a.iterations,
		memory:      a.memory,
		parallelism: a.parallelism,
		keyLength:   a.keyLength,
		isValid:     true,
	}

	b.makeHash(toCompare)

	return subtle.ConstantTimeCompare(a.hashed, b.hashed) == 1
}

// New returns a new argon2.Argon2 by hashing the given string.
func New(toHash string) (Argon2, error) {
	a := Argon2{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		keyLength:   keyLength,
		isValid:     true,
	}

	err := a.makeSalt()
	if err != nil {
		return Argon2{}, err
	}

	a.makeHash(toHash)

	return a, nil
}

// MustNew forces argon2.New.
func MustNew(toHash string) Argon2 {
	a, err := New(toHash)
	if err != nil {
		panic(fmt.Errorf("failed to create: %w", err))
	}

	return a
}

// NewByEncoded returns a new argon2.Argon2 by decoding the given previously encoded hash.
func NewByEncoded(encoded string) (Argon2, error) {
	vals := strings.Split(encoded, "$")
	if len(vals) != encodedSlicesCount {
		return Argon2{}, ErrInvalidEncodedHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return Argon2{}, fmt.Errorf("failed to decode: %w", err)
	}
	if version != argon2.Version {
		return Argon2{}, ErrIncompatibleVersion
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return Argon2{}, fmt.Errorf("failed to decode salt value: %w", err)
	}

	hashed, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return Argon2{}, fmt.Errorf("failed to decode hashed value: %w", err)
	}

	var m uint32
	var i uint32
	var p uint8
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &m, &i, &p)
	if err != nil {
		return Argon2{}, fmt.Errorf("failed to decode hash options: %w", err)
	}

	return Argon2{
		salt:        salt,
		iterations:  i,
		memory:      m,
		parallelism: p,
		keyLength:   uint32(len(hashed)),
		hashed:      hashed,
		isValid:     true,
	}, nil
}

// Bytes generates random bytes of the given size.
func Bytes(n uint32) ([]byte, error) {
	b := make([]byte, n)

	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return b, nil
}
