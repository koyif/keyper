package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// AccessTokenExpiry is the expiration duration for access tokens (15 minutes).
	AccessTokenExpiry = 15 * time.Minute

	// RefreshTokenExpiry is the expiration duration for refresh tokens (7 days).
	RefreshTokenExpiry = 7 * 24 * time.Hour

	// TokenIssuer is the issuer claim for JWT tokens.
	TokenIssuer = "keyper"
)

var (
	// ErrInvalidToken is returned when a token is invalid or malformed.
	ErrInvalidToken = errors.New("invalid token")

	// ErrExpiredToken is returned when a token has expired.
	ErrExpiredToken = errors.New("token has expired")

	// ErrInvalidSignature is returned when token signature validation fails.
	ErrInvalidSignature = errors.New("invalid token signature")
)

// CustomClaims represents JWT claims for Keyper authentication.
type CustomClaims struct {
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token generation and validation.
type JWTManager struct {
	secretKey []byte
}

// NewJWTManager creates a new JWT manager with the provided secret key.
func NewJWTManager(secretKey string) *JWTManager {
	return &JWTManager{
		secretKey: []byte(secretKey),
	}
}

// GenerateAccessToken generates a new access token for a user.
func (m *JWTManager) GenerateAccessToken(userID uuid.UUID, deviceID string) (string, time.Time, error) {
	expiresAt := time.Now().Add(AccessTokenExpiry)

	claims := CustomClaims{
		UserID:   userID.String(),
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    TokenIssuer,
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// GenerateRefreshToken generates a new refresh token for a user.
func (m *JWTManager) GenerateRefreshToken(userID uuid.UUID, deviceID string) (string, time.Time, error) {
	expiresAt := time.Now().Add(RefreshTokenExpiry)

	claims := CustomClaims{
		UserID:   userID.String(),
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    TokenIssuer,
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(), // Unique identifier for each refresh token
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// GenerateTokenPair generates both access and refresh tokens for a user.
func (m *JWTManager) GenerateTokenPair(userID uuid.UUID, deviceID string) (accessToken, refreshToken string, expiresAt time.Time, err error) {
	accessToken, expiresAt, err = m.GenerateAccessToken(userID, deviceID)
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, _, err = m.GenerateRefreshToken(userID, deviceID)
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken, refreshToken, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims.
func (m *JWTManager) ValidateToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		func(token *jwt.Token) (any, error) {
			// Validate the algorithm is what we expect
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.secretKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(TokenIssuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, fmt.Errorf("%w: malformed token", ErrInvalidToken)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, ErrInvalidSignature
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrExpiredToken
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, fmt.Errorf("%w: token not valid yet", ErrInvalidToken)
		default:
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ExtractUserID extracts the user ID from a validated token.
func (m *JWTManager) ExtractUserID(tokenString string) (uuid.UUID, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return uuid.Nil, err
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user_id in token: %w", err)
	}

	return userID, nil
}

// HashRefreshToken creates a SHA-256 hash of a refresh token for storage.
func HashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
