// ./internal/web/sqlitestore.go
package web

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
)

const (
	// Security limits for session handling
	maxCookieSize       = 4096          // 4KB max cookie size
	maxSessionDataSize  = 64 * 1024     // 64KB max session data
	maxSessionsPerClean = 10000         // Limit cleanup batch size
	cleanupInterval     = 1 * time.Hour // How often to cleanup expired sessions
	maxActiveSessions   = 100000        // Maximum active sessions
)

// SQLiteStore represents the session store with security hardening
type SQLiteStore struct {
	db             *sql.DB
	Codecs         []securecookie.Codec
	Options        *sessions.Options
	stopCleanup    chan struct{}
	cleanupRunning bool
}

// NewSQLiteStore creates a new SQLite session store with security improvements
func NewSQLiteStore(db *sql.DB, keyPairs ...[]byte) (*SQLiteStore, error) {
	if db == nil {
		return nil, errors.New("database connection cannot be nil")
	}

	if len(keyPairs) == 0 {
		return nil, errors.New("at least one key pair is required")
	}

	// Validate key pairs
	for i, key := range keyPairs {
		if len(key) != 32 && len(key) != 64 {
			return nil, fmt.Errorf("key pair %d must be 32 or 64 bytes, got %d", i, len(key))
		}
	}

	// Create the sessions table with proper constraints
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY CHECK(length(id) <= 256),
		data BLOB NOT NULL CHECK(length(data) <= 65536),
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		CHECK(expires_at > created_at)
	);
	CREATE INDEX IF NOT EXISTS idx_expires_at ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_created_at ON sessions(created_at);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		return nil, fmt.Errorf("failed to create sessions table: %w", err)
	}

	// Check current session count
	var sessionCount int
	err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessionCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count sessions: %w", err)
	}

	if sessionCount > maxActiveSessions {
		log.Warn().
			Int("count", sessionCount).
			Int("max", maxActiveSessions).
			Msg("Session count exceeds maximum, cleaning up old sessions")

		// Emergency cleanup of old sessions
		_, err := db.Exec(`
			DELETE FROM sessions 
			WHERE id IN (
				SELECT id FROM sessions 
				ORDER BY modified_at ASC 
				LIMIT ?
			)
		`, sessionCount-maxActiveSessions)

		if err != nil {
			return nil, fmt.Errorf("failed to cleanup old sessions: %w", err)
		}
	}

	store := &SQLiteStore{
		db:          db,
		Codecs:      securecookie.CodecsFromPairs(keyPairs...),
		stopCleanup: make(chan struct{}),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 30, // 30 days
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
			SameSite: http.SameSiteLaxMode,
		},
	}

	// Set maximum length for secure cookies
	store.MaxLength(maxSessionDataSize)

	// Start background cleanup goroutine
	go store.periodicCleanup()

	return store, nil
}

// Get returns a session for the given name after adding it to the registry
func (s *SQLiteStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New creates a new session with security validations
func (s *SQLiteStore) New(r *http.Request, name string) (*sessions.Session, error) {
	// Validate cookie header size to prevent GO-2025-4012
	cookieHeader := r.Header.Get("Cookie")
	if len(cookieHeader) > maxCookieSize {
		log.Warn().
			Int("size", len(cookieHeader)).
			Str("remote", r.RemoteAddr).
			Msg("Cookie header exceeds maximum size")
		return nil, errors.New("cookie header too large")
	}

	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true

	if c, err := r.Cookie(name); err == nil {
		// Additional cookie value validation
		if len(c.Value) > maxCookieSize {
			log.Warn().
				Int("size", len(c.Value)).
				Msg("Cookie value exceeds maximum size")
			return session, nil // Return new session, don't error
		}

		if err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...); err == nil {
			if err = s.load(session); err == nil {
				session.IsNew = false
			} else {
				// Log loading error but continue with new session
				log.Debug().Err(err).Str("session_id", session.ID).Msg("Failed to load session")
			}
		} else {
			log.Debug().Err(err).Msg("Failed to decode session cookie")
		}
	}

	return session, nil
}

// Save saves the session with additional security checks
func (s *SQLiteStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Delete if max age is < 0
	if session.Options.MaxAge < 0 {
		if err := s.delete(session); err != nil {
			log.Error().Err(err).Str("session_id", session.ID).Msg("Failed to delete session")
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	// Generate a new session ID if this is a new session
	if session.ID == "" {
		randomBytes := securecookie.GenerateRandomKey(32)
		if randomBytes == nil {
			return errors.New("failed to generate session key")
		}
		session.ID = base64.URLEncoding.EncodeToString(randomBytes)
	}

	// Validate session ID length
	if len(session.ID) > 256 {
		return errors.New("session ID too long")
	}

	// Check total session count before creating new sessions
	if session.IsNew {
		var sessionCount int
		err := s.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP").Scan(&sessionCount)
		if err != nil {
			log.Error().Err(err).Msg("Failed to count active sessions")
		} else if sessionCount >= maxActiveSessions {
			log.Warn().Int("count", sessionCount).Msg("Maximum active sessions reached")
			return errors.New("maximum active sessions reached")
		}
	}

	if err := s.save(session); err != nil {
		return err
	}

	// Encode session ID and set cookie
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return fmt.Errorf("failed to encode session: %w", err)
	}

	// Validate encoded cookie size
	if len(encoded) > maxCookieSize {
		log.Error().Int("size", len(encoded)).Msg("Encoded session cookie too large")
		return errors.New("session data too large")
	}

	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxLength sets the maximum length of session data
func (s *SQLiteStore) MaxLength(l int) {
	if l > maxSessionDataSize {
		log.Warn().
			Int("requested", l).
			Int("max", maxSessionDataSize).
			Msg("Requested max length exceeds limit, using maximum")
		l = maxSessionDataSize
	}

	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxLength(l)
		}
	}
}

// load loads session data from the database with validation
func (s *SQLiteStore) load(session *sessions.Session) error {
	var data []byte
	var expiresAt time.Time

	err := s.db.QueryRow(
		"SELECT data, expires_at FROM sessions WHERE id = ? AND expires_at > CURRENT_TIMESTAMP",
		session.ID,
	).Scan(&data, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("session not found or expired")
		}
		return fmt.Errorf("failed to load session: %w", err)
	}

	// Validate data size
	if len(data) > maxSessionDataSize {
		log.Warn().
			Int("size", len(data)).
			Str("session_id", session.ID).
			Msg("Session data exceeds maximum size")
		_ = s.delete(session)
		return errors.New("session data too large")
	}

	// Check if session has expired (additional check)
	if expiresAt.Before(time.Now()) {
		_ = s.delete(session)
		return errors.New("session expired")
	}

	// Decode session data
	if err := securecookie.DecodeMulti(session.Name(), string(data), &session.Values, s.Codecs...); err != nil {
		log.Warn().Err(err).Str("session_id", session.ID).Msg("Failed to decode session data")
		_ = s.delete(session)
		return fmt.Errorf("failed to decode session data: %w", err)
	}

	return nil
}

// save saves session data to the database with size validation
func (s *SQLiteStore) save(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return fmt.Errorf("failed to encode session values: %w", err)
	}

	// Validate encoded data size
	if len(encoded) > maxSessionDataSize {
		return fmt.Errorf("session data too large: %d bytes (max %d)", len(encoded), maxSessionDataSize)
	}

	var expiresAt time.Time
	if session.Options.MaxAge > 0 {
		expiresAt = time.Now().Add(time.Duration(session.Options.MaxAge) * time.Second)
	} else {
		// Default 30 days if not specified
		expiresAt = time.Now().Add(30 * 24 * time.Hour)
	}

	_, err = s.db.Exec(
		`INSERT INTO sessions (id, data, modified_at, expires_at) 
		 VALUES (?, ?, CURRENT_TIMESTAMP, ?)
		 ON CONFLICT(id) DO UPDATE SET 
		   data = excluded.data,
		   modified_at = CURRENT_TIMESTAMP,
		   expires_at = excluded.expires_at`,
		session.ID,
		[]byte(encoded),
		expiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

// delete removes session data from the database
func (s *SQLiteStore) delete(session *sessions.Session) error {
	if session.ID == "" {
		return nil
	}

	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", session.ID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// Cleanup removes expired sessions from the database with batch limiting
func (s *SQLiteStore) Cleanup() error {
	result, err := s.db.Exec(`
		DELETE FROM sessions 
		WHERE id IN (
			SELECT id FROM sessions 
			WHERE expires_at < CURRENT_TIMESTAMP 
			LIMIT ?
		)
	`, maxSessionsPerClean)

	if err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Debug().Int64("count", rowsAffected).Msg("Cleaned up expired sessions")
	}

	// Also cleanup very old sessions that might not have expiry set properly
	result, err = s.db.Exec(`
		DELETE FROM sessions 
		WHERE id IN (
			SELECT id FROM sessions 
			WHERE created_at < datetime('now', '-90 days')
			LIMIT ?
		)
	`, maxSessionsPerClean)

	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup old sessions")
	} else {
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected > 0 {
			log.Info().Int64("count", rowsAffected).Msg("Cleaned up very old sessions")
		}
	}

	return nil
}

// periodicCleanup runs cleanup in the background
func (s *SQLiteStore) periodicCleanup() {
	s.cleanupRunning = true
	defer func() {
		s.cleanupRunning = false
	}()

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	log.Info().
		Dur("interval", cleanupInterval).
		Msg("Started periodic session cleanup")

	for {
		select {
		case <-ticker.C:
			if err := s.Cleanup(); err != nil {
				log.Error().Err(err).Msg("Periodic cleanup failed")
			}
		case <-s.stopCleanup:
			log.Info().Msg("Stopping periodic session cleanup")
			return
		}
	}
}

// Close stops the background cleanup and closes resources
func (s *SQLiteStore) Close() error {
	if s.cleanupRunning {
		close(s.stopCleanup)
		// Give it a moment to finish
		time.Sleep(100 * time.Millisecond)
	}

	// Final cleanup
	return s.Cleanup()
}

// GetSessionCount returns the current number of active sessions
func (s *SQLiteStore) GetSessionCount() (int, error) {
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP",
	).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count sessions: %w", err)
	}

	return count, nil
}
