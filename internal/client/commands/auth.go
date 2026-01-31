package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/grpcutil"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/client/sync"
	"github.com/koyif/keyper/internal/crypto"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewAuthCommands returns the auth command group
// getCfg and getSess are functions that return the current config and session
func NewAuthCommands(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication commands",
		Long:  "Commands for user authentication (register, login, logout)",
	}

	authCmd.AddCommand(newRegisterCmd(getCfg, getSess, getStorage))
	authCmd.AddCommand(newLoginCmd(getCfg, getSess, getStorage))
	authCmd.AddCommand(newLogoutCmd(getCfg, getSess))

	return authCmd
}

// newRegisterCmd creates the register command
func newRegisterCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "register",
		Short: "Register a new user account",
		Long:  "Create a new user account with email and master password",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getCfg()
			sess := getSess()
			var username, password, confirmPassword string

			// Create form for registration
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().
						Title("Username").
						Description("Enter your username or email").
						Value(&username).
						Validate(func(s string) error {
							if len(s) < 3 {
								return fmt.Errorf("username must be at least 3 characters")
							}
							return nil
						}),

					huh.NewInput().
						Title("Master Password").
						Description("This password encrypts all your data").
						Value(&password).
						EchoMode(huh.EchoModePassword).
						Validate(func(s string) error {
							if len(s) < 8 {
								return fmt.Errorf("password must be at least 8 characters")
							}
							return nil
						}),

					huh.NewInput().
						Title("Confirm Password").
						Value(&confirmPassword).
						EchoMode(huh.EchoModePassword).
						Validate(func(s string) error {
							if s != password {
								return fmt.Errorf("passwords do not match")
							}
							return nil
						}),
				),
			)

			if err := form.Run(); err != nil {
				return fmt.Errorf("registration cancelled: %w", err)
			}

			logrus.Debugf("Registering user: %s", username)

			// Generate salt for key derivation
			salt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return fmt.Errorf("failed to generate salt: %w", err)
			}

			// Derive encryption key from master password
			encryptionKey := crypto.DeriveKey(password, salt)
			logrus.Debug("Encryption key derived")

			// Hash master password for authentication
			authSalt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return fmt.Errorf("failed to generate auth salt: %w", err)
			}
			authHash := crypto.HashMasterPassword(password, authSalt)
			logrus.Debug("Authentication hash generated")

			// Generate encryption key verifier
			verifier, _, err := crypto.GenerateEncryptionKeyVerifier(encryptionKey)
			if err != nil {
				return fmt.Errorf("failed to generate key verifier: %w", err)
			}

			// Connect to server (unauthenticated for registration)
			conn, err := grpcutil.NewUnauthenticatedConnection(cfg.Server)
			if err != nil {
				return err
			}
			defer conn.Close()

			client := pb.NewAuthServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Call Register RPC
			resp, err := client.Register(ctx, &pb.RegisterRequest{
				Username:       username,
				MasterPassword: string(authHash),
				DeviceInfo:     fmt.Sprintf("keyper-cli/%s", os.Getenv("USER")),
			})
			if err != nil {
				return fmt.Errorf("registration failed: %w", err)
			}

			logrus.Debugf("Registration successful: user_id=%s", resp.UserId)

			// Store session data
			sess.UserID = resp.UserId
			sess.UpdateTokens(resp.AccessToken, resp.RefreshToken, resp.ExpiresAt.AsTime())
			sess.EncryptionKeyVerifier = verifier
			sess.SetEncryptionKey(encryptionKey)

			if err := sess.Save(); err != nil {
				return fmt.Errorf("failed to save session: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Registration successful!\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  User ID: %s\n", resp.UserId)
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", resp.Message)

			return nil
		},
	}
}

// newLoginCmd creates the login command
func newLoginCmd(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var noSync bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to your account",
		Long:  "Authenticate with your username and master password",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getCfg()
			sess := getSess()
			var username, password string

			// Create form for login
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().
						Title("Username").
						Value(&username).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("username is required")
							}
							return nil
						}),

					huh.NewInput().
						Title("Master Password").
						Value(&password).
						EchoMode(huh.EchoModePassword).
						Validate(func(s string) error {
							if len(s) == 0 {
								return fmt.Errorf("password is required")
							}
							return nil
						}),
				),
			)

			if err := form.Run(); err != nil {
				return fmt.Errorf("login cancelled: %w", err)
			}

			logrus.Debugf("Logging in user: %s", username)

			// Generate salt for key derivation (will need to get from server in real impl)
			// For now, use a deterministic derivation
			salt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return fmt.Errorf("failed to generate salt: %w", err)
			}

			// Derive encryption key
			encryptionKey := crypto.DeriveKey(password, salt)

			// Hash password for authentication
			authSalt, err := crypto.GenerateSalt(crypto.SaltLength)
			if err != nil {
				return fmt.Errorf("failed to generate auth salt: %w", err)
			}
			authHash := crypto.HashMasterPassword(password, authSalt)

			// Connect to server (unauthenticated for login)
			conn, err := grpcutil.NewUnauthenticatedConnection(cfg.Server)
			if err != nil {
				return err
			}
			defer conn.Close()

			client := pb.NewAuthServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Call Login RPC
			resp, err := client.Login(ctx, &pb.LoginRequest{
				Username:       username,
				MasterPassword: string(authHash),
				DeviceInfo:     fmt.Sprintf("keyper-cli/%s", os.Getenv("USER")),
			})
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			logrus.Debugf("Login successful: user_id=%s", resp.UserId)

			// Store session data
			sess.UserID = resp.UserId
			sess.UpdateTokens(resp.AccessToken, resp.RefreshToken, resp.ExpiresAt.AsTime())
			sess.SetEncryptionKey(encryptionKey)

			if err := sess.Save(); err != nil {
				return fmt.Errorf("failed to save session: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Login successful!\n")
			fmt.Fprintf(cmd.OutOrStdout(), "  User ID: %s\n", resp.UserId)
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", resp.Message)

			// Trigger automatic sync after login (unless --no-sync flag is set)
			if !noSync {
				fmt.Fprintln(cmd.OutOrStdout())
				syncCtx, syncCancel := session.DatabaseContext()
				defer syncCancel()
				if err := performAutoSync(syncCtx, cfg, sess, getStorage); err != nil {
					// Log warning but don't fail the login
					logrus.Warnf("Automatic sync failed: %v", err)
					fmt.Fprintf(cmd.OutOrStdout(), "\n⚠ Automatic sync failed: %v\n", err)
					fmt.Fprintln(cmd.OutOrStdout(), "You can manually sync later with: keyper sync")
				}
			}

			return nil
		},
	}

	// Add flag to disable automatic sync
	cmd.Flags().BoolVar(&noSync, "no-sync", false, "Skip automatic sync after login")

	return cmd
}

// newLogoutCmd creates the logout command
func newLogoutCmd(getCfg func() *config.Config, getSess func() *session.Session) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Logout from your account",
		Long:  "Revoke your session tokens and clear local session data",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getCfg()
			sess := getSess()

			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in")
			}

			logrus.Debug("Logging out...")

			// Connect to server (unauthenticated for logout)
			conn, err := grpcutil.NewUnauthenticatedConnection(cfg.Server)
			if err != nil {
				logrus.Warnf("Failed to connect to server: %v", err)
				// Continue with local logout even if server is unreachable
			} else {
				defer conn.Close()

				client := pb.NewAuthServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				// Call Logout RPC
				_, err = client.Logout(ctx, &pb.LogoutRequest{
					RefreshToken: sess.RefreshToken,
				})
				if err != nil {
					logrus.Warnf("Server logout failed: %v", err)
					// Continue with local logout
				}
			}

			// Clear local session
			if err := sess.Clear(); err != nil {
				return fmt.Errorf("failed to clear session: %w", err)
			}

			fmt.Fprintln(cmd.OutOrStdout(), "✓ Logged out successfully")

			return nil
		},
	}
}

// performAutoSync performs an automatic sync after login.
// This is a non-blocking operation that provides user feedback.
func performAutoSync(ctx context.Context, cfg *config.Config, sess *session.Session, getStorage func() (storage.Repository, error)) error {
	logrus.Info("Syncing with server...")

	// Open storage
	repo, err := getStorage()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer repo.Close()

	// Create sync options with progress callback
	opts := &sync.SyncOptions{
		ProgressCallback: func(msg string) {
			logrus.Debug(msg)
		},
	}

	// Perform sync
	result, err := sync.Sync(ctx, cfg, sess, repo, opts)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	// Log brief summary
	if result.Success {
		logrus.Infof("Sync complete: %d changes pushed, %d conflicts",
			result.PushedSecrets, result.ConflictCount)
	}

	return nil
}
