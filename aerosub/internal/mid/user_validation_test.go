// Copyright 2026 AERO Protocol Contributors
// Unit tests for User registration validation, password complexity, and admin update.
package mid

import (
	"strings"
	"testing"
)

func TestUserRegistrationValidation(t *testing.T) {
	uDB := NewMemoryUserStore()
	uSvc := NewUserService(uDB, "test-hmac-secret-validation")

	// 1. Invalid username
	_, err := uSvc.Register(CreateUserParams{
		Username: "ab",
		Password: "password123",
		Email:    "test@aero.test",
	})
	if err == nil || !strings.Contains(err.Error(), "用户名") {
		t.Fatalf("expected username validation error, got: %v", err)
	}

	// 2. Invalid email
	_, err = uSvc.Register(CreateUserParams{
		Username: "validuser",
		Password: "password123",
		Email:    "invalid-email",
	})
	if err == nil || !strings.Contains(err.Error(), "邮箱") {
		t.Fatalf("expected email validation error, got: %v", err)
	}

	// 3. Weak password (< 8 chars)
	_, err = uSvc.Register(CreateUserParams{
		Username: "validuser",
		Password: "pass1",
		Email:    "valid@aero.test",
	})
	if err == nil || !strings.Contains(err.Error(), "密码") {
		t.Fatalf("expected password length error, got: %v", err)
	}

	// 4. Weak password (no digits)
	_, err = uSvc.Register(CreateUserParams{
		Username: "validuser",
		Password: "passwordonly",
		Email:    "valid@aero.test",
	})
	if err == nil || !strings.Contains(err.Error(), "组合") {
		t.Fatalf("expected password complexity error, got: %v", err)
	}

	// 5. Valid registration without plan
	u, err := uSvc.Register(CreateUserParams{
		Username: "validuser1",
		Password: "ValidPassword123",
		Email:    "user1@aero.test",
	})
	if err != nil {
		t.Fatalf("unexpected error for valid registration: %v", err)
	}
	if u.PlanName != "" {
		t.Fatalf("expected empty PlanName for new user without plan, got: %s", u.PlanName)
	}
	if !u.ExpireAt.IsZero() {
		t.Fatalf("expected zero ExpireAt for new user without plan, got: %v", u.ExpireAt)
	}
	// Verify no subscription was created
	subs, err := uSvc.ListSubscriptions(u.ID)
	if err == nil && len(subs) > 0 {
		t.Fatalf("expected 0 subscriptions for newly registered user, got %d", len(subs))
	}

	// 6. Test Admin updating username and password
	newUsername := "renameduser"
	newPassword := "NewSecret456!"
	err = uSvc.UpdateUserFull(u.ID, UpdateUserParams{
		Username: &newUsername,
		Password: &newPassword,
	})
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	// Login with old password should fail
	_, _, err = uSvc.Login("validuser1", "ValidPassword123")
	if err == nil {
		t.Fatalf("login with old username/password should fail")
	}

	// Login with new username and new password should succeed
	tok, loggedIn, err := uSvc.Login("renameduser", "NewSecret456!")
	if err != nil || tok == "" || loggedIn == nil {
		t.Fatalf("login with new credentials failed: %v", err)
	}
	if loggedIn.Username != "renameduser" {
		t.Fatalf("expected username to be renameduser, got: %s", loggedIn.Username)
	}
}
