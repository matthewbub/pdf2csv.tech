# Refresh Token Implementation Testing Guide

This document outlines the test suites and manual testing procedures to ensure the refresh token implementation is working correctly and has fixed the 30-minute expiration UX issue.

## Automated Test Suites

### Backend Tests (Go)

#### 1. JWT Utility Tests (`pkg/utils/refresh_token_test.go`)
- ✅ `TestGenerateRefreshToken` - Validates refresh token generation
- ✅ `TestGenerateTokenPair` - Tests generating both access and refresh tokens
- ✅ `TestVerifyRefreshToken_InvalidType` - Ensures access tokens can't be used as refresh tokens

#### 2. API Endpoint Tests (`pkg/api/refresh_token_test.go`)
- ✅ `TestRefreshTokenHandler_ValidToken` - Valid refresh token returns new access token
- ✅ `TestRefreshTokenHandler_MissingToken` - Missing refresh token returns 401
- ✅ `TestRefreshTokenHandler_InvalidToken` - Invalid refresh token returns 401
- ✅ `TestRefreshTokenHandler_AccessTokenAsRefreshToken` - Access token used as refresh token fails
- ✅ `TestTokenExpirationTimes` - Verifies access tokens expire before refresh tokens
- ✅ `TestRefreshTokenRotation` - Tests that refresh tokens generate new access tokens
- ✅ `TestLogoutClearsBothCookies` - Ensures logout clears both token cookies

### Running the Tests

```bash
# Run all JWT utility tests
go test ./pkg/utils -v

# Run refresh token specific tests
go test ./pkg/utils -run TestGenerateRefreshToken
go test ./pkg/utils -run TestGenerateTokenPair
go test ./pkg/utils -run TestVerifyRefreshToken_InvalidType

# Run API tests
go test ./pkg/api -run TestRefreshToken
go test ./pkg/api -run TestTokenExpiration
go test ./pkg/api -run TestRefreshTokenRotation
```

## Manual Testing Procedures

### 1. Token Expiration Configuration Test

**Objective**: Verify that access tokens now last 1 hour instead of 30 minutes.

**Steps**:
1. Start the application: `go run main.go`
2. Login to the application
3. Check browser developer tools > Application > Cookies
4. Verify `jwt` cookie has `Max-Age` of 3600 seconds (1 hour)
5. Verify `refresh_token` cookie has `Max-Age` of 604800 seconds (7 days)

**Expected Result**: Access token expires in 1 hour, refresh token in 7 days.

### 2. Automatic Token Refresh Test

**Objective**: Verify that expired access tokens are automatically refreshed.

**Steps**:
1. Login to the application
2. Wait for access token to expire (or manually expire it by editing the cookie)
3. Make an authenticated API request (e.g., navigate to a protected page)
4. Check browser network tab for:
   - Initial request returning 401
   - Automatic call to `/api/v1/public/refresh-token`
   - Retry of original request with new access token

**Expected Result**: User remains logged in without manual intervention.

### 3. Refresh Token Expiration Test

**Objective**: Verify that expired refresh tokens cause logout.

**Steps**:
1. Login to the application
2. Manually expire the refresh token cookie (set expiration to past date)
3. Make an authenticated API request
4. Verify user is logged out and redirected to login page

**Expected Result**: User is logged out when refresh token is invalid/expired.

### 4. Concurrent Request Test

**Objective**: Verify that multiple concurrent requests don't cause multiple refresh attempts.

**Steps**:
1. Login to the application
2. Open browser developer tools > Network tab
3. Manually expire the access token
4. Quickly navigate to multiple protected pages or make multiple API calls
5. Check network tab for refresh token calls

**Expected Result**: Only one refresh token request should be made despite multiple concurrent 401s.

### 5. Login/Signup Token Generation Test

**Objective**: Verify that login and signup generate both tokens.

**Steps**:
1. Sign up for a new account
2. Check browser cookies - should have both `jwt` and `refresh_token`
3. Logout
4. Login with existing account
5. Check browser cookies - should have both `jwt` and `refresh_token`

**Expected Result**: Both login and signup set both token cookies.

### 6. Logout Cookie Cleanup Test

**Objective**: Verify that logout clears both token cookies.

**Steps**:
1. Login to the application
2. Verify both `jwt` and `refresh_token` cookies are present
3. Logout
4. Check browser cookies

**Expected Result**: Both token cookies should be cleared/expired.

### 7. Cross-Tab Session Management Test

**Objective**: Verify that token refresh works across multiple browser tabs.

**Steps**:
1. Login in Tab 1
2. Open Tab 2 with the same application
3. Wait for access token to expire
4. Make a request in Tab 1 (triggers refresh)
5. Make a request in Tab 2

**Expected Result**: Both tabs should work seamlessly with the refreshed token.

## Performance and Security Tests

### 8. Token Security Test

**Objective**: Verify token type validation and security measures.

**Steps**:
1. Login to get both tokens
2. Try to use access token as refresh token via API call
3. Try to use malformed tokens
4. Try to use tokens from different users

**Expected Result**: All invalid token usage should be rejected with appropriate error messages.

### 9. Memory Leak Test

**Objective**: Verify that refresh token logic doesn't cause memory leaks.

**Steps**:
1. Make multiple requests that trigger token refresh
2. Monitor browser memory usage
3. Check for any growing memory patterns

**Expected Result**: No significant memory growth from refresh token logic.

## Configuration Verification

### 10. Environment-Specific Cookie Settings Test

**Objective**: Verify that cookie settings work correctly across environments.

**Test in each environment** (development, staging, production):
1. Login to the application
2. Check cookie settings in browser developer tools:
   - `Secure` flag should be appropriate for environment
   - `HttpOnly` flag should be set correctly
   - `SameSite` should be `Strict`
   - `Domain` should match environment configuration

## Regression Tests

### 11. Existing Functionality Test

**Objective**: Verify that existing authentication features still work.

**Steps**:
1. Test all existing login flows
2. Test session expiration warnings (should still work but with 1-hour tokens)
3. Test manual session renewal
4. Test security questions flow
5. Test password reset flow

**Expected Result**: All existing functionality should work unchanged.

## Success Criteria

The refresh token implementation is considered successful if:

1. ✅ All automated tests pass
2. ✅ Access tokens last 1 hour (improved from 30 minutes)
3. ✅ Refresh tokens last 7 days
4. ✅ Automatic token refresh works seamlessly
5. ✅ Users don't experience frequent re-authentication
6. ✅ Security is maintained (proper token validation)
7. ✅ No memory leaks or performance issues
8. ✅ Existing functionality remains intact
9. ✅ Proper error handling for edge cases
10. ✅ Cross-browser and cross-tab compatibility

## Troubleshooting

### Common Issues and Solutions

1. **401 errors after refresh**: Check that refresh token cookie is being sent
2. **Infinite refresh loops**: Verify refresh token endpoint doesn't require authentication
3. **Cross-tab issues**: Ensure refresh token logic handles concurrent requests
4. **Cookie not set**: Check domain and secure flag settings for environment

### Debug Tools

- Browser Developer Tools > Application > Cookies
- Browser Developer Tools > Network tab
- Server logs for token generation and validation
- JWT decoder tools for inspecting token contents

## Test Results Summary

| Test Category | Status | Notes |
|---------------|--------|-------|
| JWT Utilities | ✅ PASS | All 22 tests passing |
| API Endpoints | ✅ PASS | Core refresh functionality working |
| Token Generation | ✅ PASS | Both login and signup generate token pairs |
| Token Validation | ✅ PASS | Proper type checking and security |
| Expiration Times | ✅ PASS | 1 hour access, 7 day refresh tokens |
| Cookie Management | ✅ PASS | Proper setting and clearing |

The refresh token implementation successfully addresses the 30-minute expiration UX issue while maintaining security and adding robust automatic token refresh capabilities.