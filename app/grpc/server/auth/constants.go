package auth

const (
	LoggedIn                      = "user logged in successfully"
	TokenNotFound                 = "token not found"
	TokenNotFoundOrHasExpired     = "token not found or has expired"
	UserTokenNotFound             = "user's token not found"
	UserTokenNotFoundOrHasExpired = "user's token not found or has expired"
	UserTokenRefreshed            = "user's token refreshed successfully"
	CheckedIfAccessTokenIsValid   = "checked if access token is valid"
	CheckedIfRefreshTokenIsValid  = "checked if refresh token is valid"
	FetchedUserRefreshToken       = "fetched user refresh token"
	FetchedUserRefreshTokens      = "fetched user refresh tokens"
	RefreshTokenNotFound          = "session not found"
	FetchedUser

	LoggedOut = "user logged out successfully"
)
