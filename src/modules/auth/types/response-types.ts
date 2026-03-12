export interface UserResponse {
  id: string;
  email: string;
  isEmailVerified: boolean;
}

export interface JwtPayload {
  sub: string;
  email: string;
  isEmailVerified: boolean;
  iat?: number;
  exp?: number;
}

export interface JwtUserWithRefresh extends UserResponse {
  refreshToken: string;
}
