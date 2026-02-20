# REST API Authentication with Node.js

A secure REST API authentication system built with Node.js, Express, and JWT tokens. Features include user registration, login, role-based access control, and two-factor authentication (2FA) support.

## Features

- **User Authentication**: Secure registration and login with bcrypt password hashing
- **JWT Token System**: Access tokens (30min) and refresh tokens (1 week) for secure API access
- **Role-Based Access Control**: Support for admin, moderator, and member roles
- **Two-Factor Authentication**: Optional TOTP-based 2FA with QR code generation
- **Token Management**: Secure logout with token invalidation and refresh token rotation
- **In-Memory Database**: Uses NeDB for lightweight, file-based data storage

## Quick Start

### Prerequisites

- Node.js 14+ 
- npm or yarn

### Installation

```bash
# Clone the repository
git clone https://github.com/prasannazzz/RESTapi_auth_nodejs.git
cd RESTapi_auth_nodejs

# Install dependencies
npm install

# Start the server
npm start
```

For development with auto-reload:
```bash
npm run dev
```

The server will start on `http://localhost:3006`

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | User login (returns temp token if 2FA enabled) |
| `POST` | `/api/auth/login/2fa` | Complete 2FA login with TOTP code |
| `POST` | `/api/auth/refresh-token` | Refresh access token |
| `GET` | `/api/auth/logout` | Logout and invalidate tokens |

### Two-Factor Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/auth/2fa/generate` | Generate 2FA QR code | Yes |
| `POST` | `/api/auth/2fa/validate` | Enable 2FA with TOTP | Yes |

### User Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/users/current` | Get current user info | Yes |
| `GET` | `/api/admin` | Admin-only endpoint | Yes, Admin |
| `GET` | `/api/moderator` | Admin/Moderator endpoint | Yes, Admin/Moderator |

## Usage Examples

### Register a User

```bash
curl -X POST http://localhost:3006/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "securePassword123",
    "role": "member"
  }'
```

### Login

```bash
curl -X POST http://localhost:3006/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securePassword123"
  }'
```

### Access Protected Route

```bash
curl -X GET http://localhost:3006/api/users/current \
  -H "Authorization: YOUR_ACCESS_TOKEN"
```

### Enable Two-Factor Authentication

1. Generate QR code:
```bash
curl -X GET http://localhost:3006/api/auth/2fa/generate \
  -H "Authorization: YOUR_ACCESS_TOKEN" \
  --output qrcode.png
```

2. Scan QR code with authenticator app, then validate:
```bash
curl -X POST http://localhost:3006/api/auth/2fa/validate \
  -H "Authorization: YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"totp": "123456"}'
```

## Configuration

The application uses `config.js` for configuration:

```javascript
module.exports = {
    accessTokenSecret: 'myAccessTokenSecret',
    accessTokenExpiresIn: '30m',
    refreshTokenSecret: 'myRefreshTokenSecret', 
    refreshTokenExpiresIn: '1w',
    cacheTemporaryTokenPrefix: 'tempToken:',
    cacheTemporaryTokenExpiresInSeconds: 180
}
```

**Security Note**: Update the secrets with your own secure values in production.

## Data Storage

The application uses NeDB (file-based database) with three collections:
- `Users.db` - User accounts and profiles
- `UserRefreshTokens.db` - Active refresh tokens
- `UserInvalidTokens.db` - Blacklisted tokens

## Security Features

- **Password Hashing**: bcrypt with salt rounds (10)
- **JWT Tokens**: Signed access and refresh tokens
- **Token Rotation**: New refresh tokens issued on each refresh
- **Token Blacklisting**: Invalidated tokens stored in database
- **Role-Based Authorization**: Middleware for role-based access control
- **2FA Support**: TOTP-based two-factor authentication
- **Temporary Tokens**: Short-lived tokens for 2FA flow

## Project Structure

```
RESTapi_auth_nodejs/
├── index.js              # Main application file
├── config.js             # Configuration settings
├── package.json          # Dependencies and scripts
├── Users.db              # User database
├── UserRefreshTokens.db # Refresh tokens
├── UserInvalidTokens.db # Invalidated tokens
└── README.md            # This file
```

## Dependencies

- **express** - Web framework
- **bcrypt** - Password hashing
- **jsonwebtoken** - JWT token handling
- **nedb-promises** - In-memory database
- **node-cache** - In-memory caching
- **otplib** - TOTP generation
- **qrcode** - QR code generation
- **crypto** - Cryptographic functions

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## Support

If you have any questions or run into issues, please:
1. Check the existing [GitHub Issues](https://github.com/prasannazzz/RESTapi_auth_nodejs/issues)
2. Create a new issue with detailed information about your problem

---

**Author**: Prasanna Patil  
**Version**: 1.0.0