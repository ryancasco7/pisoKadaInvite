# PisoKadaInvite - Invite and Earn Web Application

A modern, interactive web-based referral system where users can invite others and earn ₱1 for every click on their referral link.

## Features

- ✅ User registration and authentication
- ✅ IP address verification (max 3 accounts per device/IP)
- ✅ Unique referral link generation for each user
- ✅ Real-time earnings tracking (₱1 per click)
- ✅ Interactive dashboard with live updates
- ✅ Mobile-responsive design
- ✅ Beautiful, user-friendly interface
- ✅ Recent activity tracking

## Installation

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

3. Open your browser and navigate to:
```
http://localhost:3000
```

## How It Works

1. **Registration**: Users create an account (max 3 per IP address)
2. **Referral Link**: Each user gets a unique referral code and link
3. **Earning**: When someone clicks your referral link, you earn ₱1
4. **Tracking**: All earnings and clicks are tracked in real-time
5. **Dashboard**: View your earnings, clicks, and recent activity

## Technology Stack

- **Backend**: Node.js + Express
- **Database**: SQLite
- **Authentication**: JWT (JSON Web Tokens)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Security**: bcrypt for password hashing, IP tracking for spam prevention

## API Endpoints

- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `GET /api/dashboard` - Get user dashboard data
- `GET /api/refer/:code` - Handle referral link click
- `GET /api/earnings` - Get real-time earnings update
- `POST /api/check-ip` - Check IP address registration limit

## Security Features

- Password hashing with bcrypt
- JWT token-based authentication
- IP address tracking (max 3 accounts per IP)
- One click per IP per day limit (prevents spam)

## License

ISC

